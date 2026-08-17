use std::{cmp::min, sync::Arc, time::Duration as StdDuration};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{
    Connection, FromRow, PgConnection, PgPool, Postgres, Transaction,
    postgres::{PgListener, PgPoolOptions},
};
use tokio::{
    sync::watch,
    time::{Instant, sleep_until},
};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    config::Config,
    configuration_lock::{begin_configuration_shared_transaction, lock_configuration_shared},
    journal::{JournalIntent, OperationJournal},
    remote::{RemoteExecutor, RemoteOperation, RemoteResult, RemoteServer},
    state::{ControllerMode, SharedStatus},
};

const COMMAND_CHANNEL: &str = "ctfzone_runtime_commands";
const SETTINGS_CHANNEL: &str = "ctfzone_settings_changed";
const CHALLENGE_CHANNEL: &str = "ctfzone_challenge_runtime_changed";
const ACTIVE_INSPECTION_BATCH_SIZE: i64 = 64;

#[derive(Debug, FromRow)]
struct CommandRow {
    id: Uuid,
    claim_token: Uuid,
    instance_id: Uuid,
    kind: String,
    generation: i64,
    setting_revision: i64,
    challenge_runtime_revision: i64,
    payload: Value,
    attempts: i32,
}

#[derive(Debug, FromRow)]
struct InstanceRow {
    id: Uuid,
    owner_user_id: i32,
    challenge_id: i32,
    deployment_snapshot: Value,
    desired_state: String,
    desired_expires_at: DateTime<Utc>,
    maximum_expires_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    remote_server_id: Option<Uuid>,
    remote_container_id: Option<String>,
    generation: i64,
    active: bool,
}

#[derive(FromRow)]
struct OverdueRow {
    id: Uuid,
    generation: i64,
    private_challenges_revision: i64,
    challenge_runtime_revision: i64,
    owner_user_id: i32,
    expires_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct RuntimeGate {
    setting_enabled: bool,
    setting_revision: i64,
    runtime_enabled: bool,
    runtime_revision: i64,
}

pub(crate) async fn run(
    config: Config,
    status: SharedStatus,
    journal: Arc<OperationJournal>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let remote = RemoteExecutor::new(&config);
    let mut reconnect_delay = StdDuration::from_secs(2);
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let connection = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(StdDuration::from_secs(5))
            .connect(&config.database_url);
        let pool = match tokio::select! {
            result = connection => Some(result),
            () = wait_for_shutdown(&mut shutdown) => None,
        } {
            None => return Ok(()),
            Some(Ok(pool)) => pool,
            Some(Err(connection_error)) => {
                status
                    .database_disconnected(connection_error.to_string())
                    .await;
                if let Err(journal_error) = journal.cleanup_overdue_without_database(&remote).await
                {
                    error!(%journal_error, "degraded journal recovery failed");
                }
                if sleep_or_shutdown(reconnect_delay, &mut shutdown).await {
                    return Ok(());
                }
                reconnect_delay = min(reconnect_delay * 2, StdDuration::from_secs(60));
                continue;
            }
        };
        reconnect_delay = StdDuration::from_secs(2);
        status.database_connected().await;

        match connected_session(&config, &pool, &status, &journal, &remote, &mut shutdown).await {
            Ok(()) => return Ok(()),
            Err(session_error) => {
                warn!(%session_error, "controller database session ended; reconnecting");
                status
                    .database_disconnected(session_error.to_string())
                    .await;
                pool.close().await;
                if let Err(journal_error) = journal.cleanup_overdue_without_database(&remote).await
                {
                    error!(%journal_error, "degraded journal recovery failed");
                }
                if sleep_or_shutdown(reconnect_delay, &mut shutdown).await {
                    return Ok(());
                }
            }
        }
    }
}

async fn connected_session(
    config: &Config,
    pool: &PgPool,
    status: &SharedStatus,
    journal: &OperationJournal,
    remote: &RemoteExecutor,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    require_schema(pool).await?;
    let mut leadership_connection = PgConnection::connect(&config.database_url)
        .await
        .context("failed to acquire controller leadership connection")?;
    let leadership =
        sqlx::query("SELECT pg_advisory_lock(hashtextextended('ctfzone-controller-v1',0))")
            .execute(&mut leadership_connection);
    tokio::select! {
        result = leadership => {
            result.context("failed to acquire singleton controller lease")?;
        }
        () = wait_for_shutdown(shutdown) => return Ok(()),
    }

    let mut listener = PgListener::connect(&config.database_url)
        .await
        .context("failed to create PostgreSQL notification listener")?;
    listener.listen(COMMAND_CHANNEL).await?;
    listener.listen(SETTINGS_CHANNEL).await?;
    listener.listen(CHALLENGE_CHANNEL).await?;

    recover_all_claims_on_startup(pool).await?;
    journal.reconcile_database_acknowledgements(pool).await?;
    enqueue_policy_terminations(pool, config.reconciliation_interval).await?;
    enqueue_overdue_terminations(pool, config.reconciliation_interval).await?;
    enqueue_active_inspections(pool, None).await?;
    process_available_commands(
        pool,
        config,
        journal,
        remote,
        &mut leadership_connection,
        shutdown,
    )
    .await?;
    journal.reconcile_database_acknowledgements(pool).await?;
    status.reconciled().await;
    refresh_mode(pool, status).await?;
    info!("controller startup reconciliation completed");

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        sqlx::query("SELECT 1")
            .execute(&mut leadership_connection)
            .await
            .context("controller singleton lease connection was lost")?;
        recover_stale_claims(pool, config.stale_claim_after).await?;
        enqueue_policy_terminations(pool, config.reconciliation_interval).await?;
        enqueue_overdue_terminations(pool, config.reconciliation_interval).await?;
        enqueue_active_inspections(pool, Some(config.reconciliation_interval)).await?;
        process_available_commands(
            pool,
            config,
            journal,
            remote,
            &mut leadership_connection,
            shutdown,
        )
        .await?;
        journal.reconcile_database_acknowledgements(pool).await?;
        refresh_mode(pool, status).await?;

        let delay = next_wake_delay(
            pool,
            config.reconciliation_interval,
            config.stale_claim_after,
        )
        .await?;
        let deadline = Instant::now() + delay;
        tokio::select! {
            notification = listener.recv() => {
                let notification = notification.context("PostgreSQL notification listener disconnected")?;
                info!(channel = notification.channel(), payload = notification.payload(), "controller woke from PostgreSQL notification");
            }
            () = sleep_until(deadline) => {
                info!(waited_seconds = delay.as_secs(), "controller woke for deadline/reconciliation work");
                status.reconciled().await;
            }
            () = wait_for_shutdown(shutdown) => return Ok(()),
        }
    }
}

async fn require_schema(pool: &PgPool) -> Result<()> {
    let ready =
        sqlx::query_scalar::<_, bool>("SELECT to_regclass('ctfzone.runtime_commands') IS NOT NULL")
            .fetch_one(pool)
            .await?;
    if !ready {
        bail!("runtime control-plane schema is not installed");
    }
    Ok(())
}

async fn recover_stale_claims(pool: &PgPool, stale_after: StdDuration) -> Result<()> {
    let seconds = i64::try_from(stale_after.as_secs()).unwrap_or(i64::MAX);
    let result = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_commands
        SET status='pending', claimed_at=NULL, claim_token=NULL,
            available_at=now(), last_error='controller claim recovered after restart'
        WHERE status='claimed'
          AND claimed_at < now() - make_interval(secs => $1::double precision)
        "#,
    )
    .bind(seconds as f64)
    .execute(pool)
    .await?;
    if result.rows_affected() > 0 {
        warn!(
            count = result.rows_affected(),
            "recovered abandoned controller commands"
        );
    }
    Ok(())
}

async fn recover_all_claims_on_startup(pool: &PgPool) -> Result<()> {
    let result = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_commands
        SET status='pending', claimed_at=NULL, claim_token=NULL, available_at=now(),
            last_error='controller claim recovered during single-controller startup'
        WHERE status='claimed'
        "#,
    )
    .execute(pool)
    .await?;
    if result.rows_affected() > 0 {
        warn!(
            count = result.rows_affected(),
            "recovered controller claims during startup"
        );
    }
    Ok(())
}

async fn refresh_mode(pool: &PgPool, status: &SharedStatus) -> Result<()> {
    let (setting_enabled, managed_count, active_count) =
        sqlx::query_as::<_, (bool, i64, i64)>(
            r#"
            SELECT
                COALESCE((SELECT enabled FROM ctfzone.runtime_settings WHERE key='private_challenges'),false),
                (SELECT COUNT(*) FROM ctfzone.challenge_runtime_configs WHERE runtime_mode='managed' AND enabled),
                (SELECT COUNT(*) FROM ctfzone.runtime_instances WHERE active)
            "#,
        )
        .fetch_one(pool)
        .await?;
    let mode = if setting_enabled && managed_count > 0 {
        ControllerMode::Enabled
    } else if active_count > 0 {
        ControllerMode::Draining
    } else {
        ControllerMode::Dormant
    };
    status.set_mode(mode).await;
    Ok(())
}

async fn enqueue_policy_terminations(pool: &PgPool, safety_retry_after: StdDuration) -> Result<()> {
    let safety_retry_seconds = duration_seconds(safety_retry_after);
    let candidates = sqlx::query_as::<_, (Uuid, String)>(
        r#"
        SELECT i.id,i.desired_state
        FROM ctfzone.runtime_instances i
        LEFT JOIN ctfzone.challenge_runtime_configs r ON r.challenge_id=i.challenge_id
        WHERE i.active
          AND (
              i.desired_state='stopped'
              OR NOT COALESCE((SELECT enabled FROM ctfzone.runtime_settings WHERE key='private_challenges'),false)
              OR NOT COALESCE(r.enabled,false)
              OR COALESCE(r.runtime_mode,'static') <> 'managed'
          )
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.runtime_commands c
              WHERE c.instance_id=i.id AND c.kind='terminate' AND c.status IN ('pending','claimed')
          )
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.runtime_commands c
              WHERE c.instance_id=i.id AND c.kind='terminate' AND c.status='failed'
                AND c.completed_at > now() - make_interval(secs => $1::double precision)
          )
        ORDER BY i.created_at
        "#,
    )
    .bind(safety_retry_seconds as f64)
    .fetch_all(pool)
    .await?;
    for (id, desired_state) in candidates {
        let reason = if desired_state == "stopped" {
            "cleanup_safety_retry"
        } else {
            "runtime_policy_disabled"
        };
        create_termination_command(pool, id, reason).await?;
    }
    Ok(())
}

async fn enqueue_overdue_terminations(
    pool: &PgPool,
    safety_retry_after: StdDuration,
) -> Result<()> {
    let safety_retry_seconds = duration_seconds(safety_retry_after);
    let ids = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT i.id FROM ctfzone.runtime_instances i
        WHERE i.active AND i.expires_at <= now()
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.runtime_commands c
              WHERE c.instance_id=i.id AND c.kind='terminate' AND c.status IN ('pending','claimed')
          )
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.runtime_commands c
              WHERE c.instance_id=i.id AND c.kind='terminate' AND c.status='failed'
                AND c.completed_at > now() - make_interval(secs => $1::double precision)
          )
        ORDER BY i.expires_at
        "#,
    )
    .bind(safety_retry_seconds as f64)
    .fetch_all(pool)
    .await?;
    for id in ids {
        create_termination_command(pool, id, "absolute_deadline_reached").await?;
    }
    Ok(())
}

async fn enqueue_active_inspections(pool: &PgPool, minimum_age: Option<StdDuration>) -> Result<()> {
    let minimum_age_seconds = minimum_age.map(duration_seconds).map(|value| value as f64);
    let command_ids = sqlx::query_scalar::<_, Uuid>(
        r#"
        WITH candidates AS (
            SELECT i.id,i.generation,i.private_challenges_revision,
                   i.challenge_runtime_revision
            FROM ctfzone.runtime_instances i
            WHERE i.active
              AND i.desired_state='running'
              AND i.expires_at > now()
              AND i.remote_server_id IS NOT NULL
              AND i.observed_state IN ('ready','starting','unknown')
              AND (
                  $1::double precision IS NULL
                  OR COALESCE(i.last_observed_at,i.created_at)
                     <= now() - make_interval(secs => $1::double precision)
              )
              AND NOT EXISTS (
                  SELECT 1 FROM ctfzone.runtime_commands c
                  WHERE c.instance_id=i.id AND c.status IN ('pending','claimed')
              )
            ORDER BY i.last_observed_at NULLS FIRST,i.created_at,i.id
            LIMIT $2
        )
        INSERT INTO ctfzone.runtime_commands (
            instance_id,kind,generation,setting_revision,
            challenge_runtime_revision,payload,status,requested_by_user_id
        )
        SELECT id,'inspect',generation,private_challenges_revision,
               challenge_runtime_revision,'{}'::jsonb,'pending',NULL
        FROM candidates
        ON CONFLICT DO NOTHING
        RETURNING id
        "#,
    )
    .bind(minimum_age_seconds)
    .bind(ACTIVE_INSPECTION_BATCH_SIZE)
    .fetch_all(pool)
    .await?;
    if !command_ids.is_empty() {
        info!(
            count = command_ids.len(),
            startup = minimum_age.is_none(),
            "queued bounded active-instance inspections"
        );
    }
    Ok(())
}

async fn create_termination_command(pool: &PgPool, instance_id: Uuid, reason: &str) -> Result<()> {
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    let queued =
        create_termination_command_in_transaction(&mut transaction, instance_id, reason).await?;
    transaction.commit().await?;
    if let Some((command_id, owner_user_id)) = queued {
        info!(%instance_id, %command_id, %reason, owner_user_id, "queued controller safety termination");
    }
    Ok(())
}

async fn create_termination_command_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    instance_id: Uuid,
    reason: &str,
) -> Result<Option<(Uuid, i32)>> {
    // Keep this helper safe if a future caller supplies its own transaction.
    // The lock is re-entrant when the caller already used the fenced begin
    // helper, and it must precede the runtime row lock below.
    lock_configuration_shared(transaction).await?;
    let row = sqlx::query_as::<_, OverdueRow>(
        r#"
        SELECT id,generation,private_challenges_revision,
               challenge_runtime_revision,owner_user_id,expires_at
        FROM ctfzone.runtime_instances
        WHERE id=$1 AND active
        FOR UPDATE
        "#,
    )
    .bind(instance_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let already_queued = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM ctfzone.runtime_commands
            WHERE instance_id=$1 AND kind='terminate' AND status IN ('pending','claimed')
        )
        "#,
    )
    .bind(instance_id)
    .fetch_one(&mut **transaction)
    .await?;
    if already_queued {
        return Ok(None);
    }
    let generation = row.generation + 1;
    sqlx::query(
        "UPDATE ctfzone.runtime_instances SET desired_state='stopped',generation=$1 WHERE id=$2",
    )
    .bind(generation)
    .bind(instance_id)
    .execute(&mut **transaction)
    .await?;
    let command_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO ctfzone.runtime_commands (
            instance_id,kind,generation,setting_revision,
            challenge_runtime_revision,payload,status,requested_by_user_id
        ) VALUES ($1,'terminate',$2,$3,$4,$5,'pending',NULL)
        ON CONFLICT DO NOTHING
        RETURNING id
        "#,
    )
    .bind(row.id)
    .bind(generation)
    .bind(row.private_challenges_revision)
    .bind(row.challenge_runtime_revision)
    .bind(json!({"reason": reason, "deadline": row.expires_at}))
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(command_id) = command_id {
        append_event(
            transaction,
            row.id,
            "instance.termination_requested",
            "controller",
            None,
            json!({"reason": reason, "command_id": command_id}),
        )
        .await?;
        sqlx::query("SELECT pg_notify($1,$2)")
            .bind(COMMAND_CHANNEL)
            .bind(command_id.to_string())
            .execute(&mut **transaction)
            .await?;
        return Ok(Some((command_id, row.owner_user_id)));
    }
    Ok(None)
}

async fn process_available_commands(
    pool: &PgPool,
    config: &Config,
    journal: &OperationJournal,
    remote: &RemoteExecutor,
    leadership_connection: &mut PgConnection,
    shutdown: &watch::Receiver<bool>,
) -> Result<()> {
    // Deliberate v1 concurrency bound: one in-flight runtime command globally.
    // Together with the singleton PostgreSQL lease, this preserves per-instance
    // ordering. Host selection and placement are also committed under the
    // selected remote-server row lock. Do not add parallelism until
    // per-instance command ordering remains explicitly serialized.
    while !*shutdown.borrow() {
        // The advisory lock is bound to this dedicated connection. Check it
        // before every claim so a worker whose lease connection died cannot
        // drain more work through its independent pool.
        sqlx::query("SELECT 1")
            .execute(&mut *leadership_connection)
            .await
            .context("controller singleton lease connection was lost")?;
        let Some(command) = claim_command(pool).await? else {
            break;
        };
        let command_id = command.id;
        let command_kind = command.kind.clone();
        if let Err(command_error) = execute_command(pool, &command, journal, remote).await {
            warn!(%command_id, kind = %command_kind, %command_error, "controller command failed");
            schedule_retry(pool, &command, config, &command_error.to_string()).await?;
        }
    }
    Ok(())
}

async fn claim_command(pool: &PgPool) -> Result<Option<CommandRow>> {
    sqlx::query_as::<_, CommandRow>(
        r#"
        WITH candidate AS (
            SELECT id FROM ctfzone.runtime_commands
            WHERE status='pending' AND available_at <= now()
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE ctfzone.runtime_commands c
        SET status='claimed',claimed_at=now(),claim_token=gen_random_uuid(),
            attempts=c.attempts+1
        FROM candidate
        WHERE c.id=candidate.id
        RETURNING c.id,c.claim_token,c.instance_id,c.kind,c.generation,c.setting_revision,
                  c.challenge_runtime_revision,c.payload,c.attempts
        "#,
    )
    .fetch_optional(pool)
    .await
    .context("failed to claim controller command")
}

async fn execute_command(
    pool: &PgPool,
    command: &CommandRow,
    journal: &OperationJournal,
    remote: &RemoteExecutor,
) -> Result<()> {
    let instance = load_instance(pool, command.instance_id).await?;
    if command.generation != instance.generation {
        return cancel_stale_command(pool, command, &instance).await;
    }
    match command.kind.as_str() {
        "start" => execute_start(pool, command, &instance, journal, remote).await,
        "terminate" => execute_terminate(pool, command, &instance, journal, remote).await,
        "extend" => execute_extend(pool, command, &instance, journal, remote).await,
        "inspect" | "reconcile" => execute_inspect(pool, command, &instance, journal, remote).await,
        kind => bail!("unsupported command kind {kind}"),
    }
}

async fn load_instance(pool: &PgPool, id: Uuid) -> Result<InstanceRow> {
    sqlx::query_as::<_, InstanceRow>(
        r#"
        SELECT id,owner_user_id,challenge_id,deployment_snapshot,desired_state,
               desired_expires_at,maximum_expires_at,expires_at,
               remote_server_id,remote_container_id,generation,active
        FROM ctfzone.runtime_instances WHERE id=$1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .context("command refers to a missing runtime instance")
}

async fn execute_start(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    journal: &OperationJournal,
    remote: &RemoteExecutor,
) -> Result<()> {
    if !instance.active || instance.desired_state != "running" {
        return cancel_command(
            pool,
            command,
            "instance no longer desires a running workload",
        )
        .await;
    }
    if instance.desired_expires_at <= Utc::now() {
        return expire_unstarted_instance(pool, command, instance).await;
    }
    let gate = sqlx::query_as::<_, RuntimeGate>(
        r#"
        SELECT
            COALESCE(s.enabled,false) AS setting_enabled,
            COALESCE(s.revision,0) AS setting_revision,
            COALESCE(r.enabled,false) AND COALESCE(r.runtime_mode,'static')='managed' AS runtime_enabled,
            COALESCE(r.revision,0) AS runtime_revision
        FROM (SELECT 1) seed
        LEFT JOIN ctfzone.runtime_settings s ON s.key='private_challenges'
        LEFT JOIN ctfzone.challenge_runtime_configs r ON r.challenge_id=$1
        "#,
    )
    .bind(instance.challenge_id)
    .fetch_one(pool)
    .await?;
    if !gate.setting_enabled
        || !gate.runtime_enabled
        || command.setting_revision != gate.setting_revision
        || command.challenge_runtime_revision != gate.runtime_revision
    {
        return reject_start(pool, command, instance, &gate).await;
    }

    // `mark_starting` persists placement before the remote call. A reclaimed
    // command must reuse that host; selecting again could leave one generation
    // running on two hosts if the first claimant lost leadership in flight.
    let (server, marked_starting) = if let Some(server_id) = instance.remote_server_id {
        let server = load_remote_server(pool, server_id).await?;
        let marked = mark_starting(pool, command, instance, &server).await?;
        (server, marked)
    } else {
        match select_and_mark_starting(pool, command, instance).await? {
            Some(server) => (server, true),
            None => {
                return cancel_command(
                    pool,
                    command,
                    "instance generation changed before remote workload startup",
                )
                .await;
            }
        }
    };
    let payload = remote_payload(command, instance, RemoteOperation::EnsureInstance, "start");
    if !marked_starting {
        return cancel_command(
            pool,
            command,
            "instance generation changed before remote workload startup",
        )
        .await;
    }
    let intent = journal_intent(
        command,
        instance,
        RemoteOperation::EnsureInstance,
        Some(&server),
        &payload,
    );
    journal.intent(intent).await?;
    let result = remote
        .execute(&server, RemoteOperation::EnsureInstance, &payload)
        .await?;
    require_remote_generation(&result, command.generation, "startup")?;
    if result.absent == Some(true) || result.container_id.is_none() {
        bail!("remote helper did not confirm a running workload");
    }
    require_remote_ready(&result, "startup")?;
    journal
        .remote_result(
            journal_intent(
                command,
                instance,
                RemoteOperation::EnsureInstance,
                Some(&server),
                &payload,
            ),
            &result,
        )
        .await?;
    let committed = finish_start(pool, command, instance, &server, &result).await?;
    if !committed {
        let cleanup_payload = remote_payload(
            command,
            instance,
            RemoteOperation::StopInstance,
            "generation_changed_after_start",
        );
        let cleanup_intent = journal_intent(
            command,
            instance,
            RemoteOperation::StopInstance,
            Some(&server),
            &cleanup_payload,
        );
        journal.intent(cleanup_intent).await?;
        let cleanup_result = remote
            .execute(&server, RemoteOperation::StopInstance, &cleanup_payload)
            .await?;
        journal
            .remote_result(
                journal_intent(
                    command,
                    instance,
                    RemoteOperation::StopInstance,
                    Some(&server),
                    &cleanup_payload,
                ),
                &cleanup_result,
            )
            .await?;
        require_remote_removal(&cleanup_result, command.generation)?;
        cancel_command(
            pool,
            command,
            "instance generation changed while remote workload was starting",
        )
        .await?;
        journal
            .acknowledged(journal_intent(
                command,
                instance,
                RemoteOperation::StopInstance,
                Some(&server),
                &cleanup_payload,
            ))
            .await?;
    }
    journal
        .acknowledged(journal_intent(
            command,
            instance,
            RemoteOperation::EnsureInstance,
            Some(&server),
            &payload,
        ))
        .await?;
    Ok(())
}

async fn execute_terminate(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    journal: &OperationJournal,
    remote: &RemoteExecutor,
) -> Result<()> {
    if !instance.active {
        return complete_command(pool, command).await;
    }
    let server = if let Some(server_id) = instance.remote_server_id {
        Some(load_remote_server(pool, server_id).await?)
    } else {
        None
    };
    if !mark_stopping(pool, command, instance).await? {
        return cancel_command(
            pool,
            command,
            "instance generation changed before remote workload cleanup",
        )
        .await;
    }
    if let Some(server) = server.as_ref() {
        let payload = remote_payload(
            command,
            instance,
            RemoteOperation::StopInstance,
            "terminate",
        );
        journal
            .intent(journal_intent(
                command,
                instance,
                RemoteOperation::StopInstance,
                Some(server),
                &payload,
            ))
            .await?;
        let result = remote
            .execute(server, RemoteOperation::StopInstance, &payload)
            .await?;
        journal
            .remote_result(
                journal_intent(
                    command,
                    instance,
                    RemoteOperation::StopInstance,
                    Some(server),
                    &payload,
                ),
                &result,
            )
            .await?;
        require_remote_removal(&result, command.generation)?;
        if !finish_termination(pool, command, instance).await? {
            cancel_command(
                pool,
                command,
                "instance generation changed while remote workload was stopping",
            )
            .await?;
        }
        journal
            .acknowledged(journal_intent(
                command,
                instance,
                RemoteOperation::StopInstance,
                Some(server),
                &payload,
            ))
            .await?;
    } else if !finish_termination(pool, command, instance).await? {
        cancel_command(
            pool,
            command,
            "instance generation changed before local cleanup completion",
        )
        .await?;
    }
    Ok(())
}

async fn execute_extend(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    journal: &OperationJournal,
    remote: &RemoteExecutor,
) -> Result<()> {
    if !instance.active || instance.desired_state != "running" || instance.expires_at <= Utc::now()
    {
        return cancel_command(pool, command, "instance can no longer be extended").await;
    }
    let server_id = instance
        .remote_server_id
        .context("instance has no remote server for extension")?;
    let server = load_remote_server(pool, server_id).await?;
    let payload = remote_payload(command, instance, RemoteOperation::UpdateDeadline, "extend");
    journal
        .intent(journal_intent(
            command,
            instance,
            RemoteOperation::UpdateDeadline,
            Some(&server),
            &payload,
        ))
        .await?;
    let result = remote
        .execute(&server, RemoteOperation::UpdateDeadline, &payload)
        .await?;
    journal
        .remote_result(
            journal_intent(
                command,
                instance,
                RemoteOperation::UpdateDeadline,
                Some(&server),
                &payload,
            ),
            &result,
        )
        .await?;
    if result.stale_generation == Some(true) {
        bail!(
            "remote helper refused stale deadline generation {} (effective generation {:?})",
            command.generation,
            result.effective_generation
        );
    }
    require_remote_generation(&result, command.generation, "deadline update")?;
    if !finish_extension(pool, command, instance, &result).await? {
        cancel_command(
            pool,
            command,
            "instance generation changed while its deadline was being extended",
        )
        .await?;
    }
    journal
        .acknowledged(journal_intent(
            command,
            instance,
            RemoteOperation::UpdateDeadline,
            Some(&server),
            &payload,
        ))
        .await?;
    Ok(())
}

async fn execute_inspect(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    journal: &OperationJournal,
    remote: &RemoteExecutor,
) -> Result<()> {
    let Some(server_id) = instance.remote_server_id else {
        return cancel_command(pool, command, "instance has no remote server to inspect").await;
    };
    let server = load_remote_server(pool, server_id).await?;
    let payload = remote_payload(
        command,
        instance,
        RemoteOperation::InspectInstance,
        "inspect",
    );
    journal
        .intent(journal_intent(
            command,
            instance,
            RemoteOperation::InspectInstance,
            Some(&server),
            &payload,
        ))
        .await?;
    let result = remote
        .execute(&server, RemoteOperation::InspectInstance, &payload)
        .await?;
    if result.absent != Some(true) {
        require_remote_generation(&result, command.generation, "inspection")?;
    }
    journal
        .remote_result(
            journal_intent(
                command,
                instance,
                RemoteOperation::InspectInstance,
                Some(&server),
                &payload,
            ),
            &result,
        )
        .await?;
    if !finish_inspection(pool, command, instance, &result).await? {
        cancel_command(
            pool,
            command,
            "instance generation changed while remote workload was inspected",
        )
        .await?;
    }
    journal
        .acknowledged(journal_intent(
            command,
            instance,
            RemoteOperation::InspectInstance,
            Some(&server),
            &payload,
        ))
        .await?;
    Ok(())
}

fn remote_payload(
    command: &CommandRow,
    instance: &InstanceRow,
    operation: RemoteOperation,
    reason: &str,
) -> Value {
    let mut deployment = instance.deployment_snapshot.clone();
    if !matches!(operation, RemoteOperation::EnsureInstance) {
        if let Some(deployment) = deployment.as_object_mut() {
            deployment.remove("flag_value");
        }
    }
    json!({
        "instance_id": instance.id,
        "owner_user_id": instance.owner_user_id,
        "challenge_id": instance.challenge_id,
        "generation": command.generation,
        "expires_at": instance.desired_expires_at,
        "maximum_expires_at": instance.maximum_expires_at,
        "deployment": deployment,
        "reason": reason,
        "command_payload": command.payload,
        "remote_container_id": instance.remote_container_id,
    })
}

fn require_remote_removal(result: &RemoteResult, generation: i64) -> Result<()> {
    if result.stale_generation == Some(true) {
        bail!(
            "remote helper refused stale cleanup generation {generation} (effective generation {:?})",
            result.effective_generation
        );
    }
    if result.absent != Some(true) {
        bail!("remote helper did not confirm workload removal");
    }
    Ok(())
}

fn require_remote_generation(
    result: &RemoteResult,
    generation: i64,
    operation: &str,
) -> Result<()> {
    if result.stale_generation == Some(true) || result.effective_generation != Some(generation) {
        bail!(
            "remote {operation} generation mismatch: expected {generation}, got {:?}",
            result.effective_generation
        );
    }
    Ok(())
}

fn require_remote_ready(result: &RemoteResult, operation: &str) -> Result<()> {
    if result.ready != Some(true) {
        bail!(
            "remote {operation} did not report a ready workload (runtime status {:?}, health status {:?})",
            result.runtime_status,
            result.health_status
        );
    }
    Ok(())
}

fn journal_intent<'a>(
    command: &CommandRow,
    instance: &InstanceRow,
    operation: RemoteOperation,
    remote_server: Option<&'a RemoteServer>,
    payload: &'a Value,
) -> JournalIntent<'a> {
    JournalIntent {
        instance_id: instance.id,
        command_id: command.id,
        generation: command.generation,
        setting_revision: command.setting_revision,
        challenge_runtime_revision: command.challenge_runtime_revision,
        operation,
        remote_server,
        effective_expires_at: instance.desired_expires_at,
        payload,
    }
}

async fn select_remote_server_locked(
    transaction: &mut Transaction<'_, Postgres>,
    snapshot: &Value,
) -> Result<RemoteServer> {
    let requested_pool = snapshot.get("remote_pool").and_then(Value::as_str);
    sqlx::query_as::<_, RemoteServer>(
        r#"
        SELECT s.id,s.name,s.hostname,s.ssh_port,s.ssh_user,s.helper_path,
               s.identity_file,s.host_key_alias,s.pool,s.capacity
        FROM ctfzone.remote_servers s
        WHERE s.enabled AND ($1::text IS NULL OR s.pool=$1)
          AND (
              SELECT COUNT(*) FROM ctfzone.runtime_instances i
              WHERE i.remote_server_id=s.id AND i.active
          ) < s.capacity
        ORDER BY (
            SELECT COUNT(*) FROM ctfzone.runtime_instances i
            WHERE i.remote_server_id=s.id AND i.active
        ),s.name
        FOR UPDATE OF s SKIP LOCKED
        LIMIT 1
        "#,
    )
    .bind(requested_pool)
    .fetch_optional(&mut **transaction)
    .await?
    .context("no enabled remote server has available capacity")
}

async fn load_remote_server(pool: &PgPool, id: Uuid) -> Result<RemoteServer> {
    sqlx::query_as::<_, RemoteServer>(
        r#"
        SELECT id,name,hostname,ssh_port,ssh_user,helper_path,identity_file,
               host_key_alias,pool,capacity
        FROM ctfzone.remote_servers WHERE id=$1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .context("instance remote server no longer exists")
}

async fn mark_starting(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    server: &RemoteServer,
) -> Result<bool> {
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    if !lock_command_claim(&mut transaction, command).await? {
        transaction.rollback().await?;
        return Ok(false);
    }
    let update = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET observed_state='starting',
            remote_server_id=$1,activated_at=COALESCE(activated_at,now()),
            last_observed_at=now(),failure_code=NULL,failure_message=NULL
        WHERE id=$2 AND generation=$3 AND active AND desired_state='running'
        "#,
    )
    .bind(server.id)
    .bind(instance.id)
    .bind(command.generation)
    .execute(&mut *transaction)
    .await?;
    if update.rows_affected() == 0 {
        transaction.rollback().await?;
        return Ok(false);
    }
    append_event(
        &mut transaction,
        instance.id,
        "instance.starting",
        "controller",
        None,
        json!({"command_id": command.id, "remote_server_id": server.id}),
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}

async fn select_and_mark_starting(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
) -> Result<Option<RemoteServer>> {
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    if !lock_command_claim(&mut transaction, command).await? {
        transaction.rollback().await?;
        return Ok(None);
    }
    let server =
        select_remote_server_locked(&mut transaction, &instance.deployment_snapshot).await?;
    let update = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET observed_state='starting',
            remote_server_id=$1,activated_at=COALESCE(activated_at,now()),
            last_observed_at=now(),failure_code=NULL,failure_message=NULL
        WHERE id=$2 AND generation=$3 AND active AND desired_state='running'
        "#,
    )
    .bind(server.id)
    .bind(instance.id)
    .bind(command.generation)
    .execute(&mut *transaction)
    .await?;
    if update.rows_affected() == 0 {
        transaction.rollback().await?;
        return Ok(None);
    }
    append_event(
        &mut transaction,
        instance.id,
        "instance.starting",
        "controller",
        None,
        json!({"command_id": command.id, "remote_server_id": server.id}),
    )
    .await?;
    transaction.commit().await?;
    Ok(Some(server))
}

async fn finish_start(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    server: &RemoteServer,
    result: &RemoteResult,
) -> Result<bool> {
    let effective_expires_at = result
        .effective_expires_at
        .unwrap_or(instance.desired_expires_at);
    if effective_expires_at > instance.maximum_expires_at {
        bail!("remote helper returned a deadline beyond the maximum lifetime");
    }
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    if !lock_command_claim(&mut transaction, command).await? {
        transaction.rollback().await?;
        bail!("runtime command claim lease was lost after remote startup");
    }
    let update = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET
            observed_state='ready',observed_generation=$1,
            observed_expires_at=$2,expires_at=$2,remote_server_id=$3,
            remote_container_id=$4,remote_ip=$5::inet,container_port=$6,
            published_ip=$7::inet,published_port=$8,protocol=COALESCE($9,protocol),
            public_hostname=$10,endpoint_url=$11,ready_at=COALESCE(ready_at,now()),
            last_observed_at=now(),failure_code=NULL,failure_message=NULL
        WHERE id=$12 AND generation=$1
        "#,
    )
    .bind(command.generation)
    .bind(effective_expires_at)
    .bind(server.id)
    .bind(&result.container_id)
    .bind(&result.remote_ip)
    .bind(result.container_port)
    .bind(&result.published_ip)
    .bind(result.published_port)
    .bind(&result.protocol)
    .bind(&result.public_hostname)
    .bind(&result.endpoint_url)
    .bind(instance.id)
    .execute(&mut *transaction)
    .await?;
    if update.rows_affected() == 0 {
        transaction.rollback().await?;
        return Ok(false);
    }
    append_event(
        &mut transaction,
        instance.id,
        "instance.ready",
        "controller",
        None,
        json!({
            "command_id": command.id,
            "remote_server_id": server.id,
            "expires_at": effective_expires_at,
            "published_ip": result.published_ip,
            "published_port": result.published_port,
            "endpoint_url": result.endpoint_url,
        }),
    )
    .await?;
    mark_command_completed(&mut transaction, command).await?;
    transaction.commit().await?;
    Ok(true)
}

async fn mark_stopping(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
) -> Result<bool> {
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    if !lock_command_claim(&mut transaction, command).await? {
        transaction.rollback().await?;
        return Ok(false);
    }
    let update = sqlx::query(
        "UPDATE ctfzone.runtime_instances SET observed_state='stopping',last_observed_at=now() WHERE id=$1 AND generation=$2 AND active",
    )
    .bind(instance.id)
    .bind(command.generation)
    .execute(&mut *transaction)
    .await?;
    if update.rows_affected() == 0 {
        transaction.rollback().await?;
        return Ok(false);
    }
    append_event(
        &mut transaction,
        instance.id,
        "instance.stopping",
        "controller",
        None,
        json!({"command_id": command.id}),
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}

async fn finish_termination(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
) -> Result<bool> {
    let expired = instance.expires_at <= Utc::now()
        || command.payload.get("reason").and_then(Value::as_str)
            == Some("absolute_deadline_reached");
    let observed_state = if expired { "expired" } else { "terminated" };
    let event_type = if expired {
        "instance.expired"
    } else {
        "instance.terminated"
    };
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    if !lock_command_claim(&mut transaction, command).await? {
        transaction.rollback().await?;
        return Ok(false);
    }
    let update = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET active=false,desired_state='stopped',
            observed_state=$1,observed_generation=$2,last_observed_at=now(),
            stopped_at=now(),failure_code=NULL,failure_message=NULL
        WHERE id=$3 AND generation=$2 AND active
        "#,
    )
    .bind(observed_state)
    .bind(command.generation)
    .bind(instance.id)
    .execute(&mut *transaction)
    .await?;
    if update.rows_affected() == 0 {
        transaction.rollback().await?;
        return Ok(false);
    }
    append_event(
        &mut transaction,
        instance.id,
        event_type,
        "controller",
        None,
        json!({"command_id": command.id, "intended_expires_at": instance.expires_at}),
    )
    .await?;
    append_event(
        &mut transaction,
        instance.id,
        "instance.cleanup_completed",
        "controller",
        None,
        json!({"command_id": command.id}),
    )
    .await?;
    mark_command_completed(&mut transaction, command).await?;
    transaction.commit().await?;
    Ok(true)
}

async fn finish_extension(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    result: &RemoteResult,
) -> Result<bool> {
    let effective = result
        .effective_expires_at
        .unwrap_or(instance.desired_expires_at);
    if effective > instance.maximum_expires_at || effective <= Utc::now() {
        bail!("remote helper returned an invalid extended deadline");
    }
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    if !lock_command_claim(&mut transaction, command).await? {
        transaction.rollback().await?;
        return Ok(false);
    }
    let update = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET observed_expires_at=$1,expires_at=$1,
            observed_generation=$2,last_observed_at=now(),failure_code=NULL,failure_message=NULL
        WHERE id=$3 AND generation=$2 AND active
        "#,
    )
    .bind(effective)
    .bind(command.generation)
    .bind(instance.id)
    .execute(&mut *transaction)
    .await?;
    if update.rows_affected() == 0 {
        transaction.rollback().await?;
        return Ok(false);
    }
    append_event(
        &mut transaction,
        instance.id,
        "instance.extended",
        "controller",
        None,
        json!({"command_id": command.id, "expires_at": effective}),
    )
    .await?;
    mark_command_completed(&mut transaction, command).await?;
    transaction.commit().await?;
    Ok(true)
}

async fn finish_inspection(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    result: &RemoteResult,
) -> Result<bool> {
    let absent = result.absent.unwrap_or(false);
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    if !lock_command_claim(&mut transaction, command).await? {
        transaction.rollback().await?;
        return Ok(false);
    }
    let mut cleanup_queued = None;
    if absent {
        let expired = instance.expires_at <= Utc::now() || instance.desired_state == "stopped";
        let update = sqlx::query(
            r#"
            UPDATE ctfzone.runtime_instances SET active=false,
                observed_state=$1,stopped_at=now(),last_observed_at=now(),
                failure_code=CASE WHEN $1='failed' THEN 'remote_workload_missing' ELSE NULL END
            WHERE id=$2 AND generation=$3 AND active
            "#,
        )
        .bind(if expired { "expired" } else { "failed" })
        .bind(instance.id)
        .bind(command.generation)
        .execute(&mut *transaction)
        .await?;
        if update.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(false);
        }
        append_event(
            &mut transaction,
            instance.id,
            if expired {
                "instance.expired"
            } else {
                "instance.failed"
            },
            "controller",
            None,
            json!({"command_id": command.id, "reason": "remote_workload_absent"}),
        )
        .await?;
    } else if result.ready != Some(true) {
        let message = truncate(
            &format!(
                "remote workload is not ready (runtime status {:?}, health status {:?})",
                result.runtime_status, result.health_status
            ),
            1000,
        );
        let update = sqlx::query(
            r#"
            UPDATE ctfzone.runtime_instances SET observed_state='cleanup_pending',
                failure_code='remote_workload_not_ready',failure_message=$1,
                last_observed_at=now()
            WHERE id=$2 AND generation=$3 AND active
            "#,
        )
        .bind(&message)
        .bind(instance.id)
        .bind(command.generation)
        .execute(&mut *transaction)
        .await?;
        if update.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(false);
        }
        append_event(
            &mut transaction,
            instance.id,
            "instance.failed",
            "controller",
            None,
            json!({
                "command_id": command.id,
                "reason": "remote_workload_not_ready",
                "runtime_status": result.runtime_status,
                "health_status": result.health_status,
            }),
        )
        .await?;
        cleanup_queued = create_termination_command_in_transaction(
            &mut transaction,
            instance.id,
            "remote_workload_not_ready",
        )
        .await?;
    } else {
        let update = sqlx::query(
            "UPDATE ctfzone.runtime_instances SET observed_state='ready',last_observed_at=now(),observed_generation=$1 WHERE id=$2 AND generation=$1 AND active",
        )
        .bind(command.generation)
        .bind(instance.id)
        .execute(&mut *transaction)
        .await?;
        if update.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(false);
        }
        append_event(
            &mut transaction,
            instance.id,
            "instance.reconciled",
            "controller",
            None,
            json!({"command_id": command.id}),
        )
        .await?;
    }
    mark_command_completed(&mut transaction, command).await?;
    transaction.commit().await?;
    if let Some((command_id, owner_user_id)) = cleanup_queued {
        info!(
            instance_id = %instance.id,
            %command_id,
            owner_user_id,
            "queued cleanup for a non-ready remote workload"
        );
    }
    Ok(true)
}

async fn reject_start(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    gate: &RuntimeGate,
) -> Result<()> {
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    if !lock_command_claim(&mut transaction, command).await? {
        transaction.rollback().await?;
        return Ok(());
    }
    let update = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET active=false,desired_state='stopped',
            observed_state='failed',stopped_at=now(),last_observed_at=now(),
            failure_code='runtime_policy_stale',
            failure_message='Runtime policy changed before launch'
        WHERE id=$1 AND generation=$2 AND observed_state='requested' AND active
        "#,
    )
    .bind(instance.id)
    .bind(command.generation)
    .execute(&mut *transaction)
    .await?;
    if update.rows_affected() > 0 {
        append_event(
            &mut transaction,
            instance.id,
            "instance.failed",
            "controller",
            None,
            json!({
                "command_id": command.id,
                "reason": "runtime_policy_stale",
                "current_setting_revision": gate.setting_revision,
                "current_runtime_revision": gate.runtime_revision,
            }),
        )
        .await?;
    }
    mark_command_cancelled(
        &mut transaction,
        command,
        "runtime policy changed before launch",
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn expire_unstarted_instance(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
) -> Result<()> {
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    if !lock_command_claim(&mut transaction, command).await? {
        transaction.rollback().await?;
        return Ok(());
    }
    let update = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET active=false,desired_state='stopped',
            observed_state='expired',observed_generation=$1,stopped_at=now(),
            last_observed_at=now(),failure_code=NULL,failure_message=NULL
        WHERE id=$2 AND generation=$1 AND observed_state='requested' AND active
        "#,
    )
    .bind(command.generation)
    .bind(instance.id)
    .execute(&mut *transaction)
    .await?;
    if update.rows_affected() > 0 {
        append_event(
            &mut transaction,
            instance.id,
            "instance.expired",
            "controller",
            None,
            json!({"command_id": command.id, "reason": "deadline_elapsed_before_launch"}),
        )
        .await?;
    }
    mark_command_cancelled(&mut transaction, command, "deadline elapsed before launch").await?;
    transaction.commit().await?;
    Ok(())
}

async fn cancel_stale_command(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
) -> Result<()> {
    let mut transaction = begin_configuration_shared_transaction(pool).await?;
    if !lock_command_claim(&mut transaction, command).await? {
        transaction.rollback().await?;
        return Ok(());
    }
    mark_command_cancelled(&mut transaction, command, "stale generation").await?;
    append_event(
        &mut transaction,
        instance.id,
        "command.cancelled",
        "controller",
        None,
        json!({"command_id": command.id, "reason": "stale_generation", "current_generation": instance.generation}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn cancel_command(pool: &PgPool, command: &CommandRow, reason: &str) -> Result<()> {
    let result = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_commands
        SET status='cancelled',claimed_at=NULL,claim_token=NULL,
            completed_at=now(),last_error=$1
        WHERE id=$2 AND status='claimed' AND claim_token=$3
        "#,
    )
    .bind(reason)
    .bind(command.id)
    .bind(command.claim_token)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        info!(command_id = %command.id, "ignored cancellation from a stale command claimant");
    }
    Ok(())
}

async fn complete_command(pool: &PgPool, command: &CommandRow) -> Result<()> {
    let result = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_commands
        SET status='completed',claimed_at=NULL,claim_token=NULL,
            completed_at=now(),last_error=NULL
        WHERE id=$1 AND status='claimed' AND claim_token=$2
        "#,
    )
    .bind(command.id)
    .bind(command.claim_token)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        info!(command_id = %command.id, "ignored completion from a stale command claimant");
    }
    Ok(())
}

async fn lock_command_claim(
    transaction: &mut Transaction<'_, Postgres>,
    command: &CommandRow,
) -> Result<bool> {
    let held = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT id FROM ctfzone.runtime_commands
        WHERE id=$1 AND status='claimed' AND claim_token=$2
        FOR UPDATE
        "#,
    )
    .bind(command.id)
    .bind(command.claim_token)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(held.is_some())
}

async fn mark_command_cancelled(
    transaction: &mut Transaction<'_, Postgres>,
    command: &CommandRow,
    reason: &str,
) -> Result<()> {
    let result = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_commands
        SET status='cancelled',claimed_at=NULL,claim_token=NULL,
            completed_at=now(),last_error=$1
        WHERE id=$2 AND status='claimed' AND claim_token=$3
        "#,
    )
    .bind(reason)
    .bind(command.id)
    .bind(command.claim_token)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        bail!("runtime command claim lease was lost while cancelling work");
    }
    Ok(())
}

async fn mark_command_completed(
    transaction: &mut Transaction<'_, Postgres>,
    command: &CommandRow,
) -> Result<()> {
    let result = sqlx::query(
        r#"
        UPDATE ctfzone.runtime_commands
        SET status='completed',claimed_at=NULL,claim_token=NULL,
            completed_at=now(),last_error=NULL
        WHERE id=$1 AND status='claimed' AND claim_token=$2
        "#,
    )
    .bind(command.id)
    .bind(command.claim_token)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        bail!("runtime command claim lease was lost before completion");
    }
    Ok(())
}

async fn schedule_retry(
    pool: &PgPool,
    command: &CommandRow,
    config: &Config,
    message: &str,
) -> Result<()> {
    let message = truncate(message, 1000);
    if command.attempts >= config.max_command_attempts {
        let mut transaction = begin_configuration_shared_transaction(pool).await?;
        let failed = sqlx::query(
            r#"
            UPDATE ctfzone.runtime_commands
            SET status='failed',claimed_at=NULL,claim_token=NULL,
                completed_at=now(),last_error=$1
            WHERE id=$2 AND status='claimed' AND claim_token=$3
            "#,
        )
        .bind(&message)
        .bind(command.id)
        .bind(command.claim_token)
        .execute(&mut *transaction)
        .await?;
        if failed.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(());
        }
        let state = match command.kind.as_str() {
            "extend" => "ready",
            "inspect" | "reconcile" => "unknown",
            _ => "cleanup_pending",
        };
        let instance_update = sqlx::query(
            "UPDATE ctfzone.runtime_instances SET observed_state=$1,failure_code='command_failed',failure_message=$2,last_observed_at=now() WHERE id=$3 AND generation=$4 AND active",
        )
        .bind(state)
        .bind(&message)
        .bind(command.instance_id)
        .bind(command.generation)
        .execute(&mut *transaction)
        .await?;
        let start_cleanup_required = command.kind == "start" && instance_update.rows_affected() > 0;
        if instance_update.rows_affected() > 0 {
            append_event(
                &mut transaction,
                command.instance_id,
                "instance.failed",
                "controller",
                None,
                json!({"command_id": command.id, "kind": command.kind, "error": message}),
            )
            .await?;
        }
        let cleanup_queued = if start_cleanup_required {
            create_termination_command_in_transaction(
                &mut transaction,
                command.instance_id,
                "start_command_failed",
            )
            .await?
        } else {
            None
        };
        transaction.commit().await?;
        if let Some((command_id, owner_user_id)) = cleanup_queued {
            info!(
                instance_id = %command.instance_id,
                %command_id,
                owner_user_id,
                "atomically queued cleanup after terminal start failure"
            );
        }
        return Ok(());
    }
    let backoff_seconds = retry_backoff_seconds(command.attempts);
    sqlx::query(
        r#"
        UPDATE ctfzone.runtime_commands SET status='pending',claimed_at=NULL,claim_token=NULL,
            available_at=now() + make_interval(secs => $1::double precision),last_error=$2
        WHERE id=$3 AND status='claimed' AND claim_token=$4
        "#,
    )
    .bind(backoff_seconds as f64)
    .bind(message)
    .bind(command.id)
    .bind(command.claim_token)
    .execute(pool)
    .await?;
    Ok(())
}

async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    instance_id: Uuid,
    event_type: &str,
    source: &str,
    actor_user_id: Option<i32>,
    payload: Value,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO ctfzone.runtime_instance_events
            (instance_id,event_type,source,actor_user_id,payload)
        VALUES ($1,$2,$3,$4,$5)
        "#,
    )
    .bind(instance_id)
    .bind(event_type)
    .bind(source)
    .bind(actor_user_id)
    .bind(payload)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn next_wake_delay(
    pool: &PgPool,
    maximum: StdDuration,
    stale_claim_after: StdDuration,
) -> Result<StdDuration> {
    let command_time = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT MIN(available_at) FROM ctfzone.runtime_commands WHERE status='pending'",
    )
    .fetch_one(pool)
    .await?;
    let deadline = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT MIN(expires_at) FROM ctfzone.runtime_instances WHERE active AND expires_at > now()",
    )
    .fetch_one(pool)
    .await?;
    let safety_retry = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        r#"
        SELECT MIN(f.last_failed + make_interval(secs => $1::double precision))
        FROM (
            SELECT instance_id,MAX(completed_at) AS last_failed
            FROM ctfzone.runtime_commands
            WHERE kind='terminate' AND status='failed' AND completed_at IS NOT NULL
            GROUP BY instance_id
        ) f
        JOIN ctfzone.runtime_instances i ON i.id=f.instance_id AND i.active
        WHERE f.last_failed + make_interval(secs => $1::double precision) > now()
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.runtime_commands c
              WHERE c.instance_id=f.instance_id AND c.kind='terminate'
                AND c.status IN ('pending','claimed')
          )
        "#,
    )
    .bind(duration_seconds(maximum) as f64)
    .fetch_one(pool)
    .await?;
    let stale_claim = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        r#"
        SELECT MIN(claimed_at + make_interval(secs => $1::double precision))
        FROM ctfzone.runtime_commands
        WHERE status='claimed' AND claimed_at IS NOT NULL
          AND claimed_at + make_interval(secs => $1::double precision) > now()
        "#,
    )
    .bind(duration_seconds(stale_claim_after) as f64)
    .fetch_one(pool)
    .await?;
    let next = [command_time, deadline, safety_retry, stale_claim]
        .into_iter()
        .flatten()
        .min();
    let until_next = next
        .map(|next| {
            (next - Utc::now())
                .to_std()
                .unwrap_or_else(|_| StdDuration::from_millis(10))
        })
        .unwrap_or(maximum);
    Ok(min(until_next, maximum))
}

fn duration_seconds(duration: StdDuration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

fn retry_backoff_seconds(attempts: i32) -> i64 {
    let exponent = u32::try_from(attempts.clamp(1, 6)).unwrap_or(6);
    min(5_i64 * 2_i64.pow(exponent), 300)
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn sleep_or_shutdown(duration: StdDuration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = sleep_until(Instant::now() + duration) => false,
        () = wait_for_shutdown(shutdown) => true,
    }
}

fn truncate(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_runtime_instance_writer_takes_the_configuration_fence_first() {
        let source = include_str!("worker.rs")
            .split("\n#[cfg(test)]")
            .next()
            .expect("worker source must contain production code");
        let mut writers = 0;
        for function in source.split("async fn ").skip(1) {
            let mutation = [
                "UPDATE ctfzone.runtime_instances",
                "INSERT INTO ctfzone.runtime_instances",
                "DELETE FROM ctfzone.runtime_instances",
            ]
            .into_iter()
            .filter_map(|marker| function.find(marker))
            .min();
            let Some(mutation) = mutation else {
                continue;
            };
            writers += 1;
            let fence = [
                "begin_configuration_shared_transaction(pool)",
                "lock_configuration_shared(transaction)",
            ]
            .into_iter()
            .filter_map(|marker| function.find(marker))
            .min()
            .expect("runtime_instances writer is missing the CONFIG-S fence");
            assert!(
                fence < mutation,
                "runtime_instances writer takes the CONFIG-S fence after its mutation"
            );
        }
        assert!(
            writers > 0,
            "runtime writer audit did not inspect any writers"
        );
        assert!(
            !source.contains("let mut transaction = pool.begin().await?"),
            "runtime worker transactions must use the CONFIG-S fenced begin helper"
        );
    }

    #[test]
    fn new_placement_locks_the_remote_host_before_persisting_it() {
        let source = include_str!("worker.rs");
        let selector = source
            .split("async fn select_remote_server_locked")
            .nth(1)
            .and_then(|tail| tail.split("async fn load_remote_server").next())
            .expect("locked remote-server selector must exist");
        assert!(selector.contains("FOR UPDATE OF s SKIP LOCKED"));

        let placement = source
            .split("async fn select_and_mark_starting")
            .nth(1)
            .and_then(|tail| tail.split("async fn finish_start").next())
            .expect("atomic placement function must exist");
        let lock = placement
            .find("select_remote_server_locked")
            .expect("placement must lock its selected host");
        let update = placement
            .find("UPDATE ctfzone.runtime_instances")
            .expect("placement must persist the selected host");
        assert!(lock < update);
    }

    #[test]
    fn truncates_errors_on_character_boundaries() {
        assert_eq!(truncate("aé日", 2), "aé");
    }

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(retry_backoff_seconds(1), 10);
        assert_eq!(retry_backoff_seconds(2), 20);
        assert_eq!(retry_backoff_seconds(8), 300);
        assert_eq!(retry_backoff_seconds(i32::MAX), 300);
    }

    #[test]
    fn cleanup_requires_confirmed_absence_and_rejects_stale_generation() {
        let removed = RemoteResult {
            absent: Some(true),
            ..RemoteResult::default()
        };
        assert!(require_remote_removal(&removed, 2).is_ok());

        let uncertain = RemoteResult::default();
        assert!(require_remote_removal(&uncertain, 2).is_err());

        let stale = RemoteResult {
            absent: Some(false),
            stale_generation: Some(true),
            effective_generation: Some(3),
            ..RemoteResult::default()
        };
        assert!(require_remote_removal(&stale, 2).is_err());
    }

    #[test]
    fn live_remote_results_require_the_exact_generation() {
        let exact = RemoteResult {
            effective_generation: Some(4),
            ..RemoteResult::default()
        };
        assert!(require_remote_generation(&exact, 4, "inspection").is_ok());
        assert!(require_remote_generation(&exact, 3, "inspection").is_err());
        assert!(require_remote_generation(&RemoteResult::default(), 4, "inspection").is_err());
    }

    #[test]
    fn remote_readiness_must_be_explicit() {
        let ready = RemoteResult {
            ready: Some(true),
            ..RemoteResult::default()
        };
        assert!(require_remote_ready(&ready, "startup").is_ok());

        let exited = RemoteResult {
            ready: Some(false),
            runtime_status: Some("exited".to_owned()),
            ..RemoteResult::default()
        };
        assert!(require_remote_ready(&exited, "startup").is_err());
        assert!(require_remote_ready(&RemoteResult::default(), "startup").is_err());
    }

    #[test]
    fn personalized_flag_is_dispatched_only_for_instance_startup() {
        let now = Utc::now();
        let instance_id = Uuid::new_v4();
        let command = CommandRow {
            id: Uuid::new_v4(),
            claim_token: Uuid::new_v4(),
            instance_id,
            kind: "start".to_owned(),
            generation: 1,
            setting_revision: 1,
            challenge_runtime_revision: 1,
            payload: json!({}),
            attempts: 1,
        };
        let instance = InstanceRow {
            id: instance_id,
            owner_user_id: 7,
            challenge_id: 11,
            deployment_snapshot: json!({
                "image_digest": format!("example/challenge@sha256:{}", "a".repeat(64)),
                "container_port": 31337,
                "flag_value": "flag{personalized-secret}",
            }),
            desired_state: "running".to_owned(),
            desired_expires_at: now,
            maximum_expires_at: now,
            expires_at: now,
            remote_server_id: None,
            remote_container_id: None,
            generation: 1,
            active: true,
        };

        let start = remote_payload(
            &command,
            &instance,
            RemoteOperation::EnsureInstance,
            "start",
        );
        assert_eq!(
            start
                .pointer("/deployment/flag_value")
                .and_then(Value::as_str),
            Some("flag{personalized-secret}")
        );

        for operation in [
            RemoteOperation::InspectInstance,
            RemoteOperation::StopInstance,
            RemoteOperation::UpdateDeadline,
        ] {
            let payload = remote_payload(&command, &instance, operation, "non-start");
            assert!(payload.pointer("/deployment/flag_value").is_none());
            assert_eq!(
                payload
                    .pointer("/deployment/container_port")
                    .and_then(Value::as_i64),
                Some(31337)
            );
            assert!(!payload.to_string().contains("personalized-secret"));
        }
    }
}
