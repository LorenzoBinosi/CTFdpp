use std::{cmp::min, sync::Arc, time::Duration as StdDuration};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{
    FromRow, PgPool, Postgres, Transaction,
    postgres::{PgListener, PgPoolOptions},
};
use tokio::time::{Instant, sleep, sleep_until};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    config::Config,
    journal::{JournalIntent, OperationJournal},
    remote::{RemoteExecutor, RemoteOperation, RemoteResult, RemoteServer},
    state::{ControllerMode, SharedStatus},
};

const COMMAND_CHANNEL: &str = "ctfzone_runtime_commands";
const SETTINGS_CHANNEL: &str = "ctfzone_settings_changed";
const CHALLENGE_CHANNEL: &str = "ctfzone_challenge_runtime_changed";

#[derive(Debug, FromRow)]
struct CommandRow {
    id: Uuid,
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

pub(crate) async fn run(config: Config, status: SharedStatus, journal: Arc<OperationJournal>) {
    let remote = RemoteExecutor::new(&config);
    let mut reconnect_delay = StdDuration::from_secs(2);
    loop {
        let pool = match PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(StdDuration::from_secs(5))
            .connect(&config.database_url)
            .await
        {
            Ok(pool) => pool,
            Err(connection_error) => {
                status
                    .database_disconnected(connection_error.to_string())
                    .await;
                if let Err(journal_error) = journal.cleanup_overdue_without_database(&remote).await
                {
                    error!(%journal_error, "degraded journal recovery failed");
                }
                sleep(reconnect_delay).await;
                reconnect_delay = min(reconnect_delay * 2, StdDuration::from_secs(60));
                continue;
            }
        };
        reconnect_delay = StdDuration::from_secs(2);
        status.database_connected().await;

        match connected_session(&config, &pool, &status, &journal, &remote).await {
            Ok(()) => return,
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
                sleep(reconnect_delay).await;
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
) -> Result<()> {
    require_schema(pool).await?;
    recover_stale_claims(pool, config.stale_claim_after).await?;

    let mut listener = PgListener::connect(&config.database_url)
        .await
        .context("failed to create PostgreSQL notification listener")?;
    listener.listen(COMMAND_CHANNEL).await?;
    listener.listen(SETTINGS_CHANNEL).await?;
    listener.listen(CHALLENGE_CHANNEL).await?;

    enqueue_policy_terminations(pool).await?;
    enqueue_overdue_terminations(pool).await?;
    process_available_commands(pool, config, journal, remote).await?;
    status.reconciled().await;
    refresh_mode(pool, status).await?;
    info!("controller startup reconciliation completed");

    loop {
        enqueue_policy_terminations(pool).await?;
        enqueue_overdue_terminations(pool).await?;
        process_available_commands(pool, config, journal, remote).await?;
        refresh_mode(pool, status).await?;

        let delay = next_wake_delay(pool, config.reconciliation_interval).await?;
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
        SET status='pending', claimed_at=NULL,
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

async fn enqueue_policy_terminations(pool: &PgPool) -> Result<()> {
    let ids = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT i.id
        FROM ctfzone.runtime_instances i
        LEFT JOIN ctfzone.challenge_runtime_configs r ON r.challenge_id=i.challenge_id
        WHERE i.active
          AND (
              NOT COALESCE((SELECT enabled FROM ctfzone.runtime_settings WHERE key='private_challenges'),false)
              OR NOT COALESCE(r.enabled,false)
              OR COALESCE(r.runtime_mode,'static') <> 'managed'
          )
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.runtime_commands c
              WHERE c.instance_id=i.id AND c.kind='terminate' AND c.status IN ('pending','claimed')
          )
        ORDER BY i.created_at
        "#,
    )
    .fetch_all(pool)
    .await?;
    for id in ids {
        create_termination_command(pool, id, "runtime_policy_disabled").await?;
    }
    Ok(())
}

async fn enqueue_overdue_terminations(pool: &PgPool) -> Result<()> {
    let ids = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT i.id FROM ctfzone.runtime_instances i
        WHERE i.active AND i.expires_at <= now()
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.runtime_commands c
              WHERE c.instance_id=i.id AND c.kind='terminate' AND c.status IN ('pending','claimed')
          )
        ORDER BY i.expires_at
        "#,
    )
    .fetch_all(pool)
    .await?;
    for id in ids {
        create_termination_command(pool, id, "absolute_deadline_reached").await?;
    }
    Ok(())
}

async fn create_termination_command(pool: &PgPool, instance_id: Uuid, reason: &str) -> Result<()> {
    let mut transaction = pool.begin().await?;
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
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        transaction.commit().await?;
        return Ok(());
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
    .fetch_one(&mut *transaction)
    .await?;
    if already_queued {
        transaction.commit().await?;
        return Ok(());
    }
    let generation = row.generation + 1;
    sqlx::query(
        "UPDATE ctfzone.runtime_instances SET desired_state='stopped',generation=$1 WHERE id=$2",
    )
    .bind(generation)
    .bind(instance_id)
    .execute(&mut *transaction)
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
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(command_id) = command_id {
        append_event(
            &mut transaction,
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
            .execute(&mut *transaction)
            .await?;
        info!(%instance_id, %command_id, %reason, owner_user_id = row.owner_user_id, "queued controller safety termination");
    }
    transaction.commit().await?;
    Ok(())
}

async fn process_available_commands(
    pool: &PgPool,
    config: &Config,
    journal: &OperationJournal,
    remote: &RemoteExecutor,
) -> Result<()> {
    while let Some(command) = claim_command(pool).await? {
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
        SET status='claimed',claimed_at=now(),attempts=c.attempts+1
        FROM candidate
        WHERE c.id=candidate.id
        RETURNING c.id,c.instance_id,c.kind,c.generation,c.setting_revision,
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
            command.id,
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

    let server = select_remote_server(pool, &instance.deployment_snapshot).await?;
    let payload = remote_payload(command, instance, "start");
    mark_starting(pool, command, instance, &server).await?;
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
    if result.absent == Some(true) || result.container_id.is_none() {
        bail!("remote helper did not confirm a running workload");
    }
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
        let cleanup_payload = remote_payload(command, instance, "generation_changed_after_start");
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
        cancel_command(
            pool,
            command.id,
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
        return complete_command(pool, command.id).await;
    }
    let server = if let Some(server_id) = instance.remote_server_id {
        Some(load_remote_server(pool, server_id).await?)
    } else {
        None
    };
    mark_stopping(pool, command, instance).await?;
    if let Some(server) = server.as_ref() {
        let payload = remote_payload(command, instance, "terminate");
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
        finish_termination(pool, command, instance).await?;
        journal
            .acknowledged(journal_intent(
                command,
                instance,
                RemoteOperation::StopInstance,
                Some(server),
                &payload,
            ))
            .await?;
    } else {
        finish_termination(pool, command, instance).await?;
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
        return cancel_command(pool, command.id, "instance can no longer be extended").await;
    }
    let server_id = instance
        .remote_server_id
        .context("instance has no remote server for extension")?;
    let server = load_remote_server(pool, server_id).await?;
    let payload = remote_payload(command, instance, "extend");
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
    if !finish_extension(pool, command, instance, &result).await? {
        cancel_command(
            pool,
            command.id,
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
        return cancel_command(pool, command.id, "instance has no remote server to inspect").await;
    };
    let server = load_remote_server(pool, server_id).await?;
    let payload = remote_payload(command, instance, "inspect");
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
    finish_inspection(pool, command, instance, &result).await?;
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

fn remote_payload(command: &CommandRow, instance: &InstanceRow, reason: &str) -> Value {
    json!({
        "instance_id": instance.id,
        "owner_user_id": instance.owner_user_id,
        "challenge_id": instance.challenge_id,
        "generation": command.generation,
        "expires_at": instance.desired_expires_at,
        "maximum_expires_at": instance.maximum_expires_at,
        "deployment": instance.deployment_snapshot,
        "reason": reason,
        "command_payload": command.payload,
        "remote_container_id": instance.remote_container_id,
    })
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

async fn select_remote_server(pool: &PgPool, snapshot: &Value) -> Result<RemoteServer> {
    let requested_pool = snapshot.get("remote_pool").and_then(Value::as_str);
    sqlx::query_as::<_, RemoteServer>(
        r#"
        SELECT s.id,s.name,s.hostname,s.ssh_port,s.ssh_user,s.helper_path,
               s.identity_file,s.host_key_alias,s.pool,s.capacity
        FROM ctfzone.remote_servers s
        LEFT JOIN ctfzone.runtime_instances i ON i.remote_server_id=s.id AND i.active
        WHERE s.enabled AND ($1::text IS NULL OR s.pool=$1)
        GROUP BY s.id
        HAVING COUNT(i.id) < s.capacity
        ORDER BY COUNT(i.id),s.name
        LIMIT 1
        "#,
    )
    .bind(requested_pool)
    .fetch_optional(pool)
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
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET observed_state='starting',
            remote_server_id=$1,activated_at=COALESCE(activated_at,now()),
            last_observed_at=now(),failure_code=NULL,failure_message=NULL
        WHERE id=$2 AND generation=$3
        "#,
    )
    .bind(server.id)
    .bind(instance.id)
    .bind(command.generation)
    .execute(&mut *transaction)
    .await?;
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
    Ok(())
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
    let mut transaction = pool.begin().await?;
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
    mark_command_completed(&mut transaction, command.id).await?;
    transaction.commit().await?;
    Ok(true)
}

async fn mark_stopping(pool: &PgPool, command: &CommandRow, instance: &InstanceRow) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "UPDATE ctfzone.runtime_instances SET observed_state='stopping',last_observed_at=now() WHERE id=$1 AND active",
    )
    .bind(instance.id)
    .execute(&mut *transaction)
    .await?;
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
    Ok(())
}

async fn finish_termination(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
) -> Result<()> {
    let expired = instance.expires_at <= Utc::now()
        || command.payload.get("reason").and_then(Value::as_str)
            == Some("absolute_deadline_reached");
    let observed_state = if expired { "expired" } else { "terminated" };
    let event_type = if expired {
        "instance.expired"
    } else {
        "instance.terminated"
    };
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET active=false,desired_state='stopped',
            observed_state=$1,observed_generation=$2,last_observed_at=now(),
            stopped_at=now(),failure_code=NULL,failure_message=NULL
        WHERE id=$3
        "#,
    )
    .bind(observed_state)
    .bind(command.generation)
    .bind(instance.id)
    .execute(&mut *transaction)
    .await?;
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
    mark_command_completed(&mut transaction, command.id).await?;
    transaction.commit().await?;
    Ok(())
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
    let mut transaction = pool.begin().await?;
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
    mark_command_completed(&mut transaction, command.id).await?;
    transaction.commit().await?;
    Ok(true)
}

async fn finish_inspection(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    result: &RemoteResult,
) -> Result<()> {
    let absent = result.absent.unwrap_or(false);
    let mut transaction = pool.begin().await?;
    if absent {
        let expired = instance.expires_at <= Utc::now() || instance.desired_state == "stopped";
        sqlx::query(
            r#"
            UPDATE ctfzone.runtime_instances SET active=false,
                observed_state=$1,stopped_at=now(),last_observed_at=now(),
                failure_code=CASE WHEN $1='failed' THEN 'remote_workload_missing' ELSE NULL END
            WHERE id=$2
            "#,
        )
        .bind(if expired { "expired" } else { "failed" })
        .bind(instance.id)
        .execute(&mut *transaction)
        .await?;
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
    } else {
        sqlx::query(
            "UPDATE ctfzone.runtime_instances SET observed_state='ready',last_observed_at=now(),observed_generation=$1 WHERE id=$2",
        )
        .bind(command.generation)
        .bind(instance.id)
        .execute(&mut *transaction)
        .await?;
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
    mark_command_completed(&mut transaction, command.id).await?;
    transaction.commit().await?;
    Ok(())
}

async fn reject_start(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
    gate: &RuntimeGate,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET active=false,desired_state='stopped',
            observed_state='failed',stopped_at=now(),last_observed_at=now(),
            failure_code='runtime_policy_stale',
            failure_message='Runtime policy changed before launch'
        WHERE id=$1 AND observed_state='requested'
        "#,
    )
    .bind(instance.id)
    .execute(&mut *transaction)
    .await?;
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
    sqlx::query(
        "UPDATE ctfzone.runtime_commands SET status='cancelled',completed_at=now(),last_error='runtime policy changed before launch' WHERE id=$1",
    )
    .bind(command.id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn expire_unstarted_instance(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE ctfzone.runtime_instances SET active=false,desired_state='stopped',
            observed_state='expired',observed_generation=$1,stopped_at=now(),
            last_observed_at=now(),failure_code=NULL,failure_message=NULL
        WHERE id=$2 AND generation=$1 AND observed_state='requested'
        "#,
    )
    .bind(command.generation)
    .bind(instance.id)
    .execute(&mut *transaction)
    .await?;
    append_event(
        &mut transaction,
        instance.id,
        "instance.expired",
        "controller",
        None,
        json!({"command_id": command.id, "reason": "deadline_elapsed_before_launch"}),
    )
    .await?;
    sqlx::query(
        "UPDATE ctfzone.runtime_commands SET status='cancelled',completed_at=now(),last_error='deadline elapsed before launch' WHERE id=$1",
    )
    .bind(command.id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn cancel_stale_command(
    pool: &PgPool,
    command: &CommandRow,
    instance: &InstanceRow,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "UPDATE ctfzone.runtime_commands SET status='cancelled',completed_at=now(),last_error='stale generation' WHERE id=$1",
    )
    .bind(command.id)
    .execute(&mut *transaction)
    .await?;
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

async fn cancel_command(pool: &PgPool, command_id: Uuid, reason: &str) -> Result<()> {
    sqlx::query(
        "UPDATE ctfzone.runtime_commands SET status='cancelled',completed_at=now(),last_error=$1 WHERE id=$2",
    )
    .bind(reason)
    .bind(command_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn complete_command(pool: &PgPool, command_id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE ctfzone.runtime_commands SET status='completed',completed_at=now(),last_error=NULL WHERE id=$1",
    )
    .bind(command_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn mark_command_completed(
    transaction: &mut Transaction<'_, Postgres>,
    command_id: Uuid,
) -> Result<()> {
    sqlx::query(
        "UPDATE ctfzone.runtime_commands SET status='completed',completed_at=now(),last_error=NULL WHERE id=$1",
    )
    .bind(command_id)
    .execute(&mut **transaction)
    .await?;
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
        let mut transaction = pool.begin().await?;
        sqlx::query(
            "UPDATE ctfzone.runtime_commands SET status='failed',completed_at=now(),last_error=$1 WHERE id=$2",
        )
        .bind(&message)
        .bind(command.id)
        .execute(&mut *transaction)
        .await?;
        let state = match command.kind.as_str() {
            "extend" => "ready",
            "inspect" | "reconcile" => "unknown",
            _ => "cleanup_pending",
        };
        sqlx::query(
            "UPDATE ctfzone.runtime_instances SET observed_state=$1,failure_code='command_failed',failure_message=$2,last_observed_at=now() WHERE id=$3 AND active",
        )
        .bind(state)
        .bind(&message)
        .bind(command.instance_id)
        .execute(&mut *transaction)
        .await?;
        append_event(
            &mut transaction,
            command.instance_id,
            "instance.failed",
            "controller",
            None,
            json!({"command_id": command.id, "kind": command.kind, "error": message}),
        )
        .await?;
        transaction.commit().await?;
        return Ok(());
    }
    let exponent = u32::try_from(command.attempts.clamp(1, 6)).unwrap_or(6);
    let backoff_seconds = min(5_i64 * 2_i64.pow(exponent), 300);
    sqlx::query(
        r#"
        UPDATE ctfzone.runtime_commands SET status='pending',claimed_at=NULL,
            available_at=now() + make_interval(secs => $1::double precision),last_error=$2
        WHERE id=$3
        "#,
    )
    .bind(backoff_seconds as f64)
    .bind(message)
    .bind(command.id)
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

async fn next_wake_delay(pool: &PgPool, maximum: StdDuration) -> Result<StdDuration> {
    let command_time = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT MIN(available_at) FROM ctfzone.runtime_commands WHERE status='pending'",
    )
    .fetch_one(pool)
    .await?;
    let deadline = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT MIN(expires_at) FROM ctfzone.runtime_instances WHERE active",
    )
    .fetch_one(pool)
    .await?;
    let next = [command_time, deadline].into_iter().flatten().min();
    let until_next = next
        .map(|next| {
            (next - Utc::now())
                .to_std()
                .unwrap_or_else(|_| StdDuration::from_millis(10))
        })
        .unwrap_or(maximum);
    Ok(min(until_next, maximum))
}

fn truncate(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_errors_on_character_boundaries() {
        assert_eq!(truncate("aé日", 2), "aé");
    }
}
