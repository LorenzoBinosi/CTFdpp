use std::{cmp::min, env, time::Duration};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode, Url, redirect::Policy};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use serde_json::json;
use sqlx::{FromRow, PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use tokio::{sync::watch, time::Instant};
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::SharedStatus;

const INTERNAL_REQUEST_TTL: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_OPERATIONS_PER_CYCLE: usize = 128;
const UPLOAD_CLOCK_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct StorageConfig {
    access_key: String,
    bucket: String,
    database_url: String,
    internal_url: Url,
    maintenance_interval: Duration,
    max_attempts: i32,
    max_upload_duration: Duration,
    region: String,
    secret_key: String,
    stale_claim_after: Duration,
}

#[derive(Clone)]
struct ObjectStore {
    bucket_name: String,
    bucket: Bucket,
    client: Client,
    credentials: Credentials,
}

#[derive(Debug, FromRow)]
struct ObjectOperation {
    id: Uuid,
    object_id: Uuid,
    operation: String,
    object_revision: i64,
    attempts: i32,
    claimed_by: String,
}

#[derive(Debug, FromRow)]
struct StoredObject {
    id: Uuid,
    bucket: String,
    object_key: String,
    upload_key: String,
    status: String,
    revision: i64,
    upload_expires_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct StagingCleanupGate {
    any_completed: bool,
    retry_at: Option<DateTime<Utc>>,
}

impl StorageConfig {
    pub(crate) fn from_env() -> Result<Self> {
        let access_key = required("OBJECT_STORAGE_ACCESS_KEY")?;
        let secret_key = required("OBJECT_STORAGE_SECRET_KEY")?;
        let database_url = required("DATABASE_URL")?;
        let bucket = env::var("OBJECT_STORAGE_BUCKET").unwrap_or_else(|_| "ctfzone".to_owned());
        validate_bucket(&bucket)?;
        let region = env::var("OBJECT_STORAGE_REGION").unwrap_or_else(|_| "us-east-1".to_owned());
        if region.trim().is_empty() {
            bail!("OBJECT_STORAGE_REGION must not be empty");
        }
        let internal_url = endpoint("OBJECT_STORAGE_INTERNAL_URL")?;
        let maintenance_interval =
            Duration::from_secs(positive_u64("OBJECT_MAINTENANCE_INTERVAL_SECONDS", 30)?);
        let max_upload_duration = Duration::from_secs(positive_u64(
            "OBJECT_STORAGE_MAX_UPLOAD_DURATION_SECONDS",
            900,
        )?);
        let stale_claim_after =
            Duration::from_secs(positive_u64("OBJECT_MAINTENANCE_STALE_CLAIM_SECONDS", 300)?);
        validate_storage_lease(stale_claim_after)?;

        // Constructing the bucket here validates the endpoint/bucket/region
        // combination before either worker or the HTTP health server starts.
        Bucket::new(
            internal_url.clone(),
            UrlStyle::Path,
            bucket.clone(),
            region.clone(),
        )
        .context("OBJECT_STORAGE_INTERNAL_URL cannot be used as an S3 endpoint")?;

        Ok(Self {
            access_key,
            bucket,
            database_url,
            internal_url,
            maintenance_interval,
            max_attempts: positive_i32("OBJECT_MAINTENANCE_MAX_ATTEMPTS", 8)?,
            max_upload_duration,
            region,
            secret_key,
            stale_claim_after,
        })
    }
}

impl ObjectStore {
    fn new(config: &StorageConfig) -> Result<Self> {
        let bucket = Bucket::new(
            config.internal_url.clone(),
            UrlStyle::Path,
            config.bucket.clone(),
            config.region.clone(),
        )
        .context("OBJECT_STORAGE_INTERNAL_URL cannot be used as an S3 endpoint")?;
        let client = Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(Policy::none())
            .build()
            .context("failed to build object storage HTTP client")?;
        Ok(Self {
            bucket_name: config.bucket.clone(),
            bucket,
            client,
            credentials: Credentials::new(config.access_key.clone(), config.secret_key.clone()),
        })
    }

    async fn probe(&self) -> Result<()> {
        let url: String = self
            .bucket
            .head_bucket(Some(&self.credentials))
            .sign(INTERNAL_REQUEST_TTL)
            .into();
        let response = self
            .client
            .head(url)
            .send()
            .await
            .context("object storage health request failed")?;
        if !response.status().is_success() {
            bail!(
                "object storage health request returned {}",
                response.status()
            );
        }
        Ok(())
    }

    async fn delete(&self, object_key: &str) -> Result<()> {
        if object_key.is_empty() {
            bail!("stored object key is empty");
        }
        let url: String = self
            .bucket
            .delete_object(Some(&self.credentials), object_key)
            .sign(INTERNAL_REQUEST_TTL)
            .into();
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .context("object storage delete request failed")?;
        if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
            bail!(
                "object storage delete request returned {}",
                response.status()
            );
        }
        Ok(())
    }

    async fn is_absent(&self, object_key: &str) -> Result<bool> {
        if object_key.is_empty() {
            bail!("stored object key is empty");
        }
        let url: String = self
            .bucket
            .head_object(Some(&self.credentials), object_key)
            .sign(INTERNAL_REQUEST_TTL)
            .into();
        let response = self
            .client
            .head(url)
            .send()
            .await
            .context("object storage verification request failed")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(true);
        }
        if !response.status().is_success() {
            bail!(
                "object storage verification request returned {}",
                response.status()
            );
        }
        Ok(false)
    }
}

pub(crate) async fn run(
    config: StorageConfig,
    status: SharedStatus,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let storage = ObjectStore::new(&config)?;
    let worker_id = format!("controller:{}", Uuid::new_v4());
    let mut reconnect_delay = Duration::from_secs(2);

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let connection = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&config.database_url);
        let pool = tokio::select! {
            result = connection => match result {
                Ok(pool) => pool,
                Err(error) => {
                    status.storage_disconnected(format!("database connection failed: {error}")).await;
                    if sleep_or_shutdown(reconnect_delay, &mut shutdown).await {
                        return Ok(());
                    }
                    reconnect_delay = min(reconnect_delay * 2, Duration::from_secs(60));
                    continue;
                }
            },
            () = wait_for_shutdown(&mut shutdown) => return Ok(()),
        };
        reconnect_delay = Duration::from_secs(2);

        match connected_session(&config, &pool, &storage, &worker_id, &status, &mut shutdown).await
        {
            Ok(()) => return Ok(()),
            Err(error) => {
                warn!(%error, "object storage maintenance session ended; reconnecting");
                status.storage_disconnected(error.to_string()).await;
                pool.close().await;
                if sleep_or_shutdown(reconnect_delay, &mut shutdown).await {
                    return Ok(());
                }
            }
        }
    }
}

async fn connected_session(
    config: &StorageConfig,
    pool: &PgPool,
    storage: &ObjectStore,
    worker_id: &str,
    status: &SharedStatus,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    require_schema(pool).await?;
    storage.probe().await?;
    status.storage_connected().await;
    recover_stale_claims(pool, config.stale_claim_after).await?;
    run_cycle(pool, storage, worker_id, config, status, shutdown).await?;
    status.storage_reconciled().await;
    info!("object storage startup reconciliation completed");

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let delay =
            next_wake_delay(pool, config.maintenance_interval, config.stale_claim_after).await?;
        tokio::select! {
            () = tokio::time::sleep_until(Instant::now() + delay) => {},
            () = wait_for_shutdown(shutdown) => return Ok(()),
        }
        storage.probe().await?;
        status.storage_connected().await;
        recover_stale_claims(pool, config.stale_claim_after).await?;
        run_cycle(pool, storage, worker_id, config, status, shutdown).await?;
        status.storage_reconciled().await;
    }
}

async fn run_cycle(
    pool: &PgPool,
    storage: &ObjectStore,
    worker_id: &str,
    config: &StorageConfig,
    status: &SharedStatus,
    shutdown: &watch::Receiver<bool>,
) -> Result<()> {
    enqueue_expired_upload_reconciliation(pool, config.maintenance_interval).await?;
    enqueue_missing_deletes(pool, config.maintenance_interval).await?;
    process_available_operations(pool, storage, worker_id, config, status, shutdown).await
}

async fn require_schema(pool: &PgPool) -> Result<()> {
    let ready = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT to_regclass('ctfzone.stored_objects') IS NOT NULL
           AND to_regclass('ctfzone.stored_object_events') IS NOT NULL
           AND to_regclass('ctfzone.object_operations') IS NOT NULL
        "#,
    )
    .fetch_one(pool)
    .await?;
    if !ready {
        bail!("object storage control-plane schema is not installed");
    }
    Ok(())
}

async fn recover_stale_claims(pool: &PgPool, stale_after: Duration) -> Result<()> {
    let result = sqlx::query(
        r#"
        UPDATE ctfzone.object_operations
        SET status='pending',claimed_at=NULL,claimed_by=NULL,available_at=now(),
            last_error='maintenance claim lease expired'
        WHERE status='claimed'
          AND claimed_at < now() - make_interval(secs => $1::double precision)
        "#,
    )
    .bind(duration_seconds(stale_after) as f64)
    .execute(pool)
    .await?;
    if result.rows_affected() > 0 {
        warn!(
            count = result.rows_affected(),
            "recovered stale object maintenance claims"
        );
    }
    Ok(())
}

async fn enqueue_expired_upload_reconciliation(
    pool: &PgPool,
    safety_retry_after: Duration,
) -> Result<()> {
    let result = sqlx::query(
        r#"
        INSERT INTO ctfzone.object_operations
            (object_id,operation,object_revision,status,available_at)
        SELECT o.id,'reconcile',o.revision,'pending',now()
        FROM ctfzone.stored_objects o
        WHERE o.status='pending' AND o.upload_expires_at <= now()
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.object_operations p
              WHERE p.object_id=o.id AND p.operation='reconcile'
                AND p.status IN ('pending','claimed')
          )
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.object_operations p
              WHERE p.object_id=o.id AND p.operation='reconcile' AND p.status='failed'
                AND p.object_revision=o.revision
                AND p.completed_at > now() - make_interval(secs => $1::double precision)
          )
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(duration_seconds(safety_retry_after) as f64)
    .execute(pool)
    .await?;
    if result.rows_affected() > 0 {
        info!(
            count = result.rows_affected(),
            "queued expired upload reconciliation"
        );
    }
    Ok(())
}

async fn enqueue_missing_deletes(pool: &PgPool, safety_retry_after: Duration) -> Result<()> {
    let result = sqlx::query(
        r#"
        WITH desired AS (
            SELECT o.id AS object_id,'delete_upload'::text AS operation,o.revision,
                   GREATEST(now(),o.upload_expires_at + interval '5 seconds') AS available_at
            FROM ctfzone.stored_objects o
            WHERE o.status IN ('ready','failed','deleting','deleted')
            UNION ALL
            SELECT o.id,'delete',o.revision,now()
            FROM ctfzone.stored_objects o
            WHERE o.status IN ('failed','deleting')
        )
        INSERT INTO ctfzone.object_operations
            (object_id,operation,object_revision,status,available_at)
        SELECT d.object_id,d.operation,d.revision,'pending',d.available_at
        FROM desired d
        WHERE NOT EXISTS (
              SELECT 1 FROM ctfzone.object_operations p
              WHERE p.object_id=d.object_id AND p.operation=d.operation
                AND p.status='completed'
                AND (d.operation='delete_upload' OR p.object_revision=d.revision)
          )
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.object_operations p
              WHERE p.object_id=d.object_id AND p.operation=d.operation
                AND p.status IN ('pending','claimed')
          )
          AND NOT EXISTS (
              SELECT 1 FROM ctfzone.object_operations p
              WHERE p.object_id=d.object_id AND p.operation=d.operation AND p.status='failed'
                AND p.object_revision=d.revision
                AND p.completed_at > now() - make_interval(secs => $1::double precision)
          )
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(duration_seconds(safety_retry_after) as f64)
    .execute(pool)
    .await?;
    if result.rows_affected() > 0 {
        info!(
            count = result.rows_affected(),
            "queued missing object cleanup"
        );
    }
    Ok(())
}

async fn process_available_operations(
    pool: &PgPool,
    storage: &ObjectStore,
    worker_id: &str,
    config: &StorageConfig,
    status: &SharedStatus,
    shutdown: &watch::Receiver<bool>,
) -> Result<()> {
    for _ in 0..MAX_OPERATIONS_PER_CYCLE {
        if *shutdown.borrow() {
            break;
        }
        let Some(operation) = claim_operation(pool, worker_id).await? else {
            break;
        };
        if let Err(error) = execute_operation(
            pool,
            storage,
            &operation,
            config.maintenance_interval,
            config.stale_claim_after,
            config.max_upload_duration,
        )
        .await
        {
            warn!(
                operation_id = %operation.id,
                object_id = %operation.object_id,
                kind = %operation.operation,
                %error,
                "object maintenance operation failed"
            );
            status.storage_operation_failed(error.to_string()).await;
            schedule_retry(pool, &operation, config.max_attempts, &error.to_string()).await?;
        }
    }
    Ok(())
}

async fn claim_operation(pool: &PgPool, worker_id: &str) -> Result<Option<ObjectOperation>> {
    sqlx::query_as::<_, ObjectOperation>(
        r#"
        WITH candidate AS (
            SELECT id FROM ctfzone.object_operations
            WHERE status='pending' AND available_at <= now()
              AND operation IN ('reconcile','delete_upload','delete')
            ORDER BY available_at,created_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE ctfzone.object_operations o
        SET status='claimed',claimed_at=now(),claimed_by=$1,attempts=o.attempts+1
        FROM candidate
        WHERE o.id=candidate.id
        RETURNING o.id,o.object_id,o.operation,o.object_revision,o.attempts,o.claimed_by
        "#,
    )
    .bind(worker_id)
    .fetch_optional(pool)
    .await
    .context("failed to claim object maintenance operation")
}

async fn execute_operation(
    pool: &PgPool,
    storage: &ObjectStore,
    operation: &ObjectOperation,
    safety_retry_after: Duration,
    stale_claim_after: Duration,
    max_upload_duration: Duration,
) -> Result<()> {
    match operation.operation.as_str() {
        "reconcile" => reconcile_upload(pool, operation).await,
        "delete_upload" => delete_upload(pool, storage, operation, max_upload_duration).await,
        "delete" => {
            delete_object(
                pool,
                storage,
                operation,
                safety_retry_after,
                stale_claim_after,
            )
            .await
        }
        kind => bail!("unsupported object maintenance operation {kind}"),
    }
}

async fn load_object_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    object_id: Uuid,
) -> Result<StoredObject> {
    sqlx::query_as::<_, StoredObject>(
        r#"
        SELECT id,bucket,object_key,upload_key,status,revision,upload_expires_at
        FROM ctfzone.stored_objects WHERE id=$1 FOR UPDATE
        "#,
    )
    .bind(object_id)
    .fetch_optional(&mut **transaction)
    .await?
    .context("object maintenance operation refers to a missing object")
}

async fn reconcile_upload(pool: &PgPool, operation: &ObjectOperation) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let object = load_object_for_update(&mut transaction, operation.object_id).await?;
    if object.revision != operation.object_revision {
        cancel_stale_operation(&mut transaction, operation, object.revision).await?;
        transaction.commit().await?;
        return Ok(());
    }
    if object.status != "pending" {
        cancel_operation(
            &mut transaction,
            operation,
            &format!("object status is {}", object.status),
        )
        .await?;
        transaction.commit().await?;
        return Ok(());
    }
    if object.upload_expires_at > Utc::now() {
        let rescheduled = sqlx::query(
            r#"
            UPDATE ctfzone.object_operations
            SET status='pending',claimed_at=NULL,claimed_by=NULL,available_at=$1,
                attempts=GREATEST(attempts-1,0),last_error=NULL
            WHERE id=$2 AND status='claimed' AND claimed_by=$3
            "#,
        )
        .bind(object.upload_expires_at)
        .bind(operation.id)
        .bind(&operation.claimed_by)
        .execute(&mut *transaction)
        .await?;
        if rescheduled.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(());
        }
        transaction.commit().await?;
        return Ok(());
    }

    let revision = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE ctfzone.stored_objects
        SET status='failed',revision=revision+1
        WHERE id=$1 AND revision=$2 AND status='pending'
        RETURNING revision
        "#,
    )
    .bind(object.id)
    .bind(object.revision)
    .fetch_one(&mut *transaction)
    .await?;
    append_event(
        &mut transaction,
        object.id,
        "upload_expired",
        json!({"operation_id": operation.id}),
    )
    .await?;
    // The API may have copied staging to the final key immediately before a
    // crash, without committing `ready`. Remove both keys idempotently.
    for cleanup in ["delete_upload", "delete"] {
        let available_at = if cleanup == "delete_upload" {
            object.upload_expires_at + chrono::Duration::seconds(5)
        } else {
            Utc::now()
        };
        sqlx::query(
            r#"
            INSERT INTO ctfzone.object_operations
                (object_id,operation,object_revision,status,available_at)
            VALUES ($1,$2,$3,'pending',$4)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(object.id)
        .bind(cleanup)
        .bind(revision)
        .bind(available_at)
        .execute(&mut *transaction)
        .await?;
    }
    complete_operation(&mut transaction, operation).await?;
    transaction.commit().await?;
    Ok(())
}

async fn delete_upload(
    pool: &PgPool,
    storage: &ObjectStore,
    operation: &ObjectOperation,
    max_upload_duration: Duration,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let object = load_object_for_update(&mut transaction, operation.object_id).await?;
    if object.revision != operation.object_revision {
        cancel_stale_operation(&mut transaction, operation, object.revision).await?;
        transaction.commit().await?;
        return Ok(());
    }
    if !matches!(
        object.status.as_str(),
        "ready" | "failed" | "deleting" | "deleted"
    ) {
        cancel_operation(
            &mut transaction,
            operation,
            &format!("object status is {}", object.status),
        )
        .await?;
        transaction.commit().await?;
        return Ok(());
    }
    if object.bucket != storage.bucket_name {
        bail!(
            "stored object bucket {} does not match configured bucket",
            object.bucket
        );
    }
    // The row lock closes the revision-check-to-DELETE race. Repeating this
    // request after a crash is safe because S3 DeleteObject is idempotent.
    storage.delete(&object.upload_key).await?;
    let terminal_cleanup_at =
        terminal_staging_cleanup_at(object.upload_expires_at, max_upload_duration)?;
    if Utc::now() < terminal_cleanup_at {
        // A PUT whose signed request began just before grant expiry may still
        // be streaming. Keep this cleanup nonterminal and repeat it only after
        // Caddy's shared read-body timeout guarantees upload quiescence.
        let deferred = sqlx::query(
            r#"
            UPDATE ctfzone.object_operations
            SET status='pending',claimed_at=NULL,claimed_by=NULL,
                available_at=$1,attempts=GREATEST(attempts-1,0),last_error=NULL
            WHERE id=$2 AND status='claimed' AND claimed_by=$3
            "#,
        )
        .bind(terminal_cleanup_at)
        .bind(operation.id)
        .bind(&operation.claimed_by)
        .execute(&mut *transaction)
        .await?;
        if deferred.rows_affected() == 0 {
            bail!("object maintenance claim lease was lost while deferring staging cleanup");
        }
        transaction.commit().await?;
        return Ok(());
    }
    if !storage.is_absent(&object.upload_key).await? {
        bail!("staging object still exists after terminal cleanup");
    }
    // Staging cleanup never advances lifecycle state. A final-key DELETE on
    // the same revision is the only operation allowed to finish deletion; this
    // also covers a copy that succeeded immediately before an API crash.
    append_event(
        &mut transaction,
        object.id,
        "upload_staging_deleted",
        json!({"operation_id": operation.id}),
    )
    .await?;
    complete_operation(&mut transaction, operation).await?;
    // A final delete deferred behind a claimed staging cleanup can run as soon
    // as this durable completion commits instead of waiting for the full lease.
    sqlx::query(
        r#"
        UPDATE ctfzone.object_operations
        SET available_at=LEAST(available_at,now())
        WHERE object_id=$1 AND operation='delete' AND object_revision=$2
          AND status='pending'
        "#,
    )
    .bind(object.id)
    .bind(object.revision)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn defer_final_delete_for_staging_cleanup(
    transaction: &mut Transaction<'_, Postgres>,
    operation: &ObjectOperation,
    safety_retry_after: Duration,
    stale_claim_after: Duration,
) -> Result<bool> {
    let gate = sqlx::query_as::<_, StagingCleanupGate>(
        r#"
        SELECT
          EXISTS (
            SELECT 1 FROM ctfzone.object_operations
            WHERE object_id=$1 AND operation='delete_upload'
              AND status='completed'
          ) AS any_completed,
          (
            SELECT MIN(
            CASE
              WHEN status='pending'
                THEN GREATEST(available_at,now() + interval '1 second')
              WHEN status='claimed'
                THEN GREATEST(
                    COALESCE(claimed_at,now())
                      + make_interval(secs => $4::double precision),
                    now() + interval '1 second'
                )
              WHEN status='failed'
                THEN GREATEST(
                    COALESCE(completed_at,now())
                      + make_interval(secs => $3::double precision),
                    now() + interval '1 second'
                )
            END
            )
            FROM ctfzone.object_operations
            WHERE object_id=$1 AND operation='delete_upload'
              AND object_revision=$2
              AND status IN ('pending','claimed','failed')
          ) AS retry_at
        "#,
    )
    .bind(operation.object_id)
    .bind(operation.object_revision)
    .bind(duration_seconds(safety_retry_after) as f64)
    .bind(duration_seconds(stale_claim_after) as f64)
    .fetch_one(&mut **transaction)
    .await?;
    let cleanup_ready_at = staging_cleanup_retry_at(&gate);
    let cleanup_open = cleanup_ready_at.is_some();
    if let Some(cleanup_ready_at) = cleanup_ready_at {
        let deferred = sqlx::query(
            r#"
            UPDATE ctfzone.object_operations
            SET status='pending',claimed_at=NULL,claimed_by=NULL,
                available_at=$1,attempts=GREATEST(attempts-1,0)
            WHERE id=$2 AND status='claimed' AND claimed_by=$3
            "#,
        )
        .bind(cleanup_ready_at)
        .bind(operation.id)
        .bind(&operation.claimed_by)
        .execute(&mut **transaction)
        .await?;
        if deferred.rows_affected() == 0 {
            bail!("object maintenance claim lease was lost while deferring final cleanup");
        }
    }
    Ok(cleanup_open)
}

fn staging_cleanup_retry_at(gate: &StagingCleanupGate) -> Option<DateTime<Utc>> {
    // Upload keys are immutable. One successful deletion at any revision is
    // permanent proof that staging is gone, even if a redundant operation on
    // a newer object revision later failed.
    (!gate.any_completed)
        .then(|| gate.retry_at.as_ref().cloned())
        .flatten()
}

async fn delete_object(
    pool: &PgPool,
    storage: &ObjectStore,
    operation: &ObjectOperation,
    safety_retry_after: Duration,
    stale_claim_after: Duration,
) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let object = load_object_for_update(&mut transaction, operation.object_id).await?;
    if object.revision != operation.object_revision {
        cancel_stale_operation(&mut transaction, operation, object.revision).await?;
        transaction.commit().await?;
        return Ok(());
    }
    if object.status == "deleted" {
        complete_operation(&mut transaction, operation).await?;
        transaction.commit().await?;
        return Ok(());
    }
    if !matches!(object.status.as_str(), "deleting" | "failed") {
        cancel_operation(
            &mut transaction,
            operation,
            &format!("object status is {}", object.status),
        )
        .await?;
        transaction.commit().await?;
        return Ok(());
    }
    if object.bucket != storage.bucket_name {
        bail!(
            "stored object bucket {} does not match configured bucket",
            object.bucket
        );
    }
    if object.status == "deleting"
        && defer_final_delete_for_staging_cleanup(
            &mut transaction,
            operation,
            safety_retry_after,
            stale_claim_after,
        )
        .await?
    {
        transaction.commit().await?;
        return Ok(());
    }

    // Keep the object row locked through the bounded DELETE. That prevents an
    // API revision change after validation but before the irreversible request.
    // If the process dies after S3 succeeds, the transaction rolls back and the
    // same revision safely repeats the idempotent DELETE after lease recovery.
    storage.delete(&object.object_key).await?;
    if object.status == "deleting" {
        let changed = sqlx::query(
            r#"
            UPDATE ctfzone.stored_objects
            SET status='deleted',deleted_at=COALESCE(deleted_at,now()),revision=revision+1
            WHERE id=$1 AND revision=$2 AND status='deleting'
            "#,
        )
        .bind(object.id)
        .bind(object.revision)
        .execute(&mut *transaction)
        .await?;
        if changed.rows_affected() != 1 {
            bail!("object revision changed while its row lock was held");
        }
    }
    append_event(
        &mut transaction,
        object.id,
        if object.status == "failed" {
            "failed_object_final_deleted"
        } else {
            "object_deleted"
        },
        json!({"operation_id": operation.id}),
    )
    .await?;
    complete_operation(&mut transaction, operation).await?;
    transaction.commit().await?;
    Ok(())
}

async fn cancel_stale_operation(
    transaction: &mut Transaction<'_, Postgres>,
    operation: &ObjectOperation,
    current_revision: i64,
) -> Result<()> {
    cancel_operation(
        transaction,
        operation,
        &format!(
            "stale object revision {}; current revision is {current_revision}",
            operation.object_revision
        ),
    )
    .await
}

async fn cancel_operation(
    transaction: &mut Transaction<'_, Postgres>,
    operation: &ObjectOperation,
    reason: &str,
) -> Result<()> {
    let cancelled = sqlx::query(
        r#"
        UPDATE ctfzone.object_operations
        SET status='cancelled',completed_at=now(),last_error=$1
        WHERE id=$2 AND status='claimed' AND claimed_by=$3
        "#,
    )
    .bind(reason)
    .bind(operation.id)
    .bind(&operation.claimed_by)
    .execute(&mut **transaction)
    .await?;
    if cancelled.rows_affected() == 0 {
        bail!("object maintenance claim lease was lost while cancelling work");
    }
    append_event(
        transaction,
        operation.object_id,
        "maintenance_cancelled",
        json!({"operation_id": operation.id, "operation": operation.operation, "reason": reason}),
    )
    .await
}

async fn complete_operation(
    transaction: &mut Transaction<'_, Postgres>,
    operation: &ObjectOperation,
) -> Result<()> {
    let completed = sqlx::query(
        r#"
        UPDATE ctfzone.object_operations
        SET status='completed',completed_at=now(),last_error=NULL
        WHERE id=$1 AND status='claimed' AND claimed_by=$2
        "#,
    )
    .bind(operation.id)
    .bind(&operation.claimed_by)
    .execute(&mut **transaction)
    .await?;
    if completed.rows_affected() == 0 {
        bail!("object maintenance claim lease was lost before completion");
    }
    Ok(())
}

async fn schedule_retry(
    pool: &PgPool,
    operation: &ObjectOperation,
    max_attempts: i32,
    error: &str,
) -> Result<()> {
    let error = truncate(error, 1000);
    if operation.attempts >= max_attempts {
        let mut transaction = pool.begin().await?;
        let failed = sqlx::query(
            r#"
            UPDATE ctfzone.object_operations
            SET status='failed',completed_at=now(),last_error=$1
            WHERE id=$2 AND status='claimed' AND claimed_by=$3
            "#,
        )
        .bind(&error)
        .bind(operation.id)
        .bind(&operation.claimed_by)
        .execute(&mut *transaction)
        .await?;
        if failed.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(());
        }
        append_event(
            &mut transaction,
            operation.object_id,
            "maintenance_failed",
            json!({"operation_id": operation.id, "operation": operation.operation, "error": error}),
        )
        .await?;
        transaction.commit().await?;
        return Ok(());
    }
    let backoff = retry_backoff_seconds(operation.attempts);
    sqlx::query(
        r#"
        UPDATE ctfzone.object_operations
        SET status='pending',claimed_at=NULL,claimed_by=NULL,
            available_at=now() + make_interval(secs => $1::double precision),last_error=$2
        WHERE id=$3 AND status='claimed' AND claimed_by=$4
        "#,
    )
    .bind(backoff as f64)
    .bind(error)
    .bind(operation.id)
    .bind(&operation.claimed_by)
    .execute(pool)
    .await?;
    Ok(())
}

async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    object_id: Uuid,
    event_type: &str,
    details: serde_json::Value,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO ctfzone.stored_object_events
            (object_id,event_type,source,actor_user_id,details)
        VALUES ($1,$2,'controller',NULL,$3)
        "#,
    )
    .bind(object_id)
    .bind(event_type)
    .bind(details)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn next_wake_delay(
    pool: &PgPool,
    maximum: Duration,
    stale_claim_after: Duration,
) -> Result<Duration> {
    let pending = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        r#"
        SELECT MIN(available_at) FROM ctfzone.object_operations
        WHERE status='pending' AND operation IN ('reconcile','delete_upload','delete')
        "#,
    )
    .fetch_one(pool)
    .await?;
    let stale_claim = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        r#"
        SELECT MIN(claimed_at + make_interval(secs => $1::double precision))
        FROM ctfzone.object_operations
        WHERE status='claimed' AND claimed_at IS NOT NULL
          AND claimed_at + make_interval(secs => $1::double precision) > now()
        "#,
    )
    .bind(duration_seconds(stale_claim_after) as f64)
    .fetch_one(pool)
    .await?;
    let next = [pending, stale_claim].into_iter().flatten().min();
    let delay = next
        .map(|next| {
            (next - Utc::now())
                .to_std()
                .unwrap_or_else(|_| Duration::from_millis(10))
        })
        .unwrap_or(maximum);
    Ok(min(delay, maximum))
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

async fn sleep_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        () = wait_for_shutdown(shutdown) => true,
    }
}

fn required(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    if value.trim().is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

fn endpoint(name: &str) -> Result<Url> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    let url = value
        .parse::<Url>()
        .with_context(|| format!("{name} must be a valid absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        bail!("{name} must be an HTTP(S) origin without credentials, path, query, or fragment");
    }
    Ok(url)
}

fn validate_bucket(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if !(3..=63).contains(&bytes.len())
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        || value.contains("..")
    {
        bail!("OBJECT_STORAGE_BUCKET is not a valid S3 bucket name");
    }
    Ok(())
}

fn positive_u64(name: &str, default: u64) -> Result<u64> {
    let value = env::var(name)
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .with_context(|| format!("{name} must be a positive integer"))?
        .unwrap_or(default);
    if value == 0 {
        bail!("{name} must be a positive integer");
    }
    Ok(value)
}

fn positive_i32(name: &str, default: i32) -> Result<i32> {
    let value = env::var(name)
        .ok()
        .map(|value| value.parse::<i32>())
        .transpose()
        .with_context(|| format!("{name} must be a positive integer"))?
        .unwrap_or(default);
    if value <= 0 {
        bail!("{name} must be a positive integer");
    }
    Ok(value)
}

fn validate_storage_lease(stale_claim_after: Duration) -> Result<()> {
    if stale_claim_after <= HTTP_TIMEOUT.saturating_add(Duration::from_secs(5)) {
        bail!(
            "OBJECT_MAINTENANCE_STALE_CLAIM_SECONDS must exceed the object-storage HTTP timeout by more than 5 seconds"
        );
    }
    Ok(())
}

fn terminal_staging_cleanup_at(
    upload_expires_at: DateTime<Utc>,
    max_upload_duration: Duration,
) -> Result<DateTime<Utc>> {
    let quiescence =
        chrono::Duration::from_std(max_upload_duration.saturating_add(UPLOAD_CLOCK_GRACE))?;
    upload_expires_at
        .checked_add_signed(quiescence)
        .context("staging cleanup deadline is outside the supported time range")
}

fn duration_seconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

fn retry_backoff_seconds(attempts: i32) -> i64 {
    let exponent = u32::try_from(attempts.clamp(1, 6)).unwrap_or(6);
    min(5_i64 * 2_i64.pow(exponent), 300)
}

fn truncate(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> ObjectStore {
        ObjectStore::new(&StorageConfig {
            access_key: "access".to_owned(),
            bucket: "ctfzone".to_owned(),
            database_url: "postgres://unused".to_owned(),
            internal_url: Url::parse("http://storage:8333").unwrap(),
            maintenance_interval: Duration::from_secs(30),
            max_attempts: 8,
            max_upload_duration: Duration::from_secs(900),
            region: "us-east-1".to_owned(),
            secret_key: "secret".to_owned(),
            stale_claim_after: Duration::from_secs(300),
        })
        .unwrap()
    }

    #[test]
    fn validates_bucket_names() {
        for invalid in [
            "a",
            "CTFZone",
            "-ctfzone",
            "ctfzone-",
            "ctf..zone",
            "ctf_zone",
        ] {
            assert!(validate_bucket(invalid).is_err(), "{invalid}");
        }
        assert!(validate_bucket("ctfzone-assets-1").is_ok());
    }

    #[test]
    fn internal_delete_is_signed_and_does_not_disclose_secret() {
        let store = store();
        let url: String = store
            .bucket
            .delete_object(Some(&store.credentials), "submission/example")
            .sign(INTERNAL_REQUEST_TTL)
            .into();
        assert!(url.starts_with("http://storage:8333/ctfzone/submission/example?"));
        assert!(url.contains("X-Amz-Expires=30"));
        assert!(!url.contains("secret"));
    }

    #[test]
    fn operation_backoff_is_bounded() {
        assert_eq!(retry_backoff_seconds(1), 10);
        assert_eq!(retry_backoff_seconds(2), 20);
        assert_eq!(retry_backoff_seconds(99), 300);
    }

    #[test]
    fn storage_claim_lease_outlives_internal_requests() {
        assert!(validate_storage_lease(Duration::from_secs(14)).is_ok());
        assert!(validate_storage_lease(Duration::from_secs(13)).is_err());
    }

    #[test]
    fn prior_completed_staging_cleanup_overrides_a_current_failed_retry() {
        let retry_at = Utc::now() + chrono::Duration::minutes(5);
        let gate = StagingCleanupGate {
            any_completed: true,
            retry_at: Some(retry_at),
        };
        assert_eq!(staging_cleanup_retry_at(&gate), None);

        let never_completed = StagingCleanupGate {
            any_completed: false,
            retry_at: Some(retry_at),
        };
        assert_eq!(staging_cleanup_retry_at(&never_completed), Some(retry_at));
    }

    #[test]
    fn terminal_staging_cleanup_waits_for_upload_quiescence_and_clock_grace() {
        let expires_at = DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            terminal_staging_cleanup_at(expires_at, Duration::from_secs(900)).unwrap(),
            expires_at + chrono::Duration::seconds(905)
        );
    }
}
