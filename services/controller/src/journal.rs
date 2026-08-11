use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    sync::Mutex,
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::remote::{RemoteExecutor, RemoteOperation, RemoteResult, RemoteServer};

// Historical records are already durable in PostgreSQL. The local journal only
// needs the latest state for operations that PostgreSQL has not acknowledged.
const COMPACTION_THRESHOLD_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Intent,
    RemoteResult,
    DatabaseAcknowledged,
    DegradedCleanup,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct JournalRecord {
    instance_id: Uuid,
    command_id: Uuid,
    generation: i64,
    setting_revision: i64,
    challenge_runtime_revision: i64,
    operation: RemoteOperation,
    phase: JournalPhase,
    remote_server: Option<RemoteServer>,
    effective_expires_at: DateTime<Utc>,
    remote_result: Option<RemoteResult>,
    payload: Option<Value>,
    updated_at: DateTime<Utc>,
}

pub(crate) struct JournalIntent<'a> {
    pub(crate) instance_id: Uuid,
    pub(crate) command_id: Uuid,
    pub(crate) generation: i64,
    pub(crate) setting_revision: i64,
    pub(crate) challenge_runtime_revision: i64,
    pub(crate) operation: RemoteOperation,
    pub(crate) remote_server: Option<&'a RemoteServer>,
    pub(crate) effective_expires_at: DateTime<Utc>,
    pub(crate) payload: &'a Value,
}

pub(crate) struct OperationJournal {
    path: PathBuf,
    writer: Mutex<()>,
}

impl OperationJournal {
    pub(crate) async fn open(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create journal directory {}", parent.display())
            })?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to open operation journal {}", path.display()))?;
        sync_parent_directory(&path).await?;
        Ok(Self {
            path,
            writer: Mutex::new(()),
        })
    }

    pub(crate) async fn intent(&self, intent: JournalIntent<'_>) -> Result<()> {
        self.append(&JournalRecord {
            instance_id: intent.instance_id,
            command_id: intent.command_id,
            generation: intent.generation,
            setting_revision: intent.setting_revision,
            challenge_runtime_revision: intent.challenge_runtime_revision,
            operation: intent.operation,
            phase: JournalPhase::Intent,
            remote_server: intent.remote_server.cloned(),
            effective_expires_at: intent.effective_expires_at,
            remote_result: None,
            payload: Some(intent.payload.clone()),
            updated_at: Utc::now(),
        })
        .await
    }

    pub(crate) async fn remote_result(
        &self,
        intent: JournalIntent<'_>,
        result: &RemoteResult,
    ) -> Result<()> {
        self.append(&JournalRecord {
            instance_id: intent.instance_id,
            command_id: intent.command_id,
            generation: intent.generation,
            setting_revision: intent.setting_revision,
            challenge_runtime_revision: intent.challenge_runtime_revision,
            operation: intent.operation,
            phase: JournalPhase::RemoteResult,
            remote_server: intent.remote_server.cloned(),
            effective_expires_at: result
                .effective_expires_at
                .unwrap_or(intent.effective_expires_at),
            remote_result: Some(result.clone()),
            payload: Some(intent.payload.clone()),
            updated_at: Utc::now(),
        })
        .await
    }

    pub(crate) async fn acknowledged(&self, intent: JournalIntent<'_>) -> Result<()> {
        self.append(&JournalRecord {
            instance_id: intent.instance_id,
            command_id: intent.command_id,
            generation: intent.generation,
            setting_revision: intent.setting_revision,
            challenge_runtime_revision: intent.challenge_runtime_revision,
            operation: intent.operation,
            phase: JournalPhase::DatabaseAcknowledged,
            remote_server: intent.remote_server.cloned(),
            effective_expires_at: intent.effective_expires_at,
            remote_result: None,
            payload: None,
            updated_at: Utc::now(),
        })
        .await
    }

    pub(crate) async fn cleanup_overdue_without_database(
        &self,
        remote: &RemoteExecutor,
    ) -> Result<usize> {
        let records = self.current_unacknowledged().await?;
        let mut cleaned = 0;
        for record in records.values() {
            // A successful degraded cleanup is intentionally retained until the
            // database reconnects, but the idempotent remote stop need not run on
            // every reconnect attempt while PostgreSQL remains unavailable.
            if record.phase == JournalPhase::DegradedCleanup {
                continue;
            }
            if record.effective_expires_at > Utc::now() {
                continue;
            }
            let Some(server) = record.remote_server.as_ref() else {
                continue;
            };
            let payload = json!({
                "instance_id": record.instance_id,
                "generation": record.generation,
                "reason": "degraded_deadline_recovery",
            });
            match remote
                .execute(server, RemoteOperation::StopInstance, &payload)
                .await
            {
                Ok(result) => {
                    self.append(&JournalRecord {
                        phase: JournalPhase::DegradedCleanup,
                        remote_result: Some(result),
                        payload: Some(payload),
                        updated_at: Utc::now(),
                        ..record.clone()
                    })
                    .await?;
                    cleaned += 1;
                    info!(instance_id = %record.instance_id, "cleaned overdue journaled instance while database was unavailable");
                }
                Err(error) => warn!(
                    instance_id = %record.instance_id,
                    %error,
                    "unable to clean overdue journaled instance while database was unavailable"
                ),
            }
        }
        Ok(cleaned)
    }

    async fn current_unacknowledged(&self) -> Result<HashMap<(Uuid, Uuid), JournalRecord>> {
        let _guard = self.writer.lock().await;
        self.current_unacknowledged_locked().await
    }

    async fn current_unacknowledged_locked(&self) -> Result<HashMap<(Uuid, Uuid), JournalRecord>> {
        let content = match fs::read_to_string(&self.path).await {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(error) => return Err(error).context("failed to read operation journal"),
        };
        let mut current = HashMap::new();
        for (index, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<JournalRecord>(line) {
                Ok(record) => {
                    let key = (record.instance_id, record.command_id);
                    if record.phase == JournalPhase::DatabaseAcknowledged {
                        current.remove(&key);
                    } else {
                        current.insert(key, record);
                    }
                }
                Err(error) => {
                    warn!(line = index + 1, %error, "ignored invalid operation journal line")
                }
            }
        }
        Ok(current)
    }

    async fn append(&self, record: &JournalRecord) -> Result<()> {
        let _guard = self.writer.lock().await;
        self.append_locked(record).await?;

        let immediate = matches!(
            record.phase,
            JournalPhase::DatabaseAcknowledged | JournalPhase::DegradedCleanup
        );
        let threshold_reached = fs::metadata(&self.path)
            .await
            .map(|metadata| metadata.len() >= COMPACTION_THRESHOLD_BYTES)
            .unwrap_or(false);
        if immediate || threshold_reached {
            if let Err(error) = self.compact_locked().await {
                // The just-appended record was fsynced before compaction began and
                // replacement uses an atomic rename. Compaction is best-effort and
                // must not cause an already-completed remote command to be retried.
                warn!(path = %self.path.display(), %error, "unable to compact operation journal");
            }
        }
        Ok(())
    }

    async fn append_locked(&self, record: &JournalRecord) -> Result<()> {
        let mut encoded = serde_json::to_vec(record).context("failed to encode journal record")?;
        encoded.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .context("failed to append operation journal")?;
        file.write_all(&encoded)
            .await
            .context("failed to write operation journal")?;
        file.sync_data()
            .await
            .context("failed to fsync operation journal")?;
        Ok(())
    }

    async fn compact_locked(&self) -> Result<()> {
        let mut records = self
            .current_unacknowledged_locked()
            .await?
            .into_values()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.updated_at
                .cmp(&right.updated_at)
                .then_with(|| left.instance_id.cmp(&right.instance_id))
                .then_with(|| left.command_id.cmp(&right.command_id))
        });

        let mut encoded = Vec::new();
        for record in records {
            encoded.extend(
                serde_json::to_vec(&record).context("failed to encode compacted journal record")?,
            );
            encoded.push(b'\n');
        }

        let temporary_path = temporary_path(&self.path);
        let result = async {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to create compacted operation journal {}",
                        temporary_path.display()
                    )
                })?;
            file.write_all(&encoded)
                .await
                .context("failed to write compacted operation journal")?;
            file.sync_all()
                .await
                .context("failed to fsync compacted operation journal")?;
            drop(file);

            fs::rename(&temporary_path, &self.path)
                .await
                .context("failed to atomically replace operation journal")?;
            sync_parent_directory(&self.path).await?;
            Ok(())
        }
        .await;
        if result.is_err() {
            fs::remove_file(&temporary_path).await.ok();
        }
        result
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("operations.jsonl");
    path.with_file_name(format!(".{filename}.compact-{}", Uuid::new_v4()))
}

async fn sync_parent_directory(path: &Path) -> Result<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    let directory = fs::File::open(parent)
        .await
        .with_context(|| format!("failed to open journal directory {}", parent.display()))?;
    directory
        .sync_all()
        .await
        .with_context(|| format!("failed to fsync journal directory {}", parent.display()))
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration as StdDuration};

    use chrono::Duration;

    use super::*;
    use crate::config::{Config, RemoteDriver};

    fn test_paths(name: &str) -> (PathBuf, PathBuf) {
        let directory = std::env::temp_dir().join(format!(
            "ctfzone-controller-journal-{name}-{}",
            Uuid::new_v4()
        ));
        let path = directory.join("operations.jsonl");
        (directory, path)
    }

    fn intent<'a>(
        instance_id: Uuid,
        command_id: Uuid,
        payload: &'a Value,
        remote_server: Option<&'a RemoteServer>,
        effective_expires_at: DateTime<Utc>,
    ) -> JournalIntent<'a> {
        JournalIntent {
            instance_id,
            command_id,
            generation: 1,
            setting_revision: 1,
            challenge_runtime_revision: 1,
            operation: RemoteOperation::EnsureInstance,
            remote_server,
            effective_expires_at,
            payload,
        }
    }

    #[tokio::test]
    async fn acknowledgement_compacts_away_completed_history() {
        let (directory, path) = test_paths("acknowledged");
        let journal = OperationJournal::open(path.clone()).await.unwrap();
        let first_instance = Uuid::new_v4();
        let first_command = Uuid::new_v4();
        let second_instance = Uuid::new_v4();
        let second_command = Uuid::new_v4();
        let payload = json!({"deployment": {"image_digest": "example@sha256:test"}});
        let deadline = Utc::now() + Duration::minutes(30);

        journal
            .intent(intent(
                first_instance,
                first_command,
                &payload,
                None,
                deadline,
            ))
            .await
            .unwrap();
        journal
            .intent(intent(
                second_instance,
                second_command,
                &payload,
                None,
                deadline,
            ))
            .await
            .unwrap();
        journal
            .acknowledged(intent(
                first_instance,
                first_command,
                &payload,
                None,
                deadline,
            ))
            .await
            .unwrap();

        let current = journal.current_unacknowledged().await.unwrap();
        assert_eq!(current.len(), 1);
        assert!(current.contains_key(&(second_instance, second_command)));
        assert_eq!(fs::read_to_string(&path).await.unwrap().lines().count(), 1);

        journal
            .acknowledged(intent(
                second_instance,
                second_command,
                &payload,
                None,
                deadline,
            ))
            .await
            .unwrap();
        assert!(journal.current_unacknowledged().await.unwrap().is_empty());
        assert_eq!(fs::metadata(&path).await.unwrap().len(), 0);
        fs::remove_dir_all(directory).await.unwrap();
    }

    #[tokio::test]
    async fn repeated_live_updates_are_bounded_by_threshold_compaction() {
        let (directory, path) = test_paths("threshold");
        let journal = OperationJournal::open(path.clone()).await.unwrap();
        let instance_id = Uuid::new_v4();
        let command_id = Uuid::new_v4();
        let payload = json!({"blob": "x".repeat(256 * 1024)});
        let deadline = Utc::now() + Duration::minutes(30);

        for _ in 0..8 {
            journal
                .intent(intent(instance_id, command_id, &payload, None, deadline))
                .await
                .unwrap();
        }

        assert!(fs::metadata(&path).await.unwrap().len() < COMPACTION_THRESHOLD_BYTES);
        assert_eq!(journal.current_unacknowledged().await.unwrap().len(), 1);
        fs::remove_dir_all(directory).await.unwrap();
    }

    #[tokio::test]
    async fn degraded_cleanup_is_not_repeated_while_database_remains_offline() {
        let (directory, path) = test_paths("degraded");
        let journal = OperationJournal::open(path.clone()).await.unwrap();
        let instance_id = Uuid::new_v4();
        let command_id = Uuid::new_v4();
        let payload = json!({"instance_id": instance_id});
        let server = RemoteServer {
            id: Uuid::new_v4(),
            name: "mock-runtime".to_owned(),
            hostname: "runtime.invalid".to_owned(),
            ssh_port: 22,
            ssh_user: "ctfzone_runtime".to_owned(),
            helper_path: "/usr/local/libexec/ctfzone-runtime-helper".to_owned(),
            identity_file: None,
            host_key_alias: None,
            pool: None,
            capacity: 1,
        };
        let config = Config {
            bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            database_url: "postgres://unused".to_owned(),
            journal_path: path.clone(),
            max_command_attempts: 1,
            reconciliation_interval: StdDuration::from_secs(1),
            remote_driver: RemoteDriver::Mock,
            remote_operation_timeout: StdDuration::from_secs(1),
            ssh_default_identity_file: None,
            ssh_known_hosts_file: directory.join("known_hosts"),
            stale_claim_after: StdDuration::from_secs(1),
        };
        let remote = RemoteExecutor::new(&config);
        journal
            .intent(intent(
                instance_id,
                command_id,
                &payload,
                Some(&server),
                Utc::now() - Duration::seconds(1),
            ))
            .await
            .unwrap();

        assert_eq!(
            journal
                .cleanup_overdue_without_database(&remote)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            journal
                .cleanup_overdue_without_database(&remote)
                .await
                .unwrap(),
            0
        );
        let current = journal.current_unacknowledged().await.unwrap();
        assert_eq!(current.len(), 1);
        assert_eq!(
            current.get(&(instance_id, command_id)).unwrap().phase,
            JournalPhase::DegradedCleanup
        );
        assert_eq!(fs::read_to_string(&path).await.unwrap().lines().count(), 1);
        fs::remove_dir_all(directory).await.unwrap();
    }
}
