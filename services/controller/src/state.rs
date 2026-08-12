use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControllerMode {
    Starting,
    Dormant,
    Draining,
    Enabled,
    Degraded,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct StatusSnapshot {
    pub(crate) mode: ControllerMode,
    pub(crate) database_connected: bool,
    pub(crate) initial_reconciliation_complete: bool,
    pub(crate) last_database_error: Option<String>,
    pub(crate) last_reconciled_at: Option<DateTime<Utc>>,
    pub(crate) object_storage_connected: bool,
    pub(crate) storage_initial_reconciliation_complete: bool,
    pub(crate) last_storage_error: Option<String>,
    pub(crate) last_storage_reconciled_at: Option<DateTime<Utc>>,
    pub(crate) last_transition_at: DateTime<Utc>,
}

#[derive(Clone)]
pub(crate) struct SharedStatus(Arc<RwLock<StatusSnapshot>>);

impl SharedStatus {
    pub(crate) fn new() -> Self {
        Self(Arc::new(RwLock::new(StatusSnapshot {
            mode: ControllerMode::Starting,
            database_connected: false,
            initial_reconciliation_complete: false,
            last_database_error: None,
            last_reconciled_at: None,
            object_storage_connected: false,
            storage_initial_reconciliation_complete: false,
            last_storage_error: None,
            last_storage_reconciled_at: None,
            last_transition_at: Utc::now(),
        })))
    }

    pub(crate) async fn snapshot(&self) -> StatusSnapshot {
        self.0.read().await.clone()
    }

    pub(crate) async fn database_connected(&self) {
        let mut status = self.0.write().await;
        status.database_connected = true;
        status.last_database_error = None;
    }

    pub(crate) async fn database_disconnected(&self, error: impl Into<String>) {
        let mut status = self.0.write().await;
        status.database_connected = false;
        status.initial_reconciliation_complete = false;
        status.last_database_error = Some(error.into());
        if status.mode != ControllerMode::Degraded {
            status.mode = ControllerMode::Degraded;
            status.last_transition_at = Utc::now();
        }
    }

    pub(crate) async fn reconciled(&self) {
        let mut status = self.0.write().await;
        status.initial_reconciliation_complete = true;
        status.last_reconciled_at = Some(Utc::now());
    }

    pub(crate) async fn set_mode(&self, mode: ControllerMode) {
        let mut status = self.0.write().await;
        if status.mode != mode {
            status.mode = mode;
            status.last_transition_at = Utc::now();
        }
    }

    pub(crate) async fn storage_connected(&self) {
        let mut status = self.0.write().await;
        status.object_storage_connected = true;
        status.last_storage_error = None;
    }

    pub(crate) async fn storage_disconnected(&self, error: impl Into<String>) {
        let mut status = self.0.write().await;
        status.object_storage_connected = false;
        status.storage_initial_reconciliation_complete = false;
        status.last_storage_error = Some(error.into());
    }

    pub(crate) async fn storage_operation_failed(&self, error: impl Into<String>) {
        let mut status = self.0.write().await;
        status.object_storage_connected = false;
        status.last_storage_error = Some(error.into());
    }

    pub(crate) async fn storage_reconciled(&self) {
        let mut status = self.0.write().await;
        status.storage_initial_reconciliation_complete = true;
        status.last_storage_reconciled_at = Some(Utc::now());
    }
}
