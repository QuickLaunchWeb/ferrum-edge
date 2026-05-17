//! Admin API audit logging.
//!
//! Audit events are written through a bounded worker queue per database backend.
//! The HTTP mutation path waits for the worker acknowledgement so a successful
//! mutation response means the corresponding audit event is also durable.

use crate::admin::jwt_auth::{AdminClaims, AdminRole};
use crate::config::db_backend::DatabaseBackend;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock};
use tokio::sync::{mpsc, oneshot};
use tracing::error;
use uuid::Uuid;

const AUDIT_CHANNEL_CAPACITY: usize = 1024;

static AUDIT_SINKS: LazyLock<DashMap<usize, AuditSink>> = LazyLock::new(DashMap::new);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub namespace: String,
    pub diff: Value,
}

impl AuditEvent {
    pub fn new(
        actor: &AuditActor,
        action: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
        namespace: impl Into<String>,
        diff: Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now(),
            actor: actor.sub.clone(),
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            namespace: namespace.into(),
            diff,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditActor {
    pub sub: String,
    pub role: AdminRole,
}

impl AuditActor {
    pub fn from_claims(claims: &AdminClaims) -> Result<Self, String> {
        Ok(Self {
            sub: claims.sub.clone(),
            role: claims.admin_role()?,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditListFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Clone)]
struct AuditSink {
    tx: mpsc::Sender<AuditEnvelope>,
}

struct AuditEnvelope {
    event: AuditEvent,
    ack: oneshot::Sender<Result<(), String>>,
}

impl AuditSink {
    fn spawn(db: Arc<dyn DatabaseBackend>) -> Self {
        let (tx, mut rx) = mpsc::channel::<AuditEnvelope>(AUDIT_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            while let Some(envelope) = rx.recv().await {
                let result = db
                    .insert_audit_event(&envelope.event)
                    .await
                    .map_err(|error| error.to_string());
                if let Err(ref message) = result {
                    error!(
                        audit_event_id = %envelope.event.id,
                        error = %message,
                        "Failed to persist admin audit event"
                    );
                }
                let _ = envelope.ack.send(result);
            }
        });
        Self { tx }
    }

    async fn record(&self, event: AuditEvent) -> Result<(), anyhow::Error> {
        let (ack, rx) = oneshot::channel();
        self.tx
            .send(AuditEnvelope { event, ack })
            .await
            .map_err(|_| anyhow!("admin audit worker is unavailable"))?;
        rx.await
            .map_err(|_| anyhow!("admin audit worker stopped before acknowledging event"))?
            .map_err(|message| anyhow!(message))
    }
}

fn db_key(db: &Arc<dyn DatabaseBackend>) -> usize {
    // `AdminState` owns the process-lifetime database Arc and all handler
    // clones share this inner pointer, so the address is a stable per-backend
    // worker key. If database ownership becomes reloadable, replace this with
    // an explicit backend instance id.
    Arc::as_ptr(db) as *const () as usize
}

fn sink_for_db(db: Arc<dyn DatabaseBackend>) -> AuditSink {
    let key = db_key(&db);
    AUDIT_SINKS
        .entry(key)
        .or_insert_with(|| AuditSink::spawn(db))
        .clone()
}

pub async fn record(db: Arc<dyn DatabaseBackend>, event: AuditEvent) -> Result<(), anyhow::Error> {
    sink_for_db(db).record(event).await
}

pub fn create_diff(after: Value) -> Value {
    json!({ "after": after })
}

pub fn update_diff(before: Value, after: Value) -> Value {
    json!({ "before": before, "after": after })
}

pub fn delete_diff(before: Value) -> Value {
    json!({ "before": before })
}
