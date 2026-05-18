//! Admin API audit logging.
//!
//! When enabled, audit events are written through a bounded worker queue per
//! database backend. The HTTP mutation path never waits for queue capacity; if
//! the bounded queue is full, enqueue fails fast and the committed mutation
//! response can proceed after logging the audit failure. Audit persistence is
//! best-effort and happens after the mutation response path has enqueued the
//! event.

use crate::admin::jwt_auth::{AdminClaims, AdminRole};
use crate::config::db_backend::DatabaseBackend;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock, Weak};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::{Duration, MissedTickBehavior, interval};
use tracing::error;
use uuid::Uuid;

const AUDIT_CHANNEL_CAPACITY: usize = 1024;
const AUDIT_SINK_STALE_CHECK_INTERVAL_SECONDS: u64 = 60;

static AUDIT_SINKS: LazyLock<DashMap<usize, AuditSinkEntry>> = LazyLock::new(DashMap::new);

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

#[derive(Clone)]
struct AuditSinkEntry {
    backend: Weak<dyn DatabaseBackend>,
    sink: AuditSink,
}

struct AuditEnvelope {
    event: AuditEvent,
}

impl AuditSink {
    fn spawn(key: usize, db: Weak<dyn DatabaseBackend>) -> Self {
        let (tx, mut rx) = mpsc::channel::<AuditEnvelope>(AUDIT_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            let mut stale_check =
                interval(Duration::from_secs(AUDIT_SINK_STALE_CHECK_INTERVAL_SECONDS));
            stale_check.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    maybe_envelope = rx.recv() => {
                        let Some(envelope) = maybe_envelope else {
                            break;
                        };

                        let Some(db) = db.upgrade() else {
                            remove_stale_sink(key);
                            error!(
                                audit_event_id = %envelope.event.id,
                                "Dropped admin audit event because the backend is unavailable"
                            );
                            break;
                        };

                        if let Err(message) = db
                            .insert_audit_event(&envelope.event)
                            .await
                            .map_err(|error| error.to_string())
                        {
                            error!(
                                audit_event_id = %envelope.event.id,
                                error = %message,
                                "Failed to persist admin audit event"
                            );
                        }
                    }
                    _ = stale_check.tick() => {
                        if db.upgrade().is_none() {
                            remove_stale_sink(key);
                            break;
                        }
                    }
                }
            }
        });
        Self { tx }
    }

    fn record(&self, event: AuditEvent) -> Result<(), anyhow::Error> {
        self.tx
            .try_send(AuditEnvelope { event })
            .map_err(|error| match error {
                TrySendError::Full(envelope) => anyhow!(
                    "admin audit queue is full; audit event {} was not enqueued",
                    envelope.event.id
                ),
                TrySendError::Closed(_) => anyhow!("admin audit worker is unavailable"),
            })
    }
}

fn db_key(db: &Arc<dyn DatabaseBackend>) -> usize {
    // Handler clones share this inner pointer, so the address is a stable
    // per-backend worker key while the backend Arc is alive. Stale entries are
    // tied to a Weak backend reference and removed once that backend drops.
    Arc::as_ptr(db) as *const () as usize
}

fn remove_stale_sink(key: usize) {
    AUDIT_SINKS.remove_if(&key, |_, entry| entry.backend.upgrade().is_none());
}

fn entry_matches_backend(entry: &AuditSinkEntry, db: &Arc<dyn DatabaseBackend>) -> bool {
    entry
        .backend
        .upgrade()
        .is_some_and(|existing| Arc::ptr_eq(&existing, db))
}

fn sink_for_db(db: Arc<dyn DatabaseBackend>) -> AuditSink {
    let key = db_key(&db);
    // Fast path: live entry for this exact backend pointer.
    if let Some(entry) = AUDIT_SINKS.get(&key)
        && entry_matches_backend(&entry, &db)
    {
        return entry.sink.clone();
    }

    // Slow path: take the entry write lock so the spawn-and-insert is atomic.
    // Without this, two threads can both miss the `get`, both spawn a worker,
    // and only one survives — leaving the other's mpsc Sender to be dropped at
    // the end of `record`, which closes that orphan worker before its event is
    // processed. Holding the entry lock across the live-check + spawn + insert
    // guarantees one worker per backend Arc.
    let entry = AUDIT_SINKS.entry(key).or_insert_with(|| {
        let backend = Arc::downgrade(&db);
        let sink = AuditSink::spawn(key, backend.clone());
        AuditSinkEntry { backend, sink }
    });
    if entry_matches_backend(&entry, &db) {
        return entry.sink.clone();
    }

    // The existing entry references a different (stale) backend at the same
    // address — drop it and retry. Calling `remove` while still holding the
    // RefMut would deadlock, so release it first.
    drop(entry);
    AUDIT_SINKS.remove(&key);
    let backend = Arc::downgrade(&db);
    let sink = AuditSink::spawn(key, backend.clone());
    AUDIT_SINKS.insert(
        key,
        AuditSinkEntry {
            backend,
            sink: sink.clone(),
        },
    );
    sink
}

pub fn record(
    enabled: bool,
    db: Arc<dyn DatabaseBackend>,
    event: AuditEvent,
) -> Result<(), anyhow::Error> {
    if !enabled {
        return Ok(());
    }

    let sink = sink_for_db(Arc::clone(&db));
    sink.record(event)
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
