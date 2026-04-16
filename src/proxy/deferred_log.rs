//! Deferred transaction logging for streaming responses.
//!
//! Problem: `log_with_mirror()` fires synchronously right after response
//! headers are sent. For streaming responses, this is before the body has
//! finished streaming to the client — so mid-stream disconnects, body
//! errors, and partial writes are not reflected in the log entry.
//!
//! Solution: [`DeferredTransactionLogger`] holds the `TransactionSummary`
//! and the plugin/context references needed to emit the log entry, and
//! exposes a [`fire`](DeferredTransactionLogger::fire) method that the
//! response body wrapper invokes on completion or error. A `Drop` safety
//! net ensures the log still fires if the body is dropped without
//! completing (e.g. hyper cancelled the connection after headers flushed).
//!
//! The logger is single-fire (guarded by `AtomicBool` CAS) so a normal
//! body-complete fire and the Drop safety net can never both emit.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::plugins::{Plugin, RequestContext, TransactionSummary, log_with_mirror};
use crate::retry::ErrorClass;

/// Observed outcome of a streaming response body.
///
/// Populated by the body wrapper when it reaches a terminal state (all
/// frames sent, backend error, client disconnect) and passed to
/// [`DeferredTransactionLogger::fire`] so the log entry reflects the
/// actual client-visible outcome rather than the value at header-flush time.
#[derive(Debug, Clone)]
pub struct BodyOutcome {
    /// True when the body finished sending all frames to hyper without error.
    pub body_completed: bool,
    /// Classification of a streaming error, if any. `None` for successful
    /// completion and for client-disconnect cases where the underlying body
    /// never yielded an error frame.
    pub body_error_class: Option<ErrorClass>,
    /// Total bytes of body data passed to hyper for the client.
    pub bytes_streamed_to_client: u64,
    /// True when the body did not complete because the client stopped
    /// consuming. Also true for the `Drop` safety-net path.
    pub client_disconnected: bool,
}

impl BodyOutcome {
    /// Construct an outcome representing successful body completion.
    pub fn success(bytes_streamed: u64) -> Self {
        Self {
            body_completed: true,
            body_error_class: None,
            bytes_streamed_to_client: bytes_streamed,
            client_disconnected: false,
        }
    }

    /// Construct an outcome representing a streaming error. The body
    /// partially streamed before failing, so `bytes_streamed` may be > 0.
    pub fn error(class: ErrorClass, bytes_streamed: u64, client_disconnected: bool) -> Self {
        Self {
            body_completed: false,
            body_error_class: Some(class),
            bytes_streamed_to_client: bytes_streamed,
            client_disconnected,
        }
    }

    /// Construct an outcome representing a client disconnect detected via
    /// the `Drop` safety net (no explicit error frame observed).
    pub fn client_disconnect(bytes_streamed: u64) -> Self {
        Self {
            body_completed: false,
            body_error_class: Some(ErrorClass::ClientDisconnect),
            bytes_streamed_to_client: bytes_streamed,
            client_disconnected: true,
        }
    }
}

/// Logger that defers a `log_with_mirror()` call until the response body
/// reaches a terminal state. Clone-friendly via [`Arc`].
///
/// Single-fire: the first call to [`fire`](Self::fire) wins; subsequent
/// calls (e.g. a Drop safety net running after an explicit fire) are no-ops.
pub struct DeferredTransactionLogger {
    state: Mutex<Option<LogState>>,
    fired: AtomicBool,
}

/// Captured log state. Held inside a [`Mutex`] so [`fire`](DeferredTransactionLogger::fire)
/// can `take()` it and move it into the spawned log task. After the first fire
/// the slot is `None`, but the `fired` CAS already prevents a second fire so
/// the `None` state is only visible to no-op callers.
struct LogState {
    summary: TransactionSummary,
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    ctx: Arc<RequestContext>,
}

impl DeferredTransactionLogger {
    /// Build a new deferred logger. The returned `Arc` is typically cloned
    /// into the response body wrapper so the body can call `fire` on
    /// completion or error, and into a fallback holder so a catch-all
    /// path can fire if the body is never polled.
    pub fn new(
        summary: TransactionSummary,
        plugins: Arc<Vec<Arc<dyn Plugin>>>,
        ctx: Arc<RequestContext>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Some(LogState {
                summary,
                plugins,
                ctx,
            })),
            fired: AtomicBool::new(false),
        })
    }

    /// Fire the deferred log with the given outcome. Only the first call
    /// takes effect; subsequent calls return immediately.
    ///
    /// The actual `log_with_mirror` invocation is performed on a spawned
    /// tokio task so this function does not block hyper's poll loop or a
    /// `Drop` handler. When no tokio runtime is available (process
    /// shutdown), the log is dropped silently — there is no I/O we could
    /// do from outside a runtime anyway.
    pub fn fire(&self, outcome: BodyOutcome) {
        // Single-fire semantics: AcqRel so the winner sees prior writes
        // and the loser sees our take() of state.
        if self
            .fired
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.fire_once(outcome);
    }

    fn fire_once(&self, outcome: BodyOutcome) {
        let state = match self.state.lock() {
            Ok(mut guard) => guard.take(),
            // A poisoned mutex means another thread panicked while holding
            // the guard. The state is still valid data, so recover it and
            // proceed — losing a log entry is worse than propagating poison.
            Err(poisoned) => poisoned.into_inner().take(),
        };
        let Some(state) = state else {
            return;
        };
        let LogState {
            mut summary,
            plugins,
            ctx,
        } = state;
        summary.body_completed = outcome.body_completed;
        summary.body_error_class = outcome.body_error_class;
        summary.bytes_streamed_to_client = outcome.bytes_streamed_to_client;
        summary.client_disconnected = outcome.client_disconnected;

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    log_with_mirror(plugins.as_slice(), &summary, &ctx).await;
                });
            }
            Err(_) => {
                // Outside a tokio runtime — nothing we can do.
            }
        }
    }
}

impl Drop for DeferredTransactionLogger {
    fn drop(&mut self) {
        // Safety net: if the body was dropped without explicitly firing
        // (e.g. hyper cancelled the connection mid-stream), emit a log
        // entry classified as a client disconnect. Bytes streamed default
        // to 0 because we cannot access the body's atomic counter from here
        // — callers that care about partial-byte accuracy should call
        // `fire` explicitly with the observed count.
        if !self.fired.swap(true, Ordering::AcqRel) {
            self.fire_once(BodyOutcome::client_disconnect(0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn fire_is_single_shot() {
        let counter = Arc::new(AtomicUsize::new(0));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> =
            Arc::new(vec![Arc::new(CountingPlugin(counter.clone()))]);
        let ctx = Arc::new(RequestContext::new(
            "1.2.3.4".to_string(),
            "GET".to_string(),
            "/".to_string(),
        ));
        let summary = fake_summary();

        let logger = DeferredTransactionLogger::new(summary, plugins, ctx);
        logger.fire(BodyOutcome::success(42));
        logger.fire(BodyOutcome::success(1_000_000));

        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn drop_safety_net_fires_when_never_fired() {
        let counter = Arc::new(AtomicUsize::new(0));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> =
            Arc::new(vec![Arc::new(CountingPlugin(counter.clone()))]);
        let ctx = Arc::new(RequestContext::new(
            "1.2.3.4".to_string(),
            "GET".to_string(),
            "/".to_string(),
        ));
        let logger = DeferredTransactionLogger::new(fake_summary(), plugins, ctx);
        drop(logger);

        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn drop_after_explicit_fire_does_not_double_log() {
        let counter = Arc::new(AtomicUsize::new(0));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> =
            Arc::new(vec![Arc::new(CountingPlugin(counter.clone()))]);
        let ctx = Arc::new(RequestContext::new(
            "1.2.3.4".to_string(),
            "GET".to_string(),
            "/".to_string(),
        ));
        let logger = DeferredTransactionLogger::new(fake_summary(), plugins, ctx);
        logger.fire(BodyOutcome::success(10));
        drop(logger);

        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    fn fake_summary() -> TransactionSummary {
        TransactionSummary {
            namespace: "ferrum".to_string(),
            timestamp_received: "2026-01-01T00:00:00Z".to_string(),
            client_ip: "1.2.3.4".to_string(),
            consumer_username: None,
            http_method: "GET".to_string(),
            request_path: "/".to_string(),
            matched_proxy_id: None,
            matched_proxy_name: None,
            backend_target_url: None,
            backend_resolved_ip: None,
            response_status_code: 200,
            latency_total_ms: 0.0,
            latency_gateway_processing_ms: 0.0,
            latency_backend_ttfb_ms: 0.0,
            latency_backend_total_ms: -1.0,
            latency_plugin_execution_ms: 0.0,
            latency_plugin_external_io_ms: 0.0,
            latency_gateway_overhead_ms: 0.0,
            request_user_agent: None,
            response_streamed: true,
            client_disconnected: false,
            error_class: None,
            body_error_class: None,
            body_completed: false,
            bytes_streamed_to_client: 0,
            mirror: false,
            metadata: std::collections::HashMap::new(),
        }
    }

    struct CountingPlugin(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl Plugin for CountingPlugin {
        fn name(&self) -> &str {
            "counting"
        }

        fn priority(&self) -> u16 {
            9000
        }

        async fn log(&self, _summary: &TransactionSummary) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}
