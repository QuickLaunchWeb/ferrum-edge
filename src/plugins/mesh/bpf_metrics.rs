//! `__mesh_bpf_metrics` — surfaces BPF SOCK_OPS counters as Prometheus
//! metrics.
//!
//! GAP-SC3 introduces a `BPF_PROG_TYPE_SOCK_OPS` program that emits
//! TCP-layer events (Connect, AcceptEstablished, RstSent/Received,
//! FinSent/Received, SRTT samples, BPF drop-reason hits) to a userspace
//! ringbuf. The [`crate::ebpf::event_consumer::SockOpsConsumer`] drains
//! that ringbuf and updates a shared [`BpfMetricsState`]. This plugin
//! exposes that state in Prometheus exposition format.
//!
//! ## Auto-injection
//!
//! The plugin is auto-injected as a global plugin only when the mesh
//! topology is `NodeWaypoint`. Other topologies (sidecar, ambient,
//! east/egress gateway) don't run the SOCK_OPS BPF program — emitting
//! always-zero counters from them would mislead operator dashboards.
//!
//! ## What the metrics answer
//!
//! - **`ferrum_mesh_bpf_tcp_events_total{event="connect"|"accept"|...}`**:
//!   per-event TCP-lifecycle counts. Operators correlate `accept` vs
//!   `connect` rates to spot stuck pods or pre-handshake drops.
//! - **`ferrum_mesh_bpf_drops_total{reason="bypass_uid_hit"|...}`**:
//!   how often each BPF drop reason fired. Previously invisible — the
//!   GAP-SC3 plan calls out this win explicitly.
//! - **`ferrum_mesh_bpf_ringbuf_overruns_total`**: ringbuf overruns. The
//!   `_in_overrun_regime` companion gauge stays at 1 between the warn
//!   and recovery transitions so dashboards can alert without scraping
//!   logs.
//! - **TCP-layer latency aggregates** (SRTT, syn→ack, accept→first-byte)
//!   as `_sum`/`_count` so operators can derive averages. Histogram
//!   buckets are deferred.

#![allow(dead_code)]

use std::fmt::Write;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::ebpf::bpf_metrics::{BpfDropReason, BpfMetricsSnapshot, BpfMetricsState};
use crate::plugins::{ALL_PROTOCOLS, Plugin, ProxyProtocol, priority};

/// Plugin name as it appears in plugin chain configuration. The `__mesh_`
/// prefix marks it as a reserved auto-injected mesh plugin.
pub const PLUGIN_NAME: &str = "__mesh_bpf_metrics";

/// Operator-facing config knobs.
#[derive(Debug, Clone)]
struct BpfMetricsConfig {
    /// Optional metric prefix override. Defaults to `ferrum_mesh_bpf`.
    /// Operators with multiple gateway instances on a node can use this
    /// to disambiguate the time series, mirroring the existing
    /// `prometheus_metrics` plugin's namespace_label pattern.
    prefix: String,
}

impl Default for BpfMetricsConfig {
    fn default() -> Self {
        Self {
            prefix: "ferrum_mesh_bpf".to_string(),
        }
    }
}

/// `__mesh_bpf_metrics` plugin.
///
/// Holds an `Arc<BpfMetricsState>` populated by
/// [`crate::ebpf::event_consumer::SockOpsConsumer`]. The Plugin trait
/// hooks are intentionally no-ops — this plugin's role is to register
/// itself in the plugin chain (so its presence is operator-visible via
/// `available_plugins()` / `/admin/plugins`) and to expose
/// [`Self::render_prometheus`] for the metrics endpoint to call.
pub struct MeshBpfMetrics {
    config: BpfMetricsConfig,
    state: Arc<BpfMetricsState>,
}

// Manual Debug impl: BpfMetricsState contains atomics, which Debug only
// via `Relaxed` loads of their values. We don't need that granularity for
// plugin Debug output; the prefix and a static "state=..." marker is
// enough for panic messages in tests and for `Result::unwrap` formatting.
impl std::fmt::Debug for MeshBpfMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshBpfMetrics")
            .field("config", &self.config)
            .field("state", &"<BpfMetricsState>")
            .finish()
    }
}

impl MeshBpfMetrics {
    /// Construct from operator config + the consumer's metrics state.
    ///
    /// In production the state is the same Arc the SockOpsConsumer is
    /// updating — see `inject_mesh_global_plugins()` in
    /// `src/modes/mesh/mod.rs` for the wiring point.
    pub fn with_state(config: &Value, state: Arc<BpfMetricsState>) -> Result<Self, String> {
        let parsed = parse_config(config)?;
        Ok(Self {
            config: parsed,
            state,
        })
    }

    /// Test/operator constructor: builds a plugin owning a fresh empty
    /// metrics state. Useful in plugin-validation paths and in unit
    /// tests that just check the plugin lifecycle hooks.
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::with_state(config, BpfMetricsState::new())
    }

    pub fn metrics_state(&self) -> Arc<BpfMetricsState> {
        self.state.clone()
    }

    pub fn snapshot(&self) -> BpfMetricsSnapshot {
        self.state.snapshot()
    }

    /// Render the BPF metrics in Prometheus text exposition format.
    ///
    /// Cold path — called once per `/metrics` scrape. Emits TYPE and
    /// HELP comments for each metric so the output is self-describing.
    pub fn render_prometheus(&self) -> String {
        let snap = self.state.snapshot();
        let mut out = String::with_capacity(2048);
        let p = self.config.prefix.as_str();

        // TCP-layer event counters.
        let _ = writeln!(
            out,
            "# HELP {p}_tcp_events_total TCP-layer events captured by the BPF SOCK_OPS program."
        );
        let _ = writeln!(out, "# TYPE {p}_tcp_events_total counter");
        let _ = writeln!(
            out,
            "{p}_tcp_events_total{{event=\"connect\"}} {}",
            snap.connect
        );
        let _ = writeln!(
            out,
            "{p}_tcp_events_total{{event=\"accept_established\"}} {}",
            snap.accept_established
        );
        let _ = writeln!(
            out,
            "{p}_tcp_events_total{{event=\"rst_sent\"}} {}",
            snap.rst_sent
        );
        let _ = writeln!(
            out,
            "{p}_tcp_events_total{{event=\"rst_received\"}} {}",
            snap.rst_received
        );
        let _ = writeln!(
            out,
            "{p}_tcp_events_total{{event=\"fin_sent\"}} {}",
            snap.fin_sent
        );
        let _ = writeln!(
            out,
            "{p}_tcp_events_total{{event=\"fin_received\"}} {}",
            snap.fin_received
        );

        // Drop-reason counters.
        let _ = writeln!(
            out,
            "# HELP {p}_drops_total Connection-bypass decisions by reason. \
            These were previously invisible to operators."
        );
        let _ = writeln!(out, "# TYPE {p}_drops_total counter");
        for (reason, count) in snap.drop_reasons() {
            let _ = writeln!(
                out,
                "{p}_drops_total{{reason=\"{}\"}} {count}",
                reason.label()
            );
        }
        // Mention the well-known reasons we know about, even at 0, so
        // dashboards stay informative on fresh installs.
        let _ = writeln!(
            out,
            "# HELP {p}_drop_reasons Well-known BPF drop reason labels (gauge=1 to make the label set self-documenting)."
        );
        let _ = writeln!(out, "# TYPE {p}_drop_reasons gauge");
        for reason in [
            BpfDropReason::BypassUidHit,
            BpfDropReason::ExcludeCidrHit,
            BpfDropReason::NotInIncludeCidr,
            BpfDropReason::ExcludePortHit,
        ] {
            let _ = writeln!(out, "{p}_drop_reasons{{reason=\"{}\"}} 1", reason.label());
        }

        // Latency sum/count aggregates (TCP-layer only; app-layer stays
        // in workload_metrics).
        let _ = writeln!(
            out,
            "# HELP {p}_srtt_microseconds TCP smoothed RTT samples (sum + count for mean derivation)."
        );
        let _ = writeln!(out, "# TYPE {p}_srtt_microseconds summary");
        let _ = writeln!(out, "{p}_srtt_microseconds_sum {}", snap.srtt_sample_us_sum);
        let _ = writeln!(out, "{p}_srtt_microseconds_count {}", snap.srtt_count);

        let _ = writeln!(
            out,
            "# HELP {p}_syn_to_ack_microseconds Time between SYN send and ACK observation."
        );
        let _ = writeln!(out, "# TYPE {p}_syn_to_ack_microseconds summary");
        let _ = writeln!(
            out,
            "{p}_syn_to_ack_microseconds_sum {}",
            snap.syn_to_ack_us_sum
        );
        let _ = writeln!(
            out,
            "{p}_syn_to_ack_microseconds_count {}",
            snap.syn_to_ack_count
        );

        let _ = writeln!(
            out,
            "# HELP {p}_accept_to_first_byte_microseconds Time between accept and first inbound data byte."
        );
        let _ = writeln!(out, "# TYPE {p}_accept_to_first_byte_microseconds summary");
        let _ = writeln!(
            out,
            "{p}_accept_to_first_byte_microseconds_sum {}",
            snap.accept_to_first_byte_us_sum
        );
        let _ = writeln!(
            out,
            "{p}_accept_to_first_byte_microseconds_count {}",
            snap.accept_to_first_byte_count
        );

        // Ringbuf health.
        let _ = writeln!(
            out,
            "# HELP {p}_ringbuf_events_total Total events drained from the SOCK_OPS ringbuf."
        );
        let _ = writeln!(out, "# TYPE {p}_ringbuf_events_total counter");
        let _ = writeln!(
            out,
            "{p}_ringbuf_events_total {}",
            snap.ringbuf_events_consumed
        );
        let _ = writeln!(
            out,
            "# HELP {p}_ringbuf_overruns_total Ringbuf overrun count. Non-zero = userspace consumer fell behind and the kernel dropped events. Set FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES higher."
        );
        let _ = writeln!(out, "# TYPE {p}_ringbuf_overruns_total counter");
        let _ = writeln!(out, "{p}_ringbuf_overruns_total {}", snap.ringbuf_overruns);
        let _ = writeln!(
            out,
            "# HELP {p}_ringbuf_in_overrun_regime 1 while the consumer is in an overrun regime, 0 after recovery. Pair with `_overruns_total` for alerting."
        );
        let _ = writeln!(out, "# TYPE {p}_ringbuf_in_overrun_regime gauge");
        let _ = writeln!(
            out,
            "{p}_ringbuf_in_overrun_regime {}",
            if snap.in_overrun_regime { 1 } else { 0 }
        );

        out
    }
}

fn parse_config(config: &Value) -> Result<BpfMetricsConfig, String> {
    let mut parsed = BpfMetricsConfig::default();
    if let Some(prefix) = config.get("prefix") {
        let prefix = prefix
            .as_str()
            .ok_or_else(|| "__mesh_bpf_metrics: `prefix` must be a string".to_string())?
            .trim();
        if prefix.is_empty() {
            return Err("__mesh_bpf_metrics: `prefix` must not be empty".to_string());
        }
        if !prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(
                "__mesh_bpf_metrics: `prefix` must be `[A-Za-z0-9_]+` to form valid Prometheus metric names"
                    .to_string(),
            );
        }
        parsed.prefix = prefix.to_string();
    }
    Ok(parsed)
}

#[async_trait]
impl Plugin for MeshBpfMetrics {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> u16 {
        priority::MESH_BPF_METRICS
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        // Touches no per-request state; safe across every protocol the
        // chain supports so an operator config that targets this plugin
        // at a non-mesh proxy isn't silently dropped.
        ALL_PROTOCOLS
    }

    // No hot-path hooks. The plugin is a passive metrics surface; all
    // counter updates happen on the event-consumer task that shares the
    // same `Arc<BpfMetricsState>`. The Plugin trait's default no-op
    // implementations for the request/response/stream/ws hooks are
    // exactly the right shape — we don't override any of them.
}

/// Wire `MeshBpfMetrics` into the per-proxy plugin slot.
///
/// Used by `inject_mesh_global_plugins` in `src/modes/mesh/mod.rs` to
/// attach the plugin when topology is `NodeWaypoint`. The config payload
/// is the serialized JSON we hand into the plugin cache constructor.
pub fn config_payload() -> Value {
    serde_json::json!({})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> Arc<BpfMetricsState> {
        BpfMetricsState::new()
    }

    #[test]
    fn default_config_accepted() {
        let plugin = MeshBpfMetrics::with_state(&Value::Null, metrics()).unwrap();
        assert_eq!(plugin.config.prefix, "ferrum_mesh_bpf");
    }

    #[test]
    fn empty_object_config_accepted() {
        MeshBpfMetrics::with_state(&serde_json::json!({}), metrics()).unwrap();
    }

    #[test]
    fn custom_prefix_accepted() {
        let plugin =
            MeshBpfMetrics::with_state(&serde_json::json!({ "prefix": "tenantA_bpf" }), metrics())
                .unwrap();
        assert_eq!(plugin.config.prefix, "tenantA_bpf");
    }

    #[test]
    fn invalid_prefix_rejected() {
        let err =
            MeshBpfMetrics::with_state(&serde_json::json!({ "prefix": "with spaces" }), metrics())
                .unwrap_err();
        assert!(err.contains("prefix"));

        let empty_err =
            MeshBpfMetrics::with_state(&serde_json::json!({ "prefix": "  " }), metrics())
                .unwrap_err();
        assert!(empty_err.contains("must not be empty"));
    }

    #[test]
    fn render_prometheus_emits_expected_metric_families() {
        let state = metrics();
        // Seed a few counters so the render is non-zero.
        state.record_connect();
        state.record_accept_established();
        state.record_srtt_sample(250);
        state.record_drop(BpfDropReason::BypassUidHit);
        state.record_ringbuf_overrun();
        let plugin = MeshBpfMetrics::with_state(&Value::Null, state).unwrap();

        let text = plugin.render_prometheus();
        // TCP event counters
        assert!(text.contains("ferrum_mesh_bpf_tcp_events_total{event=\"connect\"} 1"));
        assert!(text.contains("ferrum_mesh_bpf_tcp_events_total{event=\"accept_established\"} 1"));
        // Drop counters (concrete count + the self-documenting gauge)
        assert!(text.contains("ferrum_mesh_bpf_drops_total{reason=\"bypass_uid_hit\"} 1"));
        assert!(text.contains("ferrum_mesh_bpf_drop_reasons{reason=\"exclude_cidr_hit\"} 1"));
        // Latency aggregates
        assert!(text.contains("ferrum_mesh_bpf_srtt_microseconds_sum 250"));
        assert!(text.contains("ferrum_mesh_bpf_srtt_microseconds_count 1"));
        // Ringbuf health: in-regime gauge flipped to 1 after the overrun.
        assert!(text.contains("ferrum_mesh_bpf_ringbuf_overruns_total 1"));
        assert!(text.contains("ferrum_mesh_bpf_ringbuf_in_overrun_regime 1"));
    }

    #[test]
    fn render_prometheus_honors_custom_prefix() {
        let plugin =
            MeshBpfMetrics::with_state(&serde_json::json!({ "prefix": "tenantA_bpf" }), metrics())
                .unwrap();
        let text = plugin.render_prometheus();
        assert!(text.contains("tenantA_bpf_tcp_events_total{event=\"connect\"} 0"));
        assert!(!text.contains("ferrum_mesh_bpf_tcp_events_total"));
    }

    #[test]
    fn plugin_metadata_matches_reserved_priority() {
        let plugin = MeshBpfMetrics::with_state(&Value::Null, metrics()).unwrap();
        assert_eq!(plugin.name(), PLUGIN_NAME);
        assert_eq!(plugin.priority(), priority::MESH_BPF_METRICS);
    }
}
