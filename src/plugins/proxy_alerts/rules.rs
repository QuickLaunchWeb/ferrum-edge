//! Rule types and per-sample evaluation logic for `proxy_alerts`.
//!
//! Each rule type carries its own threshold spec and a list of channel ids
//! to dispatch to. The plugin's `log()` / `on_stream_disconnect()` hook
//! iterates rules, calls `Rule::observe(...)`, records into the shared
//! [`WindowStore`], snapshots the current window, and decides whether to
//! dispatch via the cooldown + recovery gates.

use std::sync::Arc;

use crate::notifications::Severity;
use crate::plugins::{DisconnectCause, StreamTransactionSummary, TransactionSummary};
use crate::retry::ErrorClass;

use super::windows::{RuleWindowSpec, WindowKind, WindowStore};

#[allow(clippy::enum_variant_names)] // All variants are millisecond metrics by intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyMetric {
    BackendTotalMs,
    BackendTtfbMs,
    TotalMs,
    StreamDurationMs,
}

impl LatencyMetric {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BackendTotalMs => "backend_total_ms",
            Self::BackendTtfbMs => "backend_ttfb_ms",
            Self::TotalMs => "total_ms",
            Self::StreamDurationMs => "stream_duration_ms",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    pub resolved_window_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RuleCommon {
    pub id: u32,
    pub name: Arc<str>,
    pub window_seconds: u32,
    pub cooldown_ms: u64,
    pub recovery: Option<RecoveryConfig>,
    pub severity: Severity,
    /// Channel ids (indexes into the plugin's channel table). Resolved at
    /// construction so the hot path does not look up channel names.
    pub channel_ids: Vec<u32>,
    /// Channel names parallel to `channel_ids`, for log/notification body
    /// fields. Sized identically to `channel_ids`.
    pub channel_names: Vec<Arc<str>>,
}

#[derive(Debug, Clone)]
pub struct ErrorRateRule {
    pub common: RuleCommon,
    pub status_codes: Vec<u16>,
    pub threshold_percent: f64,
    pub min_request_count: u64,
}

#[derive(Debug, Clone)]
pub struct StatusCodeCountRule {
    pub common: RuleCommon,
    pub status_codes: Vec<u16>,
    pub threshold_count: u64,
}

#[derive(Debug, Clone)]
pub struct LatencyPercentileRule {
    pub common: RuleCommon,
    pub metric: LatencyMetric,
    pub percentile: u8,
    pub threshold_ms: f64,
    pub min_request_count: u64,
}

#[derive(Debug, Clone)]
pub struct ErrorClassRule {
    pub common: RuleCommon,
    pub classes: Vec<ErrorClass>,
    pub threshold_count: u64,
}

#[derive(Debug, Clone)]
pub struct StreamDisconnectCauseRule {
    pub common: RuleCommon,
    pub causes: Vec<DisconnectCause>,
    pub threshold_count: u64,
}

#[derive(Debug, Clone)]
pub enum Rule {
    ErrorRate(ErrorRateRule),
    StatusCodeCount(StatusCodeCountRule),
    LatencyPercentile(LatencyPercentileRule),
    ErrorClass(ErrorClassRule),
    StreamDisconnectCause(StreamDisconnectCauseRule),
}

impl Rule {
    pub fn common(&self) -> &RuleCommon {
        match self {
            Self::ErrorRate(r) => &r.common,
            Self::StatusCodeCount(r) => &r.common,
            Self::LatencyPercentile(r) => &r.common,
            Self::ErrorClass(r) => &r.common,
            Self::StreamDisconnectCause(r) => &r.common,
        }
    }

    pub fn id(&self) -> u32 {
        self.common().id
    }

    #[allow(dead_code)] // Used by external test crate.
    pub fn name(&self) -> &str {
        &self.common().name
    }

    pub fn window_spec(&self) -> RuleWindowSpec {
        let window_seconds = self.common().window_seconds;
        let kind = match self {
            Self::LatencyPercentile(_) => WindowKind::Histogram,
            _ => WindowKind::Counter,
        };
        RuleWindowSpec {
            window_seconds,
            kind,
        }
    }

    pub fn type_str(&self) -> &'static str {
        match self {
            Self::ErrorRate(_) => "error_rate",
            Self::StatusCodeCount(_) => "status_code_count",
            Self::LatencyPercentile(_) => "latency_percentile",
            Self::ErrorClass(_) => "error_class",
            Self::StreamDisconnectCause(_) => "stream_disconnect_cause",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SampleInput<'a> {
    Http(&'a TransactionSummary),
    Stream(&'a StreamTransactionSummary),
}

impl<'a> SampleInput<'a> {
    pub fn proxy_id(&self) -> Option<&str> {
        match self {
            Self::Http(s) => s.proxy_id.as_deref(),
            Self::Stream(s) => Some(s.proxy_id.as_str()),
        }
    }

    pub fn proxy_name(&self) -> Option<&str> {
        match self {
            Self::Http(s) => s.proxy_name.as_deref(),
            Self::Stream(s) => s.proxy_name.as_deref(),
        }
    }

    pub fn namespace(&self) -> &str {
        match self {
            Self::Http(s) => s.namespace.as_str(),
            Self::Stream(s) => s.namespace.as_str(),
        }
    }
}

/// Outcome of evaluating a rule against the current window state. The
/// plugin uses these to render the dispatched notification.
#[derive(Debug, Clone)]
pub struct RuleObservation {
    /// `true` when the threshold is currently exceeded (subject to
    /// `min_request_count` etc.).
    pub breach: bool,
    /// Human-readable rendering of the observed value, e.g. `"6.7%"`,
    /// `"1873ms"`, `"204"`.
    pub observed: String,
    /// Human-readable rendering of the threshold.
    pub threshold: String,
    /// Total number of samples in the window (denominator for rates,
    /// hit count for counters, total observations for histograms).
    pub sample_count: u64,
    /// Concise "what happened" string suitable for the notification body.
    pub reason: String,
}

impl Rule {
    /// Record the sample (when applicable) and return an observation if the
    /// rule is interested in this sample type. Returns `None` for rules
    /// whose sample family doesn't apply (e.g., HTTP-only rules on stream
    /// disconnects, stream-only rules on HTTP transactions).
    pub fn observe<'a>(
        &self,
        sample: SampleInput<'a>,
        store: &WindowStore,
        now_ms: u64,
    ) -> Option<RuleObservation> {
        let proxy_id = sample.proxy_id()?;
        match self {
            Rule::ErrorRate(r) => observe_error_rate(r, sample, proxy_id, store, now_ms),
            Rule::StatusCodeCount(r) => {
                observe_status_code_count(r, sample, proxy_id, store, now_ms)
            }
            Rule::LatencyPercentile(r) => {
                observe_latency_percentile(r, sample, proxy_id, store, now_ms)
            }
            Rule::ErrorClass(r) => observe_error_class(r, sample, proxy_id, store, now_ms),
            Rule::StreamDisconnectCause(r) => {
                observe_stream_disconnect(r, sample, proxy_id, store, now_ms)
            }
        }
    }
}

fn observe_error_rate(
    rule: &ErrorRateRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let SampleInput::Http(s) = sample else {
        return None;
    };
    let matched = rule.status_codes.contains(&s.response_status_code);
    store.record_count(rule.common.id, proxy_id, matched, now_ms);
    let (matched_total, total) = store.snapshot_count(rule.common.id, proxy_id, now_ms);
    let percent = if total == 0 {
        0.0
    } else {
        (matched_total as f64 / total as f64) * 100.0
    };
    let breach = total >= rule.min_request_count && percent >= rule.threshold_percent;
    Some(RuleObservation {
        breach,
        observed: format!("{percent:.2}%"),
        threshold: format!("{:.2}%", rule.threshold_percent),
        sample_count: total,
        reason: format!(
            "{}/{} requests matched {:?} over {}s",
            matched_total, total, rule.status_codes, rule.common.window_seconds
        ),
    })
}

fn observe_status_code_count(
    rule: &StatusCodeCountRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let SampleInput::Http(s) = sample else {
        return None;
    };
    let matched = rule.status_codes.contains(&s.response_status_code);
    store.record_count(rule.common.id, proxy_id, matched, now_ms);
    let (matched_total, _) = store.snapshot_count(rule.common.id, proxy_id, now_ms);
    let breach = matched_total >= rule.threshold_count;
    Some(RuleObservation {
        breach,
        observed: matched_total.to_string(),
        threshold: rule.threshold_count.to_string(),
        sample_count: matched_total,
        reason: format!(
            "{} requests with status in {:?} over {}s",
            matched_total, rule.status_codes, rule.common.window_seconds
        ),
    })
}

fn observe_latency_percentile(
    rule: &LatencyPercentileRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let latency = match (rule.metric, sample) {
        (LatencyMetric::BackendTotalMs, SampleInput::Http(s)) => s.latency_backend_total_ms,
        (LatencyMetric::BackendTtfbMs, SampleInput::Http(s)) => s.latency_backend_ttfb_ms,
        (LatencyMetric::TotalMs, SampleInput::Http(s)) => s.latency_total_ms,
        (LatencyMetric::StreamDurationMs, SampleInput::Stream(s)) => s.duration_ms,
        _ => return None,
    };
    if latency < 0.0 || !latency.is_finite() {
        // Sentinel value (-1.0) or NaN — skip recording but still return
        // a no-breach observation so the recovery state machine can
        // progress on subsequent valid samples.
        let (estimate, total) =
            store.snapshot_percentile(rule.common.id, proxy_id, rule.percentile, now_ms);
        return Some(RuleObservation {
            breach: false,
            observed: estimate
                .map(format_latency)
                .unwrap_or_else(|| "n/a".to_string()),
            threshold: format!("{:.0}ms", rule.threshold_ms),
            sample_count: total,
            reason: format!(
                "p{} of {} over {}s",
                rule.percentile,
                rule.metric.as_str(),
                rule.common.window_seconds
            ),
        });
    }
    store.record_latency(rule.common.id, proxy_id, latency, now_ms);
    let (estimate, total) =
        store.snapshot_percentile(rule.common.id, proxy_id, rule.percentile, now_ms);
    let breach = total >= rule.min_request_count
        && estimate.map(|v| v >= rule.threshold_ms).unwrap_or(false);
    Some(RuleObservation {
        breach,
        observed: estimate
            .map(format_latency)
            .unwrap_or_else(|| "n/a".to_string()),
        threshold: format!("{:.0}ms", rule.threshold_ms),
        sample_count: total,
        reason: format!(
            "p{} of {} over {}s ({} samples)",
            rule.percentile,
            rule.metric.as_str(),
            rule.common.window_seconds,
            total
        ),
    })
}

fn observe_error_class(
    rule: &ErrorClassRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let class = match sample {
        SampleInput::Http(s) => s.error_class.or(s.body_error_class),
        SampleInput::Stream(s) => s.error_class,
    };
    let matched = match class {
        Some(c) => rule.classes.contains(&c),
        None => false,
    };
    store.record_count(rule.common.id, proxy_id, matched, now_ms);
    let (matched_total, _) = store.snapshot_count(rule.common.id, proxy_id, now_ms);
    let breach = matched_total >= rule.threshold_count;
    let class_names: Vec<&'static str> = rule.classes.iter().map(|c| c.as_str()).collect();
    Some(RuleObservation {
        breach,
        observed: matched_total.to_string(),
        threshold: rule.threshold_count.to_string(),
        sample_count: matched_total,
        reason: format!(
            "{} transactions classified as {:?} over {}s",
            matched_total, class_names, rule.common.window_seconds
        ),
    })
}

fn observe_stream_disconnect(
    rule: &StreamDisconnectCauseRule,
    sample: SampleInput<'_>,
    proxy_id: &str,
    store: &WindowStore,
    now_ms: u64,
) -> Option<RuleObservation> {
    let SampleInput::Stream(s) = sample else {
        return None;
    };
    let cause = s.disconnect_cause;
    let matched = match cause {
        Some(c) => rule.causes.contains(&c),
        None => false,
    };
    store.record_count(rule.common.id, proxy_id, matched, now_ms);
    let (matched_total, _) = store.snapshot_count(rule.common.id, proxy_id, now_ms);
    let breach = matched_total >= rule.threshold_count;
    let cause_names: Vec<&'static str> = rule
        .causes
        .iter()
        .map(|c| disconnect_cause_str(*c))
        .collect();
    Some(RuleObservation {
        breach,
        observed: matched_total.to_string(),
        threshold: rule.threshold_count.to_string(),
        sample_count: matched_total,
        reason: format!(
            "{} stream disconnects with cause in {:?} over {}s",
            matched_total, cause_names, rule.common.window_seconds
        ),
    })
}

fn disconnect_cause_str(c: DisconnectCause) -> &'static str {
    match c {
        DisconnectCause::IdleTimeout => "idle_timeout",
        DisconnectCause::RecvError => "recv_error",
        DisconnectCause::BackendError => "backend_error",
        DisconnectCause::GracefulShutdown => "graceful_shutdown",
    }
}

fn format_latency(v: f64) -> String {
    if v.is_infinite() {
        ">30000ms".to_string()
    } else {
        format!("{:.0}ms", v)
    }
}
