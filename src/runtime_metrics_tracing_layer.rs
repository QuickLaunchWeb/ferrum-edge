//! Tracing layer that counts log events for `/metrics/runtime`.
//!
//! Classification is deliberately bounded and static. We count the module
//! target into a small category vocabulary rather than using raw targets as
//! labels, preserving the gateway's cardinality discipline.

use std::sync::Arc;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use crate::runtime_metrics::{LogLevel, RuntimeMetrics};

pub struct CountingLayer {
    metrics: Arc<RuntimeMetrics>,
}

impl CountingLayer {
    pub fn new(metrics: Arc<RuntimeMetrics>) -> Self {
        Self { metrics }
    }
}

impl<S> Layer<S> for CountingLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if !should_count_target(event.metadata().target()) {
            return;
        }
        let level = level_to_runtime(*event.metadata().level());
        let category = classify_target(event.metadata().target());
        self.metrics.record_log(level, category);
    }
}

fn level_to_runtime(level: Level) -> LogLevel {
    match level {
        Level::TRACE => LogLevel::Trace,
        Level::DEBUG => LogLevel::Debug,
        Level::INFO => LogLevel::Info,
        Level::WARN => LogLevel::Warn,
        Level::ERROR => LogLevel::Error,
    }
}

pub fn classify_target(target: &str) -> &'static str {
    if target.contains("http3") {
        "http3"
    } else if target.contains("grpc") {
        "grpc"
    } else if target.contains("modes::mesh")
        || target.contains("plugins::mesh")
        || target.contains("::mesh")
        || target.contains("xds")
    {
        "mesh"
    } else if target.contains("dns") {
        "dns"
    } else if target.contains("pool") || target.contains("connection_pool") {
        "pool"
    } else if target.contains("config") {
        "config"
    } else if target.contains("admin") {
        "admin"
    } else if target.contains("plugins") {
        "plugin"
    } else if target.contains("proxy") {
        "proxy"
    } else {
        "other"
    }
}

pub fn should_count_target(target: &str) -> bool {
    target.starts_with("ferrum_edge") || target.starts_with("custom_plugins")
}

#[cfg(test)]
mod tests {
    #[test]
    fn target_classification_is_bounded() {
        assert_eq!(
            super::classify_target("ferrum_edge::proxy::grpc_proxy"),
            "grpc"
        );
        assert_eq!(
            super::classify_target("ferrum_edge::modes::mesh::runtime"),
            "mesh"
        );
        assert_eq!(
            super::classify_target("ferrum_edge::connection_pool"),
            "pool"
        );
        assert_eq!(super::classify_target("something_else"), "other");
    }

    #[test]
    fn target_counting_is_project_scoped() {
        assert!(super::should_count_target("ferrum_edge::proxy"));
        assert!(super::should_count_target("custom_plugins::my_plugin"));
        assert!(!super::should_count_target("hyper::proto"));
    }
}
