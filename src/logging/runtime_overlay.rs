//! RTDS log-level consumer.
//!
//! Reserved key: `ferrum.log.level` (string). Values are passed straight to
//! the tracing reload handle as `RUST_LOG`-style filter directives so
//! operators can express anything `EnvFilter::new()` accepts
//! (`"info"`, `"ferrum_edge=trace,hyper=warn"`, etc.).
//!
//! Behaviour:
//!
//! - Key absent → no-op. Operators dropping the key from a future RTDS
//!   layer does NOT roll back to a previous filter; the binary keeps
//!   whatever was last installed (or the startup default if nothing has
//!   ever been pushed). Rolling back requires the CP to push the previous
//!   value explicitly.
//! - Key present but wrong shape (number / bool / fractional_percent) →
//!   warn and no-op, do not crash the slice install.
//! - Empty / blank string → warn and no-op.
//! - Filter parse failure → warn and no-op (preserves the last-good
//!   filter).
//!
//! The reloader is registered by the binary at startup (see
//! `src/main.rs::init_logging` → `crate::logging::set_log_level_reloader`).
//! When no reloader is registered (validate-only mode, library-only tests,
//! file mode with logging suppressed) the consumer is a no-op.

use tracing::warn;

use crate::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};

pub(crate) const LOG_LEVEL_KEY: &str = "ferrum.log.level";

/// Apply the RTDS log-level overlay slot to the process-global tracing
/// reload handle. Returns the directive that was applied (for tests),
/// `None` when the key was absent / unusable / no reloader registered.
pub fn apply_overlay(overlay: &MeshRuntimeOverlay) -> Option<String> {
    let value = overlay.fields.get(LOG_LEVEL_KEY)?;
    let directive = match value {
        RuntimeValue::String(s) => s.trim(),
        _ => {
            warn!(
                key = LOG_LEVEL_KEY,
                "RTDS overlay value is not a string; log-level update skipped"
            );
            return None;
        }
    };
    if directive.is_empty() {
        warn!(
            key = LOG_LEVEL_KEY,
            "RTDS overlay log-level directive is empty; skipping"
        );
        return None;
    }
    let Some(reloader) = super::log_level_reloader() else {
        // Binary hasn't registered a reloader (validate-only mode, tests,
        // file mode with custom logging). Not an error.
        return None;
    };
    match reloader.reload(directive) {
        Ok(()) => Some(directive.to_string()),
        Err(err) => {
            warn!(
                key = LOG_LEVEL_KEY,
                directive = directive,
                error = %err,
                "RTDS overlay log-level reload failed; keeping previous filter"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn overlay_with_log_level(value: RuntimeValue) -> MeshRuntimeOverlay {
        let mut fields = HashMap::new();
        fields.insert(LOG_LEVEL_KEY.to_string(), value);
        MeshRuntimeOverlay { fields }
    }

    #[test]
    fn missing_key_returns_none() {
        let overlay = MeshRuntimeOverlay::default();
        assert_eq!(apply_overlay(&overlay), None);
    }

    #[test]
    fn non_string_value_returns_none() {
        // A reloader may or may not have been installed by another test in
        // the same binary. We only assert the apply path doesn't panic and
        // returns None for non-string values.
        let overlay = overlay_with_log_level(RuntimeValue::Number(42.0));
        assert_eq!(apply_overlay(&overlay), None);
    }

    #[test]
    fn empty_string_returns_none() {
        let overlay = overlay_with_log_level(RuntimeValue::String("   ".into()));
        assert_eq!(apply_overlay(&overlay), None);
    }
}
