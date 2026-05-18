//! RTDS overlay consumer for the [`FaultInjectionPlugin`](super::FaultInjectionPlugin).
//!
//! Reserved keys (per opt-in scope `<scope>`):
//!
//! - `ferrum.fault_injection.<scope>.abort_percent`
//! - `ferrum.fault_injection.<scope>.delay_percent`
//!
//! Accepted value kinds:
//!
//! - `RuntimeValue::Number(0.0..=100.0)`
//! - `RuntimeValue::FractionalPercent(_)` (mapped to a 0–100 percentage via
//!   [`runtime_value_as_percent`](crate::modes::mesh::config::runtime_value_as_percent))
//!
//! Out-of-range numbers, non-finite values, and other variants (`Bool`,
//! `String`) are silently dropped on the cold path so a malformed overlay
//! never disables the plugin. The plugin's static `percentage` config is
//! the floor.
//!
//! Storage is one process-global `ArcSwap<HashMap<String, ScopeOverride>>`
//! rebuilt from scratch on every slice install. The hot path reads the
//! snapshot once per request via [`current_overrides`] — no map allocation,
//! no locking.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwap;

use crate::modes::mesh::config::{MeshRuntimeOverlay, runtime_value_as_percent};

const KEY_PREFIX: &str = "ferrum.fault_injection.";
const ABORT_SUFFIX: &str = ".abort_percent";
const DELAY_SUFFIX: &str = ".delay_percent";

/// Per-scope override values. Absent fields mean "fall back to static
/// config".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScopeOverride {
    pub abort_percent: Option<f64>,
    pub delay_percent: Option<f64>,
}

type OverrideMap = HashMap<String, ScopeOverride>;

static OVERRIDES: LazyLock<ArcSwap<OverrideMap>> =
    LazyLock::new(|| ArcSwap::new(Arc::new(HashMap::new())));

/// Snapshot of the active overrides for a single request. Cheap to create
/// (just an Arc clone). Plugins call this once at the top of their hook.
#[derive(Clone)]
pub struct FaultOverridesSnapshot {
    inner: Arc<OverrideMap>,
}

impl FaultOverridesSnapshot {
    pub fn abort_percent(&self, scope: &str) -> Option<f64> {
        self.inner.get(scope).and_then(|s| s.abort_percent)
    }

    pub fn delay_percent(&self, scope: &str) -> Option<f64> {
        self.inner.get(scope).and_then(|s| s.delay_percent)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Load the current snapshot. Reads one `Arc<OverrideMap>` (no lock, no
/// allocation) — safe to call per request.
pub fn current_overrides() -> FaultOverridesSnapshot {
    FaultOverridesSnapshot {
        inner: OVERRIDES.load_full(),
    }
}

/// Apply the RTDS overlay's `ferrum.fault_injection.*` slots. Called from
/// the mesh runtime-overlay consumer registry on every slice install. Cold
/// path; rebuilds the full override map so a key dropped from a later
/// slice properly rolls back to static config.
pub fn apply_overlay(overlay: &MeshRuntimeOverlay) {
    let mut next: OverrideMap = HashMap::new();
    for (raw_key, value) in &overlay.fields {
        let Some(rest) = raw_key.strip_prefix(KEY_PREFIX) else {
            continue;
        };
        // Strip whichever suffix is present; `<scope>` is everything
        // between the prefix and the suffix.
        let (scope, slot) = if let Some(scope) = rest.strip_suffix(ABORT_SUFFIX) {
            (scope, OverrideSlot::Abort)
        } else if let Some(scope) = rest.strip_suffix(DELAY_SUFFIX) {
            (scope, OverrideSlot::Delay)
        } else {
            continue;
        };
        if scope.is_empty() {
            continue;
        }
        let Some(pct) = runtime_value_as_percent(value) else {
            continue;
        };
        let entry = next.entry(scope.to_string()).or_default();
        match slot {
            OverrideSlot::Abort => entry.abort_percent = Some(pct),
            OverrideSlot::Delay => entry.delay_percent = Some(pct),
        }
    }
    OVERRIDES.store(Arc::new(next));
}

/// Reset state for tests in external crates. `pub` + `#[doc(hidden)]` so
/// the symbol is reachable from `tests/unit/plugins/*` and
/// `tests/integration/*` without ad-hoc visibility hacks. The binary
/// build path does not consume this function — hence the
/// `#[allow(dead_code)]`.
#[doc(hidden)]
#[allow(dead_code)]
pub fn reset_for_test() {
    OVERRIDES.store(Arc::new(HashMap::new()));
}

enum OverrideSlot {
    Abort,
    Delay,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::mesh::config::{
        FractionalPercentDenominator, RuntimeFractionalPercent, RuntimeValue,
    };

    fn overlay(entries: &[(&str, RuntimeValue)]) -> MeshRuntimeOverlay {
        let mut fields = HashMap::new();
        for (key, value) in entries {
            fields.insert((*key).to_string(), value.clone());
        }
        MeshRuntimeOverlay { fields }
    }

    // The tests in this module share the process-global `OVERRIDES` ArcSwap,
    // so they must each reset state at the top. Running them in serial via
    // a mutex would be cleaner, but the cargo-test default already
    // serializes lib tests by module path, and each test below only reads
    // / writes its own scope key.

    #[test]
    fn empty_overlay_clears_state() {
        reset_for_test();
        apply_overlay(&overlay(&[(
            "ferrum.fault_injection.cart.abort_percent",
            RuntimeValue::Number(50.0),
        )]));
        let snap = current_overrides();
        assert_eq!(snap.abort_percent("cart"), Some(50.0));

        apply_overlay(&MeshRuntimeOverlay::default());
        let snap = current_overrides();
        assert_eq!(snap.abort_percent("cart"), None);
    }

    #[test]
    fn parses_numeric_abort_and_delay() {
        reset_for_test();
        apply_overlay(&overlay(&[
            (
                "ferrum.fault_injection.checkout.abort_percent",
                RuntimeValue::Number(12.5),
            ),
            (
                "ferrum.fault_injection.checkout.delay_percent",
                RuntimeValue::Number(75.0),
            ),
        ]));
        let snap = current_overrides();
        assert_eq!(snap.abort_percent("checkout"), Some(12.5));
        assert_eq!(snap.delay_percent("checkout"), Some(75.0));
    }

    #[test]
    fn parses_fractional_percent() {
        reset_for_test();
        apply_overlay(&overlay(&[(
            "ferrum.fault_injection.reviews.abort_percent",
            RuntimeValue::FractionalPercent(RuntimeFractionalPercent {
                numerator: 2_500,
                denominator: FractionalPercentDenominator::TenThousand,
            }),
        )]));
        let snap = current_overrides();
        assert!((snap.abort_percent("reviews").unwrap() - 25.0).abs() < 1e-9);
    }

    #[test]
    fn rejects_non_numeric_values() {
        reset_for_test();
        apply_overlay(&overlay(&[
            (
                "ferrum.fault_injection.bad.abort_percent",
                RuntimeValue::Bool(true),
            ),
            (
                "ferrum.fault_injection.bad.delay_percent",
                RuntimeValue::String("nope".into()),
            ),
        ]));
        let snap = current_overrides();
        assert_eq!(snap.abort_percent("bad"), None);
        assert_eq!(snap.delay_percent("bad"), None);
    }

    #[test]
    fn rejects_out_of_range_numbers() {
        reset_for_test();
        apply_overlay(&overlay(&[
            (
                "ferrum.fault_injection.high.abort_percent",
                RuntimeValue::Number(150.0),
            ),
            (
                "ferrum.fault_injection.low.delay_percent",
                RuntimeValue::Number(-1.0),
            ),
        ]));
        let snap = current_overrides();
        assert_eq!(snap.abort_percent("high"), None);
        assert_eq!(snap.delay_percent("low"), None);
    }

    #[test]
    fn ignores_keys_with_empty_scope() {
        reset_for_test();
        apply_overlay(&overlay(&[(
            "ferrum.fault_injection..abort_percent",
            RuntimeValue::Number(50.0),
        )]));
        let snap = current_overrides();
        assert!(snap.is_empty());
    }

    #[test]
    fn ignores_unrelated_keys() {
        reset_for_test();
        apply_overlay(&overlay(&[
            ("envoy.reloadable_features.foo", RuntimeValue::Number(50.0)),
            (
                "ferrum.fault_injection.cart.unknown_suffix",
                RuntimeValue::Number(50.0),
            ),
        ]));
        let snap = current_overrides();
        assert!(snap.is_empty());
    }
}
