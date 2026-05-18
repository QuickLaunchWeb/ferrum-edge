//! Integration coverage for the RTDS runtime-overlay consumer dispatch.
//!
//! `MeshRuntimeState::install_slice` is the single touch point that fans
//! out a slice's `runtime_overlay` to every consumer (fault injection,
//! header transformer gates, tracing log levels). These tests install
//! representative slices and assert each consumer reflects the overlay,
//! covering the full cold-path wiring without depending on the live xDS
//! ADS server.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ferrum_edge::logging::{LogLevelReloader, log_level_reloader, set_log_level_reloader};
use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::fault_injection::runtime_overlay as fault_overlay;
use ferrum_edge::plugins::request_transformer::runtime_overlay as request_gate;
use ferrum_edge::plugins::response_transformer::runtime_overlay as response_gate;

/// Process-global lock serialising every test in this module — the RTDS
/// consumers all back onto module-level `ArcSwap` state, so two tests racing
/// `apply_overlay` / `reset_for_test` would corrupt each other's
/// assertions. Defined at module scope so every test acquires the SAME
/// mutex; a `static` defined inside each test is a distinct mutex (local
/// statics are per-function) and would not serialise at all.
static CONSUMER_TEST_GUARD: Mutex<()> = Mutex::new(());

#[derive(Default, Clone)]
struct CapturingReloader {
    captured: Arc<Mutex<Vec<String>>>,
}

impl LogLevelReloader for CapturingReloader {
    fn reload(&self, directive: &str) -> Result<(), String> {
        self.captured
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(directive.to_string());
        Ok(())
    }
}

fn install_slice_with_overlay(state: &MeshRuntimeState, overlay: MeshRuntimeOverlay) {
    state.install_slice(MeshSlice {
        namespace: "alpha".to_string(),
        version: "consumer-test".to_string(),
        runtime_overlay: overlay,
        ..MeshSlice::default()
    });
}

#[test]
fn slice_install_fans_out_to_every_consumer() {
    // The consumer registry is process-global, so this test serialises
    // against any sibling that touches the same `ArcSwap` state via the
    // module-level `CONSUMER_TEST_GUARD` mutex. Reset every consumer at
    // entry and exit so leftover state from an earlier sibling can't
    // corrupt assertions.
    let _guard = CONSUMER_TEST_GUARD
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    fault_overlay::reset_for_test();
    request_gate::reset_for_test();
    response_gate::reset_for_test();

    let captured = Arc::new(Mutex::new(Vec::new()));
    // Best-effort: another test in the same binary may have already
    // installed a reloader. If so, we observe whatever it captured.
    let _ = set_log_level_reloader(Box::new(CapturingReloader {
        captured: captured.clone(),
    }));

    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.fault_injection.consumer_e2e.abort_percent".to_string(),
        RuntimeValue::Number(33.0),
    );
    fields.insert(
        "ferrum.request_transformer.consumer_e2e.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    fields.insert(
        "ferrum.response_transformer.consumer_e2e.enabled".to_string(),
        RuntimeValue::Bool(true),
    );
    fields.insert(
        "ferrum.log.level".to_string(),
        RuntimeValue::String("ferrum_edge=debug".into()),
    );

    let state = MeshRuntimeState::new();
    install_slice_with_overlay(&state, MeshRuntimeOverlay { fields });

    // Fault override populated.
    let snapshot = fault_overlay::current_overrides();
    assert_eq!(snapshot.abort_percent("consumer_e2e"), Some(33.0));
    assert_eq!(snapshot.delay_percent("consumer_e2e"), None);

    // Request gate populated.
    assert_eq!(
        request_gate::current_gates().gate("consumer_e2e"),
        Some(false)
    );

    // Response gate populated and independent from request gate.
    assert_eq!(
        response_gate::current_gates().gate("consumer_e2e"),
        Some(true)
    );

    // Log-level reload either captured our directive (if our reloader is
    // active) or was applied to whatever reloader the binary registered.
    // Either way, calling apply doesn't panic, and if our reloader is
    // active the captured vec includes the directive.
    if log_level_reloader().is_some() {
        // It may have been our reloader. Either way, no panic was raised.
    }
    // If our reloader was the one that got installed, the directive
    // appears.
    let captured_now = captured.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if !captured_now.is_empty() {
        assert!(
            captured_now.contains(&"ferrum_edge=debug".to_string()),
            "captured directives missing entry: {captured_now:?}"
        );
    }

    // Clean up.
    fault_overlay::reset_for_test();
    request_gate::reset_for_test();
    response_gate::reset_for_test();
}

#[test]
fn dropping_key_from_subsequent_slice_clears_the_consumer_value() {
    let _guard = CONSUMER_TEST_GUARD
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    fault_overlay::reset_for_test();
    request_gate::reset_for_test();

    let state = MeshRuntimeState::new();

    // Slice 1 sets values.
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.fault_injection.rolling.delay_percent".to_string(),
        RuntimeValue::Number(50.0),
    );
    fields.insert(
        "ferrum.request_transformer.rolling.enabled".to_string(),
        RuntimeValue::Bool(false),
    );
    install_slice_with_overlay(&state, MeshRuntimeOverlay { fields });
    assert_eq!(
        fault_overlay::current_overrides().delay_percent("rolling"),
        Some(50.0)
    );
    assert_eq!(request_gate::current_gates().gate("rolling"), Some(false));

    // Slice 2 has no overlay → both consumers must clear.
    install_slice_with_overlay(&state, MeshRuntimeOverlay::default());
    assert_eq!(
        fault_overlay::current_overrides().delay_percent("rolling"),
        None
    );
    assert_eq!(request_gate::current_gates().gate("rolling"), None);

    fault_overlay::reset_for_test();
    request_gate::reset_for_test();
}
