//! Consumers for the xDS RTDS-driven [`MeshRuntimeOverlay`].
//!
//! Operators ship runtime knobs through the mesh xDS client; every accepted
//! slice runs through [`apply_overlay`] before the snapshot is published so
//! plugin hot paths can read the current value off a process-global
//! `ArcSwap` instead of walking the overlay on every request.
//!
//! Consumer dispatch is by reserved key namespace:
//!
//! - `ferrum.fault_injection.<scope>.abort_percent` /
//!   `ferrum.fault_injection.<scope>.delay_percent` — drive the
//!   [`fault_injection`](crate::plugins::fault_injection) plugin via
//!   [`crate::plugins::fault_injection::runtime_overlay`].
//! - `ferrum.log.level` — rebuild the tracing `EnvFilter` via the global
//!   reload handle installed at startup (`crate::logging::reload_layer`).
//! - `ferrum.request_transformer.<scope>.enabled` /
//!   `ferrum.response_transformer.<scope>.enabled` — gate the header /
//!   query / body rules of opted-in `request_transformer` /
//!   `response_transformer` plugins.
//!
//! GAP-3E note: the registry is intentionally tiny — each consumer owns its
//! own state and reads what it cares about. Adding a new consumer is a
//! single `apply_*` call from [`apply_overlay`] plus its own module-global
//! `ArcSwap` (or equivalent reload handle).

#![allow(dead_code)]

use crate::modes::mesh::config::MeshRuntimeOverlay;

/// Apply every RTDS-driven runtime knob exposed on `overlay`. Called from
/// `MeshRuntimeState::install_slice` after the slice is staged so consumers
/// always see the value that's about to be (or has just been) published on
/// the lock-free snapshot.
///
/// Cold path; allocations are bounded by the number of `ferrum.*` keys in
/// the overlay. No-op when none are present.
pub fn apply_overlay(overlay: &MeshRuntimeOverlay) {
    crate::plugins::fault_injection::runtime_overlay::apply_overlay(overlay);
    crate::plugins::request_transformer::runtime_overlay::apply_overlay(overlay);
    crate::plugins::response_transformer::runtime_overlay::apply_overlay(overlay);
    crate::logging::runtime_overlay::apply_overlay(overlay);
}
