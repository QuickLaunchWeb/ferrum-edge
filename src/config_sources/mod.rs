//! External configuration source translators.
//!
//! Each source translates into the canonical `GatewayConfig` / `MeshConfig`
//! model. Sources do not talk directly to control protocols or proxy runtime
//! state.

pub mod k8s;
