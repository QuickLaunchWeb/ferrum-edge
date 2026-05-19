//! CNI-style install scaffolding for the node-agent.
//!
//! The CNI binary (`bin/ferrum-cni`) implements the minimal CNI spec on the
//! wire (stdin JSON + CNI_* env vars + stdout JSON) and forwards each ADD /
//! DEL / CHECK invocation to the long-lived node-agent over a Unix domain
//! socket. The node-agent owns BPF program lifecycle, map maintenance, and
//! metrics; the CNI binary is the thin per-pod hook the kubelet drives during
//! sandbox setup.
//!
//! Two distinct on-wire shapes live in this module:
//!
//! - [`spec`] — the CNI specification's stdin/stdout JSON, plus the
//!   parsed-env representation of `CNI_*` invocation variables.
//! - [`rpc`] — the small node-agent RPC the CNI binary speaks once it has
//!   extracted the K8s pod metadata from CNI args. Keeping these shapes
//!   distinct keeps the CNI parser independent of the node-agent surface
//!   so we can evolve either side without churning the other.
//!
//! Why both? The CNI spec defines the byte-for-byte JSON the kubelet hands
//! us; the node-agent RPC is internal and intentionally minimal (no
//! interface/IP allocation responsibilities — Ferrum chains behind the
//! cluster's primary CNI which already owns those). The two boundaries
//! correspond exactly to what is "spec mandated" vs "internal to Ferrum",
//! and the type split keeps that clear.
//!
//! See `docs/node_agent.md` "CNI plugin install" for the install steps and
//! fallback semantics (the kube-rs watcher in
//! `src/modes/node_agent.rs` continues to enroll pods if the CNI install
//! hasn't landed or the cluster's primary CNI rejects the chained config).

pub mod client;
pub mod rpc;
pub mod spec;
