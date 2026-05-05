//! xDS conformance hooks.
//!
//! Phase B ships the protocol state machine and a local set of test cases that
//! mirror the Envoy xds-conformance scenarios Ferrum must pass as the resource
//! encoders become richer in later phases.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdsConformanceCase {
    ResourceRemovalDuringUpdate,
    PartialNackPerTypeUrl,
    VersionDriftRejected,
    DeltaSubscribeUnsubscribe,
}

pub fn required_phase_b_cases() -> &'static [XdsConformanceCase] {
    &[
        XdsConformanceCase::ResourceRemovalDuringUpdate,
        XdsConformanceCase::PartialNackPerTypeUrl,
        XdsConformanceCase::VersionDriftRejected,
        XdsConformanceCase::DeltaSubscribeUnsubscribe,
    ]
}
