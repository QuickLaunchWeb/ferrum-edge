//! Shared percent-roll helper for fault-injection style plugins.
//!
//! Both the proxy-scoped [`fault_injection`](crate::plugins::fault_injection)
//! plugin and the per-rule `Fault` action carried by
//! [`mesh_route_dispatch`](crate::plugins::mesh_route_dispatch) make the same
//! per-request "did this percentile roll hit?" decision. Keeping the math in
//! one place ensures both surfaces stay semantically identical: same RNG,
//! same threshold mapping, same handling of the `>= 100.0` short-circuit.
//!
//! ## Sampling model
//!
//! Each call to [`FaultRoller::roll_pair`] consumes one `AtomicU64::fetch_add`
//! and one `splitmix64` mix, then splits the 64-bit mix into two independent
//! 32-bit samples (delay = high 32, abort = low 32). Each sample is compared
//! against `(percentage / 100) * 2^32` to decide whether the roll hit.
//!
//! ## Hot-path properties
//!
//! - Zero allocations.
//! - One relaxed atomic increment per call.
//! - Pure arithmetic — no syscalls, no `thread_rng()` lazy init, no locks.

use std::sync::atomic::{AtomicU64, Ordering};

const PROBABILITY_DENOMINATOR: u64 = 1 << 32;

/// Per-instance roll counter. Wrap one of these per plugin instance (or per
/// per-rule action carrier) so concurrent requests get distinct samples and
/// percentile distributions converge to the configured percentage.
///
/// `AtomicU64` is sufficient for monotonic counter semantics on every
/// platform Ferrum builds for; the actual randomness comes from
/// [`splitmix64`] post-mixing the counter.
#[derive(Debug, Default)]
pub struct FaultRoller {
    counter: AtomicU64,
}

/// Outcome of one paired roll for delay + abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultRollOutcome {
    pub delay_triggered: bool,
    pub abort_triggered: bool,
}

impl FaultRoller {
    pub fn new() -> Self {
        Self::default()
    }

    /// Roll for both delay and abort percentages in one atomic-counter
    /// increment.
    ///
    /// `None` for either percentage skips that side (returns `false`).
    /// `Some(pct)` rolls a single 32-bit sample against `pct / 100`.
    /// `pct >= 100.0` is a definite hit, `pct <= 0.0` is a definite miss.
    pub fn roll_pair(
        &self,
        delay_percentage: Option<f64>,
        abort_percentage: Option<f64>,
    ) -> FaultRollOutcome {
        let sample = splitmix64(self.counter.fetch_add(1, Ordering::Relaxed));
        let delay_sample = (sample >> 32) as u32;
        let abort_sample = sample as u32;
        FaultRollOutcome {
            delay_triggered: delay_percentage.is_some_and(|pct| probability_hit(delay_sample, pct)),
            abort_triggered: abort_percentage.is_some_and(|pct| probability_hit(abort_sample, pct)),
        }
    }
}

/// Compare a 32-bit sample against a percentage threshold.
///
/// `percentage >= 100.0` always hits; `percentage <= 0.0` never hits.
/// Non-finite (`NaN`, `+Inf`, `-Inf`) inputs are treated as misses so a
/// future bug that lets garbage reach the hot path can never accidentally
/// fire 100% faults. Config validators reject non-finite / out-of-range
/// inputs at construction; this is defense-in-depth.
pub fn probability_hit(sample: u32, percentage: f64) -> bool {
    if !percentage.is_finite() {
        return false;
    }
    if percentage >= 100.0 {
        return true;
    }
    if percentage <= 0.0 {
        return false;
    }
    let threshold = ((percentage / 100.0) * PROBABILITY_DENOMINATOR as f64) as u64;
    u64::from(sample) < threshold
}

/// 64-bit SplitMix used as a stateless mixer over a monotonic counter.
/// Identical constants to the canonical `splitmix64` finalizer — keeps
/// sample distribution identical to the original fault-injection plugin.
pub fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E3779B97F4A7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D049BB133111EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_zero_never_hits() {
        for s in [0u32, 1, 100, u32::MAX] {
            assert!(!probability_hit(s, 0.0));
        }
    }

    #[test]
    fn percent_hundred_always_hits() {
        for s in [0u32, 1, 100, u32::MAX] {
            assert!(probability_hit(s, 100.0));
        }
    }

    #[test]
    fn percent_nonfinite_misses() {
        assert!(!probability_hit(0, f64::NAN));
        assert!(!probability_hit(0, f64::INFINITY));
        assert!(!probability_hit(0, f64::NEG_INFINITY));
    }

    #[test]
    fn rolls_distribute_around_target_percentage() {
        let roller = FaultRoller::new();
        let mut delay_hits = 0u32;
        let mut abort_hits = 0u32;
        let trials = 20_000u32;
        for _ in 0..trials {
            let outcome = roller.roll_pair(Some(50.0), Some(10.0));
            if outcome.delay_triggered {
                delay_hits += 1;
            }
            if outcome.abort_triggered {
                abort_hits += 1;
            }
        }
        // Delay should be near 50%; abort near 10%. Generous bounds: this is
        // a smoke test, not a chi-squared validation.
        assert!(
            (8_000..=12_000).contains(&delay_hits),
            "delay hits {delay_hits} out of {trials} should be near 50%"
        );
        assert!(
            (1_500..=2_500).contains(&abort_hits),
            "abort hits {abort_hits} out of {trials} should be near 10%"
        );
    }

    #[test]
    fn none_percentage_never_hits() {
        let roller = FaultRoller::new();
        for _ in 0..32 {
            let outcome = roller.roll_pair(None, None);
            assert!(!outcome.delay_triggered);
            assert!(!outcome.abort_triggered);
        }
    }
}
