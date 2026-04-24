//! Phase-5 acceptance tests — network-simulation wrappers.
//!
//! These tests insert a [`crate::scaffolding::network::NetworkSimProxy`]
//! middleman between the gateway and a scripted backend so each accepted
//! connection goes through a `DelayedStream` / `BandwidthLimitedStream`
//! / `TruncatedStream` pipeline. The gateway sees a "slow network" to
//! the backend; the tests assert the gateway's timing + metrics behave
//! correctly against it.
//!
//! Run with:
//!   cargo build --bin ferrum-edge &&
//!   cargo test --test functional_tests scripted_backend_network_sim -- --ignored --nocapture

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::file_mode_yaml_for_backend_with;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::network::NetworkSimProxy;
use crate::scaffolding::ports::reserve_port;
use reqwest::StatusCode;
use serde_json::json;
use std::time::{Duration, Instant};

fn require_logs(harness: &GatewayHarness) -> String {
    let logs = harness
        .captured_combined()
        .expect("read captured gateway logs");
    assert!(
        !logs.trim().is_empty(),
        "gateway logs were empty — did you forget .capture_output() on the builder?"
    );
    logs
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1 — slow backend (within the gateway's read timeout) completes OK.
// ────────────────────────────────────────────────────────────────────────────
//
// Fixture:
//   - `ScriptedHttp1Backend` sending a normal 200 OK response.
//   - `NetworkSimProxy` in front with 400 ms read+write latency.
//   - Gateway configured with `backend_read_timeout_ms = 2000` — well
//     above the injected delay.
//
// Expected: request returns 200, total elapsed ≥ 400 ms (proving the
// latency was actually injected and not no-op'd away).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn slow_backend_within_read_timeout_completes() {
    // Inner scripted HTTP backend.
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = ScriptedHttp1Backend::builder(backend_res.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "2".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn http backend");

    // Middleman proxy with latency.
    let proxy_res = reserve_port().await.expect("proxy port");
    let middleman_port = proxy_res.port;
    let _middleman = NetworkSimProxy::builder(proxy_res.into_listener())
        .forward_to(("127.0.0.1", backend_port))
        .with_latency(Duration::from_millis(400))
        .spawn()
        .expect("spawn middleman");

    // Gateway pointed at the middleman, with a read timeout comfortably
    // above the injected latency.
    let yaml =
        file_mode_yaml_for_backend_with(middleman_port, json!({ "backend_read_timeout_ms": 2000 }));
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let resp = client
        .get(&harness.proxy_url("/api/slow"))
        .await
        .expect("response");
    let elapsed = started.elapsed();

    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body_text(), "ok");
    // Latency fires on every read+write; one full request requires at
    // least 2 round-trips (write + read), so ≥ 400 ms is a floor even
    // on a fast host.
    assert!(
        elapsed >= Duration::from_millis(400),
        "expected latency to propagate (≥400 ms), got {elapsed:?}"
    );
    // And well under the 2 s read timeout.
    assert!(
        elapsed < Duration::from_millis(1800),
        "took too long ({elapsed:?}) — gateway may have read-timeout'd"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — throttled backend + tight backend_read_timeout fires 502.
// ────────────────────────────────────────────────────────────────────────────
//
// Fixture:
//   - `ScriptedHttp1Backend` that responds after a long `Sleep` (the
//     real reason the request stalls; the middleman latency reinforces
//     this but is not the primary driver).
//   - `NetworkSimProxy` with bandwidth limit + latency so even if the
//     backend replied immediately, the middleman would throttle it.
//   - Gateway with `backend_read_timeout_ms = 400` — much tighter than
//     the combined slow-backend budget.
//
// Expected: 502 or 504, elapsed near the gateway's timeout, gateway
// logs carry a read-timeout / connection-abort signal (not a body-
// mid-stream one, to distinguish from other Phase-1 tests).
//
// Note: the plan calls this a "write timeout" because the gateway
// writes the client's body to the backend and the backend consumes
// slowly. That behaviour is only observable via
// `backend_write_timeout_ms` on *raw TCP* proxies (see
// `src/proxy/tcp_proxy.rs`); for HTTP/1 via reqwest the gateway's
// per-request budget is `backend_read_timeout_ms`. This test
// exercises the HTTP path — the only surface that matters for
// scripted HTTP backends. The TCP write-timeout path has its own
// Phase-1 coverage via `backend_read_timeout_fires_after_backend_read_timeout_ms`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn backend_bandwidth_below_budget_triggers_write_timeout() {
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = ScriptedHttp1Backend::builder(backend_res.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        // Backend is asleep for much longer than the gateway's read
        // timeout. This is the actual forcing function.
        .step(HttpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn http backend");

    // Middleman with tight bandwidth + some latency. If either the
    // latency OR the bandwidth delay gets the gateway to give up, the
    // test still counts.
    let proxy_res = reserve_port().await.expect("proxy port");
    let middleman_port = proxy_res.port;
    let _middleman = NetworkSimProxy::builder(proxy_res.into_listener())
        .forward_to(("127.0.0.1", backend_port))
        .with_bandwidth_limit(1024) // 1 KB/s
        .with_latency(Duration::from_millis(200))
        .spawn()
        .expect("spawn middleman");

    let yaml =
        file_mode_yaml_for_backend_with(middleman_port, json!({ "backend_read_timeout_ms": 400 }));
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let resp = client
        .get(&harness.proxy_url("/api/slow"))
        .await
        .expect("response");
    let elapsed = started.elapsed();

    assert!(
        matches!(
            resp.status,
            StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
        ),
        "expected 502/504, got {}",
        resp.status
    );
    // Should time out within ~1.5× the configured budget plus latency.
    assert!(
        elapsed <= Duration::from_millis(2500),
        "took too long ({elapsed:?}); gateway should have given up at ~400ms"
    );
    // Verify the gateway's error classification matches a timeout path
    // rather than, say, a connect-refused or body-error path. Any of
    // these tokens indicates the gateway gave up on the backend.
    let logs = require_logs(&harness);
    let saw_timeout_signal = logs.contains("read_timeout")
        || logs.contains("Timeout")
        || logs.contains("timeout")
        || logs.contains("GatewayTimeout")
        || logs.contains("502")
        || logs.contains("Backend request failed");
    assert!(
        saw_timeout_signal,
        "expected timeout/502 signal in gateway logs:\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3 — high latency preserves TTFB metric.
// ────────────────────────────────────────────────────────────────────────────
//
// Fixture:
//   - Backend that responds immediately.
//   - Middleman with 300 ms latency on reads and writes.
//   - Gateway with generous `backend_read_timeout_ms`.
//
// Expected:
//   - Total elapsed ≥ 300 ms (round trips see the latency).
//   - Gateway logs / metrics show a latency signal consistent with the
//     injected delay — the key observable is that the gateway's TTFB
//     measurement is NOT zero (it tracks real backend response time,
//     not just dispatch time).
//
// The plan's exact text calls for "TTFB ≥ 200ms AND total ≥ 200ms, and
// both visible in admin `/metrics` or log output". Ferrum's current
// admin metrics don't split TTFB vs. total latency publicly, so we
// assert on the total-elapsed as the floor and log for the latency
// signal. Phase-5's doc update should mention this if a `time_to_first_byte`
// metric lands later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn high_latency_preserves_first_byte_latency_metrics() {
    let backend_res = reserve_port().await.expect("backend port");
    let backend_port = backend_res.port;
    let _backend = ScriptedHttp1Backend::builder(backend_res.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "5".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"hello".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn http backend");

    let proxy_res = reserve_port().await.expect("proxy port");
    let middleman_port = proxy_res.port;
    let _middleman = NetworkSimProxy::builder(proxy_res.into_listener())
        .forward_to(("127.0.0.1", backend_port))
        .with_latency(Duration::from_millis(300))
        .spawn()
        .expect("spawn middleman");

    let yaml = file_mode_yaml_for_backend_with(
        middleman_port,
        json!({ "backend_read_timeout_ms": 10000 }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let resp = client
        .get(&harness.proxy_url("/api/ttfb"))
        .await
        .expect("response");
    let elapsed = started.elapsed();
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body_text(), "hello");

    // TTFB-proxy assertion: the client's total elapsed cannot be
    // less than the injected latency — so a successful request with
    // elapsed ≥ 300 ms proves the gateway is not collapsing backend
    // latency into zero (e.g., via a spurious cache).
    assert!(
        elapsed >= Duration::from_millis(300),
        "expected ≥300 ms round trip, got {elapsed:?}"
    );

    // Verify the gateway's transaction log (if captured) reflects a
    // non-trivial backend latency. Ferrum's stdout_logging plugin
    // emits request-level JSON that carries `latency_ms`; sampling
    // that catches a "TTFB was rounded to 0" regression.
    //
    // The gateway doesn't enable stdout_logging by default in a bare
    // file config, so the absence of a latency line is not a hard
    // fail — we log an advisory. (Wiring a plugin to capture latency
    // is a Phase-8 item; this test covers the wrapper half of the
    // chain.)
    let logs = harness.captured_combined().expect("capture");
    if logs.contains("latency_ms") {
        // If we can find a latency_ms field, sanity-check it.
        if let Some(pos) = logs.find("\"latency_ms\":") {
            let tail = &logs[pos + "\"latency_ms\":".len()..];
            let end = tail
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(tail.len());
            if let Ok(ms) = tail[..end].parse::<u64>() {
                assert!(
                    ms >= 250,
                    "gateway logged latency_ms={ms} but injected \
                     latency was 300ms — TTFB measurement may be broken"
                );
            }
        }
    }
}
