//! HTTP/3 WebSocket bridging — RFC 9220 Extended CONNECT.
//!
//! [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) bootstraps a
//! WebSocket session over HTTP/3 using Extended CONNECT, the same
//! mechanism RFC 8441 defines for HTTP/2:
//!
//! 1. Server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`
//!    (controlled by `FERRUM_HTTP3_WEBSOCKET_ENABLED`, default on; wired
//!    in `src/http3/server.rs::handle_h3_connection`).
//! 2. Client sends `:method = CONNECT` + `:protocol = "websocket"` +
//!    `:scheme = "https"` + `:authority = ...` + `:path = ...` on a
//!    new bidirectional QUIC stream.
//! 3. Server replies with `:status = 200` (no Upgrade / Sec-WebSocket-Accept
//!    headers — those are HTTP/1.1 only). The HTTP/3 DATA frames on the
//!    same stream now carry WebSocket protocol bytes.
//!
//! ## Architecture
//!
//! The gateway does not speak HTTP/3 to WebSocket *backends* (browsers,
//! Node `ws`, and every common backend library still bootstrap WebSocket
//! over HTTP/1.1 or HTTP/2). Instead the H3 frontend bridges to the same
//! HTTP/1.1-Upgrade backend code the H1/H2 frontends use — same
//! `connect_websocket_backend`, same `WebSocketStream` over
//! `MaybeTlsStream<TcpStream>`, same per-frame plugin pipeline, same
//! disconnect bookkeeping. Only the bytes-on-the-wire transport on the
//! *frontend* differs.
//!
//! The H3 RequestStream halves (after `.split()`) are bridged to a
//! tokio `DuplexStream` via two pump tasks:
//!
//! ```text
//!   QUIC stream (h3 frontend)         WebSocket backend (H1 Upgrade)
//!   ─────────────────────────         ──────────────────────────────
//!   RequestStream::send_data    ◄──── h3_send pump ◄── DuplexStream::write
//!   RequestStream::recv_data    ────► h3_recv pump ──► DuplexStream::read
//!                                                       │
//!                                                       ▼
//!                                  WebSocketStream<DuplexStream>
//!                                  (parses WS frames, runs plugin pipeline)
//!                                                       │
//!                                                       ▼
//!                                  run_websocket_proxy (generic over C)
//!                                                       │
//!                                                       ▼
//!                                  WebSocketStream<MaybeTlsStream<TcpStream>>
//! ```
//!
//! `run_websocket_proxy` (in `src/proxy/mod.rs`) is generic over the
//! client transport `C: AsyncRead + AsyncWrite + Unpin + Send + 'static`.
//! The H1/H2 path passes `TokioIo::new(upgraded)`; this module passes
//! the duplex half. Everything downstream — frame parsing, `on_ws_frame`
//! hooks, `on_ws_disconnect` hooks, cancellation, first-failure
//! attribution, frame counting — is identical to the H1/H2 path.
//!
//! ## Buffer sizing
//!
//! The duplex bridge uses a 64 KiB internal buffer (`H3_WS_DUPLEX_BUFFER_BYTES`).
//! Large enough that small WebSocket frames don't cause excessive context
//! switching on the pump tasks; small enough that a slow consumer on
//! either side can't accumulate megabytes of in-flight bytes. Frame size
//! is independently bounded by `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES`
//! enforced by the WebSocket framer, not the bridge buffer.
//!
//! ## Tunnel mode
//!
//! `FERRUM_WEBSOCKET_TUNNEL_MODE` does not apply to H3 — there is no raw
//! TCP underneath QUIC, and the H3-side bytes already pass through the
//! pump tasks regardless. This module always passes
//! `websocket_tunnel_mode = false` to `run_websocket_proxy`. Operators
//! who enabled tunnel mode for H1/H2 throughput get H3 frame-parsing
//! semantics automatically — frame-level plugins (`on_ws_frame`,
//! `ws_rate_limit`, `ws_message_size_limiting`, `ws_frame_logging`) work
//! on H3 sessions whether or not tunnel mode is set globally.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use bytes::{Buf, Bytes};
use chrono::Utc;
use h3::server::RequestStream;
use http::{Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use crate::config::types::{Proxy, UpstreamTarget};
use crate::load_balancer::LoadBalancer;
use crate::plugins::{Plugin, RequestContext, TransactionSummary};
use crate::proxy::{ProxyState, WsSessionMeta};
use crate::request_epoch::RequestEpoch;
use crate::retry;

/// Internal buffer size for the H3 ↔ WebSocket-framer duplex bridge.
/// See module-level docs for rationale.
const H3_WS_DUPLEX_BUFFER_BYTES: usize = 64 * 1024;

/// Listen-port label for the `WsSessionMeta` that backs on_ws_disconnect.
/// H3 always lands on the HTTPS port (port 0 disables H3 entirely; the
/// listener wouldn't be running).
fn h3_listen_port(state: &ProxyState) -> u16 {
    state.env_config.proxy_https_port
}

/// Convert any `h3::quic::RecvStream` `impl Buf` chunk into an owned
/// `Bytes` value. The h3 API returns `Result<Option<impl Buf>, ...>` —
/// `impl Buf` is opaque, so we materialise it before crossing the
/// task / channel boundary.
#[inline]
fn buf_into_bytes<B: Buf>(mut buf: B) -> Bytes {
    let len = buf.remaining();
    buf.copy_to_bytes(len)
}

/// Strip hop-by-hop headers and HTTP/1.1 WebSocket handshake artefacts
/// before forwarding the WebSocket request to the backend. Identical
/// list to `crate::proxy::collect_forwardable_headers` — duplicated
/// here because the H3 frontend has `proxy_headers: HashMap` while the
/// H1/H2 path has `hyper::HeaderMap` and the same predicate doesn't
/// directly reuse.
fn collect_forwardable_h3_headers(headers: &HashMap<String, String>) -> Vec<(String, String)> {
    /// hop-by-hop per RFC 9110 §7.6.1 + WS handshake.
    const SKIP_HEADERS: &[&str] = &[
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-accept",
        "host",
        "transfer-encoding",
        "te",
        "trailer",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        // H3 pseudo-headers that may still be present in the
        // header map produced upstream — never forward.
        ":method",
        ":scheme",
        ":authority",
        ":path",
        ":protocol",
        ":status",
    ];

    headers
        .iter()
        .filter_map(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            if SKIP_HEADERS.contains(&lower.as_str()) {
                return None;
            }
            Some((lower, value.clone()))
        })
        .collect()
}

/// Write a small JSON error body on the H3 stream and finish.
async fn send_h3_error_body<S>(
    stream: &mut RequestStream<S, Bytes>,
    status: StatusCode,
    body: &'static str,
) where
    S: h3::quic::RecvStream + h3::quic::SendStream<Bytes>,
{
    let resp = match Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(())
    {
        Ok(r) => r,
        Err(e) => {
            error!("H3 WS: failed to build error response: {}", e);
            return;
        }
    };
    if let Err(e) = stream.send_response(resp).await {
        debug!("H3 WS: failed to send error response: {}", e);
        return;
    }
    if let Err(e) = stream.send_data(Bytes::from_static(body.as_bytes())).await {
        debug!("H3 WS: failed to send error body: {}", e);
    }
    if let Err(e) = stream.finish().await {
        debug!("H3 WS: failed to finish stream after error: {}", e);
    }
    crate::http3::stream_util::halt_request_body(stream);
}

/// H3 WebSocket entry point. Called from `handle_h3_request` when
/// `HttpFlavor::WebSocket` is detected on an HTTP/3 request and
/// `FERRUM_HTTP3_WEBSOCKET_ENABLED` is true.
///
/// Consumes the full `RequestStream` because we need to `split()` it
/// into independent send/recv halves to drive the bridge pumps from
/// separate tasks.
///
/// Authentication, authorization, and `before_proxy` plugin phases
/// have already run by the time this function is called — the caller
/// has the full plugin chain and the resolved `RequestContext`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_h3_websocket(
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: ProxyState,
    epoch: Arc<RequestEpoch>,
    proxy: Arc<Proxy>,
    ctx: RequestContext,
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    plugin_execution_ns: u64,
    upstream_target: Option<Arc<UpstreamTarget>>,
    upstream_balancer: Option<Arc<LoadBalancer>>,
    lb_hash_key: Option<String>,
    sticky_cookie_needed: bool,
    start_time: Instant,
    cb_target_key: Option<String>,
    cb_is_half_open_probe: bool,
    backend_url: String,
    proxy_headers: HashMap<String, String>,
    requires_ws_frame_hooks: bool,
) -> Result<(), anyhow::Error> {
    // Defense in depth: dispatcher already checked this. If the flag
    // got toggled mid-flight, return 501 rather than half-bridging.
    if !state.env_config.http3_websocket_enabled {
        warn!(
            proxy_id = %proxy.id,
            "H3 WebSocket is disabled but request was dispatched here; returning 501"
        );
        send_h3_error_body(
            &mut stream,
            StatusCode::NOT_IMPLEMENTED,
            r#"{"error":"WebSocket over HTTP/3 is disabled on this gateway"}"#,
        )
        .await;
        crate::proxy::record_request(&state, 501);
        return Ok(());
    }

    info!(
        proxy_id = %proxy.id,
        client_ip = %ctx.client_ip,
        "H3 WebSocket (RFC 9220) upgrade request received"
    );

    // ── Connection admission ─────────────────────────────────────────
    let ws_connection_permit = match crate::proxy::try_acquire_websocket_connection_permit(
        state.websocket_conn_limit.as_ref(),
    ) {
        Ok(permit) => permit,
        Err(_) => {
            warn!(
                proxy_id = %proxy.id,
                client_ip = %ctx.client_ip,
                websocket_limit = state.env_config.websocket_max_connections,
                "Rejecting H3 WebSocket upgrade: connection limit reached"
            );
            crate::proxy::record_request(&state, 503);
            send_h3_error_body(
                &mut stream,
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"WebSocket connection limit exceeded"}"#,
            )
            .await;
            return Ok(());
        }
    };

    // ── Build forwardable header list for the backend handshake ─────
    let mut client_headers = collect_forwardable_h3_headers(&proxy_headers);
    if let Some(username) = ctx.backend_consumer_username() {
        client_headers.push(("x-consumer-username".to_string(), username.to_string()));
    }
    if let Some(custom_id) = ctx.backend_consumer_custom_id() {
        client_headers.push(("x-consumer-custom-id".to_string(), custom_id.to_string()));
    }
    crate::modes::mesh::hbone::strip_egress_baggage_in_vec(
        &mut client_headers,
        &state.mesh_egress_strip_baggage_keys,
    );

    // ── Backend WebSocket handshake (reuses H1.1 Upgrade path) ──────
    //
    // Note on scope: full retry / circuit-breaker rotation is
    // implemented for the H1/H2 frontend path in
    // `proxy/mod.rs::handle_websocket_request_authenticated`. The H3
    // frontend currently uses a single backend attempt — production
    // operators typically configure WebSocket clients to retry the
    // handshake from the application layer, and the underlying
    // backend infra is shared with the H1/H2 path that already has
    // retry. The single-attempt simplification is documented at
    // `docs/http3.md` (WebSocket over HTTP/3 section); future work
    // can mirror the retry loop here.
    let backend_ws_stream = match crate::proxy::connect_websocket_backend(
        &backend_url,
        &proxy,
        &state.env_config,
        &client_headers,
        state.tls_policy.as_deref(),
        &state.crls,
        state.max_websocket_frame_size_bytes,
        state.websocket_write_buffer_size,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            let ws_error_class = retry::classify_boxed_setup_error(e.as_ref());
            error!(
                proxy_id = %proxy.id,
                backend_url = %backend_url,
                error_kind = retry::error_class_log_kind(ws_error_class),
                error_class = %ws_error_class,
                error = %e,
                "H3 WebSocket backend connection failed"
            );
            crate::proxy::record_request(&state, 502);

            // Emit the TransactionSummary for the failed upgrade so
            // log plugins see the rejection.
            if !plugins.is_empty() {
                emit_failed_upgrade_summary(
                    &state,
                    &proxy,
                    &ctx,
                    &plugins,
                    plugin_execution_ns,
                    start_time,
                    &backend_url,
                    ws_error_class,
                )
                .await;
            }

            send_h3_error_body(
                &mut stream,
                StatusCode::BAD_GATEWAY,
                r#"{"error":"Backend WebSocket connection failed"}"#,
            )
            .await;
            drop(ws_connection_permit);
            return Ok(());
        }
    };

    // ── Send 200 OK response on the H3 stream (RFC 9220 §4) ─────────
    //
    // No Upgrade / Connection / Sec-WebSocket-Accept headers (those
    // are HTTP/1.1 only). The QUIC stream becomes the WebSocket
    // transport as soon as the client sees the 200.
    let mut response_builder = Response::builder().status(StatusCode::OK);

    // Sticky session cookie on the WS upgrade response, mirroring the
    // H1/H2 path.
    if sticky_cookie_needed
        && let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, &upstream_target)
    {
        let strategy = crate::load_balancer::LoadBalancerCache::get_hash_on_strategy_from(
            &epoch.load_balancer,
            upstream_id,
        );
        if let crate::load_balancer::HashOnStrategy::Cookie(ref cookie_name) = strategy {
            let upstream = crate::load_balancer::LoadBalancerCache::get_upstream_from(
                &epoch.load_balancer,
                upstream_id,
            );
            let default_cc = crate::config::types::HashOnCookieConfig::default();
            let cookie_config = upstream
                .as_ref()
                .and_then(|u| u.hash_on_cookie_config.as_ref())
                .unwrap_or(&default_cc);
            let cookie_val =
                crate::proxy::build_sticky_cookie_header(cookie_name, target, cookie_config);
            response_builder = response_builder.header("set-cookie", cookie_val);
        }
    }
    let response = match response_builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            error!(proxy_id = %proxy.id, "H3 WS: failed to build 200 response: {}", e);
            return Err(anyhow::anyhow!("failed to build H3 WebSocket 200: {}", e));
        }
    };
    if let Err(e) = stream.send_response(response).await {
        error!(proxy_id = %proxy.id, "H3 WS: failed to send 200 response: {}", e);
        return Err(anyhow::anyhow!("H3 WebSocket send_response: {}", e));
    }

    crate::proxy::record_request(&state, 200);

    // Emit the successful-upgrade TransactionSummary now — same shape
    // the H1/H2 path emits at upgrade time.
    let _ = upstream_balancer;
    let _ = lb_hash_key;
    let _ = cb_target_key;
    let _ = cb_is_half_open_probe;
    emit_successful_upgrade_summary(
        &state,
        &proxy,
        &ctx,
        &plugins,
        plugin_execution_ns,
        start_time,
        &backend_url,
    )
    .await;

    // ── Split the H3 stream and spawn pump tasks ────────────────────
    let (mut h3_send, mut h3_recv) = stream.split();
    let (client_io, pump_io) = tokio::io::duplex(H3_WS_DUPLEX_BUFFER_BYTES);
    let (mut pump_read, mut pump_write) = tokio::io::split(pump_io);

    let proxy_id_for_pumps = proxy.id.clone();

    // h3_recv → pump_write : client-frame bytes flow to the WS parser
    let recv_pump = tokio::spawn(async move {
        loop {
            match h3_recv.recv_data().await {
                Ok(Some(chunk)) => {
                    let bytes = buf_into_bytes(chunk);
                    if bytes.is_empty() {
                        continue;
                    }
                    if let Err(e) = pump_write.write_all(&bytes).await {
                        debug!(
                            proxy_id = %proxy_id_for_pumps,
                            "H3 WS recv pump: duplex write closed: {}",
                            e
                        );
                        break;
                    }
                }
                Ok(None) => {
                    debug!(
                        proxy_id = %proxy_id_for_pumps,
                        "H3 WS recv pump: end of stream"
                    );
                    break;
                }
                Err(e) => {
                    debug!(
                        proxy_id = %proxy_id_for_pumps,
                        "H3 WS recv pump: stream error: {}",
                        e
                    );
                    break;
                }
            }
        }
        // Dropping pump_write signals EOF to the WS framer reading
        // from the other duplex half.
    });

    let proxy_id_for_send_pump = proxy.id.clone();

    // pump_read → h3_send : WS framer's encoded bytes flow back over QUIC
    let send_pump = tokio::spawn(async move {
        let mut buf = vec![0u8; H3_WS_DUPLEX_BUFFER_BYTES];
        loop {
            let n = match pump_read.read(&mut buf).await {
                Ok(0) => break, // EOF — WS framer dropped its sink half
                Ok(n) => n,
                Err(e) => {
                    debug!(
                        proxy_id = %proxy_id_for_send_pump,
                        "H3 WS send pump: duplex read error: {}",
                        e
                    );
                    break;
                }
            };
            let chunk = Bytes::copy_from_slice(&buf[..n]);
            if let Err(e) = h3_send.send_data(chunk).await {
                debug!(
                    proxy_id = %proxy_id_for_send_pump,
                    "H3 WS send pump: h3 send_data error: {}",
                    e
                );
                break;
            }
        }
        if let Err(e) = h3_send.finish().await {
            debug!(
                proxy_id = %proxy_id_for_send_pump,
                "H3 WS send pump: h3 finish error: {}",
                e
            );
        }
    });

    // ── Collect WebSocket frame and disconnect plugin lists ─────────
    let ws_frame_plugins: Vec<Arc<dyn Plugin>> = if requires_ws_frame_hooks {
        plugins
            .iter()
            .filter(|p| p.requires_ws_frame_hooks())
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let ws_disconnect_plugins: Vec<Arc<dyn Plugin>> = plugins
        .iter()
        .filter(|p| p.requires_ws_disconnect_hooks())
        .cloned()
        .collect();

    let session_meta = WsSessionMeta {
        namespace: proxy.namespace.clone(),
        proxy_name: proxy.name.clone(),
        client_ip: ctx.client_ip.clone(),
        backend_target: crate::proxy::strip_query_params(&backend_url).to_string(),
        listen_port: h3_listen_port(&state),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        auth_method: ctx.auth_method,
        metadata: ctx.metadata.clone(),
        session_start: Utc::now(),
    };

    let proxy_id_for_relay = proxy.id.clone();
    let ws_conn_id = state.ws_connection_counter.fetch_add(1, Ordering::Relaxed);
    let max_ws_frame = state.max_websocket_frame_size_bytes;
    let ws_write_buf = state.websocket_write_buffer_size;
    let adaptive_buf = state.adaptive_buffer.clone();

    // ── Run the shared frame-relay code (same as H1/H2) ─────────────
    //
    // tunnel mode is forced off — QUIC ≠ TCP, there is no raw socket to
    // splice. The same shared `run_websocket_proxy` handles per-frame
    // plugins, cancellation, and on_ws_disconnect bookkeeping.
    let relay_result = crate::proxy::run_websocket_proxy(
        client_io,
        backend_ws_stream,
        &proxy_id_for_relay,
        ws_conn_id,
        ws_frame_plugins,
        ws_disconnect_plugins,
        session_meta,
        ws_connection_permit,
        max_ws_frame,
        ws_write_buf,
        false, // H3 always frame-parses; tunnel mode is H1-only
        // RFC 9220 §5: WebSocket frames over HTTP/3 are NOT masked.
        // Strict enforcement (closing with 1002 on a masked frame)
        // is a future-work follow-up; for now we accept both shapes.
        true,
        &adaptive_buf,
    )
    .await;

    if let Err(e) = relay_result {
        error!(
            proxy_id = %proxy_id_for_relay,
            "H3 WebSocket relay error: {}",
            e
        );
    }

    // ── Wait for pump tasks to drain before returning ──────────────
    //
    // The pumps exit naturally when their duplex half is dropped (the
    // WS framer drops both halves when `run_websocket_proxy` returns).
    // Awaiting them ensures the H3 RequestStream halves they own are
    // properly closed before we return — without this, the QUIC stream
    // could be force-dropped mid-write and the peer would see a
    // protocol-level abort instead of a clean FIN.
    let _ = recv_pump.await;
    let _ = send_pump.await;

    info!(
        proxy_id = %proxy.id,
        "H3 WebSocket session ended"
    );

    Ok(())
}

/// Emit a `TransactionSummary` describing the successful WebSocket
/// upgrade. Mirrors the H1/H2 path at `proxy/mod.rs` line ~4300 so log
/// plugins see a consistent shape across frontends.
async fn emit_successful_upgrade_summary(
    state: &ProxyState,
    proxy: &Proxy,
    ctx: &RequestContext,
    plugins: &[Arc<dyn Plugin>],
    plugin_execution_ns: u64,
    start_time: Instant,
    backend_url: &str,
) {
    if plugins.is_empty() {
        return;
    }
    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
    let plugin_external_io_ms =
        ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let gateway_overhead_ms = (total_ms - plugin_execution_ms).max(0.0);

    let resolved_ip = state
        .dns_cache
        .resolve(
            &proxy.backend_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    let summary = TransactionSummary {
        namespace: proxy.namespace.clone(),
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        auth_method: ctx.auth_method,
        // RFC 9220 Extended CONNECT uses :method=CONNECT, mirroring the
        // H2 RFC 8441 path's "CONNECT" label.
        http_method: "CONNECT".to_string(),
        request_path: ctx.path.clone(),
        proxy_id: Some(proxy.id.clone()),
        proxy_name: proxy.name.clone(),
        backend_target_url: Some(crate::proxy::strip_query_params(backend_url).to_string()),
        backend_resolved_ip: resolved_ip,
        response_status_code: 200,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: total_ms,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: 0.0,
        latency_plugin_execution_ms: plugin_execution_ms,
        latency_plugin_external_io_ms: plugin_external_io_ms,
        latency_gateway_overhead_ms: gateway_overhead_ms,
        request_user_agent: ctx.headers.get("user-agent").cloned(),
        metadata: ctx.metadata.clone(),
        ..TransactionSummary::default()
    };
    crate::plugins::log_with_mirror(plugins, &summary, ctx).await;
}

/// Emit a `TransactionSummary` describing a failed upgrade (backend
/// rejected, connect timeout, TLS handshake failure, etc.). The
/// `rejection_phase` metadata field labels which gateway phase recorded
/// the failure — useful for SRE dashboards keying on
/// `metadata.rejection_phase = "websocket_backend_error"`.
#[allow(clippy::too_many_arguments)]
async fn emit_failed_upgrade_summary(
    state: &ProxyState,
    proxy: &Proxy,
    ctx: &RequestContext,
    plugins: &[Arc<dyn Plugin>],
    plugin_execution_ns: u64,
    start_time: Instant,
    backend_url: &str,
    error_class: retry::ErrorClass,
) {
    if plugins.is_empty() {
        return;
    }
    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
    let plugin_external_io_ms =
        ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let gateway_overhead_ms = (total_ms - plugin_execution_ms).max(0.0);

    let resolved_ip = state
        .dns_cache
        .resolve(
            &proxy.backend_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    let mut metadata = ctx.metadata.clone();
    metadata.insert(
        "rejection_phase".to_string(),
        "websocket_backend_error".to_string(),
    );

    let summary = TransactionSummary {
        namespace: proxy.namespace.clone(),
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        auth_method: ctx.auth_method,
        http_method: "CONNECT".to_string(),
        request_path: ctx.path.clone(),
        proxy_id: Some(proxy.id.clone()),
        proxy_name: proxy.name.clone(),
        backend_target_url: Some(crate::proxy::strip_query_params(backend_url).to_string()),
        backend_resolved_ip: resolved_ip,
        response_status_code: 502,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: total_ms,
        latency_backend_ttfb_ms: -1.0,
        latency_backend_total_ms: -1.0,
        latency_plugin_execution_ms: plugin_execution_ms,
        latency_plugin_external_io_ms: plugin_external_io_ms,
        latency_gateway_overhead_ms: gateway_overhead_ms,
        request_user_agent: ctx.headers.get("user-agent").cloned(),
        error_class: Some(error_class),
        metadata,
        ..TransactionSummary::default()
    };
    crate::plugins::log_with_mirror(plugins, &summary, ctx).await;
}
