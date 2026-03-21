# WebSocket Proxying

Ferrum Gateway supports bidirectional WebSocket proxying for `ws://` and `wss://` backend protocols.

## Architecture

WebSocket requests are detected via the `Upgrade: websocket` header and routed separately from normal HTTP:

1. **Upgrade detection** - `is_websocket_upgrade()` checks for WebSocket upgrade headers
2. **Route matching** - Uses the same router cache as HTTP for O(1) lookups
3. **Authentication** - Proxies with plugins go through `handle_websocket_request_authenticated()`; those without go through `handle_websocket_request()`
4. **Handshake** - Gateway returns HTTP 101 Switching Protocols with the `sec-websocket-accept` key
5. **Connection takeover** - `OnUpgrade` is extracted from the request; a spawned task awaits the upgrade and begins proxying
6. **Bidirectional forwarding** - `handle_websocket_proxying()` splits both client and backend streams, forwarding messages in both directions via `tokio::select!`

```
Client <--ws--> Gateway <--ws/wss--> Backend
```

The gateway terminates the client WebSocket connection and opens a separate connection to the backend. Text, binary, ping, pong, and close frames are all forwarded.

## TLS for `wss://` Backends

Backend WebSocket connections use `tokio_tungstenite::connect_async()` with the `rustls-tls-webpki-roots` feature. This means:

- **TLS library**: rustls (not native-tls/OpenSSL)
- **Root CA store**: `webpki-roots` (Mozilla's root certificates compiled into the binary) — **not** the OS system trust store
- **Client certificates**: Not supported for WebSocket backends
- **Custom CA bundles**: Not supported for WebSocket backends

This is a known gap compared to HTTP/HTTPS backends, which support `danger_accept_invalid_certs`, custom CA bundles, and client certificates via the `reqwest::Client` configuration in `connection_pool.rs`.

## Key Files

| File | Purpose |
|------|---------|
| `src/proxy/mod.rs` | WebSocket upgrade handling and bidirectional proxying |
| `tests/functional/functional_websocket_test.rs` | Functional tests |
| `tests/unit/gateway_core/websocket_auth_tests.rs` | Auth integration tests |
| `tests/helpers/bin/websocket_echo_server.rs` | Echo server for testing |

## Known Limitations

- WebSocket backend TLS does not respect proxy-level settings (`backend_tls_verify_server_cert`, `backend_tls_ca_bundle_path`, `backend_tls_client_cert_path`)
- No WebSocket-specific timeouts or frame size limits are configured (uses tokio-tungstenite defaults)
- No header forwarding from the original client request to the backend WebSocket connection
