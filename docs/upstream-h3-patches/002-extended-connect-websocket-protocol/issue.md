### Summary

`h3::ext::Protocol` only recognises `"webtransport"` and `"connect-udp"`,
which prevents `h3` 0.0.8 from accepting HTTP/3 Extended CONNECT
requests carrying `:protocol = "websocket"` (RFC 9220). The server
rejects the HEADERS frame as malformed before the application can ever
see the request.

### Reproduction

1. Build an `h3::server::Builder` with `enable_extended_connect(true)`.
2. Send a CONNECT request from a client over QUIC with:
   - `:method = CONNECT`
   - `:scheme = https`
   - `:authority = example.com`
   - `:path = /chat`
   - `:protocol = websocket`
3. The server returns `HeaderError::invalid_value` for `:protocol`
   instead of surfacing the request to `accept()`.

### Expected

`accept()` returns the request with `request.extensions().get::<Protocol>()`
holding the parsed value, exactly as it does today for `webtransport` and
`connect-udp`.

### Root cause

`h3/src/ext.rs`:

```rust
impl FromStr for Protocol {
    type Err = InvalidProtocol;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "webtransport" => Ok(Self(ProtocolInner::WebTransport)),
            "connect-udp" => Ok(Self(ProtocolInner::ConnectUdp)),
            _ => Err(InvalidProtocol),
        }
    }
}
```

`h3/src/proto/headers.rs` (`try_value`) then turns `InvalidProtocol` into
`HeaderError::invalid_value`, which rejects the entire HEADERS frame.

### Spec references

- [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) — Bootstrapping
  WebSockets with HTTP/3. Mirrors RFC 8441 § 4 for HTTP/2 (already
  supported by `h3` via WebTransport's `enable_extended_connect`
  plumbing).
- IANA "HTTP Upgrade Token" / `:protocol` registry includes
  `"websocket"`.

### Fix

Add `Protocol::WEB_SOCKET` as a third recognised value, mirroring the
existing `WEB_TRANSPORT` and `CONNECT_UDP` constants. No API breaking
changes; downstream callers that match on `Protocol` already need a
wildcard arm (the enum is opaque from outside the crate).

A draft PR with the patch + round-trip tests is ready at
[link to PR after filing].

### Affected versions

- `h3` 0.0.8 (and earlier — the variants list has been stable since
  Extended CONNECT support was added).
- HEAD as of this issue.

### Why this matters

WebSocket-over-HTTP/3 deployments need this variant to be representable
through the parsed `:protocol` API. Today the only workaround is to
fork `h3`, which is what we're currently doing
([ferrum-edge/ferrum-edge#...](#)) and would like to stop doing.
