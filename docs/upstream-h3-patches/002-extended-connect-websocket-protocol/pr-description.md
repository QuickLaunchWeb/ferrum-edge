ext: add `Protocol::WEB_SOCKET` for RFC 9220

Fixes #NNN.

### What

Adds `Protocol::WEB_SOCKET` as a third recognised value of the
`:protocol` Extended CONNECT pseudo-header, mirroring the existing
`WEB_TRANSPORT` and `CONNECT_UDP` constants.

### Why

[RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) defines WebSocket
bootstrapping over HTTP/3 using Extended CONNECT, the same mechanism
RFC 8441 standardised for HTTP/2. `h3` already implements all of the
necessary plumbing — `Builder::enable_extended_connect`, HEADERS-frame
acceptance of `:protocol`, bidirectional DATA framing on a CONNECT
stream — but the `Protocol` `FromStr` impl rejects `"websocket"` and
the `proto::headers::try_value` shim turns that rejection into a
malformed-HEADERS error.

Result: applications cannot accept WebSocket-over-HTTP/3 with stock
`h3`, even though every piece of the wire protocol is implemented.

### How

`h3/src/ext.rs`:

- Add `ProtocolInner::WebSocket` to the inner enum.
- Add `Protocol::WEB_SOCKET` const.
- Add the `"websocket"` arm in `FromStr`.
- Add the `"websocket"` arm in `as_str`.

Plus three unit tests covering:

1. `"websocket"` round-trips via `FromStr` → `as_str`.
2. Unknown protocol values are still rejected.
3. Existing protocols (`webtransport`, `connect-udp`) are unaffected.

No public API removals. Downstream callers matching on `Protocol` are
already required to include a wildcard arm (the inner enum is private),
so adding a variant is forward-compatible.

### Testing

```
cargo test -p h3
```

### Notes for reviewers

- Considered `Protocol::Other(Cow<'static, str>)` for full
  extensibility, but that would expand the public enum and force every
  existing match arm in downstream crates to add a wildcard. Rejected
  in favor of the minimum addition.
- Considered making `Protocol` opaque and providing
  `Protocol::from_str_unchecked` — would reframe `InvalidProtocol` as
  advisory rather than authoritative. Out of scope for adding one
  IANA-registered value.
