//! Extensions for the HTTP/3 protocol.

use std::str::FromStr;

/// Describes the `:protocol` pseudo-header for extended connect
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(Copy, PartialEq, Debug, Clone)]
pub struct Protocol(ProtocolInner);

impl Protocol {
    /// WebTransport protocol
    pub const WEB_TRANSPORT: Protocol = Protocol(ProtocolInner::WebTransport);
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(ProtocolInner::ConnectUdp);
    /// RFC 9220 — Bootstrapping WebSockets with HTTP/3 (`:protocol = "websocket"`).
    ///
    /// Mirrors RFC 8441's HTTP/2 Extended CONNECT, applied to HTTP/3.
    /// See: <https://www.rfc-editor.org/rfc/rfc9220>
    pub const WEB_SOCKET: Protocol = Protocol(ProtocolInner::WebSocket);

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            ProtocolInner::WebTransport => "webtransport",
            ProtocolInner::ConnectUdp => "connect-udp",
            ProtocolInner::WebSocket => "websocket",
        }
    }
}

#[derive(Copy, PartialEq, Debug, Clone)]
enum ProtocolInner {
    WebTransport,
    ConnectUdp,
    WebSocket,
}

/// Error when parsing the protocol
pub struct InvalidProtocol;

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("webtransport") {
            Ok(Self(ProtocolInner::WebTransport))
        } else if s.eq_ignore_ascii_case("connect-udp") {
            Ok(Self(ProtocolInner::ConnectUdp))
        } else if s.eq_ignore_ascii_case("websocket") {
            Ok(Self(ProtocolInner::WebSocket))
        } else {
            Err(InvalidProtocol)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Protocol {
        // `InvalidProtocol` intentionally doesn't impl `Debug`, so `.expect()`
        // and `.unwrap()` don't compile against `Result<Protocol, InvalidProtocol>`.
        // The same restriction will apply downstream after this lands, so the
        // tests use match.
        match s.parse::<Protocol>() {
            Ok(p) => p,
            Err(_) => panic!("expected `{}` to parse as a known Protocol", s),
        }
    }

    #[test]
    fn websocket_from_str_round_trip() {
        let p = parse("websocket");
        assert_eq!(p.as_str(), "websocket");
        assert_eq!(p, Protocol::WEB_SOCKET);
    }

    #[test]
    fn websocket_from_str_is_ascii_case_insensitive() {
        for value in ["WebSocket", "WEBSOCKET", "webSocket"] {
            let p = parse(value);
            assert_eq!(p.as_str(), "websocket");
            assert_eq!(p, Protocol::WEB_SOCKET);
        }
    }

    #[test]
    fn unknown_protocol_still_rejected() {
        assert!("unknownproto".parse::<Protocol>().is_err());
    }

    #[test]
    fn existing_protocols_unaffected() {
        let wt = parse("webtransport");
        assert_eq!(wt.as_str(), "webtransport");
        assert_eq!(wt, Protocol::WEB_TRANSPORT);

        let cu = parse("connect-udp");
        assert_eq!(cu.as_str(), "connect-udp");
        assert_eq!(cu, Protocol::CONNECT_UDP);
    }
}
