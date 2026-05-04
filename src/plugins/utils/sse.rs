//! Shared helpers for detecting Server-Sent Events (SSE) requests.
//!
//! SSE responses (`text/event-stream`) are inherently unbounded streams. Plugins
//! that buffer the response body (e.g., `response_caching`, `body_validator`,
//! `response_transformer`, `response_size_limiting`) MUST skip buffering for
//! SSE — otherwise the buffer collects events forever and the gateway returns
//! 502 once `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` is hit, instead of streaming
//! events to the client.
//!
//! The proxy handler already has a response-side bypass via
//! `is_streaming_content_type()` (checks the backend's `Content-Type`), but
//! that bypass only applies when the matching plugin permits streaming. Once
//! a plugin pins the response into the buffered path, the response-side
//! escape hatch never runs.
//!
//! These helpers operate on the request-side `Accept` header (the canonical
//! SSE intent signal per the WHATWG EventSource spec). Plugins call
//! `is_sse_request(ctx)` from `should_buffer_response_body()` to opt out of
//! buffering before the response-side check happens.
//!
//! Backends may legitimately return `text/event-stream` for non-SSE-aware
//! clients — in those cases the proxy's response-side `is_streaming_content_type`
//! check still streams the body via the existing escape hatch. This helper
//! covers the request-side case.
use super::super::RequestContext;

/// Returns `true` when the request's `Accept` header indicates Server-Sent
/// Events (i.e., contains `text/event-stream`). Matches the WHATWG EventSource
/// contract used by browser SSE clients (`new EventSource(...)`).
///
/// Used by plugins that buffer response bodies to short-circuit buffering for
/// SSE — buffering an unbounded event stream would 502 the response once the
/// max-response-size limit is hit instead of streaming events.
#[inline]
pub fn is_sse_request(ctx: &RequestContext) -> bool {
    ctx.headers
        .get("accept")
        .is_some_and(|accept| accept_includes_event_stream(accept))
}

/// Returns `true` when an `Accept` header value (which may be a comma-separated
/// list of media-range entries) includes `text/event-stream`. The match is
/// exact on the media type itself: a candidate like `text/event-stream-like`
/// is rejected, but parameters (`text/event-stream; q=1.0`) are accepted.
#[inline]
fn accept_includes_event_stream(accept: &str) -> bool {
    accept.split(',').any(|part| {
        let trimmed = part.trim();
        // Strip optional media-type parameters (`; q=...`, `; charset=...`).
        let media_type = trimmed.split(';').next().unwrap_or(trimmed).trim_end();
        media_type.eq_ignore_ascii_case("text/event-stream")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_accept(accept: Option<&str>) -> RequestContext {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/events".to_string(),
        );
        if let Some(value) = accept {
            ctx.headers.insert("accept".to_string(), value.to_string());
        }
        ctx
    }

    #[test]
    fn detects_plain_event_stream() {
        assert!(is_sse_request(&ctx_with_accept(Some("text/event-stream"))));
    }

    #[test]
    fn detects_event_stream_in_list() {
        assert!(is_sse_request(&ctx_with_accept(Some(
            "text/html, text/event-stream, */*"
        ))));
    }

    #[test]
    fn detects_event_stream_with_quality() {
        assert!(is_sse_request(&ctx_with_accept(Some(
            "text/event-stream; q=1.0"
        ))));
    }

    #[test]
    fn detects_uppercase_event_stream() {
        assert!(is_sse_request(&ctx_with_accept(Some("TEXT/EVENT-STREAM"))));
    }

    #[test]
    fn rejects_non_sse_accept() {
        assert!(!is_sse_request(&ctx_with_accept(Some("application/json"))));
    }

    #[test]
    fn rejects_missing_accept() {
        assert!(!is_sse_request(&ctx_with_accept(None)));
    }

    #[test]
    fn rejects_substring_match() {
        // `text/event-stream-like` is a different media type and must NOT
        // match — the helper splits on `;` to isolate the media type and
        // compares case-insensitively for equality.
        assert!(!is_sse_request(&ctx_with_accept(Some(
            "text/event-stream-like"
        ))));
    }

    #[test]
    fn detects_event_stream_with_trailing_space_before_semicolon() {
        // RFC 9110 allows OWS around the `;` parameter delimiter. Accept the
        // common shape we see in the wild.
        assert!(is_sse_request(&ctx_with_accept(Some(
            "text/event-stream ; q=0.9"
        ))));
    }
}
