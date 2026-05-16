//! Bounded response-body readers for plugin HTTP calls.
//!
//! Plugins that issue out-of-band HTTP calls (serverless function invocation,
//! request mirroring, etc.) need to read the response body to either forward
//! it to the client or capture metadata such as size. Calling
//! `reqwest::Response::bytes().await` blindly is unsafe: a misbehaving (or
//! malicious) sink can stream a body of unbounded size, and the entire payload
//! is allocated into memory **before** any size check fires. A 10 GB response
//! to a serverless-function plugin allocates 10 GB regardless of the
//! configured `max_response_body_bytes`.
//!
//! [`read_response_body_bounded`] streams chunks from the network, enforces
//! the limit byte-by-byte, and aborts the read as soon as the running total
//! crosses the threshold. Successful reads can still return up to `max_bytes`,
//! but the initial allocation is capped even when an upstream advertises a
//! huge `Content-Length`. This mirrors the approach in
//! `proxy::collect_response_with_limit` so plugin-side reads share the same
//! hardened pattern.

use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::Value;

// Bound only the upfront allocation. Larger in-limit bodies still grow the
// buffer organically, which avoids letting Content-Length force a large alloc
// before the first byte streams in.
const MAX_INITIAL_RESPONSE_BODY_CAPACITY: usize = 1024 * 1024;

/// Error returned by [`read_response_body_bounded`].
#[derive(Debug)]
pub enum BoundedReadError {
    /// The accumulated body length exceeded `max_bytes` while streaming.
    ///
    /// `read_so_far` is the running total when the check fired, which is
    /// guaranteed to be `> max_bytes`. The remainder of the response is
    /// dropped — the caller does not see the full size.
    LimitExceeded {
        max_bytes: usize,
        read_so_far: usize,
    },
    /// A transport-level error surfaced from the underlying byte stream.
    Stream(reqwest::Error),
}

impl std::fmt::Display for BoundedReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundedReadError::LimitExceeded {
                max_bytes,
                read_so_far,
            } => {
                write!(
                    f,
                    "response body size {} exceeds max_response_body_bytes {}",
                    read_so_far, max_bytes
                )
            }
            BoundedReadError::Stream(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for BoundedReadError {}

/// Parse a common `max_response_body_bytes`-style plugin config field.
pub fn parse_max_response_body_bytes(
    config: &Value,
    plugin_name: &str,
    key: &str,
    default: usize,
) -> Result<usize, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => {
            let raw = v.as_u64().ok_or_else(|| {
                format!("{plugin_name}: '{key}' must be an unsigned integer, got: {v}")
            })?;
            if raw == 0 {
                return Err(format!("{plugin_name}: '{key}' must be greater than zero"));
            }
            usize::try_from(raw).map_err(|_| {
                format!("{plugin_name}: '{key}' is too large for this platform: {raw}")
            })
        }
    }
}

/// Stream a `reqwest::Response` body and accumulate chunks into a `Vec<u8>`,
/// aborting as soon as the running total exceeds `max_bytes`.
///
/// Returns `Ok(body)` when the full body fits inside the limit, or
/// `Err(BoundedReadError::LimitExceeded)` as soon as the limit is crossed
/// (without finishing the stream). Transport errors are surfaced as
/// `Err(BoundedReadError::Stream)`.
///
/// The `content-length` hint, when present, is used to pre-size the buffer up
/// to a small ceiling. This avoids a huge upfront allocation when an operator
/// configures a high `max_bytes` and the upstream advertises a very large but
/// still-in-limit body. When absent, the buffer grows organically.
pub async fn read_response_body_bounded(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BoundedReadError> {
    // Pre-size from Content-Length when available, but never larger than a
    // modest ceiling. A misbehaving sink or oversized operator setting should
    // not be able to force a huge allocation before streaming starts.
    let initial_capacity = response
        .content_length()
        .map(|cl| {
            usize::try_from(cl)
                .unwrap_or(usize::MAX)
                .min(max_bytes)
                .min(MAX_INITIAL_RESPONSE_BODY_CAPACITY)
        })
        .unwrap_or(0);

    let mut buf: Vec<u8> = Vec::with_capacity(initial_capacity);
    let mut total = 0usize;
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk: Bytes = chunk_result.map_err(BoundedReadError::Stream)?;
        total = total.saturating_add(chunk.len());
        if total > max_bytes {
            return Err(BoundedReadError::LimitExceeded {
                max_bytes,
                read_so_far: total,
            });
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

/// Stream a `reqwest::Response` body to determine its total length without
/// retaining the bytes, aborting as soon as the running total exceeds
/// `max_bytes`.
///
/// Used by `request_mirror` when the upstream response has no
/// `content-length`: the response body is otherwise discarded (only the size
/// is reported in mirror metadata), so allocating the buffer is wasteful and
/// counterproductive — we just need a bounded size.
///
/// Returns the total size on success, or `BoundedReadError::LimitExceeded`
/// once the threshold is crossed (the stream is cancelled at that point).
/// Transport errors are surfaced as `BoundedReadError::Stream`.
pub async fn measure_response_body_bounded(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<u64, BoundedReadError> {
    let mut total: u64 = 0;
    let max_bytes_u64 = max_bytes as u64;
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk: Bytes = chunk_result.map_err(BoundedReadError::Stream)?;
        total = total.saturating_add(chunk.len() as u64);
        if total > max_bytes_u64 {
            return Err(BoundedReadError::LimitExceeded {
                max_bytes,
                read_so_far: total as usize,
            });
        }
    }

    Ok(total)
}
