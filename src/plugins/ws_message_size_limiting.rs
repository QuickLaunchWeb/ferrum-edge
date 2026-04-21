//! WebSocket Message Size Limiting Plugin
//!
//! Enforces per-proxy maximum frame sizes on WebSocket connections.
//! When a frame exceeds the configured `max_frame_bytes`, the connection
//! is closed with WebSocket close code 1009 (Message Too Big).
//!
//! This is the WebSocket equivalent of `request_size_limiting` for HTTP.
//! It operates at the frame level via the `on_ws_frame` hook, inspecting
//! every Text, Binary, and Ping frame in both directions.
//!
//! Config:
//! ```json
//! {
//!   "max_frame_bytes": 65536,
//!   "close_reason": "Message too large"
//! }
//! ```

use async_trait::async_trait;
use serde_json::Value;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tracing::warn;

use super::utils::size_limit::{SizeLimiter, required_positive_usize};
use super::{Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};

pub struct WsMessageSizeLimiting {
    max_frame_bytes: usize,
    close_reason: String,
}

impl WsMessageSizeLimiting {
    const MAX_CLOSE_REASON_BYTES: usize = 123;

    pub fn new(config: &Value) -> Result<Self, String> {
        let max_frame_bytes =
            required_positive_usize(config, "max_frame_bytes", "ws_message_size_limiting")?;

        let mut close_reason = config["close_reason"]
            .as_str()
            .unwrap_or("Message too large")
            .to_string();
        if close_reason.len() > Self::MAX_CLOSE_REASON_BYTES {
            warn!(
                max_bytes = Self::MAX_CLOSE_REASON_BYTES,
                "ws_message_size_limiting: 'close_reason' exceeds WebSocket limit — truncating"
            );
            close_reason.truncate(Self::truncate_utf8_boundary(
                &close_reason,
                Self::MAX_CLOSE_REASON_BYTES,
            ));
        }

        Ok(Self {
            max_frame_bytes,
            close_reason,
        })
    }

    fn truncate_utf8_boundary(value: &str, max_bytes: usize) -> usize {
        let mut end = value.len().min(max_bytes);
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        end
    }

    /// Returns the byte length of a WebSocket message payload.
    fn frame_size(message: &Message) -> usize {
        match message {
            Message::Text(s) => s.len(),
            Message::Binary(b) => b.len(),
            Message::Ping(d) | Message::Pong(d) => d.len(),
            Message::Close(_) | Message::Frame(_) => 0,
        }
    }
}

impl SizeLimiter for WsMessageSizeLimiting {
    fn plugin_name(&self) -> &'static str {
        "ws_message_size_limiting"
    }

    fn max_size_bytes(&self) -> u128 {
        self.max_frame_bytes as u128
    }
}

#[async_trait]
impl Plugin for WsMessageSizeLimiting {
    fn name(&self) -> &str {
        "ws_message_size_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::WS_MESSAGE_SIZE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        true
    }

    async fn on_ws_frame(
        &self,
        proxy_id: &str,
        _connection_id: u64,
        direction: WebSocketFrameDirection,
        message: &Message,
    ) -> Option<Message> {
        if !self.is_enabled() {
            return None;
        }

        let size = Self::frame_size(message);
        if self.exceeds_limit(size as u128) {
            let dir_label = match direction {
                WebSocketFrameDirection::ClientToBackend => "client->backend",
                WebSocketFrameDirection::BackendToClient => "backend->client",
            };
            warn!(
                plugin = self.plugin_name(),
                proxy_id = %proxy_id,
                direction = dir_label,
                frame_size = size,
                max_frame_bytes = self.max_size_bytes(),
                "WebSocket frame exceeds size limit, closing connection"
            );
            return Some(Message::Close(Some(CloseFrame {
                code: CloseCode::Size,
                reason: self.close_reason.clone().into(),
            })));
        }

        None
    }
}
