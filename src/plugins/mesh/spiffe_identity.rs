//! SPIFFE Identity Extraction Plugin
//!
//! Extracts a SPIFFE ID from the peer certificate's URI SAN and populates
//! `ctx.peer_spiffe_id`. Mesh deployments add this plugin to their proxy
//! config; non-mesh deployments never instantiate it — zero cost.

use async_trait::async_trait;
use serde_json::Value;
use tracing::debug;

use crate::plugins::{
    HTTP_FAMILY_AND_STREAM_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext,
    StreamConnectionContext, priority,
};

pub struct SpiffeIdentity;

impl SpiffeIdentity {
    pub fn new(config: &Value) -> Result<Self, String> {
        match config {
            Value::Null => Ok(Self),
            Value::Object(obj) if obj.is_empty() => Ok(Self),
            Value::Object(_) => {
                Err("spiffe_identity: no configuration fields are supported".to_string())
            }
            other => Err(format!(
                "spiffe_identity: config must be an object, got: {other}"
            )),
        }
    }
}

#[async_trait]
impl Plugin for SpiffeIdentity {
    fn name(&self) -> &str {
        "spiffe_identity"
    }

    fn priority(&self) -> u16 {
        priority::SPIFFE_IDENTITY
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_FAMILY_AND_STREAM_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if ctx.peer_spiffe_id.is_some() {
            return PluginResult::Continue;
        }
        if let Some(der) = ctx.tls_client_cert_der.as_ref() {
            match crate::identity::spiffe::try_extract_spiffe_id(der.as_ref()) {
                Ok(Some(id)) => {
                    debug!("spiffe_identity: peer SPIFFE ID extracted: {}", id);
                    ctx.peer_spiffe_id = Some(id);
                }
                Ok(None) => {}
                Err(e) => {
                    debug!(
                        "spiffe_identity: peer cert has SPIFFE URI but it is malformed: {}",
                        e
                    );
                }
            }
        }
        PluginResult::Continue
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        if let Some(der) = ctx.tls_client_cert_der.as_ref() {
            match crate::identity::spiffe::try_extract_spiffe_id(der.as_ref()) {
                Ok(Some(id)) => {
                    debug!("spiffe_identity: stream peer SPIFFE ID: {}", id);
                    ctx.insert_metadata("peer_spiffe_id".to_string(), id.to_string());
                }
                Ok(None) => {}
                Err(e) => {
                    debug!(
                        "spiffe_identity: stream peer cert SPIFFE URI malformed: {}",
                        e
                    );
                }
            }
        }
        PluginResult::Continue
    }
}
