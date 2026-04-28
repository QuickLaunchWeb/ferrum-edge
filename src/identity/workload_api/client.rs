//! SPIFFE Workload API gRPC client.
//!
//! Speaks to a SPIRE agent (or any other Workload API server) over a Unix
//! domain socket. The default socket path follows the SPIFFE convention:
//! `/run/spire/agent/agent.sock`. Operators may override via
//! `FERRUM_MESH_WORKLOAD_API_SOCKET`.
//!
//! The client exposes:
//! - [`WorkloadApiClient::fetch_x509_svid_stream`] — long-lived bidirectional
//!   stream returning fresh [`SvidBundle`] every time the agent rotates the
//!   SVID or a federated bundle changes.
//! - [`WorkloadApiClient::fetch_x509_svid_once`] — convenience helper that
//!   returns the FIRST bundle from the stream and drops the connection.

use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, info, warn};

use super::proto::X509svidRequest;
use super::proto::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use crate::identity::spiffe::{SpiffeId, TrustDomain};
use crate::identity::{SvidBundle, TrustBundle, TrustBundleSet};

/// Default Unix-socket path used when `FERRUM_MESH_WORKLOAD_API_SOCKET` is unset.
pub const DEFAULT_WORKLOAD_API_SOCKET: &str = "/run/spire/agent/agent.sock";

/// gRPC client wrapper.
pub struct WorkloadApiClient {
    inner: SpiffeWorkloadApiClient<Channel>,
    socket_path: String,
}

impl WorkloadApiClient {
    /// Connect to the SPIRE agent at `socket_path`. The connection is
    /// established lazily — failures surface on first RPC.
    pub async fn connect(socket_path: impl Into<String>) -> Result<Self, WorkloadApiClientError> {
        let socket_path = socket_path.into();
        let uri = format!("unix://{socket_path}");
        let endpoint = Endpoint::try_from(uri)
            .map_err(|e| WorkloadApiClientError::Config(format!("invalid UDS URI: {e}")))?
            .connect_timeout(Duration::from_secs(5));
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| WorkloadApiClientError::Transport(e.to_string()))?;
        let inner = SpiffeWorkloadApiClient::new(channel);
        info!(socket = %socket_path, "connected to SPIFFE Workload API agent");
        Ok(Self { inner, socket_path })
    }

    /// The underlying socket path, useful for diagnostics.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Open the streaming `FetchX509SVID` RPC and translate each agent
    /// response into a [`SvidBundle`].
    ///
    /// Returns a `Stream` plus a oneshot signal that fires once the FIRST
    /// SvidBundle has been observed — useful for startup paths that need to
    /// "wait for an SVID to be ready" before proceeding.
    pub async fn fetch_x509_svid_stream(
        &mut self,
    ) -> Result<
        (
            impl Stream<Item = Result<SvidBundle, WorkloadApiClientError>> + Send + 'static,
            mpsc::UnboundedReceiver<()>,
        ),
        WorkloadApiClientError,
    > {
        let response = self
            .inner
            .fetch_x509svid(X509svidRequest {})
            .await
            .map_err(|e| WorkloadApiClientError::Rpc(e.to_string()))?;
        let mut inbound = response.into_inner();

        // Inner channel relays decoded bundles. Notify channel fires once
        // when the FIRST bundle arrives so callers can do "wait for ready"
        // synchronisation independently of consuming the stream.
        let (out_tx, out_rx) =
            mpsc::unbounded_channel::<Result<SvidBundle, WorkloadApiClientError>>();
        let (notify_tx, notify_rx) = mpsc::unbounded_channel::<()>();

        tokio::spawn(async move {
            let mut sent_first = false;
            while let Some(msg_result) = inbound.next().await {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = out_tx.send(Err(WorkloadApiClientError::Rpc(format!(
                            "Workload API stream error: {e}"
                        ))));
                        return;
                    }
                };
                if msg.svids.is_empty() {
                    debug!("Workload API server pushed an empty X509SVIDResponse — skipping");
                    continue;
                }
                let bundle_res = svid_response_to_bundle(msg);
                let was_ok = bundle_res.is_ok();
                if out_tx.send(bundle_res).is_err() {
                    return;
                }
                if was_ok && !sent_first {
                    let _ = notify_tx.send(());
                    sent_first = true;
                }
            }
        });

        Ok((UnboundedReceiverStream::new(out_rx), notify_rx))
    }

    /// Helper for callers that just want to grab the first SvidBundle and
    /// move on. Production paths should keep the stream open and consume
    /// rotations via [`fetch_x509_svid_stream`](Self::fetch_x509_svid_stream).
    pub async fn fetch_x509_svid_once(&mut self) -> Result<SvidBundle, WorkloadApiClientError> {
        let (mut stream, _) = self.fetch_x509_svid_stream().await?;
        stream
            .next()
            .await
            .ok_or_else(|| WorkloadApiClientError::Rpc("stream closed before first SVID".into()))?
    }
}

/// Convert one `X509SVIDResponse` into a [`SvidBundle`]. Picks the first
/// SVID in the response (per spec, the "default identity" for the workload).
fn svid_response_to_bundle(
    msg: super::proto::X509svidResponse,
) -> Result<SvidBundle, WorkloadApiClientError> {
    let first = msg
        .svids
        .into_iter()
        .next()
        .ok_or_else(|| WorkloadApiClientError::Rpc("X509SVIDResponse has no SVIDs".into()))?;

    let spiffe_id = SpiffeId::new(first.spiffe_id.clone()).map_err(|e| {
        WorkloadApiClientError::Rpc(format!(
            "agent returned malformed SPIFFE ID '{}': {}",
            first.spiffe_id, e
        ))
    })?;
    let trust_domain = spiffe_id.trust_domain().clone();

    // Cert chain is a single byte blob containing one or more concatenated
    // DER certs (leaf first). We use rustls-pemfile-style splitter: parse
    // each ASN.1 SEQUENCE and slice at its end.
    let cert_chain_der = split_concatenated_der(&first.x509_svid)
        .map_err(|e| WorkloadApiClientError::Rpc(format!("SVID chain parse failed: {e}")))?;
    if cert_chain_der.is_empty() {
        return Err(WorkloadApiClientError::Rpc(
            "SVID has no certificates".into(),
        ));
    }

    let local_bundle_der = split_concatenated_der(&first.bundle)
        .map_err(|e| WorkloadApiClientError::Rpc(format!("trust bundle parse failed: {e}")))?;

    let mut trust_bundles = TrustBundleSet {
        local: TrustBundle {
            trust_domain: trust_domain.clone(),
            x509_authorities: local_bundle_der,
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: if first.hint > 0 {
                Some(first.hint as u64)
            } else {
                None
            },
        },
        federated: Default::default(),
    };

    for (td_str, bundle_bytes) in msg.federated_bundles {
        match TrustDomain::new(td_str.clone()) {
            Ok(td) => match split_concatenated_der(&bundle_bytes) {
                Ok(certs) => {
                    trust_bundles.federated.insert(
                        td.clone(),
                        TrustBundle {
                            trust_domain: td,
                            x509_authorities: certs,
                            jwt_authorities: Vec::new(),
                            refresh_hint_seconds: None,
                        },
                    );
                }
                Err(e) => warn!("federated bundle for '{}' is malformed: {}", td_str, e),
            },
            Err(e) => warn!(
                "federated bundle key '{}' is not a trust domain: {}",
                td_str, e
            ),
        }
    }

    Ok(SvidBundle {
        spiffe_id,
        cert_chain_der,
        private_key_pkcs8_der: first.x509_svid_key,
        trust_bundles,
    })
}

/// Split a buffer that holds one or more concatenated DER certs. Each cert
/// starts with the ASN.1 SEQUENCE tag (0x30) followed by a length-of-length
/// byte. We parse just enough to slice at the next boundary.
fn split_concatenated_der(buf: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while cursor < buf.len() {
        if buf[cursor] != 0x30 {
            return Err(format!("expected SEQUENCE tag at offset {cursor}"));
        }
        if cursor + 2 > buf.len() {
            return Err("buffer ends mid-tag".to_string());
        }
        let first_len = buf[cursor + 1];
        let (header_len, content_len) = if first_len & 0x80 == 0 {
            (2, first_len as usize)
        } else {
            let n = (first_len & 0x7f) as usize;
            if cursor + 2 + n > buf.len() {
                return Err("buffer ends inside multi-byte length".to_string());
            }
            let mut content_len = 0usize;
            for i in 0..n {
                content_len = (content_len << 8) | buf[cursor + 2 + i] as usize;
            }
            (2 + n, content_len)
        };
        let total = header_len + content_len;
        if cursor + total > buf.len() {
            return Err("DER length exceeds buffer".to_string());
        }
        out.push(buf[cursor..cursor + total].to_vec());
        cursor += total;
    }
    Ok(out)
}

/// Errors raised by the Workload API client.
#[derive(Debug, thiserror::Error)]
pub enum WorkloadApiClientError {
    #[error("Workload API client config error: {0}")]
    Config(String),
    #[error("Workload API transport error: {0}")]
    Transport(String),
    #[error("Workload API RPC error: {0}")]
    Rpc(String),
}

#[cfg(test)]
mod tests {
    use super::split_concatenated_der;

    #[test]
    fn split_empty_buffer() {
        assert!(split_concatenated_der(&[]).unwrap().is_empty());
    }

    #[test]
    fn split_two_short_form_certs() {
        // Two minimal "SEQUENCE { OCTET STRING <empty> }" blobs concatenated:
        // 0x30 0x02 0x04 0x00  (4 bytes each)
        let blob = [0x30, 0x02, 0x04, 0x00, 0x30, 0x02, 0x04, 0x00];
        let out = split_concatenated_der(&blob).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], vec![0x30, 0x02, 0x04, 0x00]);
        assert_eq!(out[1], vec![0x30, 0x02, 0x04, 0x00]);
    }

    #[test]
    fn split_long_form_length() {
        // 0x30 0x81 0x05 followed by 5 content bytes.
        let blob = [0x30, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let out = split_concatenated_der(&blob).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 8);
    }

    #[test]
    fn split_rejects_non_sequence_tag() {
        let blob = [0x31, 0x00];
        assert!(split_concatenated_der(&blob).is_err());
    }
}
