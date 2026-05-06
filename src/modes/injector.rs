//! Kubernetes sidecar-injector mode (Layer 8).
//!
//! The serving path is a narrow AdmissionReview webhook. It only produces JSON
//! patches; all mesh runtime work remains in `FERRUM_MODE=mesh`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use crate::capture::{CaptureConfig, CaptureMode, DEFAULT_PROXY_UID, IptablesPlan};
use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::tls::{self, TlsPolicy};

const DEFAULT_INJECTOR_LISTEN_ADDR: &str = "0.0.0.0:9443";
const DEFAULT_SIDECAR_IMAGE: &str = "ferrum-edge:latest";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectorConfig {
    pub listen_addr: SocketAddr,
    pub namespace: String,
    pub sidecar_image: String,
    pub require_annotation: bool,
    pub capture_mode: CaptureMode,
    pub proxy_uid: Option<u32>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_handshake_timeout_seconds: u64,
}

impl InjectorConfig {
    pub fn from_env_config(env_config: &EnvConfig) -> Result<Self, String> {
        let listen_addr = resolve_ferrum_var("FERRUM_INJECTOR_LISTEN_ADDR")
            .unwrap_or_else(|| DEFAULT_INJECTOR_LISTEN_ADDR.to_string())
            .parse::<SocketAddr>()
            .map_err(|e| format!("Invalid FERRUM_INJECTOR_LISTEN_ADDR: {e}"))?;
        let sidecar_image = resolve_ferrum_var("FERRUM_INJECTOR_SIDECAR_IMAGE")
            .unwrap_or_else(|| DEFAULT_SIDECAR_IMAGE.to_string());
        let require_annotation = resolve_ferrum_var("FERRUM_INJECTOR_REQUIRE_ANNOTATION")
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(true);
        let capture_mode = CaptureMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_MODE")
                .unwrap_or_else(|| "explicit".to_string()),
        )?;
        let proxy_uid =
            resolve_ferrum_var("FERRUM_MESH_PROXY_UID").and_then(|value| value.parse::<u32>().ok());
        let tls_cert_path = resolve_ferrum_var("FERRUM_INJECTOR_TLS_CERT_PATH");
        let tls_key_path = resolve_ferrum_var("FERRUM_INJECTOR_TLS_KEY_PATH");
        match (&tls_cert_path, &tls_key_path) {
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) => {
                return Err(
                    "FERRUM_INJECTOR_TLS_CERT_PATH requires FERRUM_INJECTOR_TLS_KEY_PATH"
                        .to_string(),
                );
            }
            (None, Some(_)) => {
                return Err(
                    "FERRUM_INJECTOR_TLS_KEY_PATH requires FERRUM_INJECTOR_TLS_CERT_PATH"
                        .to_string(),
                );
            }
        }

        Ok(Self {
            listen_addr,
            namespace: env_config.namespace.clone(),
            sidecar_image,
            require_annotation,
            capture_mode,
            proxy_uid,
            tls_cert_path,
            tls_key_path,
            tls_handshake_timeout_seconds: env_config.frontend_tls_handshake_timeout_seconds,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JsonPatchOperation {
    pub op: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct AdmissionReview {
    #[serde(rename = "apiVersion")]
    api_version: Option<String>,
    kind: Option<String>,
    request: Option<AdmissionRequest>,
}

#[derive(Debug, Deserialize)]
struct AdmissionRequest {
    uid: String,
    object: Value,
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let config = InjectorConfig::from_env_config(&env_config)
        .map_err(|e| anyhow::anyhow!("invalid injector configuration: {e}"))?;
    let tls_acceptor = build_tls_acceptor(&env_config, &config)?;
    let config = Arc::new(config);
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(
        listen_addr = %config.listen_addr,
        namespace = %config.namespace,
        tls = tls_acceptor.is_some(),
        "Ferrum injector admission webhook listening"
    );
    let mut shutdown_rx = shutdown_tx.subscribe();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, remote_addr)) => {
                        let config = Arc::clone(&config);
                        let tls_acceptor = tls_acceptor.clone();
                        tokio::spawn(async move {
                            if let Some(acceptor) = tls_acceptor {
                                match tls::accept_with_optional_timeout(
                                    &acceptor,
                                    stream,
                                    config.tls_handshake_timeout_seconds,
                                    &remote_addr,
                                )
                                .await
                                {
                                    Ok(tls_stream) => {
                                        serve_injector_connection(tls_stream, config, remote_addr)
                                            .await;
                                    }
                                    Err(e) => debug!(
                                        remote_addr = %remote_addr,
                                        error = %e,
                                        "Injector TLS handshake failed"
                                    ),
                                }
                            } else {
                                serve_injector_connection(stream, config, remote_addr).await;
                            }
                        });
                    }
                    Err(e) => error!("Failed to accept injector connection: {}", e),
                }
            }
            _ = shutdown_rx.changed() => {
                info!("Injector admission webhook shutting down");
                return Ok(());
            }
        }
    }
}

fn build_tls_acceptor(
    env_config: &EnvConfig,
    config: &InjectorConfig,
) -> Result<Option<TlsAcceptor>, anyhow::Error> {
    let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) else {
        return Ok(None);
    };

    let tls_policy = TlsPolicy::from_env_config(env_config)?;
    let server_config = tls::load_tls_config_with_client_auth(
        cert_path,
        key_path,
        None,
        false,
        &tls_policy,
        env_config.tls_cert_expiry_warning_days,
        &[],
    )
    .map_err(|e| anyhow::anyhow!("Invalid injector TLS configuration: {}", e))?;
    Ok(Some(TlsAcceptor::from(server_config)))
}

async fn serve_injector_connection<S>(
    stream: S,
    config: Arc<InjectorConfig>,
    remote_addr: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| {
        let config = Arc::clone(&config);
        async move { handle_injector_request(req, config).await }
    });
    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
        debug!(remote_addr = %remote_addr, error = %e, "Injector connection error");
    }
}

async fn handle_injector_request(
    req: Request<Incoming>,
    config: Arc<InjectorConfig>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::POST || req.uri().path() != "/mutate" {
        return Ok(response(StatusCode::NOT_FOUND, "not found"));
    }

    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                format!("failed to read AdmissionReview body: {e}"),
            ));
        }
    };

    match admission_response(&body, &config) {
        Ok(value) => Ok(json_response(StatusCode::OK, value)),
        Err(e) => Ok(response(StatusCode::BAD_REQUEST, e)),
    }
}

pub fn admission_response(body: &[u8], config: &InjectorConfig) -> Result<Value, String> {
    let review: AdmissionReview =
        serde_json::from_slice(body).map_err(|e| format!("invalid AdmissionReview JSON: {e}"))?;
    let api_version = review
        .api_version
        .unwrap_or_else(|| "admission.k8s.io/v1".to_string());
    let kind = review.kind.unwrap_or_else(|| "AdmissionReview".to_string());
    let Some(request) = review.request else {
        return Err("AdmissionReview.request is required".to_string());
    };
    let patches = build_sidecar_patch(&request.object, config);

    let mut response = json!({
        "apiVersion": api_version,
        "kind": kind,
        "response": {
            "uid": request.uid,
            "allowed": true
        }
    });

    if !patches.is_empty() {
        let patch_json =
            serde_json::to_vec(&patches).map_err(|e| format!("failed to serialize patch: {e}"))?;
        let patch = base64::engine::general_purpose::STANDARD.encode(patch_json);
        if let Some(resp) = response.get_mut("response").and_then(Value::as_object_mut) {
            resp.insert(
                "patchType".to_string(),
                Value::String("JSONPatch".to_string()),
            );
            resp.insert("patch".to_string(), Value::String(patch));
        }
    }

    Ok(response)
}

pub fn build_sidecar_patch(pod: &Value, config: &InjectorConfig) -> Vec<JsonPatchOperation> {
    if !should_inject(pod, config) {
        return Vec::new();
    }

    let mut patch = Vec::new();
    ensure_metadata_annotations(pod, &mut patch);
    patch.push(JsonPatchOperation {
        op: "add",
        path: "/metadata/annotations/ferrum.io~1injected".to_string(),
        value: Some(Value::String("true".to_string())),
    });
    patch.push(JsonPatchOperation {
        op: "add",
        path: "/spec/containers/-".to_string(),
        value: Some(sidecar_container(config)),
    });

    if config.capture_mode == CaptureMode::Iptables {
        ensure_init_containers(pod, &mut patch);
        patch.push(JsonPatchOperation {
            op: "add",
            path: "/spec/initContainers/-".to_string(),
            value: Some(init_container(config)),
        });
    }

    patch
}

fn should_inject(pod: &Value, config: &InjectorConfig) -> bool {
    let annotations = pod
        .pointer("/metadata/annotations")
        .and_then(Value::as_object);
    let labels = pod.pointer("/metadata/labels").and_then(Value::as_object);

    if value_is_false(annotations.and_then(|m| m.get("sidecar.istio.io/inject")))
        || value_is_false(annotations.and_then(|m| m.get("ferrum.io/inject")))
        || value_is_false(labels.and_then(|m| m.get("ferrum.io/mesh")))
    {
        return false;
    }

    if !config.require_annotation {
        return true;
    }

    value_is_true(annotations.and_then(|m| m.get("ferrum.io/inject")))
        || labels
            .and_then(|m| m.get("ferrum.io/mesh"))
            .and_then(Value::as_str)
            .is_some_and(|value| value == "enabled")
}

fn value_is_true(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| value == "true")
}

fn value_is_false(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| matches!(value, "false" | "disabled"))
}

fn ensure_metadata_annotations(pod: &Value, patch: &mut Vec<JsonPatchOperation>) {
    if pod.pointer("/metadata/annotations").is_none() {
        patch.push(JsonPatchOperation {
            op: "add",
            path: "/metadata/annotations".to_string(),
            value: Some(json!({})),
        });
    }
}

fn ensure_init_containers(pod: &Value, patch: &mut Vec<JsonPatchOperation>) {
    if pod.pointer("/spec/initContainers").is_none() {
        patch.push(JsonPatchOperation {
            op: "add",
            path: "/spec/initContainers".to_string(),
            value: Some(json!([])),
        });
    }
}

fn sidecar_container(config: &InjectorConfig) -> Value {
    json!({
        "name": "ferrum-edge",
        "image": config.sidecar_image,
        "imagePullPolicy": "IfNotPresent",
        "securityContext": {
            "runAsUser": config.proxy_uid.unwrap_or(DEFAULT_PROXY_UID),
            "allowPrivilegeEscalation": false
        },
        "ports": [
            {"containerPort": 15001, "name": "outbound"},
            {"containerPort": 15006, "name": "inbound"}
        ],
        "env": [
            {"name": "FERRUM_MODE", "value": "mesh"},
            {"name": "FERRUM_MESH_TOPOLOGY", "value": "sidecar"},
            {"name": "FERRUM_MESH_CAPTURE_MODE", "value": format!("{:?}", config.capture_mode).to_ascii_lowercase()}
        ]
    })
}

fn init_container(config: &InjectorConfig) -> Value {
    let plan = IptablesPlan::for_config(&capture_config(config));
    json!({
        "name": "ferrum-edge-init",
        "image": config.sidecar_image,
        "imagePullPolicy": "IfNotPresent",
        "securityContext": {
            "capabilities": {"add": ["NET_ADMIN", "NET_RAW"]},
            "runAsUser": 0
        },
        "env": [
            {"name": "FERRUM_MESH_CAPTURE_MODE", "value": "iptables"},
            {"name": "FERRUM_MESH_PROXY_UID", "value": config.proxy_uid.unwrap_or(DEFAULT_PROXY_UID).to_string()}
        ],
        "command": ["/bin/sh", "-c"],
        "args": [plan.commands.join("\n")]
    })
}

fn capture_config(config: &InjectorConfig) -> CaptureConfig {
    let mut capture = CaptureConfig::explicit(15006, 15001);
    capture.mode = config.capture_mode;
    capture.proxy_uid = Some(config.proxy_uid.unwrap_or(DEFAULT_PROXY_UID));
    capture
}

fn json_response(status: StatusCode, value: Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(value.to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response
}

fn response(status: StatusCode, body: impl Into<String>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.into())));
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EnvConfig;

    fn test_config(require_annotation: bool, capture_mode: CaptureMode) -> InjectorConfig {
        InjectorConfig {
            listen_addr: "127.0.0.1:9443".parse().expect("test addr"),
            namespace: "default".to_string(),
            sidecar_image: "ferrum-edge:test".to_string(),
            require_annotation,
            capture_mode,
            proxy_uid: Some(1337),
            tls_cert_path: None,
            tls_key_path: None,
            tls_handshake_timeout_seconds: 10,
        }
    }

    #[test]
    fn patch_requires_opt_in_by_default() {
        let pod = json!({"metadata": {"labels": {}}, "spec": {"containers": []}});
        let patch = build_sidecar_patch(&pod, &test_config(true, CaptureMode::Explicit));
        assert!(patch.is_empty());
    }

    #[test]
    fn patch_injects_sidecar_when_enabled() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let patch = build_sidecar_patch(&pod, &test_config(true, CaptureMode::Iptables));

        assert!(patch.iter().any(|op| op.path == "/spec/containers/-"));
        assert!(patch.iter().any(|op| op.path == "/spec/initContainers/-"));
    }

    #[test]
    fn admission_response_encodes_json_patch() {
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "abc",
                "object": {
                    "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
                    "spec": {"containers": []}
                }
            }
        });
        let response = admission_response(
            review.to_string().as_bytes(),
            &test_config(true, CaptureMode::Explicit),
        )
        .expect("admission response");

        assert_eq!(
            response.pointer("/response/allowed"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            response.pointer("/response/patchType"),
            Some(&Value::String("JSONPatch".to_string()))
        );
    }

    #[test]
    fn injector_config_defaults_parse_from_env_config() {
        let env = EnvConfig::default();
        let config = InjectorConfig::from_env_config(&env).expect("injector config");
        assert_eq!(config.listen_addr.port(), 9443);
        assert_eq!(config.capture_mode, CaptureMode::Explicit);
        assert!(config.tls_cert_path.is_none());
    }
}
