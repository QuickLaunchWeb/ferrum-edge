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
use crate::identity::spiffe::TrustDomain;
use crate::tls::{self, TlsPolicy};

const DEFAULT_INJECTOR_LISTEN_ADDR: &str = "0.0.0.0:9443";
const DEFAULT_SIDECAR_IMAGE: &str = "ferrum-edge:latest";
const DEFAULT_INJECTOR_TRUST_DOMAIN: &str = "cluster.local";
const SIDECAR_ENV_KEYS: &[&str] = &[
    "FERRUM_DP_CP_GRPC_URLS",
    "FERRUM_CP_DP_GRPC_JWT_ISSUER",
    "FERRUM_DP_GRPC_TLS_CA_CERT_PATH",
    "FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH",
    "FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH",
    "FERRUM_DP_GRPC_TLS_NO_VERIFY",
    "FERRUM_MESH_CONFIG_PROTOCOL",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKeyRef {
    pub name: String,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectorConfig {
    pub listen_addr: SocketAddr,
    pub namespace: String,
    pub sidecar_image: String,
    pub sidecar_env: Vec<(String, String)>,
    pub jwt_secret_ref: Option<SecretKeyRef>,
    pub require_annotation: bool,
    pub capture_mode: CaptureMode,
    pub proxy_uid: Option<u32>,
    pub trust_domain: String,
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
        let sidecar_env = sidecar_env_from_runtime();
        let jwt_secret_ref = jwt_secret_ref_from_runtime()?;
        let require_annotation = resolve_ferrum_var("FERRUM_INJECTOR_REQUIRE_ANNOTATION")
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(true);
        let capture_mode = CaptureMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_MODE")
                .unwrap_or_else(|| "explicit".to_string()),
        )?;
        let proxy_uid =
            resolve_ferrum_var("FERRUM_MESH_PROXY_UID").and_then(|value| value.parse::<u32>().ok());
        let trust_domain = resolve_ferrum_var("FERRUM_INJECTOR_TRUST_DOMAIN")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_INJECTOR_TRUST_DOMAIN.to_string());
        validate_injector_trust_domain(&trust_domain)?;
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
            sidecar_env,
            jwt_secret_ref,
            require_annotation,
            capture_mode,
            proxy_uid,
            trust_domain,
            tls_cert_path,
            tls_key_path,
            tls_handshake_timeout_seconds: env_config.frontend_tls_handshake_timeout_seconds,
        })
    }
}

fn validate_injector_trust_domain(value: &str) -> Result<(), String> {
    TrustDomain::new(value.to_string())
        .map(|_| ())
        .map_err(|e| format!("Invalid FERRUM_INJECTOR_TRUST_DOMAIN: {e}"))
}

fn jwt_secret_ref_from_runtime() -> Result<Option<SecretKeyRef>, String> {
    let name = resolve_ferrum_var("FERRUM_INJECTOR_JWT_SECRET_REF_NAME")
        .filter(|value| !value.trim().is_empty());
    let key = resolve_ferrum_var("FERRUM_INJECTOR_JWT_SECRET_REF_KEY")
        .filter(|value| !value.trim().is_empty());

    match (name, key) {
        (Some(name), Some(key)) => Ok(Some(SecretKeyRef { name, key })),
        (None, None) => Ok(None),
        (Some(_), None) => Err(
            "FERRUM_INJECTOR_JWT_SECRET_REF_NAME requires FERRUM_INJECTOR_JWT_SECRET_REF_KEY"
                .to_string(),
        ),
        (None, Some(_)) => Err(
            "FERRUM_INJECTOR_JWT_SECRET_REF_KEY requires FERRUM_INJECTOR_JWT_SECRET_REF_NAME"
                .to_string(),
        ),
    }
}

fn sidecar_env_from_runtime() -> Vec<(String, String)> {
    SIDECAR_ENV_KEYS
        .iter()
        .filter_map(|key| {
            resolve_ferrum_var(key)
                .filter(|value| !value.trim().is_empty())
                .map(|value| ((*key).to_string(), value))
        })
        .collect()
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
    namespace: Option<String>,
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
    let patches =
        build_sidecar_patch_for_namespace(&request.object, config, request.namespace.as_deref());

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

fn build_sidecar_patch_for_namespace(
    pod: &Value,
    config: &InjectorConfig,
    admission_namespace: Option<&str>,
) -> Vec<JsonPatchOperation> {
    if !should_inject(pod, config) {
        return Vec::new();
    }

    let mut patch = Vec::new();
    let pod_namespace = pod_namespace(pod, admission_namespace, config);
    ensure_metadata_annotations(pod, &mut patch);
    patch.push(JsonPatchOperation {
        op: "add",
        path: "/metadata/annotations/ferrum.io~1injected".to_string(),
        value: Some(Value::String("true".to_string())),
    });
    patch.push(JsonPatchOperation {
        op: "add",
        path: "/spec/containers/-".to_string(),
        value: Some(sidecar_container(config, pod, &pod_namespace)),
    });

    if config.capture_mode == CaptureMode::Ebpf {
        patch.push(JsonPatchOperation {
            op: "add",
            path: "/metadata/annotations/ferrum.io~1capture-mode".to_string(),
            value: Some(Value::String("ebpf".to_string())),
        });
    }

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
        || annotations
            .and_then(|m| m.get("ferrum.io/injected"))
            .is_some()
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

fn pod_namespace(
    pod: &Value,
    admission_namespace: Option<&str>,
    config: &InjectorConfig,
) -> String {
    admission_namespace
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            pod.pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or(&config.namespace)
        .to_string()
}

fn pod_service_account(pod: &Value) -> &str {
    pod.pointer("/spec/serviceAccountName")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("default")
}

fn workload_spiffe_id(config: &InjectorConfig, pod: &Value, namespace: &str) -> String {
    format!(
        "spiffe://{}/ns/{namespace}/sa/{}",
        config.trust_domain,
        pod_service_account(pod)
    )
}

fn sidecar_env(config: &InjectorConfig, pod: &Value, namespace: &str) -> Vec<Value> {
    let mut env = vec![
        json!({"name": "FERRUM_MODE", "value": "mesh"}),
        json!({"name": "FERRUM_NAMESPACE", "value": namespace}),
        json!({"name": "FERRUM_MESH_TOPOLOGY", "value": "sidecar"}),
        json!({"name": "FERRUM_MESH_CAPTURE_MODE", "value": format!("{:?}", config.capture_mode).to_ascii_lowercase()}),
        json!({"name": "FERRUM_MESH_WORKLOAD_SPIFFE_ID", "value": workload_spiffe_id(config, pod, namespace)}),
    ];
    env.extend(
        config
            .sidecar_env
            .iter()
            .map(|(name, value)| json!({"name": name, "value": value})),
    );
    if let Some(secret_ref) = &config.jwt_secret_ref {
        env.push(json!({
            "name": "FERRUM_CP_DP_GRPC_JWT_SECRET",
            "valueFrom": {
                "secretKeyRef": {
                    "name": secret_ref.name,
                    "key": secret_ref.key
                }
            }
        }));
    }
    env
}

fn sidecar_container(config: &InjectorConfig, pod: &Value, namespace: &str) -> Value {
    json!({
        "name": "ferrum-edge",
        "image": config.sidecar_image,
        "imagePullPolicy": "IfNotPresent",
        "args": ["run"],
        "securityContext": {
            "runAsUser": config.proxy_uid.unwrap_or(DEFAULT_PROXY_UID),
            "allowPrivilegeEscalation": false
        },
        "ports": [
            {"containerPort": 15001, "name": "outbound"},
            {"containerPort": 15006, "name": "inbound"}
        ],
        "env": sidecar_env(config, pod, namespace)
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
            sidecar_env: vec![(
                "FERRUM_DP_CP_GRPC_URLS".to_string(),
                "http://cp:50051".to_string(),
            )],
            jwt_secret_ref: Some(SecretKeyRef {
                name: "ferrum-edge-secrets".to_string(),
                key: "cp-dp-grpc-jwt-secret".to_string(),
            }),
            require_annotation,
            capture_mode,
            proxy_uid: Some(1337),
            trust_domain: "cluster.local".to_string(),
            tls_cert_path: None,
            tls_key_path: None,
            tls_handshake_timeout_seconds: 10,
        }
    }

    #[test]
    fn patch_requires_opt_in_by_default() {
        let pod = json!({"metadata": {"labels": {}}, "spec": {"containers": []}});
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Explicit),
            None,
        );
        assert!(patch.is_empty());
    }

    #[test]
    fn patch_skips_already_injected_pod() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {"ferrum.io/injected": "true"}
            },
            "spec": {"containers": []}
        });
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Explicit),
            None,
        );
        assert!(patch.is_empty());
    }

    #[test]
    fn patch_injects_sidecar_when_enabled() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "serviceAccountName": "api",
                "containers": [{"name": "app", "image": "app:test"}]
            }
        });
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            None,
        );

        assert!(patch.iter().any(|op| op.path == "/spec/containers/-"));
        assert!(patch.iter().any(|op| op.path == "/spec/initContainers/-"));
        let sidecar = patch
            .iter()
            .find(|op| op.path == "/spec/containers/-")
            .and_then(|op| op.value.as_ref())
            .expect("sidecar container");
        let env = sidecar
            .get("env")
            .and_then(Value::as_array)
            .expect("sidecar env");
        assert_eq!(sidecar.get("args"), Some(&json!(["run"])));
        assert!(env.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("FERRUM_DP_CP_GRPC_URLS")
                && entry.get("value").and_then(Value::as_str) == Some("http://cp:50051")
        }));
        assert!(env.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("FERRUM_MESH_WORKLOAD_SPIFFE_ID")
                && entry.get("value").and_then(Value::as_str)
                    == Some("spiffe://cluster.local/ns/default/sa/api")
        }));
        let jwt_secret = env
            .iter()
            .find(|entry| {
                entry.get("name").and_then(Value::as_str) == Some("FERRUM_CP_DP_GRPC_JWT_SECRET")
            })
            .expect("jwt secret env");
        assert!(jwt_secret.get("value").is_none());
        assert_eq!(
            jwt_secret.pointer("/valueFrom/secretKeyRef/name"),
            Some(&Value::String("ferrum-edge-secrets".to_string()))
        );
        assert_eq!(
            jwt_secret.pointer("/valueFrom/secretKeyRef/key"),
            Some(&Value::String("cp-dp-grpc-jwt-secret".to_string()))
        );
    }

    #[test]
    fn admission_response_encodes_json_patch() {
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "abc",
                "namespace": "payments",
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
        let patch = response
            .pointer("/response/patch")
            .and_then(Value::as_str)
            .expect("encoded patch");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(patch)
            .expect("valid base64 patch");
        let operations: Vec<Value> = serde_json::from_slice(&decoded).expect("json patch");
        let sidecar = operations
            .iter()
            .find(|op| op.get("path").and_then(Value::as_str) == Some("/spec/containers/-"))
            .and_then(|op| op.get("value"))
            .expect("sidecar patch");
        let env = sidecar
            .get("env")
            .and_then(Value::as_array)
            .expect("sidecar env");
        assert!(env.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("FERRUM_NAMESPACE")
                && entry.get("value").and_then(Value::as_str) == Some("payments")
        }));
        assert!(env.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("FERRUM_MESH_WORKLOAD_SPIFFE_ID")
                && entry.get("value").and_then(Value::as_str)
                    == Some("spiffe://cluster.local/ns/payments/sa/default")
        }));
    }

    #[test]
    fn injector_config_defaults_parse_from_env_config() {
        let env = EnvConfig::default();
        let config = InjectorConfig::from_env_config(&env).expect("injector config");
        assert_eq!(config.listen_addr.port(), 9443);
        assert_eq!(config.capture_mode, CaptureMode::Explicit);
        assert_eq!(config.trust_domain, DEFAULT_INJECTOR_TRUST_DOMAIN);
        assert!(config.tls_cert_path.is_none());
    }

    #[test]
    fn injector_config_rejects_invalid_trust_domain() {
        let err =
            validate_injector_trust_domain("CLUSTER.LOCAL").expect_err("invalid trust domain");
        assert!(err.contains("FERRUM_INJECTOR_TRUST_DOMAIN"));
    }
}
