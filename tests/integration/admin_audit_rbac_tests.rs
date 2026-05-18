use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::{
    admin::{
        AdminState,
        jwt_auth::{JwtConfig, JwtManager},
        serve_admin_on_listener,
    },
    config::db_loader::{DatabaseStore, DbPoolConfig},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-admin-audit-rbac-32chars";
const JWT_ISSUER: &str = "test-ferrum-edge";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn token(subject: &str, role: Option<&str>) -> String {
    let now = Utc::now();
    let mut claims = json!({
        "iss": JWT_ISSUER,
        "sub": subject,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(role) = role {
        claims["role"] = json!(role);
    }
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 2,
        min_connections: 0,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir
        .path()
        .join(format!("audit-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect sqlite store")
}

fn admin_state(db: DatabaseStore) -> AdminState {
    AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: jwt_manager(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(listener, state, shutdown_rx, None).await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            return (format!("http://{}", actual), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", actual);
}

fn upstream_payload(id: &str) -> Value {
    json!({
        "id": id,
        "name": format!("upstream-{id}"),
        "targets": [
            {"host": "10.0.0.10", "port": 8080, "weight": 100}
        ],
        "algorithm": "round_robin"
    })
}

async fn post_json(base: &str, path: &str, bearer: &str, body: &Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(bearer)
        .json(body)
        .send()
        .await
        .expect("POST request");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn post_raw(base: &str, path: &str, bearer: &str, body: Vec<u8>) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(bearer)
        .body(body)
        .send()
        .await
        .expect("POST request");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn get_json(base: &str, path: &str, bearer: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .get(format!("{base}{path}"))
        .bearer_auth(bearer)
        .send()
        .await
        .expect("GET request");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn wait_for_audit_total(base: &str, path: &str, bearer: &str, expected: u64) -> Value {
    let mut last_body = json!({});
    let mut last_status = 0;
    for _ in 0..100 {
        let (status, body) = get_json(base, path, bearer).await;
        last_status = status;
        last_body = body;
        if status == 200 && last_body["total"].as_u64() == Some(expected) {
            return last_body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!(
        "audit list did not reach total={expected}; last status={last_status}, body={last_body:?}"
    );
}

#[tokio::test]
async fn viewer_role_is_rejected_on_admin_mutation() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;

    let viewer = token("view-only", Some("viewer"));
    let (status, body) =
        post_json(&base, "/upstreams", &viewer, &upstream_payload("rbac-u1")).await;

    assert_eq!(status, 403, "viewer mutation body: {body:?}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("required role is 'operator'"),
        "unexpected RBAC error body: {body:?}"
    );
}

#[tokio::test]
async fn viewer_restore_is_rejected_before_large_body_buffering() {
    let tmp = TempDir::new().unwrap();
    let mut state = admin_state(make_store(&tmp).await);
    state.admin_restore_max_body_size_mib = 0;
    let (base, _shutdown) = start_admin(state).await;

    let viewer = token("view-only", Some("viewer"));
    let (status, body) = post_raw(
        &base,
        "/restore?confirm=true",
        &viewer,
        br#"{"version":"1","proxies":[]}"#.to_vec(),
    )
    .await;

    assert_eq!(status, 403, "viewer restore body: {body:?}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("required role is 'admin'"),
        "unexpected RBAC error body: {body:?}"
    );
}

#[tokio::test]
async fn upstream_mutation_writes_queryable_audit_event() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let operator = token("mesh-operator", Some("operator"));
    let admin = token("security-admin", Some("admin"));

    let (status, body) = post_json(
        &base,
        "/upstreams",
        &operator,
        &upstream_payload("audit-u1"),
    )
    .await;
    assert_eq!(status, 201, "upstream create failed: {body:?}");

    let audit_body = wait_for_audit_total(&base, "/audit?resource_type=upstream", &admin, 1).await;
    assert_eq!(audit_body["total"], 1);

    let items = audit_body["items"].as_array().expect("audit items");
    let event = &items[0];
    assert_eq!(event["actor"], "mesh-operator");
    assert_eq!(event["action"], "create");
    assert_eq!(event["resource_type"], "upstream");
    assert_eq!(event["resource_id"], "audit-u1");
    assert_eq!(event["namespace"], "ferrum");
    assert_eq!(event["diff"]["after"]["id"], "audit-u1");
}

#[tokio::test]
async fn audit_list_rejects_offset_above_backend_range() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));

    let (status, body) = get_json(&base, "/audit?offset=4294967296", &admin).await;

    assert_eq!(status, 400, "oversized offset body: {body:?}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("offset"),
        "unexpected audit offset error body: {body:?}"
    );
}

#[tokio::test]
async fn partial_batch_mutation_writes_audit_event() {
    let tmp = TempDir::new().unwrap();
    let state = admin_state(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("security-admin", Some("admin"));

    let (status, body) = post_json(
        &base,
        "/upstreams",
        &admin,
        &upstream_payload("batch-duplicate-u1"),
    )
    .await;
    assert_eq!(status, 201, "upstream seed failed: {body:?}");

    let batch = json!({
        "consumers": [{
            "id": "partial-batch-c1",
            "username": "partial-batch-user"
        }],
        "upstreams": [upstream_payload("batch-duplicate-u1")]
    });
    let (status, body) = post_json(&base, "/batch", &admin, &batch).await;
    assert_eq!(status, 207, "partial batch body: {body:?}");
    assert_eq!(body["created"]["consumers"], 1);
    assert_eq!(body["created"]["upstreams"], 0);

    let audit_body = wait_for_audit_total(
        &base,
        "/audit?resource_type=gateway_config&action=batch_create",
        &admin,
        1,
    )
    .await;
    assert_eq!(audit_body["total"], 1);

    let items = audit_body["items"].as_array().expect("audit items");
    let event = &items[0];
    assert_eq!(event["actor"], "security-admin");
    assert_eq!(event["action"], "batch_create");
    assert_eq!(event["resource_type"], "gateway_config");
    assert_eq!(event["diff"]["after"]["consumers"], 1);
    assert_eq!(event["diff"]["after"]["upstreams"], 0);
}
