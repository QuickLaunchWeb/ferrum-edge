use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Backend protocol for a proxy resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackendProtocol {
    Http,
    Https,
    Ws,
    Wss,
    Grpc,
}

impl std::fmt::Display for BackendProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
            Self::Ws => write!(f, "ws"),
            Self::Wss => write!(f, "wss"),
            Self::Grpc => write!(f, "grpc"),
        }
    }
}

/// Authentication mode for a proxy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Single,
    Multi,
}

impl Default for AuthMode {
    fn default() -> Self {
        Self::Single
    }
}

/// Plugin scope (global or per-proxy).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluginScope {
    Global,
    Proxy,
}

/// A proxy resource defines a route from a listen_path to a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub listen_path: String,
    pub backend_protocol: BackendProtocol,
    pub backend_host: String,
    pub backend_port: u16,
    #[serde(default)]
    pub backend_path: Option<String>,
    #[serde(default = "default_true")]
    pub strip_listen_path: bool,
    #[serde(default)]
    pub preserve_host_header: bool,
    #[serde(default = "default_connect_timeout")]
    pub backend_connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout")]
    pub backend_read_timeout_ms: u64,
    #[serde(default = "default_write_timeout")]
    pub backend_write_timeout_ms: u64,
    #[serde(default)]
    pub backend_tls_client_cert_path: Option<String>,
    #[serde(default)]
    pub backend_tls_client_key_path: Option<String>,
    #[serde(default = "default_true")]
    pub backend_tls_verify_server_cert: bool,
    #[serde(default)]
    pub backend_tls_server_ca_cert_path: Option<String>,
    #[serde(default)]
    pub dns_override: Option<String>,
    #[serde(default)]
    pub dns_cache_ttl_seconds: Option<u64>,
    #[serde(default)]
    pub auth_mode: AuthMode,
    #[serde(default)]
    pub plugins: Vec<PluginAssociation>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Links a proxy to a plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginAssociation {
    pub plugin_config_id: String,
}

/// A consumer resource (API user).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consumer {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub custom_id: Option<String>,
    #[serde(default)]
    pub credentials: HashMap<String, serde_json::Value>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// A plugin configuration resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub id: String,
    pub plugin_name: String,
    #[serde(default)]
    pub config: serde_json::Value,
    pub scope: PluginScope,
    #[serde(default)]
    pub proxy_id: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Full gateway configuration snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayConfig {
    pub proxies: Vec<Proxy>,
    pub consumers: Vec<Consumer>,
    pub plugin_configs: Vec<PluginConfig>,
    #[serde(default = "Utc::now")]
    pub loaded_at: DateTime<Utc>,
}

impl GatewayConfig {
    /// Validate that all proxy listen_paths are unique.
    pub fn validate_unique_listen_paths(&self) -> Result<(), Vec<String>> {
        let mut seen = HashMap::new();
        let mut duplicates = Vec::new();
        for proxy in &self.proxies {
            if let Some(existing) = seen.insert(&proxy.listen_path, &proxy.id) {
                duplicates.push(format!(
                    "Duplicate listen_path '{}' found in proxy '{}' (conflicts with '{}')",
                    proxy.listen_path, proxy.id, existing
                ));
            }
        }
        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Build a sorted list of listen_paths for longest prefix matching.
    pub fn build_route_table(&self) -> Vec<(String, String)> {
        let mut routes: Vec<(String, String)> = self
            .proxies
            .iter()
            .map(|p| (p.listen_path.clone(), p.id.clone()))
            .collect();
        // Sort by path length descending for longest prefix match
        routes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        routes
    }
}

fn default_true() -> bool {
    true
}

fn default_connect_timeout() -> u64 {
    5000
}

fn default_read_timeout() -> u64 {
    30000
}

fn default_write_timeout() -> u64 {
    30000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unique_listen_paths_valid() {
        let config = GatewayConfig {
            proxies: vec![
                Proxy {
                    id: "1".into(),
                    name: None,
                    listen_path: "/api/v1".into(),
                    backend_protocol: BackendProtocol::Http,
                    backend_host: "localhost".into(),
                    backend_port: 3000,
                    backend_path: None,
                    strip_listen_path: true,
                    preserve_host_header: false,
                    backend_connect_timeout_ms: 5000,
                    backend_read_timeout_ms: 30000,
                    backend_write_timeout_ms: 30000,
                    backend_tls_client_cert_path: None,
                    backend_tls_client_key_path: None,
                    backend_tls_verify_server_cert: true,
                    backend_tls_server_ca_cert_path: None,
                    dns_override: None,
                    dns_cache_ttl_seconds: None,
                    auth_mode: AuthMode::Single,
                    plugins: vec![],
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
                Proxy {
                    id: "2".into(),
                    name: None,
                    listen_path: "/api/v2".into(),
                    backend_protocol: BackendProtocol::Http,
                    backend_host: "localhost".into(),
                    backend_port: 3001,
                    backend_path: None,
                    strip_listen_path: true,
                    preserve_host_header: false,
                    backend_connect_timeout_ms: 5000,
                    backend_read_timeout_ms: 30000,
                    backend_write_timeout_ms: 30000,
                    backend_tls_client_cert_path: None,
                    backend_tls_client_key_path: None,
                    backend_tls_verify_server_cert: true,
                    backend_tls_server_ca_cert_path: None,
                    dns_override: None,
                    dns_cache_ttl_seconds: None,
                    auth_mode: AuthMode::Single,
                    plugins: vec![],
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
            ],
            consumers: vec![],
            plugin_configs: vec![],
            loaded_at: Utc::now(),
        };
        assert!(config.validate_unique_listen_paths().is_ok());
    }

    #[test]
    fn test_unique_listen_paths_duplicate() {
        let config = GatewayConfig {
            proxies: vec![
                Proxy {
                    id: "1".into(),
                    name: None,
                    listen_path: "/api/v1".into(),
                    backend_protocol: BackendProtocol::Http,
                    backend_host: "localhost".into(),
                    backend_port: 3000,
                    backend_path: None,
                    strip_listen_path: true,
                    preserve_host_header: false,
                    backend_connect_timeout_ms: 5000,
                    backend_read_timeout_ms: 30000,
                    backend_write_timeout_ms: 30000,
                    backend_tls_client_cert_path: None,
                    backend_tls_client_key_path: None,
                    backend_tls_verify_server_cert: true,
                    backend_tls_server_ca_cert_path: None,
                    dns_override: None,
                    dns_cache_ttl_seconds: None,
                    auth_mode: AuthMode::Single,
                    plugins: vec![],
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
                Proxy {
                    id: "2".into(),
                    name: None,
                    listen_path: "/api/v1".into(),
                    backend_protocol: BackendProtocol::Http,
                    backend_host: "localhost".into(),
                    backend_port: 3001,
                    backend_path: None,
                    strip_listen_path: true,
                    preserve_host_header: false,
                    backend_connect_timeout_ms: 5000,
                    backend_read_timeout_ms: 30000,
                    backend_write_timeout_ms: 30000,
                    backend_tls_client_cert_path: None,
                    backend_tls_client_key_path: None,
                    backend_tls_verify_server_cert: true,
                    backend_tls_server_ca_cert_path: None,
                    dns_override: None,
                    dns_cache_ttl_seconds: None,
                    auth_mode: AuthMode::Single,
                    plugins: vec![],
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
            ],
            consumers: vec![],
            plugin_configs: vec![],
            loaded_at: Utc::now(),
        };
        assert!(config.validate_unique_listen_paths().is_err());
    }

    #[test]
    fn test_route_table_sorted_by_length() {
        let config = GatewayConfig {
            proxies: vec![
                Proxy {
                    id: "short".into(),
                    name: None,
                    listen_path: "/api".into(),
                    backend_protocol: BackendProtocol::Http,
                    backend_host: "localhost".into(),
                    backend_port: 3000,
                    backend_path: None,
                    strip_listen_path: true,
                    preserve_host_header: false,
                    backend_connect_timeout_ms: 5000,
                    backend_read_timeout_ms: 30000,
                    backend_write_timeout_ms: 30000,
                    backend_tls_client_cert_path: None,
                    backend_tls_client_key_path: None,
                    backend_tls_verify_server_cert: true,
                    backend_tls_server_ca_cert_path: None,
                    dns_override: None,
                    dns_cache_ttl_seconds: None,
                    auth_mode: AuthMode::Single,
                    plugins: vec![],
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
                Proxy {
                    id: "long".into(),
                    name: None,
                    listen_path: "/api/v1/users".into(),
                    backend_protocol: BackendProtocol::Http,
                    backend_host: "localhost".into(),
                    backend_port: 3001,
                    backend_path: None,
                    strip_listen_path: true,
                    preserve_host_header: false,
                    backend_connect_timeout_ms: 5000,
                    backend_read_timeout_ms: 30000,
                    backend_write_timeout_ms: 30000,
                    backend_tls_client_cert_path: None,
                    backend_tls_client_key_path: None,
                    backend_tls_verify_server_cert: true,
                    backend_tls_server_ca_cert_path: None,
                    dns_override: None,
                    dns_cache_ttl_seconds: None,
                    auth_mode: AuthMode::Single,
                    plugins: vec![],
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                },
            ],
            consumers: vec![],
            plugin_configs: vec![],
            loaded_at: Utc::now(),
        };
        let routes = config.build_route_table();
        assert_eq!(routes[0].1, "long"); // longest path first
        assert_eq!(routes[1].1, "short");
    }
}
