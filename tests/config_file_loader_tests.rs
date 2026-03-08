use ferrum_gateway::config::file_loader::load_config_from_file;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_load_yaml_config() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3000
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.proxies[0].listen_path, "/api/v1");
}

#[test]
fn test_load_json_config() {
    let json = r#"{
  "proxies": [{
    "id": "proxy-1",
    "listen_path": "/api/v1",
    "backend_protocol": "http",
    "backend_host": "localhost",
    "backend_port": 3000
  }],
  "consumers": [],
  "plugin_configs": []
}"#;
    let mut file = NamedTempFile::with_suffix(".json").unwrap();
    write!(file, "{}", json).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();
    assert_eq!(config.proxies.len(), 1);
}

#[test]
fn test_duplicate_listen_path_rejected() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3000
  - id: "proxy-2"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 3001
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let result = load_config_from_file(file.path().to_str().unwrap());
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("duplicate") || error_msg.contains("Duplicate"));
}
