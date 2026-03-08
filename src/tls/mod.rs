use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tracing::info;

/// Load TLS server configuration from cert and key files.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, anyhow::Error> {
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let cert_chain: Vec<_> = certs(&mut BufReader::new(cert_file))
        .filter_map(|r| r.ok())
        .collect();

    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    info!("TLS configuration loaded from {} and {}", cert_path, key_path);
    Ok(Arc::new(config))
}
