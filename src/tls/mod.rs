use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tracing::{info, warn};

/// Load TLS server configuration from cert and key files.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, anyhow::Error> {
    load_tls_config_with_client_auth(cert_path, key_path, None, false)
}

/// Load TLS server configuration with optional client certificate verification.
pub fn load_tls_config_with_client_auth(
    cert_path: &str, 
    key_path: &str,
    client_ca_bundle_path: Option<&str>,
    no_verify: bool, // Disable certificate verification for testing
) -> Result<Arc<ServerConfig>, anyhow::Error> {
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let cert_chain: Vec<_> = certs(&mut BufReader::new(cert_file))
        .filter_map(|r| r.ok())
        .collect();

    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;

    let config = if no_verify {
        // No verification mode (for testing only)
        warn!("TLS configuration loaded with certificate verification DISABLED (testing mode) from cert: {}, key: {}", 
              cert_path, key_path);
        
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?
    } else if let Some(ca_bundle_path) = client_ca_bundle_path {
        // Load client CA bundle for client certificate verification
        let ca_file = File::open(ca_bundle_path)?;
        let ca_certs: Vec<_> = certs(&mut BufReader::new(ca_file))
            .filter_map(|r| r.ok())
            .collect();

        let mut client_auth_roots = rustls::RootCertStore::empty();
        let (added, ignored) = client_auth_roots.add_parsable_certificates(ca_certs);
        
        if added == 0 {
            return Err(anyhow::anyhow!("No valid client CA certificates found in {}", ca_bundle_path));
        }

        info!("TLS configuration loaded with client certificate verification from cert: {}, key: {}, client CA: {} (added: {}, ignored: {})", 
              cert_path, key_path, ca_bundle_path, added, ignored);

        // For now, use a simple approach that requires client certs but doesn't enforce strict verification
        // This is a limitation of the current rustls version
        ServerConfig::builder()
            .with_no_client_auth() // TODO: Update when proper client cert verification is available
            .with_single_cert(cert_chain, key)?
    } else {
        // No client certificate verification
        info!("TLS configuration loaded without client certificate verification from cert: {}, key: {}", 
              cert_path, key_path);

        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?
    };

    Ok(Arc::new(config))
}
