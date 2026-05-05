//! Mesh runtime mode scaffolding.
//!
//! Phase C introduces the gated mesh data-plane mode. The runtime surface is
//! deliberately additive: existing gateway modes do not instantiate this module
//! unless `FERRUM_MODE=mesh`.

pub mod config_consumer;
pub mod hbone;
pub mod runtime;

use anyhow::Context as _;
use tracing::info;

use crate::config::{EnvConfig, MeshConfigSource};

/// Run the mesh data-plane mode.
pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let runtime = runtime::MeshRuntimeConfig::from_env(&env_config);
    info!(
        topology = %runtime.topology,
        config_source = %runtime.config_source,
        inbound = %runtime.inbound_addr,
        outbound = %runtime.outbound_addr,
        hbone = ?runtime.hbone_addr,
        "Starting mesh runtime mode"
    );

    if runtime.config_source == MeshConfigSource::File {
        let path = env_config
            .file_config_path
            .as_deref()
            .context("FERRUM_FILE_CONFIG_PATH is required for file-backed mesh mode")?;
        let config = crate::config::file_loader::load_config_from_file(
            path,
            env_config.tls_cert_expiry_warning_days,
            &env_config.backend_allow_ips,
            &env_config.namespace,
        )?;
        if let Some(mesh) = config.mesh.as_ref() {
            let errors = mesh.validate();
            if !errors.is_empty() {
                return Err(anyhow::anyhow!(
                    "Mesh configuration validation failed: {}",
                    errors.join("; ")
                ));
            }
        }
        info!(
            proxies = config.proxies.len(),
            workloads = config.mesh.as_ref().map(|m| m.workloads.len()).unwrap_or(0),
            policies = config
                .mesh
                .as_ref()
                .map(|m| m.mesh_policies.len())
                .unwrap_or(0),
            "Loaded file-backed mesh config"
        );
    }

    let mut shutdown_rx = shutdown_tx.subscribe();
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            break;
        }
    }
    info!("Mesh runtime mode shutting down");
    Ok(())
}
