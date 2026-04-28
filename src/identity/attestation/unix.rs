//! Unix-socket peer-credentials attestor.
//!
//! Reads `SO_PEERCRED` (PID/UID/GID) on the Unix domain socket the workload
//! API server is listening on, then walks `/proc/<pid>/exe` and computes a
//! SHA-256 fingerprint of the binary. Operators map either the UID or the
//! binary fingerprint to a SPIFFE ID via static config.
//!
//! Linux-first: macOS exposes `LOCAL_PEERPID` but not `LOCAL_PEEREUID` for
//! arbitrary sockets, and Windows has no equivalent. On non-Linux, the
//! attestor returns [`AttestError::NotApplicable`] so callers can fall back
//! to other attestors.

use async_trait::async_trait;
use std::collections::HashMap;

#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use super::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use crate::identity::spiffe::{SpiffeId, TrustDomain};

/// One mapping rule.
#[derive(Debug, Clone)]
pub struct UnixIdentityRule {
    /// If set, the rule matches only when the peer UID is this value.
    pub require_uid: Option<u32>,
    /// If set, the rule matches only when the peer's binary SHA-256 matches.
    pub require_binary_sha256: Option<String>,
    /// SPIFFE ID to assign on match. Must be in the configured trust domain.
    pub spiffe_id: SpiffeId,
}

/// Configuration for the unix-peer attestor.
#[derive(Debug, Clone)]
pub struct UnixAttestorConfig {
    pub trust_domain: TrustDomain,
    pub rules: Vec<UnixIdentityRule>,
}

/// Unix-socket peer-credentials attestor.
pub struct UnixAttestor {
    config: UnixAttestorConfig,
}

impl UnixAttestor {
    pub fn new(config: UnixAttestorConfig) -> Result<Self, AttestError> {
        if config.rules.is_empty() {
            return Err(AttestError::Config(
                "unix attestor requires at least one rule".to_string(),
            ));
        }
        for rule in &config.rules {
            if rule.spiffe_id.trust_domain() != &config.trust_domain {
                return Err(AttestError::Config(format!(
                    "rule SPIFFE ID '{}' is outside the configured trust domain '{}'",
                    rule.spiffe_id, config.trust_domain
                )));
            }
        }
        Ok(Self { config })
    }
}

#[async_trait]
impl Attestor for UnixAttestor {
    fn kind(&self) -> &'static str {
        "unix"
    }

    async fn attest(&self, peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
        // We need at minimum a PID or UID; without those there's nothing to
        // match against.
        if peer.pid.is_none() && peer.uid.is_none() {
            return Err(AttestError::NotApplicable);
        }

        let pid = peer.pid;
        let uid = peer.uid;

        #[cfg(target_os = "linux")]
        let binary_sha256 = match pid {
            Some(p) if p > 0 => binary_fingerprint_linux(p)?,
            _ => None,
        };
        #[cfg(not(target_os = "linux"))]
        let binary_sha256: Option<String> = None;

        for rule in &self.config.rules {
            let uid_ok = match rule.require_uid {
                Some(expected) => uid == Some(expected),
                None => true,
            };
            let bin_ok = match &rule.require_binary_sha256 {
                Some(expected) => binary_sha256.as_deref() == Some(expected.as_str()),
                None => true,
            };
            if uid_ok && bin_ok {
                let mut selectors = HashMap::new();
                if let Some(p) = pid {
                    selectors.insert("unix:pid".to_string(), p.to_string());
                }
                if let Some(u) = uid {
                    selectors.insert("unix:uid".to_string(), u.to_string());
                }
                if let Some(g) = peer.gid {
                    selectors.insert("unix:gid".to_string(), g.to_string());
                }
                if let Some(ref sha) = binary_sha256 {
                    selectors.insert("unix:binary-sha256".to_string(), sha.clone());
                }
                return Ok(WorkloadIdentity {
                    spiffe_id: rule.spiffe_id.clone(),
                    selectors,
                    attestor_kind: self.kind().to_string(),
                });
            }
        }

        Err(AttestError::Failed(
            "no unix attestor rule matched the peer".to_string(),
        ))
    }
}

// PERF/SECURITY (Phase B caching deferral):
//
// The current implementation reads `/proc/<pid>/exe` and SHA-256s the entire
// binary on every attestation. Two concerns to resolve before the unix
// attestor sees production sidecar load:
//
//   - **TOCTOU**: an exec-after-attestation race lets a workload swap its
//     binary between the attestation read and the SVID issuance. The pid is
//     the same, but the binary the cert authorises is not the binary that
//     gets to use it.
//   - **DoS**: a 100 MB binary hashed under attestation churn is slow. With
//     a malicious or misbehaving workload spamming `FetchX509SVID` reconnects,
//     the attestor becomes a synchronous bottleneck for the workload-API
//     server.
//
// Phase B should cache fingerprints by `(pid, dev, ino, mtime)` with a TTL
// so repeat attestations are O(1) and post-fork cert reissuance does not
// re-hash. Until then, callers should rate-limit attestation requests at
// the workload-API-server layer (existing rate-limiting plugins can do
// this).
#[cfg(target_os = "linux")]
fn binary_fingerprint_linux(pid: i32) -> Result<Option<String>, AttestError> {
    let exe = PathBuf::from(format!("/proc/{}/exe", pid));
    let resolved = match std::fs::read_link(&exe) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => {
            return Err(AttestError::Io(format!(
                "failed to read /proc/{}/exe: {}",
                pid, e
            )));
        }
    };
    let bytes = match std::fs::read(&resolved) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AttestError::Io(format!(
                "failed to read binary '{}': {}",
                resolved.display(),
                e
            )));
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(Some(hex::encode(hasher.finalize())))
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn binary_fingerprint_linux(_pid: i32) -> Result<Option<String>, AttestError> {
    Ok(None)
}
