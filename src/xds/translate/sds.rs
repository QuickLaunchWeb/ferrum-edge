//! Trust bundle + SVID → `Secret` translation.
//!
//! SDS produces two named secrets per workload:
//!
//! - **`default`** (cert + key) — the workload's own X.509-SVID. The
//!   sidecar uses this when terminating mTLS (inbound listener) or
//!   originating mTLS (outbound clusters).
//! - **`ROOTCA`** (validation context) — concatenated PEM trust anchors
//!   for the workload's local trust domain plus all federated trust
//!   domains the slice references.
//!
//! Phase B foundation note: the issuing CP doesn't *have* the workload's
//! private key (the workload generates the CSR), so the `default` cert
//! emitted here is empty for now and will be populated by Phase C when
//! the data plane workload-API client populates it. We still emit the
//! Secret message so xDS clients see the resource appear in the
//! catalog, and the SDS subscription handshake completes.

use envoy_types::pb::envoy::config::core::v3::DataSource;
use envoy_types::pb::envoy::config::core::v3::data_source::Specifier as DataSourceSpec;
use envoy_types::pb::envoy::extensions::transport_sockets::tls::v3::secret::Type as SecretType;
use envoy_types::pb::envoy::extensions::transport_sockets::tls::v3::{
    CertificateValidationContext, Secret, TlsCertificate,
};

use super::{DEFAULT_SDS_CERT_NAME, DEFAULT_SDS_VALIDATION_NAME, SecretSet};
use crate::config::mesh::MeshSlice;
use crate::config::types::GatewayConfig;
use crate::xds::snapshot::NodeIdentity;

pub fn translate(
    slice: Option<&MeshSlice>,
    _identity: &NodeIdentity,
    config: &GatewayConfig,
) -> SecretSet {
    let mut out = SecretSet::new();

    // 1) `default` — placeholder TLS cert. Phase C populates from the
    //    SVID rotation pipeline; the resource is emitted unconditionally
    //    so xDS clients can subscribe by name.
    out.insert(
        DEFAULT_SDS_CERT_NAME.to_string(),
        Secret {
            name: DEFAULT_SDS_CERT_NAME.to_string(),
            r#type: Some(SecretType::TlsCertificate(TlsCertificate::default())),
        },
    );

    // 2) `ROOTCA` — built from the slice's trust bundle (or, if the
    //    slice is empty, the gateway-level trust bundle).
    let trust_bundles = slice
        .and_then(|s| s.trust_bundles.as_ref())
        .or(config.trust_bundles.as_ref());

    if let Some(bundles) = trust_bundles {
        let mut pem_chain = String::new();
        // Local + federated authorities concatenated. Each entry in the
        // slice's `x509_authorities` is base64(DER); we wrap it in PEM
        // so Envoy's existing PEM parser accepts it.
        for cert_b64 in &bundles.local.x509_authorities {
            pem_chain.push_str("-----BEGIN CERTIFICATE-----\n");
            pem_chain.push_str(cert_b64);
            pem_chain.push_str("\n-----END CERTIFICATE-----\n");
        }
        for fed in &bundles.federated {
            for cert_b64 in &fed.x509_authorities {
                pem_chain.push_str("-----BEGIN CERTIFICATE-----\n");
                pem_chain.push_str(cert_b64);
                pem_chain.push_str("\n-----END CERTIFICATE-----\n");
            }
        }
        out.insert(
            DEFAULT_SDS_VALIDATION_NAME.to_string(),
            Secret {
                name: DEFAULT_SDS_VALIDATION_NAME.to_string(),
                r#type: Some(SecretType::ValidationContext(
                    CertificateValidationContext {
                        trusted_ca: Some(DataSource {
                            specifier: Some(DataSourceSpec::InlineString(pem_chain)),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )),
            },
        );
    } else {
        // No trust bundles configured at all — emit an empty
        // ValidationContext so subscriptions still resolve.
        out.insert(
            DEFAULT_SDS_VALIDATION_NAME.to_string(),
            Secret {
                name: DEFAULT_SDS_VALIDATION_NAME.to_string(),
                r#type: Some(SecretType::ValidationContext(
                    CertificateValidationContext::default(),
                )),
            },
        );
    }

    out
}
