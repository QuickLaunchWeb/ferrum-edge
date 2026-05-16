use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use super::proto;
use super::snapshot::{XdsResource, XdsSnapshot};
use crate::modes::mesh::slice::MeshSlice;

pub const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
pub const RDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
pub const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
pub const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
pub const SDS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";
pub const ECDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig";

/// Inner `type_url` Ferrum uses for the DestinationRule-carrier ECDS payload.
/// CPs that want full DR semantics across xDS wrap the original DR JSON in a
/// TypedExtensionConfig with this inner type. GAP-2K's recovery path
/// recognizes the marker and applies the embedded DR locally.
pub const FERRUM_ECDS_DESTINATION_RULE_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier";

pub const XDS_TYPE_URLS: [&str; 6] = [
    LDS_TYPE_URL,
    RDS_TYPE_URL,
    CDS_TYPE_URL,
    EDS_TYPE_URL,
    SDS_TYPE_URL,
    ECDS_TYPE_URL,
];

pub fn translate_mesh_slice_to_snapshot(slice: &MeshSlice) -> XdsSnapshot {
    let mut resources = Vec::new();
    resources.extend(translate_lds(slice));
    resources.extend(translate_rds(slice));
    resources.extend(translate_cds(slice));
    resources.extend(translate_eds(slice));
    resources.extend(translate_sds(slice));
    resources.extend(translate_ecds(slice));
    let version = content_version(&slice.version, &resources);
    for resource in &mut resources {
        resource.version = version.clone();
    }
    XdsSnapshot::new(slice.node_id.clone(), version, resources)
}

pub fn translate_lds(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    for service in &slice.services {
        for port in &service.ports {
            let name = format!(
                "listener/{}/{}/{}",
                service.namespace, service.name, port.port
            );
            push_unique_resource(
                &mut resources,
                &mut seen_names,
                name.clone(),
                LDS_TYPE_URL,
                &slice.version,
                proto::Listener { name },
            );
        }
    }
    resources
}

pub fn translate_rds(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    for service in &slice.services {
        let name = format!("route/{}/{}", service.namespace, service.name);
        push_unique_resource(
            &mut resources,
            &mut seen_names,
            name.clone(),
            RDS_TYPE_URL,
            &slice.version,
            proto::RouteConfiguration { name },
        );
    }
    resources
}

pub fn translate_cds(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    for service in &slice.services {
        for port in &service.ports {
            let name = cluster_name(&service.namespace, &service.name, port.port);
            push_unique_resource(
                &mut resources,
                &mut seen_names,
                name.clone(),
                CDS_TYPE_URL,
                &slice.version,
                proto::Cluster { name },
            );
        }
    }
    for entry in &slice.service_entries {
        for port in &entry.ports {
            let name = cluster_name(&entry.namespace, &entry.name, port.port);
            push_unique_resource(
                &mut resources,
                &mut seen_names,
                name.clone(),
                CDS_TYPE_URL,
                &slice.version,
                proto::Cluster { name },
            );
        }
    }
    resources
}

pub fn translate_eds(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    for service in &slice.services {
        for port in &service.ports {
            let name = cluster_name(&service.namespace, &service.name, port.port);
            push_unique_resource(
                &mut resources,
                &mut seen_names,
                name.clone(),
                EDS_TYPE_URL,
                &slice.version,
                proto::ClusterLoadAssignment { cluster_name: name },
            );
        }
    }
    for entry in &slice.service_entries {
        for port in &entry.ports {
            let name = cluster_name(&entry.namespace, &entry.name, port.port);
            push_unique_resource(
                &mut resources,
                &mut seen_names,
                name.clone(),
                EDS_TYPE_URL,
                &slice.version,
                proto::ClusterLoadAssignment { cluster_name: name },
            );
        }
    }
    resources
}

/// Translate operator-defined `MeshSlice.extension_configs` into ECDS resources.
///
/// Each entry becomes a top-level `XdsResource` whose `value` is the encoded
/// `envoy.config.core.v3.TypedExtensionConfig` (i.e., `{name, typed_config:
/// Any{type_url, value}}`). Clients subscribe under `ECDS_TYPE_URL` and
/// dispatch on the inner `typed_config.type_url`.
///
/// The GAP-2K DestinationRule-carrier path emits one entry per DR with the
/// inner `type_url == FERRUM_ECDS_DESTINATION_RULE_TYPE_URL` and the original
/// DR JSON as the inner bytes; the DP xDS consumer recognizes that marker
/// and applies the embedded DR locally.
pub fn translate_ecds(slice: &MeshSlice) -> Vec<XdsResource> {
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    for extension in &slice.extension_configs {
        if extension.name.is_empty() || !seen_names.insert(extension.name.clone()) {
            continue;
        }
        let typed_config = proto::Any {
            type_url: extension.type_url.clone(),
            value: extension.value.clone(),
        };
        let message = proto::TypedExtensionConfig {
            name: extension.name.clone(),
            typed_config: Some(typed_config),
        };
        resources.push(resource(
            extension.name.clone(),
            ECDS_TYPE_URL,
            &slice.version,
            message,
        ));
    }
    resources
}

pub fn translate_sds(slice: &MeshSlice) -> Vec<XdsResource> {
    let Some(bundle_set) = slice.trust_bundles.as_ref() else {
        return Vec::new();
    };
    let mut resources = Vec::new();
    let mut seen_names = HashSet::new();
    let local = bundle_set.local.trust_domain.as_str();
    let local_name = format!("secret/spiffe-bundle/{local}");
    push_unique_resource(
        &mut resources,
        &mut seen_names,
        local_name.clone(),
        SDS_TYPE_URL,
        &slice.version,
        proto::Secret { name: local_name },
    );
    for bundle in &bundle_set.federated {
        let trust_domain = bundle.trust_domain.as_str();
        let name = format!("secret/spiffe-bundle/{trust_domain}");
        push_unique_resource(
            &mut resources,
            &mut seen_names,
            name.clone(),
            SDS_TYPE_URL,
            &slice.version,
            proto::Secret { name },
        );
    }
    resources
}

fn cluster_name(namespace: &str, name: &str, port: u16) -> String {
    format!("cluster/{namespace}/{name}/{port}")
}

fn push_unique_resource<M>(
    resources: &mut Vec<XdsResource>,
    seen_names: &mut HashSet<String>,
    name: String,
    type_url: &str,
    version: &str,
    message: M,
) where
    M: Message,
{
    if seen_names.insert(name.clone()) {
        resources.push(resource(name, type_url, version, message));
    }
}

fn resource<M>(name: String, type_url: &str, version: &str, message: M) -> XdsResource
where
    M: Message,
{
    XdsResource {
        name,
        type_url: type_url.to_string(),
        version: version.to_string(),
        value: message.encode_to_vec(),
    }
}

fn content_version(base_version: &str, resources: &[XdsResource]) -> String {
    let mut hasher = Sha256::new();
    let mut resources: Vec<&XdsResource> = resources.iter().collect();
    resources.sort_by(|left, right| {
        left.type_url
            .cmp(&right.type_url)
            .then_with(|| left.name.cmp(&right.name))
    });
    for resource in resources {
        hasher.update(resource.type_url.as_bytes());
        hasher.update([0]);
        hasher.update(resource.name.as_bytes());
        hasher.update([0]);
        hasher.update(&resource.value);
        hasher.update([0xff]);
    }
    let digest = hex::encode(hasher.finalize());
    format!("{base_version}:{}", &digest[..16])
}
