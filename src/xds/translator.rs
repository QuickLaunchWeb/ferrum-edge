use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use super::proto;
use super::runtime_proto;
use super::snapshot::{XdsResource, XdsSnapshot};
use crate::modes::mesh::config::{
    FractionalPercentDenominator, MeshRuntimeOverlay, RuntimeFractionalPercent, RuntimeValue,
};
use crate::modes::mesh::slice::MeshSlice;

pub const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
pub const RDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
pub const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
pub const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
pub const SDS_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";
pub const ECDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig";
pub const RTDS_TYPE_URL: &str = "type.googleapis.com/envoy.service.runtime.v3.Runtime";

/// Inner `type_url` Ferrum uses for the DestinationRule-carrier ECDS payload.
/// CPs that want full DR semantics across xDS wrap the original DR JSON in a
/// TypedExtensionConfig with this inner type. GAP-2K's recovery path
/// recognizes the marker and applies the embedded DR locally.
pub const FERRUM_ECDS_DESTINATION_RULE_TYPE_URL: &str =
    "type.googleapis.com/ferrum.config.extension.v3.DestinationRuleCarrier";

pub const XDS_TYPE_URLS: [&str; 7] = [
    LDS_TYPE_URL,
    RDS_TYPE_URL,
    CDS_TYPE_URL,
    EDS_TYPE_URL,
    SDS_TYPE_URL,
    ECDS_TYPE_URL,
    RTDS_TYPE_URL,
];

pub fn translate_mesh_slice_to_snapshot(slice: &MeshSlice) -> XdsSnapshot {
    let mut resources = Vec::new();
    resources.extend(translate_lds(slice));
    resources.extend(translate_rds(slice));
    resources.extend(translate_cds(slice));
    resources.extend(translate_eds(slice));
    resources.extend(translate_sds(slice));
    resources.extend(translate_ecds(slice));
    // Per-resource versions are content-derived so two snapshots with the
    // same resource bytes carry identical resource versions. This is the
    // basis for delta xDS wire-byte reduction: clients that report the
    // resource via `initial_resource_versions` (or that previously ACKed it on
    // this stream) get the resource skipped on the next response when its
    // content hasn't changed. The aggregate `snapshot.version` still
    // changes whenever any resource bytes change.
    //
    // The per-resource hash deliberately excludes `slice.version` so a slice
    // bumping its base version (e.g. on a `loaded_at` timestamp tick) does
    // not invalidate every cached resource version on the client side.
    for resource in &mut resources {
        resource.version = per_resource_version(resource);
    }
    let version = content_version(&slice.version, &resources);
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

/// Per-resource version: first 8 bytes (16 hex chars) of
/// `SHA-256(type_url || 0x00 || name || 0x00 || value)`. Truncation keeps the
/// version field small on the wire; with ~10k resources per type URL the
/// birthday-bound collision probability is ~3e-12. On a live stream, the
/// delta-response filter pairs this version check with a byte-equality check
/// on `value` against the previous ACKed snapshot before skipping a resource;
/// reconnect `initial_resource_versions` skips by the reported version match.
fn per_resource_version(resource: &XdsResource) -> String {
    let mut hasher = Sha256::new();
    hasher.update(resource.type_url.as_bytes());
    hasher.update([0]);
    hasher.update(resource.name.as_bytes());
    hasher.update([0]);
    hasher.update(&resource.value);
    hex::encode(&hasher.finalize()[..8])
}

/// Translate one Envoy `envoy.service.runtime.v3.Runtime` resource (one RTDS
/// "layer") into a `MeshRuntimeOverlay`.
///
/// This is the single decode site for RTDS resources. The overlay is then
/// carried on `MeshSlice.runtime_overlay` and fanned out to consumers
/// (fault injection, request/response transformer gates, tracing log level)
/// at slice install via `runtime_overlay_consumers::apply_overlay`.
///
/// Top-level fields in the Runtime's `layer` struct are flattened into
/// `MeshRuntimeOverlay.fields` keyed by field name. Field values are mapped:
///
///   - `number_value`        → `RuntimeValue::Number`
///   - `string_value`        → `RuntimeValue::String`
///   - `bool_value`          → `RuntimeValue::Bool`
///   - struct shaped like an Envoy `FractionalPercent`
///     (`numerator: number, denominator: "HUNDRED"|"TEN_THOUSAND"|"MILLION"`)
///     → `RuntimeValue::FractionalPercent`
///   - other struct / list / null values are silently skipped (RTDS layers
///     don't ship them in practice; avoid inventing placeholder semantics
///     until a consumer needs them)
pub fn translate_rtds_layer(layer: &runtime_proto::Runtime) -> MeshRuntimeOverlay {
    let Some(layer_struct) = layer.layer.as_ref() else {
        return MeshRuntimeOverlay::default();
    };
    let mut overlay = MeshRuntimeOverlay::default();
    for (key, value) in &layer_struct.fields {
        if let Some(runtime_value) = runtime_value_from_proto(value) {
            overlay.fields.insert(key.clone(), runtime_value);
        }
    }
    overlay
}

fn runtime_value_from_proto(value: &runtime_proto::Value) -> Option<RuntimeValue> {
    use runtime_proto::value::Kind;
    match value.kind.as_ref()? {
        Kind::NumberValue(number) => Some(RuntimeValue::Number(*number)),
        Kind::StringValue(string) => Some(RuntimeValue::String(string.clone())),
        Kind::BoolValue(boolean) => Some(RuntimeValue::Bool(*boolean)),
        Kind::StructValue(structure) => fractional_percent_from_struct(structure),
        Kind::NullValue(_) | Kind::ListValue(_) => None,
    }
}

fn fractional_percent_from_struct(structure: &runtime_proto::Struct) -> Option<RuntimeValue> {
    let numerator_value = structure.fields.get("numerator")?;
    let denominator_value = structure.fields.get("denominator")?;

    let numerator = match numerator_value.kind.as_ref()? {
        runtime_proto::value::Kind::NumberValue(number) if number.is_finite() && *number >= 0.0 => {
            *number as u32
        }
        _ => return None,
    };
    let denominator_token = match denominator_value.kind.as_ref()? {
        runtime_proto::value::Kind::StringValue(text) => text.as_str(),
        _ => return None,
    };
    let denominator = match denominator_token {
        "HUNDRED" => FractionalPercentDenominator::Hundred,
        "TEN_THOUSAND" => FractionalPercentDenominator::TenThousand,
        "MILLION" => FractionalPercentDenominator::Million,
        _ => return None,
    };

    // Only accept structs that look like an Envoy FractionalPercent
    // (numerator + denominator and nothing else). Larger structs would have
    // been a different `Value::struct_value` payload; rejecting them keeps
    // the mapping unambiguous and reversible.
    if structure.fields.len() != 2 {
        return None;
    }

    Some(RuntimeValue::FractionalPercent(RuntimeFractionalPercent {
        numerator,
        denominator,
    }))
}
