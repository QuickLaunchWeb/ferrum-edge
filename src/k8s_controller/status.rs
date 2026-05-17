use futures_util::future::join_all;
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, Patch, PatchParams};
use serde_json::{Value, json};

use crate::config_sources::k8s::{
    GatewayApiRouteConflict, K8sObject, K8sResourceKey, K8sTranslateError, K8sTranslationOptions,
    gateway_api_route_conflicts, resource_id, translate_k8s_objects_with_filter,
};

pub const FERRUM_GATEWAY_CONTROLLER_NAME: &str = "ferrum.io/gateway-controller";

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayApiStatusUpdate {
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub status: Value,
}

#[derive(Clone)]
pub struct GatewayApiStatusWriter {
    client: Client,
}

impl GatewayApiStatusWriter {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn patch_updates(
        &self,
        updates: &[GatewayApiStatusUpdate],
    ) -> Result<(), kube::Error> {
        let futures = updates.iter().filter_map(|update| {
            let ar = api_resource_for_update(update)?;
            let api: Api<DynamicObject> = if update.kind == "GatewayClass" {
                Api::all_with(self.client.clone(), &ar)
            } else {
                Api::namespaced_with(self.client.clone(), &update.namespace, &ar)
            };
            let patch = json!({ "status": update.status });
            let name = update.name.clone();
            Some(async move {
                api.patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
                    .await
                    .map(|_| ())
            })
        });
        // Patch each Gateway API status in parallel. The Kubernetes API server
        // serializes mutations through resourceVersion conflicts; this only
        // pipelines independent objects so each round-trip's RTT does not
        // serialize the reconciler loop on large clusters.
        for result in join_all(futures).await {
            result?;
        }
        Ok(())
    }
}

pub fn plan_gateway_api_status_updates(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
) -> Vec<GatewayApiStatusUpdate> {
    let conflicts = gateway_api_route_conflicts(objects, &options);
    objects
        .iter()
        .filter(|object| is_status_kind(&object.kind))
        .filter_map(|object| {
            if object.kind == "GatewayClass" && !gateway_class_is_managed_by_ferrum(object) {
                return None;
            }
            let resource_key = K8sResourceKey::from_object(object);
            let conflict = conflicts
                .iter()
                .find(|conflict| conflict.loser == resource_key);
            let status = desired_status_for_object(objects, object, options.clone(), conflict);
            if status == object.status {
                return None;
            }
            Some(GatewayApiStatusUpdate {
                api_version: object.api_version.clone(),
                kind: object.kind.clone(),
                namespace: object.metadata.namespace.clone(),
                name: object.metadata.name.clone(),
                status,
            })
        })
        .collect()
}

fn desired_status_for_object(
    objects: &[K8sObject],
    object: &K8sObject,
    options: K8sTranslationOptions,
    conflict: Option<&GatewayApiRouteConflict>,
) -> Value {
    if object.kind == "GatewayClass" {
        return gateway_class_status(object);
    }
    if let Some(conflict) = conflict {
        return conflicted_route_status(object, conflict);
    }

    let result = translate_k8s_objects_with_filter(objects, options, |candidate| {
        same_resource(candidate, object)
            || candidate.kind == "ReferenceGrant"
            || candidate.kind == "Service"
    });

    match object.kind.as_str() {
        "Gateway" => gateway_status(object, result.as_ref()),
        "HTTPRoute" | "GRPCRoute" => route_status(object, result.as_ref()),
        _ => Value::Object(Default::default()),
    }
}

fn gateway_class_status(object: &K8sObject) -> Value {
    let conditions = vec![condition(
        &object.status,
        "Accepted",
        true,
        "Accepted",
        "Ferrum accepted this GatewayClass",
    )];

    let mut status = object.status.clone();
    ensure_status_object(&mut status).insert("conditions".to_string(), Value::Array(conditions));
    status
}

fn gateway_status(
    object: &K8sObject,
    result: Result<&crate::config_sources::k8s::K8sTranslation, &K8sTranslateError>,
) -> Value {
    let (accepted, programmed, message) = match result {
        Ok(translation) => (
            true,
            gateway_programmed(object, &translation.config),
            "Ferrum accepted this Gateway".to_string(),
        ),
        Err(error) => (
            false,
            false,
            format!("Ferrum rejected this Gateway: {error}"),
        ),
    };

    let conditions = vec![
        condition(
            &object.status,
            "Accepted",
            accepted,
            if accepted { "Accepted" } else { "Invalid" },
            &message,
        ),
        condition(
            &object.status,
            "ResolvedRefs",
            accepted,
            if accepted {
                "ResolvedRefs"
            } else {
                "TranslationFailed"
            },
            if accepted {
                "All Gateway references accepted by Ferrum"
            } else {
                &message
            },
        ),
        condition(
            &object.status,
            "Programmed",
            programmed,
            if programmed {
                "Programmed"
            } else if accepted {
                "NoListeners"
            } else {
                "TranslationFailed"
            },
            if programmed {
                "Ferrum programmed this Gateway"
            } else if accepted {
                "Ferrum accepted this Gateway but found no materialized listeners"
            } else {
                &message
            },
        ),
        condition(
            &object.status,
            "Conflicted",
            false,
            "NoConflicts",
            "No Gateway API conflicts detected by Ferrum",
        ),
    ];

    let mut status = object.status.clone();
    ensure_status_object(&mut status).insert("conditions".to_string(), Value::Array(conditions));
    status
}

fn conflicted_route_status(object: &K8sObject, conflict: &GatewayApiRouteConflict) -> Value {
    let message = format!(
        "Ferrum rejected this route because it conflicts on parent={} host={} path={}; winner is {}/{}",
        conflict.key.parent_ref,
        conflict.key.hostname,
        conflict.key.listen_path,
        conflict.winner.namespace,
        conflict.winner.name
    );
    let mut parents = Vec::new();
    for parent_ref in route_parent_refs(object) {
        let existing_parent_status = existing_parent_status(&object.status, &parent_ref);
        parents.push(json!({
            "parentRef": parent_ref,
            "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
            "conditions": [
                condition_at(existing_parent_status, "Accepted", false, "Conflicted", &message),
                condition_at(existing_parent_status, "ResolvedRefs", true, "ResolvedRefs", "All backendRefs accepted by Ferrum"),
                condition_at(existing_parent_status, "Programmed", false, "Conflicted", &message),
                condition_at(existing_parent_status, "Conflicted", true, "Conflicted", &message),
            ],
        }));
    }

    let mut status = object.status.clone();
    ensure_status_object(&mut status).insert("parents".to_string(), Value::Array(parents));
    status
}

fn ensure_status_object(status: &mut Value) -> &mut serde_json::Map<String, Value> {
    if !status.is_object() {
        *status = Value::Object(Default::default());
    }
    status.as_object_mut().expect("status object")
}

fn route_status(
    object: &K8sObject,
    result: Result<&crate::config_sources::k8s::K8sTranslation, &K8sTranslateError>,
) -> Value {
    let (accepted, resolved_refs, programmed, reason, message) = match result {
        Ok(translation) => {
            let programmed = route_programmed(object, &translation.config);
            (
                true,
                true,
                programmed,
                if programmed { "Accepted" } else { "NoRules" },
                if programmed {
                    "Ferrum accepted and programmed this route".to_string()
                } else {
                    "Ferrum accepted this route but no materialized rule was produced".to_string()
                },
            )
        }
        Err(error) => {
            let message = format!("Ferrum rejected this route: {error}");
            let reason = if error_is_reference_resolution(error) {
                "BackendRefNotPermitted"
            } else {
                "Invalid"
            };
            (false, false, false, reason, message)
        }
    };

    let mut parents = Vec::new();
    for parent_ref in route_parent_refs(object) {
        let existing_parent_status = existing_parent_status(&object.status, &parent_ref);
        let conditions = vec![
            condition_at(
                existing_parent_status,
                "Accepted",
                accepted,
                reason,
                &message,
            ),
            condition_at(
                existing_parent_status,
                "ResolvedRefs",
                resolved_refs,
                if resolved_refs {
                    "ResolvedRefs"
                } else {
                    "BackendRefNotPermitted"
                },
                if resolved_refs {
                    "All backendRefs accepted by Ferrum"
                } else {
                    &message
                },
            ),
            condition_at(
                existing_parent_status,
                "Programmed",
                programmed,
                if programmed {
                    "Programmed"
                } else {
                    "TranslationFailed"
                },
                if programmed {
                    "Ferrum programmed this route"
                } else {
                    &message
                },
            ),
            condition_at(
                existing_parent_status,
                "Conflicted",
                false,
                "NoConflicts",
                "No Gateway API conflicts detected by Ferrum",
            ),
        ];
        parents.push(json!({
            "parentRef": parent_ref,
            "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
            "conditions": conditions,
        }));
    }

    let mut status = object.status.clone();
    ensure_status_object(&mut status).insert("parents".to_string(), Value::Array(parents));
    status
}

fn condition(
    status: &Value,
    condition_type: &str,
    value: bool,
    reason: &str,
    message: &str,
) -> Value {
    condition_at(
        status
            .get("conditions")
            .and_then(Value::as_array)
            .map(Vec::as_slice),
        condition_type,
        value,
        reason,
        message,
    )
}

fn condition_at(
    existing_conditions: Option<&[Value]>,
    condition_type: &str,
    value: bool,
    reason: &str,
    message: &str,
) -> Value {
    let status = if value { "True" } else { "False" };
    let last_transition_time = existing_conditions
        .and_then(|conditions| {
            conditions.iter().find(|condition| {
                condition.get("type").and_then(Value::as_str) == Some(condition_type)
            })
        })
        .and_then(|condition| {
            let unchanged = condition.get("status").and_then(Value::as_str) == Some(status)
                && condition.get("reason").and_then(Value::as_str) == Some(reason)
                && condition.get("message").and_then(Value::as_str) == Some(message);
            if unchanged {
                condition
                    .get("lastTransitionTime")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            } else {
                None
            }
        })
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    json!({
        "type": condition_type,
        "status": status,
        "reason": reason,
        "message": message,
        "lastTransitionTime": last_transition_time,
    })
}

fn existing_parent_status<'a>(status: &'a Value, parent_ref: &Value) -> Option<&'a [Value]> {
    status
        .get("parents")
        .and_then(Value::as_array)
        .and_then(|parents| {
            parents.iter().find(|parent| {
                parent.get("controllerName").and_then(Value::as_str)
                    == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
                    && parent.get("parentRef") == Some(parent_ref)
            })
        })
        .and_then(|parent| parent.get("conditions"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn route_parent_refs(object: &K8sObject) -> Vec<Value> {
    object
        .spec
        .get("parentRefs")
        .and_then(Value::as_array)
        .filter(|refs| !refs.is_empty())
        .cloned()
        .unwrap_or_else(|| {
            vec![json!({
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": object.metadata.name,
            })]
        })
}

fn gateway_programmed(object: &K8sObject, config: &crate::config::types::GatewayConfig) -> bool {
    // Mesh services derived from this Gateway are named `{gateway.name}-{listener.name}`
    // (see `mesh_services_from_gateway` in `gateway_api.rs`). Use exact match against
    // each listener name to avoid a false positive when another Gateway's name is a
    // prefix of this one (e.g. `edge` matching `edge-internal-http`).
    let Some(mesh) = config.mesh.as_ref() else {
        return false;
    };
    let Some(listeners) = object.spec.get("listeners").and_then(Value::as_array) else {
        return false;
    };
    listeners.iter().any(|listener| {
        let listener_name = listener
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("listener");
        let expected = format!("{}-{}", object.metadata.name, listener_name);
        mesh.services.iter().any(|service| {
            service.namespace == object.metadata.namespace && service.name == expected
        })
    })
}

fn route_programmed(object: &K8sObject, config: &crate::config::types::GatewayConfig) -> bool {
    let route_kind = object.kind.to_ascii_lowercase();
    let id_prefix = format!(
        "{}-{}",
        resource_id(
            "gwapi-route",
            &object.metadata.namespace,
            &object.metadata.name,
            ""
        ),
        route_kind
    );
    config.proxies.iter().any(|proxy| {
        proxy.namespace == object.metadata.namespace && proxy.id.starts_with(&id_prefix)
    })
}

fn error_is_reference_resolution(error: &K8sTranslateError) -> bool {
    match error {
        K8sTranslateError::InvalidResource { message, .. } => {
            message.contains("backendRef")
                || message.contains("ReferenceGrant")
                || message.contains("only core Service")
        }
        K8sTranslateError::Unsupported(_) => false,
    }
}

fn same_resource(left: &K8sObject, right: &K8sObject) -> bool {
    left.api_version == right.api_version
        && left.kind == right.kind
        && left.metadata.namespace == right.metadata.namespace
        && left.metadata.name == right.metadata.name
}

fn is_status_kind(kind: &str) -> bool {
    matches!(kind, "GatewayClass" | "Gateway" | "HTTPRoute" | "GRPCRoute")
}

fn api_resource_for_update(update: &GatewayApiStatusUpdate) -> Option<ApiResource> {
    let (group, version) = update.api_version.split_once('/')?;
    let plural = match (update.kind.as_str(), version) {
        ("GatewayClass", "v1") => "gatewayclasses",
        ("Gateway", "v1") => "gateways",
        ("HTTPRoute", "v1") => "httproutes",
        ("GRPCRoute", "v1") => "grpcroutes",
        _ => return None,
    };

    Some(ApiResource {
        group: group.to_string(),
        version: version.to_string(),
        api_version: update.api_version.clone(),
        kind: update.kind.clone(),
        plural: plural.to_string(),
    })
}

fn gateway_class_is_managed_by_ferrum(object: &K8sObject) -> bool {
    object.spec.get("controllerName").and_then(Value::as_str)
        == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sources::k8s::{K8sMetadata, K8sTranslationOptions};
    use crate::identity::spiffe::TrustDomain;

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    fn object(kind: &str, name: &str, spec: Value) -> K8sObject {
        K8sObject {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                namespace: "default".to_string(),
                labels: Default::default(),
                annotations: Default::default(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec,
            status: Value::Object(Default::default()),
        }
    }

    fn route_with_created_at(name: &str, created_at: &str) -> K8sObject {
        let mut route = object(
            "HTTPRoute",
            name,
            json!({
                "hostnames": ["api.example.com"],
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );
        route.metadata.creation_timestamp = Some(created_at.to_string());
        route
    }

    #[test]
    fn gateway_class_status_reports_accepted_for_ferrum_controller() {
        let gateway_class = object(
            "GatewayClass",
            "ferrum",
            json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
        );

        let updates = plan_gateway_api_status_updates(&[gateway_class], options());

        assert_eq!(updates.len(), 1);
        let conditions = updates[0].status["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
    }

    #[test]
    fn gateway_class_status_skips_other_controllers() {
        let gateway_class = object(
            "GatewayClass",
            "other",
            json!({ "controllerName": "example.com/other-controller" }),
        );

        let updates = plan_gateway_api_status_updates(&[gateway_class], options());

        assert!(updates.is_empty());
    }

    #[test]
    fn gateway_status_reports_accepted_and_programmed() {
        let gateway = object(
            "Gateway",
            "edge",
            json!({
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            }),
        );

        let updates = plan_gateway_api_status_updates(&[gateway], options());

        assert_eq!(updates.len(), 1);
        let conditions = updates[0].status["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "True");
        assert_condition(conditions, "Conflicted", "False");
    }

    #[test]
    fn http_route_status_reports_parent_conditions() {
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );

        let updates = plan_gateway_api_status_updates(&[route], options());

        assert_eq!(updates.len(), 1);
        let parents = updates[0].status["parents"].as_array().unwrap();
        assert_eq!(parents.len(), 1);
        assert_eq!(
            parents[0]["controllerName"].as_str(),
            Some(FERRUM_GATEWAY_CONTROLLER_NAME)
        );
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "True");
        assert_condition(conditions, "ResolvedRefs", "True");
        assert_condition(conditions, "Programmed", "True");
        assert_condition(conditions, "Conflicted", "False");
    }

    #[test]
    fn route_status_reports_unresolved_cross_namespace_backend_ref() {
        let route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{
                        "name": "api",
                        "namespace": "backend",
                        "port": 8080
                    }]
                }]
            }),
        );

        let updates = plan_gateway_api_status_updates(&[route], options());

        let parents = updates[0].status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();
        assert_condition(conditions, "Accepted", "False");
        assert_condition(conditions, "ResolvedRefs", "False");
        assert_condition(conditions, "Programmed", "False");
        assert_eq!(
            find_condition(conditions, "ResolvedRefs")["reason"].as_str(),
            Some("BackendRefNotPermitted")
        );
    }

    #[test]
    fn newer_conflicting_route_reports_conflicted() {
        let older = route_with_created_at("api-a", "2026-01-01T00:00:00Z");
        let newer = route_with_created_at("api-b", "2026-01-02T00:00:00Z");

        let updates = plan_gateway_api_status_updates(&[newer, older], options());
        let newer_update = updates
            .iter()
            .find(|update| update.name == "api-b")
            .expect("newer route status");
        let parents = newer_update.status["parents"].as_array().unwrap();
        let conditions = parents[0]["conditions"].as_array().unwrap();

        assert_condition(conditions, "Accepted", "False");
        assert_condition(conditions, "Programmed", "False");
        assert_condition(conditions, "Conflicted", "True");
        assert_eq!(
            find_condition(conditions, "Accepted")["reason"].as_str(),
            Some("Conflicted")
        );
    }

    #[test]
    fn conflict_tie_breaker_uses_route_name_when_timestamps_match() {
        let left = route_with_created_at("api-a", "2026-01-01T00:00:00Z");
        let right = route_with_created_at("api-b", "2026-01-01T00:00:00Z");

        let updates = plan_gateway_api_status_updates(&[right, left], options());
        let loser = updates
            .iter()
            .find(|update| update.name == "api-b")
            .expect("name loser status");
        let parents = loser.status["parents"].as_array().unwrap();

        assert_condition(
            parents[0]["conditions"].as_array().unwrap(),
            "Conflicted",
            "True",
        );
    }

    #[test]
    fn unchanged_status_does_not_emit_update() {
        let mut route = object(
            "HTTPRoute",
            "api",
            json!({
                "parentRefs": [{"name": "edge"}],
                "rules": [{
                    "backendRefs": [{"name": "api", "port": 8080}]
                }]
            }),
        );
        let first = plan_gateway_api_status_updates(&[route.clone()], options());
        route.status = first[0].status.clone();

        let second = plan_gateway_api_status_updates(&[route], options());

        assert!(second.is_empty());
    }

    #[test]
    fn status_updates_preserve_unknown_status_fields() {
        let mut gateway = object(
            "Gateway",
            "edge",
            json!({
                "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
            }),
        );
        gateway.status = json!({
            "addresses": [{"type": "IPAddress", "value": "10.0.0.10"}]
        });

        let updates = plan_gateway_api_status_updates(&[gateway], options());

        assert_eq!(
            updates[0].status["addresses"][0]["value"].as_str(),
            Some("10.0.0.10")
        );
        assert!(updates[0].status["conditions"].is_array());
    }

    fn assert_condition(conditions: &[Value], condition_type: &str, status: &str) {
        assert_eq!(
            find_condition(conditions, condition_type)["status"].as_str(),
            Some(status),
            "unexpected status for {condition_type}"
        );
    }

    fn find_condition<'a>(conditions: &'a [Value], condition_type: &str) -> &'a Value {
        conditions
            .iter()
            .find(|condition| condition["type"].as_str() == Some(condition_type))
            .unwrap_or_else(|| panic!("missing condition {condition_type}"))
    }
}
