use kube::api::DynamicObject;

use crate::config_sources::k8s::{K8sMetadata, K8sObject};

pub fn dynamic_object_to_k8s_object(
    obj: &DynamicObject,
    api_version: &str,
    kind: &str,
) -> K8sObject {
    let metadata = K8sMetadata {
        name: obj.metadata.name.clone().unwrap_or_default(),
        namespace: obj
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| "default".to_string()),
        labels: obj
            .metadata
            .labels
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        deletion_timestamp: obj
            .metadata
            .deletion_timestamp
            .as_ref()
            .map(|ts| ts.0.to_string()),
    };

    let spec = obj
        .data
        .get("spec")
        .cloned()
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
    let status = obj
        .data
        .get("status")
        .cloned()
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata,
        spec,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;
    use serde_json::json;

    fn make_dynamic_object(name: &str, namespace: &str, spec: serde_json::Value) -> DynamicObject {
        DynamicObject {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            types: None,
            data: json!({ "spec": spec }),
        }
    }

    #[test]
    fn converts_dynamic_object_to_k8s_object() {
        let spec = json!({"mtls": {"mode": "STRICT"}});
        let dyn_obj = make_dynamic_object("my-policy", "prod", spec.clone());

        let result =
            dynamic_object_to_k8s_object(&dyn_obj, "security.istio.io/v1", "PeerAuthentication");

        assert_eq!(result.kind, "PeerAuthentication");
        assert_eq!(result.api_version, "security.istio.io/v1");
        assert_eq!(result.metadata.name, "my-policy");
        assert_eq!(result.metadata.namespace, "prod");
        assert_eq!(result.spec, spec);
    }

    #[test]
    fn handles_missing_metadata_fields() {
        let dyn_obj = DynamicObject {
            metadata: ObjectMeta::default(),
            types: None,
            data: json!({}),
        };

        let result = dynamic_object_to_k8s_object(&dyn_obj, "v1", "Service");

        assert_eq!(result.metadata.name, "");
        assert_eq!(result.metadata.namespace, "default");
        assert!(result.metadata.labels.is_empty());
        assert!(result.spec.is_object());
    }

    #[test]
    fn preserves_labels() {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("app".to_string(), "frontend".to_string());
        labels.insert("version".to_string(), "v2".to_string());

        let dyn_obj = DynamicObject {
            metadata: ObjectMeta {
                name: Some("svc".to_string()),
                namespace: Some("ns".to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            types: None,
            data: json!({"spec": {}}),
        };

        let result = dynamic_object_to_k8s_object(&dyn_obj, "v1", "Service");
        assert_eq!(result.metadata.labels.get("app").unwrap(), "frontend");
        assert_eq!(result.metadata.labels.get("version").unwrap(), "v2");
    }
}
