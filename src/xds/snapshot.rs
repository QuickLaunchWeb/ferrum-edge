use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::proto;

/// One xDS resource encoded as an Any payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdsResource {
    pub name: String,
    pub type_url: String,
    pub version: String,
    pub value: Vec<u8>,
}

impl XdsResource {
    pub fn to_any(&self) -> proto::Any {
        proto::Any {
            type_url: self.type_url.clone(),
            value: self.value.clone(),
        }
    }

    pub fn to_delta_resource(&self) -> proto::Resource {
        proto::Resource {
            version: self.version.clone(),
            resource: Some(self.to_any()),
            name: self.name.clone(),
            aliases: Vec::new(),
        }
    }
}

/// Full xDS snapshot for one node ID. Node ID is a security boundary:
/// snapshots are never shared across nodes even when their resources happen
/// to be byte-identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdsSnapshot {
    pub node_id: String,
    pub version: String,
    resources_by_type: HashMap<String, Vec<XdsResource>>,
}

impl XdsSnapshot {
    pub fn new(node_id: String, version: String, resources: Vec<XdsResource>) -> Self {
        let mut resources_by_type: HashMap<String, Vec<XdsResource>> = HashMap::new();
        for resource in resources {
            resources_by_type
                .entry(resource.type_url.clone())
                .or_default()
                .push(resource);
        }
        for resources in resources_by_type.values_mut() {
            resources.sort_by(|a, b| a.name.cmp(&b.name));
        }
        Self {
            node_id,
            version,
            resources_by_type,
        }
    }

    pub fn resources(&self, type_url: &str) -> Vec<XdsResource> {
        self.resources_by_type
            .get(type_url)
            .cloned()
            .unwrap_or_default()
    }

    pub fn filtered_resources(&self, type_url: &str, names: &[String]) -> Vec<XdsResource> {
        let resources = self.resources(type_url);
        if names.is_empty() {
            return resources;
        }
        let wanted: HashSet<&str> = names.iter().map(String::as_str).collect();
        resources
            .into_iter()
            .filter(|resource| wanted.contains(resource.name.as_str()))
            .collect()
    }

    pub fn removed_resource_names(&self, next: &Self, type_url: &str) -> Vec<String> {
        let next_names: HashSet<String> = next
            .resources(type_url)
            .into_iter()
            .map(|resource| resource.name)
            .collect();
        let mut removed: Vec<String> = self
            .resources(type_url)
            .into_iter()
            .filter_map(|resource| {
                if next_names.contains(&resource.name) {
                    None
                } else {
                    Some(resource.name)
                }
            })
            .collect();
        removed.sort();
        removed
    }
}

/// Lock-free per-node snapshot cache for ADS.
#[derive(Default)]
pub struct XdsSnapshotCache {
    snapshots: DashMap<String, Arc<XdsSnapshot>>,
}

impl XdsSnapshotCache {
    pub fn new() -> Self {
        Self {
            snapshots: DashMap::new(),
        }
    }

    pub fn get(&self, node_id: &str) -> Option<Arc<XdsSnapshot>> {
        self.snapshots
            .get(node_id)
            .map(|snapshot| Arc::clone(snapshot.value()))
    }

    pub fn insert(&self, snapshot: XdsSnapshot) -> Option<Arc<XdsSnapshot>> {
        self.snapshots
            .insert(snapshot.node_id.clone(), Arc::new(snapshot))
    }

    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}
