//! Registry of connected mesh config-stream nodes.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct MeshNodeInfo {
    pub node_id: String,
    pub version: String,
    pub namespace: String,
    pub connected_at: DateTime<Utc>,
    pub last_update_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct MeshNodeRegistry {
    nodes: DashMap<String, MeshNodeInfo>,
}

impl MeshNodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
        }
    }

    pub fn insert(&self, info: MeshNodeInfo) {
        self.nodes.insert(info.node_id.clone(), info);
    }

    pub fn remove_if_stale(&self, node_id: &str, expected_connected_at: DateTime<Utc>) {
        self.nodes.remove_if(node_id, |_, info| {
            info.connected_at == expected_connected_at
        });
    }

    pub fn touch_all(&self) {
        let now = Utc::now();
        for mut entry in self.nodes.iter_mut() {
            entry.last_update_at = now;
        }
    }

    pub fn snapshot(&self) -> Vec<MeshNodeInfo> {
        self.nodes
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn registry_info(node_id: &str, version: &str, connected_at: DateTime<Utc>) -> MeshNodeInfo {
        MeshNodeInfo {
            node_id: node_id.to_string(),
            version: version.to_string(),
            namespace: "ferrum".to_string(),
            connected_at,
            last_update_at: connected_at,
        }
    }

    #[test]
    fn mesh_registry_insert_replaces_same_node() {
        let registry = MeshNodeRegistry::new();
        let first_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let second_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "old-version", first_connected_at));
        registry.insert(registry_info("node-a", "new-version", second_connected_at));

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "new-version");
        assert_eq!(snapshot[0].connected_at, second_connected_at);
    }

    #[test]
    fn mesh_registry_stale_drop_does_not_remove_newer_entry() {
        let registry = MeshNodeRegistry::new();
        let old_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();
        let new_connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 2).unwrap();

        registry.insert(registry_info("node-a", "old-version", old_connected_at));
        registry.insert(registry_info("node-a", "new-version", new_connected_at));
        registry.remove_if_stale("node-a", old_connected_at);

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].version, "new-version");
        assert_eq!(snapshot[0].connected_at, new_connected_at);
    }

    #[test]
    fn mesh_registry_removes_matching_entry() {
        let registry = MeshNodeRegistry::new();
        let connected_at = Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 1).unwrap();

        registry.insert(registry_info("node-a", "mesh-version", connected_at));
        assert_eq!(registry.len(), 1);

        registry.remove_if_stale("node-a", connected_at);
        assert!(registry.is_empty());
    }
}
