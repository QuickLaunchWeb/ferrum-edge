use std::sync::Arc;

use kube::api::DynamicObject;
use kube::runtime::reflector;
use tokio::sync::watch;

use crate::config_sources::k8s::K8sObject;
use crate::k8s_controller::convert::dynamic_object_to_k8s_object;

pub struct CrdResourceStore {
    pub api_version: String,
    pub kind: String,
    store: reflector::Store<DynamicObject>,
}

impl CrdResourceStore {
    pub fn new(api_version: String, kind: String, store: reflector::Store<DynamicObject>) -> Self {
        Self {
            api_version,
            kind,
            store,
        }
    }

    pub fn snapshot(&self) -> Vec<K8sObject> {
        self.store
            .state()
            .iter()
            .map(|obj| dynamic_object_to_k8s_object(obj.as_ref(), &self.api_version, &self.kind))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.store.state().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct ResourceStoreSet {
    stores: Vec<Arc<CrdResourceStore>>,
    change_tx: watch::Sender<u64>,
    change_rx: watch::Receiver<u64>,
    revision: std::sync::atomic::AtomicU64,
}

impl Default for ResourceStoreSet {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceStoreSet {
    pub fn new() -> Self {
        let (change_tx, change_rx) = watch::channel(0);
        Self {
            stores: Vec::new(),
            change_tx,
            change_rx,
            revision: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn add_store(&mut self, store: Arc<CrdResourceStore>) {
        self.stores.push(store);
    }

    pub fn snapshot_all(&self) -> Vec<K8sObject> {
        let mut objects = Vec::new();
        for store in &self.stores {
            objects.extend(store.snapshot());
        }
        objects
    }

    pub fn notify_change(&self) {
        let rev = self
            .revision
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        let _ = self.change_tx.send(rev);
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.change_rx.clone()
    }

    pub fn total_resources(&self) -> usize {
        self.stores.iter().map(|s| s.len()).sum()
    }
}
