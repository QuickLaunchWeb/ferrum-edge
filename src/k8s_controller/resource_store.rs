use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
    notifier: ResourceChangeNotifier,
}

#[derive(Clone)]
pub struct ResourceChangeNotifier {
    change_tx: Arc<watch::Sender<u64>>,
    revision: Arc<AtomicU64>,
}

impl ResourceChangeNotifier {
    pub fn notify_change(&self) {
        let rev = self.revision.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = self.change_tx.send(rev);
    }
}

impl Default for ResourceStoreSet {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceStoreSet {
    pub fn new() -> Self {
        let (change_tx, _change_rx) = watch::channel(0);
        Self {
            stores: Vec::new(),
            notifier: ResourceChangeNotifier {
                change_tx: Arc::new(change_tx),
                revision: Arc::new(AtomicU64::new(0)),
            },
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
        self.notifier.notify_change();
    }

    pub fn change_notifier(&self) -> ResourceChangeNotifier {
        self.notifier.clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.notifier.change_tx.subscribe()
    }

    pub fn total_resources(&self) -> usize {
        self.stores.iter().map(|s| s.len()).sum()
    }
}
