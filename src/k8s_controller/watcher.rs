use std::sync::Arc;
use std::time::Duration;

use futures_util::TryStreamExt;
use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use kube::discovery;
use kube::runtime::reflector;
use kube::runtime::watcher;
use kube::{Api, Client};
use tracing::{debug, error, info, warn};

use super::resource_store::{CrdResourceStore, ResourceStoreSet};

pub struct CrdSpec {
    pub group: &'static str,
    pub version: &'static str,
    pub kind: &'static str,
    pub plural: &'static str,
}

pub const ISTIO_CRDS: &[CrdSpec] = &[
    CrdSpec {
        group: "security.istio.io",
        version: "v1",
        kind: "AuthorizationPolicy",
        plural: "authorizationpolicies",
    },
    CrdSpec {
        group: "security.istio.io",
        version: "v1",
        kind: "PeerAuthentication",
        plural: "peerauthentications",
    },
    CrdSpec {
        group: "security.istio.io",
        version: "v1",
        kind: "RequestAuthentication",
        plural: "requestauthentications",
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "VirtualService",
        plural: "virtualservices",
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "DestinationRule",
        plural: "destinationrules",
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "ServiceEntry",
        plural: "serviceentries",
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "WorkloadEntry",
        plural: "workloadentries",
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "Sidecar",
        plural: "sidecars",
    },
    CrdSpec {
        group: "telemetry.istio.io",
        version: "v1",
        kind: "Telemetry",
        plural: "telemetries",
    },
];

pub const GATEWAY_API_CRDS: &[CrdSpec] = &[
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "Gateway",
        plural: "gateways",
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "HTTPRoute",
        plural: "httproutes",
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "GRPCRoute",
        plural: "grpcroutes",
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1alpha2",
        kind: "TLSRoute",
        plural: "tlsroutes",
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1alpha2",
        kind: "TCPRoute",
        plural: "tcproutes",
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1beta1",
        kind: "ReferenceGrant",
        plural: "referencegrants",
    },
];

async fn is_crd_group_installed(client: &Client, group: &str) -> bool {
    match discovery::oneshot::group(client, group).await {
        Ok(_) => true,
        Err(e) => {
            debug!(
                group,
                error = %e,
                "CRD group not installed, skipping"
            );
            false
        }
    }
}

fn build_api_for_crd(
    client: &Client,
    crd: &CrdSpec,
    namespaces: &[String],
) -> (Api<DynamicObject>, ApiResource) {
    let gvk = GroupVersionKind::gvk(crd.group, crd.version, crd.kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, crd.plural);

    let api = if namespaces.is_empty() {
        Api::all_with(client.clone(), &ar)
    } else if namespaces.len() == 1 {
        Api::namespaced_with(client.clone(), &namespaces[0], &ar)
    } else {
        // kube-rs doesn't support multi-namespace in a single Api;
        // use all-namespace watch and filter in the reconciler.
        Api::all_with(client.clone(), &ar)
    };

    (api, ar)
}

pub async fn start_crd_watchers(
    client: Client,
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    watch_istio: bool,
    watch_gateway_api: bool,
    namespaces: Vec<String>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();

    let mut crd_specs: Vec<&CrdSpec> = Vec::new();
    if watch_istio {
        crd_specs.extend(ISTIO_CRDS);
    }
    if watch_gateway_api {
        crd_specs.extend(GATEWAY_API_CRDS);
    }

    // Deduplicate by group to check installation once per API group.
    let mut checked_groups = std::collections::HashSet::new();
    let mut installed_groups = std::collections::HashSet::new();

    for crd in &crd_specs {
        if !checked_groups.insert(crd.group) {
            continue;
        }
        if is_crd_group_installed(&client, crd.group).await {
            installed_groups.insert(crd.group);
            info!(group = crd.group, "CRD group detected");
        } else {
            warn!(
                group = crd.group,
                "CRD group not installed, its resources will not be watched. \
                 Install the CRDs and restart the controller to enable."
            );
        }
    }

    for crd in crd_specs {
        if !installed_groups.contains(crd.group) {
            continue;
        }

        let (api, ar) = build_api_for_crd(&client, crd, &namespaces);
        let api_version = format!("{}/{}", crd.group, crd.version);
        let kind = crd.kind.to_string();

        let writer = reflector::store::Writer::new(ar.clone());
        let store = writer.as_reader();
        let crd_store = Arc::new(CrdResourceStore::new(
            api_version.clone(),
            kind.clone(),
            store,
        ));

        {
            let mut set = store_set.lock().await;
            set.add_store(crd_store);
        }

        let store_set_ref = store_set.clone();
        let mut watcher_shutdown = shutdown.clone();
        let watcher_config = watcher::Config::default();

        let handle = tokio::spawn(async move {
            let stream = reflector::reflector(writer, watcher(api, watcher_config));

            tokio::pin!(stream);

            loop {
                tokio::select! {
                    biased;
                    _ = watcher_shutdown.changed() => {
                        if *watcher_shutdown.borrow() {
                            debug!(kind, "Watcher shutting down");
                            return;
                        }
                    }
                    item = stream.try_next() => {
                        match item {
                            Ok(Some(_event)) => {
                                let set = store_set_ref.lock().await;
                                set.notify_change();
                            }
                            Ok(None) => {
                                info!(kind, "Watch stream ended");
                                return;
                            }
                            Err(e) => {
                                error!(
                                    kind,
                                    error = %e,
                                    "Watch error, kube-rs will retry with backoff"
                                );
                            }
                        }
                    }
                }
            }
        });

        handles.push(handle);
        info!(kind = crd.kind, group = crd.group, "Started CRD watcher");
    }

    handles
}

pub fn spawn_crd_reprobe_task(
    client: Client,
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    watch_istio: bool,
    watch_gateway_api: bool,
    namespaces: Vec<String>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    let mut reprobe_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(interval);
        timer.tick().await; // skip first

        loop {
            tokio::select! {
                biased;
                _ = reprobe_shutdown.changed() => {
                    if *reprobe_shutdown.borrow() {
                        return;
                    }
                }
                _ = timer.tick() => {
                    debug!("Re-probing CRD group availability");
                    let new_handles = start_crd_watchers(
                        client.clone(),
                        store_set.clone(),
                        watch_istio,
                        watch_gateway_api,
                        namespaces.clone(),
                        shutdown.clone(),
                    ).await;
                    // New handles run independently; we don't need to track
                    // them here since they self-manage via shutdown.
                    drop(new_handles);
                }
            }
        }
    })
}
