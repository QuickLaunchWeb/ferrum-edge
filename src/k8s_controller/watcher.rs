use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures_util::TryStreamExt;
use kube::api::{ApiResource, DynamicObject};
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

pub struct CoreResourceSpec {
    pub group: &'static str,
    pub version: &'static str,
    pub kind: &'static str,
    pub plural: &'static str,
    pub namespaced: bool,
}

#[derive(Clone, Copy)]
pub struct WatcherSelection {
    pub watch_istio: bool,
    pub watch_gateway_api: bool,
    pub watch_core: bool,
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

pub const K8S_CORE_RESOURCES: &[CoreResourceSpec] = &[
    CoreResourceSpec {
        group: "",
        version: "v1",
        kind: "Pod",
        plural: "pods",
        namespaced: true,
    },
    CoreResourceSpec {
        group: "",
        version: "v1",
        kind: "Service",
        plural: "services",
        namespaced: true,
    },
    CoreResourceSpec {
        group: "discovery.k8s.io",
        version: "v1",
        kind: "EndpointSlice",
        plural: "endpointslices",
        namespaced: true,
    },
    // Node labels provide topology.kubernetes.io/{region,zone} for workload
    // locality. Cluster-scoped watch only; namespace watch lists do not apply.
    CoreResourceSpec {
        group: "",
        version: "v1",
        kind: "Node",
        plural: "nodes",
        namespaced: false,
    },
];

fn watch_scopes(namespaces: &[String]) -> Vec<Option<String>> {
    if namespaces.is_empty() {
        return vec![None];
    }
    namespaces.iter().cloned().map(Some).collect()
}

fn watch_scope_label(scope: Option<&str>) -> String {
    match scope {
        Some(namespace) => format!("namespace:{namespace}"),
        None => "all".to_string(),
    }
}

fn build_apis_for_resource(
    client: &Client,
    ar: &ApiResource,
    namespaces: &[String],
    namespaced: bool,
) -> Vec<(Api<DynamicObject>, ApiResource, String)> {
    let scopes = if namespaced {
        watch_scopes(namespaces)
    } else {
        vec![None]
    };
    scopes
        .into_iter()
        .map(|scope| {
            let api = match scope.as_deref() {
                Some(namespace) => Api::namespaced_with(client.clone(), namespace, ar),
                None => Api::all_with(client.clone(), ar),
            };
            let scope_label = watch_scope_label(scope.as_deref());
            (api, ar.clone(), scope_label)
        })
        .collect()
}

fn find_crd_resource(api_group: &discovery::ApiGroup, crd: &CrdSpec) -> Option<ApiResource> {
    api_group
        .versioned_resources(crd.version)
        .into_iter()
        .map(|(ar, _caps)| ar)
        .find(|ar| ar.kind == crd.kind && ar.plural == crd.plural)
}

pub async fn start_crd_watchers(
    client: Client,
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    watch_istio: bool,
    watch_gateway_api: bool,
    watch_core: bool,
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

    // Deduplicate discovery by group, but gate watcher registration by the
    // exact served kind/version below. A cluster can expose a group without
    // serving every optional CRD version Ferrum knows about.
    let mut checked_groups = HashSet::new();
    let mut installed_groups: HashMap<&'static str, discovery::ApiGroup> = HashMap::new();

    for crd in &crd_specs {
        if !checked_groups.insert(crd.group) {
            continue;
        }
        match discovery::oneshot::group(&client, crd.group).await {
            Ok(api_group) => {
                installed_groups.insert(crd.group, api_group);
                info!(group = crd.group, "CRD group detected");
            }
            Err(e) => {
                warn!(
                    group = crd.group,
                    error = %e,
                    "CRD group not installed, its resources will not be watched. \
                     Install the CRDs and restart the controller to enable."
                );
            }
        }
    }

    for crd in crd_specs {
        let Some(api_group) = installed_groups.get(crd.group) else {
            continue;
        };
        let api_version = format!("{}/{}", crd.group, crd.version);
        let kind = crd.kind.to_string();

        let Some(ar) = find_crd_resource(api_group, crd) else {
            debug!(
                group = crd.group,
                version = crd.version,
                kind = crd.kind,
                "CRD kind/version not served, skipping watcher registration"
            );
            continue;
        };

        for (api, ar, scope) in build_apis_for_resource(&client, &ar, &namespaces, true) {
            if store_set
                .lock()
                .await
                .has_store_for_scope(&api_version, &kind, &scope)
            {
                debug!(
                    kind = %kind,
                    api_version = %api_version,
                    scope = %scope,
                    "CRD watcher already running, skipping duplicate start"
                );
                continue;
            }

            let writer = reflector::store::Writer::new(ar.clone());
            let store = writer.as_reader();
            let crd_store = Arc::new(CrdResourceStore::new_scoped(
                api_version.clone(),
                kind.clone(),
                scope.clone(),
                store,
            ));

            let change_notifier = {
                let mut set = store_set.lock().await;
                if !set.add_store(crd_store) {
                    debug!(
                        kind = %kind,
                        api_version = %api_version,
                        scope = %scope,
                        "CRD watcher already running, skipping duplicate start"
                    );
                    continue;
                }
                set.change_notifier()
            };

            let mut watcher_shutdown = shutdown.clone();
            let cleanup_scope = scope.clone();
            let task_kind = kind.clone();
            let watcher_config = watcher::Config::default();

            let handle = tokio::spawn(async move {
                let stream = reflector::reflector(writer, watcher(api, watcher_config));

                tokio::pin!(stream);

                loop {
                    tokio::select! {
                        biased;
                        _ = watcher_shutdown.changed() => {
                            if *watcher_shutdown.borrow() {
                                debug!(kind = %task_kind, scope = %cleanup_scope, "Watcher shutting down");
                                return;
                            }
                        }
                        item = stream.try_next() => {
                            match item {
                                Ok(Some(_event)) => {
                                    change_notifier.notify_change();
                                }
                                Ok(None) => {
                                    info!(
                                        kind = %task_kind,
                                        scope = %cleanup_scope,
                                        "Watch stream ended; retaining last reflector snapshot"
                                    );
                                    return;
                                }
                                Err(e) => {
                                    error!(
                                        kind = %task_kind,
                                        scope = %cleanup_scope,
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
            info!(
                kind = crd.kind,
                group = crd.group,
                scope = %scope,
                "Started CRD watcher"
            );
        }
    }

    if watch_core {
        for resource in K8S_CORE_RESOURCES {
            let api_version = if resource.group.is_empty() {
                resource.version.to_string()
            } else {
                format!("{}/{}", resource.group, resource.version)
            };
            let ar = ApiResource {
                group: resource.group.to_string(),
                version: resource.version.to_string(),
                api_version: api_version.clone(),
                kind: resource.kind.to_string(),
                plural: resource.plural.to_string(),
            };
            let kind = resource.kind.to_string();

            for (api, ar, scope) in
                build_apis_for_resource(&client, &ar, &namespaces, resource.namespaced)
            {
                if store_set
                    .lock()
                    .await
                    .has_store_for_scope(&api_version, &kind, &scope)
                {
                    debug!(
                        kind = %kind,
                        api_version = %api_version,
                        scope = %scope,
                        "K8s core watcher already running, skipping duplicate start"
                    );
                    continue;
                }

                let writer = reflector::store::Writer::new(ar.clone());
                let store = writer.as_reader();
                let crd_store = Arc::new(CrdResourceStore::new_scoped(
                    api_version.clone(),
                    kind.clone(),
                    scope.clone(),
                    store,
                ));

                let change_notifier = {
                    let mut set = store_set.lock().await;
                    if !set.add_store(crd_store) {
                        debug!(
                            kind = %kind,
                            api_version = %api_version,
                            scope = %scope,
                            "K8s core watcher already running, skipping duplicate start"
                        );
                        continue;
                    }
                    set.change_notifier()
                };

                let mut watcher_shutdown = shutdown.clone();
                let cleanup_scope = scope.clone();
                let task_kind = kind.clone();
                let watcher_config = watcher::Config::default();

                let handle = tokio::spawn(async move {
                    let stream = reflector::reflector(writer, watcher(api, watcher_config));

                    tokio::pin!(stream);

                    loop {
                        tokio::select! {
                            biased;
                            _ = watcher_shutdown.changed() => {
                                if *watcher_shutdown.borrow() {
                                    debug!(kind = %task_kind, scope = %cleanup_scope, "Watcher shutting down");
                                    return;
                                }
                            }
                            item = stream.try_next() => {
                                match item {
                                    Ok(Some(_event)) => {
                                        change_notifier.notify_change();
                                    }
                                    Ok(None) => {
                                        info!(
                                            kind = %task_kind,
                                            scope = %cleanup_scope,
                                            "Watch stream ended; retaining last reflector snapshot"
                                        );
                                        return;
                                    }
                                    Err(e) => {
                                        error!(
                                            kind = %task_kind,
                                            scope = %cleanup_scope,
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
                info!(
                    kind = resource.kind,
                    group = resource.group,
                    scope = %scope,
                    "Started K8s core watcher"
                );
            }
        }
    }

    handles
}

pub fn spawn_crd_reprobe_task(
    client: Client,
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    selection: WatcherSelection,
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
                        selection.watch_istio,
                        selection.watch_gateway_api,
                        selection.watch_core,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_scopes_uses_all_namespaces_when_unset() {
        assert_eq!(watch_scopes(&[]), vec![None]);
    }

    #[test]
    fn watch_scopes_preserves_each_configured_namespace() {
        assert_eq!(
            watch_scopes(&["default".to_string(), "prod".to_string()]),
            vec![Some("default".to_string()), Some("prod".to_string())]
        );
        assert_eq!(
            watch_scope_label(Some("prod")),
            "namespace:prod".to_string()
        );
    }

    #[test]
    fn k8s_core_resources_cover_pod_service_endpointslice_and_node() {
        let kinds: HashSet<&str> = K8S_CORE_RESOURCES
            .iter()
            .map(|resource| resource.kind)
            .collect();
        assert!(kinds.contains("Pod"));
        assert!(kinds.contains("Service"));
        assert!(kinds.contains("EndpointSlice"));
        assert!(kinds.contains("Node"));
        assert!(
            K8S_CORE_RESOURCES
                .iter()
                .find(|resource| resource.kind == "Node")
                .is_some_and(|resource| !resource.namespaced),
            "Node must be cluster-scoped so namespace watch lists do not create invalid Node APIs"
        );
    }
}
