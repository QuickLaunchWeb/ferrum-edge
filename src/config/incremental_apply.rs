//! Shared incremental config application helpers.
//!
//! CP mode, ConfigSync, and xDS stream-local snapshots all consume the same
//! database delta shape. Keep the retain/upsert behavior centralized so those
//! paths cannot drift as resource types evolve.

use std::collections::{HashMap, HashSet};

use crate::config::db_loader::IncrementalResult;
use crate::config::types::GatewayConfig;

/// Apply an incremental result to a config snapshot in-place.
///
/// Removes deleted resources by ID, upserts added/modified resources, and
/// updates `loaded_at` to the delta's poll timestamp.
pub(crate) fn apply_incremental_to_config_snapshot(
    config: &mut GatewayConfig,
    result: IncrementalResult,
) {
    let poll_timestamp = result.poll_timestamp;
    apply_incremental_resources(config, result);
    config.loaded_at = poll_timestamp;
}

fn apply_incremental_resources(config: &mut GatewayConfig, result: IncrementalResult) {
    let removed_proxies: HashSet<&str> = result
        .removed_proxy_ids
        .iter()
        .map(String::as_str)
        .collect();
    let removed_consumers: HashSet<&str> = result
        .removed_consumer_ids
        .iter()
        .map(String::as_str)
        .collect();
    let removed_plugins: HashSet<&str> = result
        .removed_plugin_config_ids
        .iter()
        .map(String::as_str)
        .collect();
    let removed_upstreams: HashSet<&str> = result
        .removed_upstream_ids
        .iter()
        .map(String::as_str)
        .collect();

    config
        .proxies
        .retain(|proxy| !removed_proxies.contains(proxy.id.as_str()));
    config
        .consumers
        .retain(|consumer| !removed_consumers.contains(consumer.id.as_str()));
    config
        .plugin_configs
        .retain(|plugin| !removed_plugins.contains(plugin.id.as_str()));
    config
        .upstreams
        .retain(|upstream| !removed_upstreams.contains(upstream.id.as_str()));

    upsert_by_id(
        &mut config.proxies,
        result.added_or_modified_proxies,
        |proxy| proxy.id.as_str(),
    );
    upsert_by_id(
        &mut config.consumers,
        result.added_or_modified_consumers,
        |consumer| consumer.id.as_str(),
    );
    upsert_by_id(
        &mut config.plugin_configs,
        result.added_or_modified_plugin_configs,
        |plugin| plugin.id.as_str(),
    );
    upsert_by_id(
        &mut config.upstreams,
        result.added_or_modified_upstreams,
        |upstream| upstream.id.as_str(),
    );
}

/// Upsert items into a vec by ID: replace existing entries, append new ones.
pub(crate) fn upsert_by_id<T, F>(existing: &mut Vec<T>, updates: Vec<T>, get_id: F)
where
    F: Fn(&T) -> &str,
{
    let mut index: HashMap<String, usize> = existing
        .iter()
        .enumerate()
        .map(|(i, item)| (get_id(item).to_string(), i))
        .collect();

    for item in updates {
        let id = get_id(&item).to_string();
        if let Some(&pos) = index.get(id.as_str()) {
            existing[pos] = item;
        } else {
            let pos = existing.len();
            existing.push(item);
            index.insert(id, pos);
        }
    }
}
