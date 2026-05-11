//! Process-global registry of named [`SummarySchema`] definitions.
//!
//! Populated by the `transaction_log_schema` plugin at construction time;
//! consumed by other logging plugins that reference a schema by name via
//! `schema_ref:`.
//!
//! The inner map is wholly replaced on config reload via [`begin_reload`] +
//! [`commit_reload`] so renamed/removed schemas don't leak.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use super::SummarySchema;

#[derive(Default)]
struct RegistryState {
    /// Live map consulted by `lookup_named`.
    schemas: HashMap<String, Arc<SummarySchema>>,
    /// Staging area built by `register_named` during reload; promoted on
    /// `commit_reload`.
    staging: Option<HashMap<String, Arc<SummarySchema>>>,
}

fn registry() -> &'static RwLock<RegistryState> {
    static REGISTRY: OnceLock<RwLock<RegistryState>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(RegistryState::default()))
}

/// Begin building a fresh named-schema map. Called once per config-load
/// pass before any `transaction_log_schema` plugin's `new()` runs.
///
/// If a previous reload was started but never committed, its staging is
/// discarded.
pub fn begin_reload() {
    let mut state = registry().write().expect("log_schema registry poisoned");
    state.staging = Some(HashMap::new());
}

/// Register a named schema into the in-progress reload staging area.
///
/// When called between [`begin_reload`] and [`commit_reload`] (the normal
/// loader path), writes to the staging map and rejects duplicates.
///
/// When called outside a reload pass (e.g., from admin-API single-plugin
/// validation via `validate_plugin_config`), this is a no-op. Validation
/// just needs `SummarySchema::compile` to succeed; the registry stays
/// untouched and will be re-populated by the next config-reload pass.
pub fn register_named(name: &str, schema: Arc<SummarySchema>) -> Result<(), String> {
    let mut state = registry().write().expect("log_schema registry poisoned");
    let Some(staging) = state.staging.as_mut() else {
        return Ok(()); // validation-mode no-op
    };
    if staging.contains_key(name) {
        return Err(format!(
            "transaction_log_schema: named schema '{name}' registered more than once"
        ));
    }
    staging.insert(name.to_string(), schema);
    Ok(())
}

/// Promote the staging area to be the live map. Called after all
/// `transaction_log_schema` plugins for this reload pass have constructed.
pub fn commit_reload() {
    let mut state = registry().write().expect("log_schema registry poisoned");
    if let Some(staging) = state.staging.take() {
        state.schemas = staging;
    }
}

/// Look up a named schema. Returns `None` if no schema with this name
/// is registered (either never registered, or removed by a reload).
pub fn lookup_named(name: &str) -> Option<Arc<SummarySchema>> {
    let state = registry().read().expect("log_schema registry poisoned");
    state.schemas.get(name).cloned()
}

/// Snapshot of the registered names (for diagnostics / admin endpoints).
#[allow(dead_code)]
pub fn registered_names() -> Vec<String> {
    let state = registry().read().expect("log_schema registry poisoned");
    let mut names: Vec<String> = state.schemas.keys().cloned().collect();
    names.sort();
    names
}

/// Test-only: forcefully clear both live and staging state.
///
/// Production callers must use `begin_reload` / `register_named` /
/// `commit_reload`. Exposed (not `#[cfg(test)]`) because integration
/// tests in `tests/integration/` are a separate crate and cannot see
/// items gated on the library's `cfg(test)`.
#[doc(hidden)]
#[allow(dead_code)]
pub fn reset_for_tests() {
    let mut state = registry().write().expect("log_schema registry poisoned");
    state.schemas.clear();
    state.staging = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::utils::log_schema::{
        FieldSpec, MetadataPolicy, SummarySchema, SummaryType, TimestampFormat,
    };
    use std::sync::Mutex;

    // The registry is process-global; serialize tests that touch it so they
    // don't race each other under `cargo test --test`.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static M: OnceLock<Mutex<()>> = OnceLock::new();
        M.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn empty_schema() -> Arc<SummarySchema> {
        Arc::new(SummarySchema {
            summary_type: SummaryType::Both,
            fields: Vec::<FieldSpec>::new(),
            metadata: MetadataPolicy::Nested,
            timestamp_format: TimestampFormat::Rfc3339,
        })
    }

    #[test]
    fn register_without_begin_is_validation_noop() {
        let _g = lock();
        reset_for_tests();
        // No begin_reload — should succeed silently without registering.
        assert!(register_named("x", empty_schema()).is_ok());
        assert!(lookup_named("x").is_none());
    }

    #[test]
    fn commit_publishes_staging() {
        let _g = lock();
        reset_for_tests();
        begin_reload();
        register_named("a", empty_schema()).unwrap();
        // Not yet live.
        assert!(lookup_named("a").is_none());
        commit_reload();
        assert!(lookup_named("a").is_some());
    }

    #[test]
    fn duplicate_within_reload_rejected() {
        let _g = lock();
        reset_for_tests();
        begin_reload();
        register_named("a", empty_schema()).unwrap();
        let r = register_named("a", empty_schema());
        assert!(r.is_err());
    }

    #[test]
    fn reload_replaces_previous_set() {
        let _g = lock();
        reset_for_tests();
        // First reload: register "a".
        begin_reload();
        register_named("a", empty_schema()).unwrap();
        commit_reload();
        assert!(lookup_named("a").is_some());

        // Second reload: register only "b". "a" should vanish.
        begin_reload();
        register_named("b", empty_schema()).unwrap();
        commit_reload();
        assert!(lookup_named("a").is_none());
        assert!(lookup_named("b").is_some());
    }

    #[test]
    fn registered_names_sorted() {
        let _g = lock();
        reset_for_tests();
        begin_reload();
        register_named("zebra", empty_schema()).unwrap();
        register_named("alpha", empty_schema()).unwrap();
        register_named("mango", empty_schema()).unwrap();
        commit_reload();
        assert_eq!(registered_names(), vec!["alpha", "mango", "zebra"]);
    }
}
