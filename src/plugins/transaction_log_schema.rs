//! `transaction_log_schema` — config-only plugin that registers named
//! [`SummarySchema`] definitions for other logging plugins to reference
//! via `schema_ref:`.
//!
//! The plugin has no lifecycle hooks; it exists solely to carry compiled
//! schemas into the named-schemas registry. Loaders sort
//! `transaction_log_schema` plugins ahead of all others so the registry is
//! populated before any plugin tries to resolve a `schema_ref`.
//!
//! Restricted to `PluginScope::Global` — schemas are process-global.
//!
//! ## Config
//!
//! ```yaml
//! plugin_name: transaction_log_schema
//! scope: global
//! config:
//!   schemas:
//!     splunk_cim:
//!       summary_type: both
//!       rename: { proxy_id: route_id }
//!     datadog:
//!       summary_type: http
//!       static_fields: { source: "ferrum-edge" }
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::Plugin;
use crate::plugins::utils::log_schema::{SummarySchema, registry};

#[derive(Debug)]
pub struct TransactionLogSchema {
    /// Per-plugin-instance handle to every schema it registered into the
    /// process-global named-schemas registry. Held so the plugin owns at
    /// least one strong reference and for future loader integrations
    /// (e.g., an explicit post-construction publish step).
    #[allow(dead_code)]
    schemas: HashMap<String, Arc<SummarySchema>>,
}

impl TransactionLogSchema {
    pub fn new(config: &Value) -> Result<Self, String> {
        let schemas_value = config.get("schemas").ok_or_else(|| {
            "transaction_log_schema: 'schemas' is required (an object mapping name -> schema definition)".to_string()
        })?;
        let obj = schemas_value
            .as_object()
            .ok_or_else(|| "transaction_log_schema: 'schemas' must be an object".to_string())?;
        if obj.is_empty() {
            return Err(
                "transaction_log_schema: 'schemas' must contain at least one named schema"
                    .to_string(),
            );
        }

        let mut schemas: HashMap<String, Arc<SummarySchema>> = HashMap::with_capacity(obj.len());
        for (name, schema_value) in obj {
            if name.is_empty() {
                return Err("transaction_log_schema: schema names must be non-empty".to_string());
            }
            // Compile (validates everything). Plugin name uses the schema
            // entry name so error messages point at the offending entry.
            let plugin_label = format!("transaction_log_schema[{name}]");
            let compiled = SummarySchema::compile(schema_value, &plugin_label)?;

            // Stage the local map FIRST so a defensive duplicate check can
            // short-circuit before the process-global registry is mutated.
            // `serde_json::Map` deduplicates keys before this point so the
            // branch is unreachable in practice, but ordering it this way
            // keeps the registry consistent with the plugin instance even
            // if the precondition ever changes.
            if schemas.insert(name.clone(), compiled.clone()).is_some() {
                return Err(format!(
                    "transaction_log_schema: duplicate schema name '{name}' within the same plugin config"
                ));
            }

            // Register into the live staging area (no-op during validation;
            // populates during a loader reload bracket).
            registry::register_named(name, compiled)?;
        }

        Ok(Self { schemas })
    }

    /// All schemas declared by this plugin instance. Used by tests; future
    /// loader code can call this to publish schemas explicitly when the
    /// validation-mode `register_named` no-op is undesirable.
    #[allow(dead_code)]
    pub fn schemas(&self) -> &HashMap<String, Arc<SummarySchema>> {
        &self.schemas
    }
}

#[async_trait]
impl Plugin for TransactionLogSchema {
    fn name(&self) -> &str {
        "transaction_log_schema"
    }

    fn priority(&self) -> u16 {
        super::priority::TRANSACTION_LOG_SCHEMA
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::utils::log_schema::registry;
    use serde_json::json;

    // Tests that touch the registry hold the reload-bracket serializer
    // for their entire scope (reentrant with the internal begin/commit
    // calls inside the plugin construction).
    fn lock() -> registry::ReloadBracketTestGuard {
        registry::lock_for_tests()
    }

    #[test]
    fn missing_schemas_rejected() {
        let _g = lock();
        registry::reset_for_tests();
        let e = TransactionLogSchema::new(&json!({})).unwrap_err();
        assert!(e.contains("'schemas' is required"), "got: {e}");
    }

    #[test]
    fn empty_schemas_rejected() {
        let _g = lock();
        registry::reset_for_tests();
        let e = TransactionLogSchema::new(&json!({ "schemas": {} })).unwrap_err();
        assert!(e.contains("at least one"), "got: {e}");
    }

    #[test]
    fn schemas_not_object_rejected() {
        let _g = lock();
        registry::reset_for_tests();
        let e = TransactionLogSchema::new(&json!({ "schemas": [] })).unwrap_err();
        assert!(e.contains("must be an object"), "got: {e}");
    }

    #[test]
    fn empty_name_rejected() {
        let _g = lock();
        registry::reset_for_tests();
        let e = TransactionLogSchema::new(&json!({
            "schemas": { "": { "summary_type": "http" } }
        }))
        .unwrap_err();
        assert!(e.contains("non-empty"), "got: {e}");
    }

    #[test]
    fn bad_inner_schema_propagates_error() {
        let _g = lock();
        registry::reset_for_tests();
        let e = TransactionLogSchema::new(&json!({
            "schemas": {
                "good": { "summary_type": "http" },
                "bad":  { "omit": ["not_a_field"] }
            }
        }))
        .unwrap_err();
        // Compile errors are prefixed with the schema label.
        assert!(e.contains("[bad]"), "got: {e}");
        assert!(e.contains("unknown field 'not_a_field'"), "got: {e}");
    }

    #[test]
    fn validation_call_does_not_pollute_registry() {
        let _g = lock();
        registry::reset_for_tests();
        // No begin_reload bracket — this simulates admin-API validation.
        let plugin = TransactionLogSchema::new(&json!({
            "schemas": {
                "splunk_cim": { "summary_type": "both", "rename": { "proxy_id": "route_id" } }
            }
        }))
        .expect("plugin constructed");
        assert_eq!(plugin.schemas().len(), 1);
        // Registry remains empty.
        assert!(registry::lookup_named("splunk_cim").is_none());
    }

    #[test]
    fn reload_bracket_publishes_to_registry() {
        let _g = lock();
        registry::reset_for_tests();
        registry::begin_reload();
        let _plugin = TransactionLogSchema::new(&json!({
            "schemas": {
                "splunk_cim": { "summary_type": "both", "rename": { "proxy_id": "route_id" } },
                "datadog": { "summary_type": "http" }
            }
        }))
        .expect("plugin constructed");
        registry::commit_reload();
        assert!(registry::lookup_named("splunk_cim").is_some());
        assert!(registry::lookup_named("datadog").is_some());
    }

    #[test]
    fn duplicate_across_plugins_in_reload_rejected() {
        let _g = lock();
        registry::reset_for_tests();
        registry::begin_reload();
        let _p1 = TransactionLogSchema::new(&json!({
            "schemas": { "splunk_cim": { "summary_type": "both" } }
        }))
        .unwrap();
        let r = TransactionLogSchema::new(&json!({
            "schemas": { "splunk_cim": { "summary_type": "http" } }
        }));
        assert!(r.is_err());
    }
}
