//! Operating mode entry points for the Ferrum Edge gateway.
//!
//! The gateway binary runs in exactly one mode, selected by `FERRUM_MODE`:
//!
//! | Mode       | Proxy | Admin API   | Config Source                    |
//! |------------|-------|-------------|----------------------------------|
//! | `database` | Yes   | Read/Write  | PostgreSQL/MySQL/SQLite polling   |
//! | `file`     | Yes   | Read-only   | YAML/JSON file, SIGHUP reload    |
//! | `cp`       | No    | Read/Write  | DB polling + gRPC broadcast to DPs |
//! | `dp`       | Yes   | Read-only   | gRPC stream from CP              |
//! | `migrate`  | No    | No          | Runs DB migrations then exits    |
//!
//! All modes share the same `ProxyState` and atomic config swap mechanism.
//! Config changes (from any source) are validated, then swapped atomically
//! via `ArcSwap` — in-flight requests see old or new config, never partial.

pub mod control_plane;
pub mod data_plane;
pub mod database;
pub mod file;
pub mod migrate;

use std::sync::Arc;
use tracing::{info, warn};

use crate::config::db_backend::DatabaseBackend;

/// Handle pending custom-plugin database migrations at startup for the
/// `database` and `cp` modes.
///
/// Behavior is controlled by `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS`:
///
/// - `false` (default): list any pending plugin migrations as a `warn!` log
///   line and leave them unapplied. The operator is expected to run
///   `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` before serving traffic
///   that depends on the new schema. This preserves the long-standing
///   contract that schema changes never run automatically at gateway boot.
///
/// - `true`: apply all pending plugin migrations now, before
///   `load_full_config()`. Useful for embedded deployments (e.g., SQLite
///   where the binary owns the database) that want a single binary upgrade
///   to also bring plugin schema up to date.
///
/// The warning ALWAYS fires when migrations are pending and auto-apply is
/// off, so operators always know what they need to run. When auto-apply is
/// on and the migration succeeds, an `info!` line records what was applied.
///
/// Errors propagate when auto-apply is on (a failed plugin migration is
/// fatal — the gateway should not come up with an inconsistent schema).
/// When auto-apply is off, the warning is informational and never fails
/// startup.
pub(crate) async fn handle_startup_plugin_migrations(
    db: &Arc<dyn DatabaseBackend>,
    auto_apply: bool,
    mode: &str,
) -> Result<(), anyhow::Error> {
    let plugin_migrations = crate::custom_plugins::collect_all_custom_plugin_migrations();
    handle_startup_plugin_migrations_with_list(db, auto_apply, mode, &plugin_migrations).await
}

/// Internal entry point that takes the plugin-migration list as a parameter
/// so unit tests can pass a synthetic plugin without depending on the
/// build-time `collect_all_custom_plugin_migrations()` registry.
async fn handle_startup_plugin_migrations_with_list(
    db: &Arc<dyn DatabaseBackend>,
    auto_apply: bool,
    mode: &str,
    plugin_migrations: &[(&str, Vec<crate::config::migrations::CustomPluginMigration>)],
) -> Result<(), anyhow::Error> {
    if plugin_migrations.is_empty() {
        return Ok(());
    }

    let pending = match db.pending_plugin_migrations(plugin_migrations).await {
        Ok(p) => p,
        Err(e) => {
            // Probe failure shouldn't block startup; the operator can still
            // run `FERRUM_MIGRATE_ACTION=up` to recover. Log loud enough.
            warn!(
                "Could not determine pending custom-plugin migrations ({}). \
                 Run FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up to verify \
                 schema if you have plugins with bundled migrations.",
                e
            );
            return Ok(());
        }
    };

    if pending.is_empty() {
        return Ok(());
    }

    let pending_summary: Vec<String> = pending
        .iter()
        .map(|m| format!("[{}] V{}: {}", m.plugin_name, m.version, m.name))
        .collect();

    if auto_apply {
        info!(
            "FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true and {} pending custom-plugin migration(s) \
             detected ({}). Applying now (mode={}).",
            pending_summary.len(),
            pending_summary.join(", "),
            mode
        );
        let applied = db.apply_plugin_migrations(plugin_migrations).await?;
        info!(
            "Applied {} custom-plugin migration(s) at startup: {}",
            applied.len(),
            applied
                .iter()
                .map(|m| format!(
                    "[{}] V{}: {} ({}ms)",
                    m.plugin_name, m.version, m.name, m.execution_time_ms
                ))
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else {
        warn!(
            "{} pending custom-plugin migration(s) detected but \
             FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS is not enabled — schema NOT updated. \
             Pending: {}. Run FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up before serving \
             traffic that depends on the new schema, or set \
             FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true to auto-apply at startup.",
            pending_summary.len(),
            pending_summary.join(", ")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Inline tests for `handle_startup_plugin_migrations_with_list`.
    //!
    //! Per CLAUDE.md "Test Placement", tests for `pub(crate)` items live
    //! inline in source — they cannot be reached from the external
    //! `tests/` crate without changing visibility.
    use super::*;
    use crate::config::db_backend::DatabaseBackend;
    use crate::config::db_loader::{DatabaseStore, DbPoolConfig};
    use crate::config::migrations::CustomPluginMigration;

    async fn fresh_store() -> (Arc<dyn DatabaseBackend>, tempfile::TempDir) {
        // File-backed (not `::memory:`) so the multi-connection pool sees
        // a consistent view. `_ferrum_migrations` is created during
        // `connect_with_tls_config` and must be visible to subsequent
        // connections checked out from the pool.
        let temp_dir = tempfile::TempDir::new().expect("temp dir");
        let db_path = temp_dir.path().join("modes_handle_startup_test.db");
        let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
        let store = DatabaseStore::connect_with_tls_config(
            "sqlite",
            &db_url,
            false,
            None,
            None,
            None,
            false,
            DbPoolConfig::default(),
        )
        .await
        .expect("test store should connect");
        (Arc::new(store), temp_dir)
    }

    fn synthetic_pending_migration() -> Vec<(&'static str, Vec<CustomPluginMigration>)> {
        vec![(
            "modes_handle_startup_test",
            vec![CustomPluginMigration {
                version: 1,
                name: "create_modes_test_table",
                checksum: "v1_modes_handle_chk",
                sql: "CREATE TABLE IF NOT EXISTS modes_handle_test_data (id TEXT PRIMARY KEY)",
                sql_postgres: None,
                sql_mysql: None,
            }],
        )]
    }

    #[tokio::test]
    async fn auto_apply_true_runs_pending_migration() {
        // FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true: gateway must apply
        // pending plugin migrations at startup so plugin INSERT/SELECT
        // calls in `log()` don't fail with "no such table".
        let (db, _tmp) = fresh_store().await;
        let migrations = synthetic_pending_migration();

        // Sanity check: pending before invocation.
        let pending_before = db.pending_plugin_migrations(&migrations).await.unwrap();
        assert_eq!(pending_before.len(), 1);

        handle_startup_plugin_migrations_with_list(&db, true, "database", &migrations)
            .await
            .expect("auto-apply path should not error");

        // After auto-apply, pending must be empty AND the table must exist.
        let pending_after = db.pending_plugin_migrations(&migrations).await.unwrap();
        assert!(pending_after.is_empty(), "auto-apply must clear pending");

        // Reaching into the concrete store is awkward through `dyn`, so
        // query through a fresh helper: trying to apply again must be a
        // no-op, which proves V1 was committed.
        let second_apply = db.apply_plugin_migrations(&migrations).await.unwrap();
        assert!(
            second_apply.is_empty(),
            "second apply must be a no-op once auto-apply has committed V1"
        );
    }

    #[tokio::test]
    async fn auto_apply_false_warns_only_and_does_not_apply() {
        // FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=false (default): gateway
        // must NOT mutate the schema. Pending migrations stay pending,
        // and a warn! is emitted (not asserted here — log assertion is
        // brittle; the contract under test is that no schema change
        // occurs).
        let (db, _tmp) = fresh_store().await;
        let migrations = synthetic_pending_migration();

        let pending_before = db.pending_plugin_migrations(&migrations).await.unwrap();
        assert_eq!(pending_before.len(), 1);

        handle_startup_plugin_migrations_with_list(&db, false, "database", &migrations)
            .await
            .expect("warn-only path should not error");

        // Pending is still pending — the gateway did not apply.
        let pending_after = db.pending_plugin_migrations(&migrations).await.unwrap();
        assert_eq!(
            pending_after.len(),
            1,
            "warn-only path must NOT apply pending migrations"
        );
        assert_eq!(pending_after[0].plugin_name, "modes_handle_startup_test");
        assert_eq!(pending_after[0].version, 1);
    }

    #[tokio::test]
    async fn empty_plugin_list_is_noop_in_both_modes() {
        let (db, _tmp) = fresh_store().await;
        let empty: Vec<(&str, Vec<CustomPluginMigration>)> = vec![];

        handle_startup_plugin_migrations_with_list(&db, false, "database", &empty)
            .await
            .expect("warn-only with empty list is a no-op");
        handle_startup_plugin_migrations_with_list(&db, true, "cp", &empty)
            .await
            .expect("auto-apply with empty list is a no-op");
    }

    #[tokio::test]
    async fn auto_apply_idempotent_across_repeated_startups() {
        // Restart-loop scenario: with auto-apply enabled, the second
        // startup must be a no-op once the first has committed.
        let (db, _tmp) = fresh_store().await;
        let migrations = synthetic_pending_migration();

        handle_startup_plugin_migrations_with_list(&db, true, "database", &migrations)
            .await
            .unwrap();
        handle_startup_plugin_migrations_with_list(&db, true, "database", &migrations)
            .await
            .expect("second startup with auto-apply should be a no-op");

        let pending = db.pending_plugin_migrations(&migrations).await.unwrap();
        assert!(pending.is_empty());
    }
}
