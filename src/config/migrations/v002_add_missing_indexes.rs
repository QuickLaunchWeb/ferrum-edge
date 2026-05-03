use sqlx::AnyPool;
use tracing::info;

use super::Migration;

/// V2: Add missing indexes for pre-migration databases.
///
/// Fresh databases already have these indexes from V001 (sql_dialect.rs), but
/// databases that existed before the migration system was introduced get V001
/// marked as applied via bootstrap without running its SQL. This migration
/// ensures the indexes are present on all databases.
///
/// All statements use `CREATE INDEX IF NOT EXISTS` so they are safe to run on
/// both fresh databases (idempotent no-op) and pre-migration databases (creates
/// the missing indexes). MySQL does not reliably support `IF NOT EXISTS` on
/// `CREATE INDEX`, so we strip it and ignore duplicate-key errors (error 1061).
pub struct V002AddMissingIndexes;

impl Migration for V002AddMissingIndexes {
    fn version(&self) -> i64 {
        2
    }

    fn name(&self) -> &str {
        "add_missing_indexes"
    }

    fn checksum(&self) -> &str {
        "v002_add_missing_indexes"
    }
}

impl V002AddMissingIndexes {
    pub async fn up(&self, pool: &AnyPool, db_type: &str) -> Result<(), anyhow::Error> {
        let indexes = [
            // Junction table: proxy_plugins.plugin_config_id needs an index for
            // DELETE FROM proxy_plugins WHERE plugin_config_id = ? (full scan otherwise).
            "CREATE INDEX IF NOT EXISTS idx_proxy_plugins_plugin_config_id ON proxy_plugins (plugin_config_id)",
            // Compound (namespace, updated_at) indexes for incremental polling:
            // SELECT * FROM <table> WHERE namespace = ? AND updated_at > ?
            "CREATE INDEX IF NOT EXISTS idx_proxies_ns_updated ON proxies (namespace, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_consumers_ns_updated ON consumers (namespace, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_plugin_configs_ns_updated ON plugin_configs (namespace, updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_upstreams_ns_updated ON upstreams (namespace, updated_at)",
        ];

        let is_mysql = db_type == "mysql";

        for idx_sql in indexes {
            if is_mysql {
                // MySQL does not reliably support CREATE INDEX IF NOT EXISTS.
                // Strip the clause and ignore duplicate-key errors (1061).
                let mysql_sql = idx_sql.replace("IF NOT EXISTS ", "");
                match sqlx::query(&mysql_sql).execute(pool).await {
                    Ok(_) => {}
                    Err(e) => {
                        let msg = e.to_string();
                        if !msg.contains("1061") {
                            return Err(e.into());
                        }
                    }
                }
            } else {
                sqlx::query(idx_sql).execute(pool).await?;
            }
        }

        info!(
            "V002: Created missing indexes on proxy_plugins, proxies, consumers, plugin_configs, upstreams"
        );
        Ok(())
    }
}
