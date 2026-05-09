use sqlx::AnyPool;

use super::Migration;

/// V2: Add DestinationRule runtime support fields.
///
/// Adds columns for subset routing, ejection cap, and per-connection request limits:
/// - `proxies.pool_max_requests_per_connection` (INTEGER) — max requests before recycling a backend connection
/// - `proxies.upstream_subset` (TEXT) — named subset of the upstream to route to
/// - `upstreams.subsets` (TEXT/JSON) — subset definitions with label selectors
pub struct V002DestinationRuleFields;

impl Migration for V002DestinationRuleFields {
    fn version(&self) -> i64 {
        2
    }

    fn name(&self) -> &str {
        "destination_rule_fields"
    }

    fn checksum(&self) -> &str {
        "v002_destination_rule_fields"
    }
}

impl V002DestinationRuleFields {
    pub async fn up(&self, pool: &AnyPool, db_type: &str) -> Result<(), anyhow::Error> {
        // SQLite does not support adding multiple columns in a single ALTER TABLE,
        // so we issue one statement per column. All three databases support this form.
        //
        // Fresh databases already have these columns from V001, so we must tolerate
        // "duplicate column" errors (the migration tracker marks V2 as applied
        // regardless — idempotent).

        let col_type_text = if db_type == "mysql" {
            "VARCHAR(255)"
        } else {
            "TEXT"
        };

        // --- proxies table ---
        add_column_if_missing(
            pool,
            "ALTER TABLE proxies ADD COLUMN pool_max_requests_per_connection INTEGER",
        )
        .await?;

        let sql2 = format!("ALTER TABLE proxies ADD COLUMN upstream_subset {col_type_text}");
        add_column_if_missing(pool, &sql2).await?;

        // --- upstreams table ---
        add_column_if_missing(pool, "ALTER TABLE upstreams ADD COLUMN subsets TEXT").await?;

        Ok(())
    }
}

/// Execute an ALTER TABLE ADD COLUMN statement, silently ignoring "duplicate column"
/// errors. This makes the migration idempotent when the column already exists
/// (e.g., fresh databases where V001 includes the column in CREATE TABLE).
async fn add_column_if_missing(pool: &AnyPool, sql: &str) -> Result<(), anyhow::Error> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            // SQLite: "duplicate column name: ..."
            // PostgreSQL: "column \"...\" of relation \"...\" already exists"
            // MySQL: "Duplicate column name '...'"
            if msg.contains("duplicate column") || msg.contains("already exists") {
                Ok(())
            } else {
                Err(e.into())
            }
        }
    }
}
