use sqlx::AnyPool;

use super::Migration;

/// V2: Add DestinationRule runtime support fields.
///
/// Adds columns for subset routing, ejection cap, and per-connection request limits:
/// - `proxies.pool_max_requests_per_connection` (INTEGER) — DestinationRule schema-compatibility field
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

fn is_duplicate_column_error(error: &sqlx::Error) -> bool {
    let Some(db_error) = error.as_database_error() else {
        return false;
    };

    if let Some(code) = db_error.code() {
        match code.as_ref() {
            // PostgreSQL duplicate_column
            "42701" |
            // MySQL / MariaDB duplicate column
            "42S21" => return true,
            _ => {}
        }
    }

    let msg = db_error.message().to_ascii_lowercase();
    // SQLite: "duplicate column name: ...". Some drivers expose no portable
    // code, so keep the fallback narrow to column-specific text instead of
    // treating every "already exists" error as idempotent.
    msg.contains("duplicate column")
        || msg.contains("duplicate column name")
        || (msg.contains("column") && msg.contains("already exists"))
}

/// Execute an ALTER TABLE ADD COLUMN statement, silently ignoring "duplicate column"
/// errors. This makes the migration idempotent when the column already exists
/// (e.g., fresh databases where V001 includes the column in CREATE TABLE).
async fn add_column_if_missing(pool: &AnyPool, sql: &str) -> Result<(), anyhow::Error> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => Ok(()),
        Err(e) => {
            if is_duplicate_column_error(&e) {
                Ok(())
            } else {
                Err(e.into())
            }
        }
    }
}
