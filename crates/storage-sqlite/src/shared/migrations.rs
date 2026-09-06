//! Installation-wide shared.sqlite3 migration domain. Independent of account
//! and app-cache ledgers; never copies their histories or application records.
use super::error::sqlite_error;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

struct Migration {
    version: i64,
    name: &'static str,
    apply: fn(&Transaction<'_>) -> StorageResult<()>,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "0001_shared_store",
    apply: version_1,
}];
const VERSION_1_SQL: &str = include_str!("v1.sql");
const LEGACY_SQL: &str = include_str!("legacy.sql");
const LEDGER: &str = "shared_schema_migrations";
const LEDGER_SQL: &str = "CREATE TABLE IF NOT EXISTS shared_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix_seconds INTEGER NOT NULL
);";
const TABLES: &[&str] = &[
    "directory_users",
    "directory_user_follows",
    "relay_telemetry_settings",
    "audit_log_settings",
    "telemetry_install",
];

pub(super) fn run_all(conn: &mut Connection) -> StorageResult<()> {
    run(conn, MIGRATIONS)
}

fn run(conn: &mut Connection, migrations: &[Migration]) -> StorageResult<()> {
    for (index, migration) in migrations.iter().enumerate() {
        if migration.version != index as i64 + 1 {
            return Err(invalid_history());
        }
    }
    // Already-current opens acquire no write lock. Pending opens recheck the
    // entire prefix after BEGIN IMMEDIATE, not just before waiting for a writer.
    let applied = applied_count(conn, migrations)?;
    for (index, migration) in migrations.iter().enumerate().skip(applied) {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let applied = applied_count(&tx, migrations)?;
        if applied > index {
            tx.commit().map_err(sqlite_error)?;
            continue;
        }
        if applied != index {
            return Err(invalid_history());
        }
        tx.execute_batch(LEDGER_SQL).map_err(sqlite_error)?;
        (migration.apply)(&tx)?;
        let inserted = tx
            .execute(
                "INSERT INTO shared_schema_migrations (version, name, applied_at_unix_seconds)
             VALUES (?1, ?2, CAST(strftime('%s', 'now') AS INTEGER))",
                params![migration.version, migration.name],
            )
            .map_err(sqlite_error)?;
        // A trigger using RAISE(IGNORE), or changing/deleting the inserted row,
        // must not let an unrecorded migration commit.
        if inserted != 1 || applied_count(&tx, migrations)? != index + 1 {
            return Err(invalid_history());
        }
        tx.commit().map_err(sqlite_error)?;
    }
    Ok(())
}

fn applied_count(conn: &Connection, migrations: &[Migration]) -> StorageResult<usize> {
    if !table_exists(conn, LEDGER)? {
        return Ok(0);
    }
    let reference = Connection::open_in_memory().map_err(sqlite_error)?;
    reference.execute_batch(LEDGER_SQL).map_err(sqlite_error)?;
    if !table_matches(conn, &reference, LEDGER)? {
        return Err(invalid_history());
    }
    let latest_supported = migrations.last().map_or(0, |m| m.version);
    // Inspect numeric versions first, so a future version refuses before any
    // body runs even if its name has an unfamiliar SQLite storage type.
    let found: Option<i64> = conn
        .query_row(
            "SELECT max(version) FROM shared_schema_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(..) => sqlite_error(error),
            _ => invalid_history(),
        })?;
    if let Some(found) = found
        && found > latest_supported
    {
        return Err(StorageError::UnsupportedSchemaVersion {
            found,
            latest_supported,
        });
    }
    let mut statement = conn
        .prepare("SELECT version, name FROM shared_schema_migrations ORDER BY version")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    let mut count = 0;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let version: i64 = row.get(0).map_err(|_| invalid_history())?;
        let name: String = row.get(1).map_err(|_| invalid_history())?;
        let Some(expected) = migrations.get(count) else {
            return Err(invalid_history());
        };
        if version != expected.version || name != expected.name {
            return Err(invalid_history());
        }
        count += 1;
    }
    Ok(count)
}

// Views and other objects with a reserved name must be validated, not treated
// as a missing table. The caller checks that their type/DDL is a real table.
fn table_exists(conn: &Connection, name: &str) -> StorageResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = ?1)",
        [name],
        |r| r.get(0),
    )
    .map_err(sqlite_error)
}

fn invalid_history() -> StorageError {
    StorageError::Backend("invalid shared store migration history".into())
}

fn invalid_shape() -> StorageError {
    StorageError::Backend("invalid shared store schema shape".into())
}

fn version_1(tx: &Transaction<'_>) -> StorageResult<()> {
    let reference = Connection::open_in_memory().map_err(sqlite_error)?;
    reference
        .execute_batch(VERSION_1_SQL)
        .map_err(sqlite_error)?;
    let legacy = Connection::open_in_memory().map_err(sqlite_error)?;
    legacy.execute_batch(LEGACY_SQL).map_err(sqlite_error)?;
    let appended = Connection::open_in_memory().map_err(sqlite_error)?;
    appended
        .execute_batch(VERSION_1_SQL)
        .map_err(sqlite_error)?;
    // The additive repair in 9db9dbc0 put this column AFTER updated_at_ms.
    appended.execute_batch("ALTER TABLE audit_log_settings ADD COLUMN data_mode TEXT NOT NULL DEFAULT 'obfuscated_sensitive_data'")
        .map_err(sqlite_error)?;

    // Accept the review's additive endpoint layout defensively. History proves
    // the inline layout only; this is not evidence of an additional shipped build.
    appended
        .execute_batch("ALTER TABLE relay_telemetry_settings ADD COLUMN otlp_endpoint TEXT")
        .map_err(sqlite_error)?;

    let mut legacy_endpoint = false;
    for table in TABLES {
        if !table_exists(tx, table)? {
            continue;
        }
        let has_trigger: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?1)",
            [table], |r| r.get(0),
        ).map_err(sqlite_error)?;
        // No historical shared-table triggers exist. Refuse side effects that
        // could alter live rows during adoption. Current opens do not recheck triggers.
        if has_trigger {
            return Err(invalid_shape());
        }
        if table_matches(tx, &reference, table)? {
            continue;
        }
        let alternatives: &[&Connection] = match *table {
            "relay_telemetry_settings" | "audit_log_settings" => &[&legacy, &appended],
            _ => &[],
        };
        let mut recognized = false;
        for alternative in alternatives {
            if table_matches(tx, alternative, table)? {
                recognized = true;
                break;
            }
        }
        if !recognized {
            return Err(invalid_shape());
        }
        legacy_endpoint |= *table == "relay_telemetry_settings";
    }
    // Missing tables are safe to create only after existing ones are recognized.
    // Leave old unused directory tables and all their rows untouched.
    tx.execute_batch(VERSION_1_SQL).map_err(sqlite_error)?;
    if legacy_endpoint {
        tx.execute("UPDATE relay_telemetry_settings SET otlp_endpoint = NULL WHERE otlp_endpoint IS NOT NULL", [])
            .map_err(sqlite_error)?;
    }
    // Validate the only FK in the live v1 contract. Retired tables are outside
    // this migration's authority; existing orphaned rows there remain untouched
    // and must not make live settings or the installation identity unavailable.
    let mut check = tx
        .prepare("PRAGMA foreign_key_check(directory_user_follows)")
        .map_err(sqlite_error)?;
    if check
        .query([])
        .map_err(sqlite_error)?
        .next()
        .map_err(sqlite_error)?
        .is_some()
    {
        return Err(invalid_shape());
    }
    Ok(())
}

/// Compare introspected structure AND conservative frozen DDL. PRAGMAs cover
/// all columns (including hidden/generated), keys, FKs and index definitions;
/// DDL additionally pins CHECK expressions, collations, conflict policies,
/// deferrability and table options. Unknown equivalent SQL may fail closed.
fn table_matches(conn: &Connection, reference: &Connection, name: &str) -> StorageResult<bool> {
    let ddl = |db: &Connection| -> StorageResult<Option<String>> {
        db.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |r| r.get(0),
        )
        .optional()
        .map_err(sqlite_error)
    };
    let (Some(actual), Some(expected)) = (ddl(conn)?, ddl(reference)?) else {
        return Ok(false);
    };
    if normalized_ddl(&actual) != normalized_ddl(&expected) {
        return Ok(false);
    }
    for query in [
        "SELECT * FROM pragma_table_xinfo(?1) ORDER BY cid",
        "SELECT * FROM pragma_foreign_key_list(?1) ORDER BY id, seq",
        "SELECT name, \"unique\", origin, partial FROM pragma_index_list(?1) ORDER BY name",
    ] {
        if structure(conn, query, name)? != structure(reference, query, name)? {
            return Ok(false);
        }
    }
    let indexes = structure(
        reference,
        "SELECT name FROM pragma_index_list(?1) ORDER BY name",
        name,
    )?;
    for row in indexes {
        let rusqlite::types::Value::Text(index) = &row[0] else {
            return Err(invalid_shape());
        };
        let query = "SELECT * FROM pragma_index_xinfo(?1) ORDER BY seqno";
        if structure(conn, query, index)? != structure(reference, query, index)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn structure(
    conn: &Connection,
    query: &str,
    name: &str,
) -> StorageResult<Vec<Vec<rusqlite::types::Value>>> {
    let mut statement = conn.prepare(query).map_err(sqlite_error)?;
    let columns = statement.column_count();
    statement
        .query_map([name], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .map_err(sqlite_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(sqlite_error)
}

/// Ignore formatting outside quoted tokens only. Do not normalize literals:
/// defaults and CHECK text are contract, including whitespace and letter case.
fn normalized_ddl(sql: &str) -> String {
    let mut quoted = None;
    let mut result = String::new();
    for ch in sql.chars() {
        if let Some(end) = quoted {
            result.push(ch);
            if ch == end {
                quoted = None;
            }
        } else if matches!(ch, '\'' | '"' | '`' | '[') {
            quoted = Some(if ch == '[' { ']' } else { ch });
            result.push(ch);
        } else if !ch.is_ascii_whitespace() {
            result.push(ch.to_ascii_lowercase());
        }
    }
    result
}

#[cfg(test)]
#[path = "migration_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "assurance_tests.rs"]
mod assurance_tests;
