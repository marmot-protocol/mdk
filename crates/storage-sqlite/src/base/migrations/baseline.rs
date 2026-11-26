//! Fresh-database baseline for the account/session migration ledger.
//!
//! A database created empty used to replay every registered migration in its
//! own transaction. Many of those bodies are `ALTER TABLE` statements, and
//! SQLite re-parses the whole schema for each one, so the first open of a new
//! account spent seconds rebuilding a schema that a few hundred `CREATE`
//! statements describe exactly. `baseline.sql` holds those statements and the
//! seed rows: what a full replay of migrations `1..=BASELINE_VERSION` leaves in
//! an empty database, dumped by [`tests::dump`]. An empty database applies it in
//! one transaction, records the covered migrations, and replays only later
//! ones. A database with any ledger row never uses it.
//!
//! Seed rows are inserted before triggers are created, and values a fresh
//! database draws for itself while migrating ([`RENEWED_PER_DATABASE`]) are
//! emitted as their SQL generator expressions in `baseline.sql`, so every new
//! database draws its own without running a post-load `UPDATE` or firing
//! triggers.
//!
//! `tests::baseline_file_matches_a_full_replay` fails if the file and a replay
//! differ. Regenerate it after changing that range (registered migrations never
//! change) with `MDK_WRITE_MIGRATION_BASELINE=1 cargo test -p storage-sqlite
//! baseline_file_matches_a_full_replay`, or raise `BASELINE_VERSION` (up to
//! `HEAD`) the same way so newer migrations join the fast path.
use super::Migration;
use crate::SqliteResultExt;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, TransactionBehavior, params};

/// The last migration `baseline.sql` covers.
pub(crate) const BASELINE_VERSION: i64 = 227;

/// A value a fresh database draws for itself while migrating. A migration that
/// adds one needs an entry in [`RENEWED_PER_DATABASE`]; `cross::migrated_template`'s
/// `two_fresh_databases_differ_only_in_renewed_values` finds it, including
/// values drawn from the clock.
#[cfg(any(test, feature = "test-support"))]
pub(crate) struct RenewedColumn {
    pub(crate) table: &'static str,
    pub(crate) column: &'static str,
    pub(crate) expression: &'static str,
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) const RENEWED_PER_DATABASE: &[RenewedColumn] = &[
    RenewedColumn {
        table: "chat_presentation_meta",
        column: "store_epoch",
        expression: "randomblob(16)",
    },
    RenewedColumn {
        table: "cgka_schema_migrations",
        column: "applied_at_unix_seconds",
        expression: "CAST(strftime('%s', 'now') AS INTEGER)",
    },
];

const BASELINE_SQL: &str = include_str!("baseline.sql");

/// Tables the runner writes itself; their rows are not part of the baseline.
const LEDGER_TABLES: [&str; 2] = ["cgka_schema_migrations", "cgka_database_origin"];

/// Whether `connection` holds the two ledger tables, empty, and no other
/// schema object (not even an index or trigger on them). Any other database
/// replays migrations one by one as before.
fn starts_empty(connection: &Connection) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT NOT EXISTS (SELECT 1 FROM cgka_schema_migrations)
            AND NOT EXISTS (
                SELECT 1 FROM sqlite_schema
                WHERE NOT (type = 'table' AND name IN (?1, ?2))
            )",
        params![LEDGER_TABLES[0], LEDGER_TABLES[1]],
        |row| row.get(0),
    )
}

/// Apply the baseline to a database that [`starts_empty`] and record every
/// migration it covers. Progress names [`BASELINE_VERSION`] once and reports
/// the committed ledger count.
pub(super) fn apply(
    connection: &mut Connection,
    migrations: &[Migration],
    observer: Option<&dyn Fn(crate::StorageOpenProgress)>,
) -> StorageResult<usize> {
    let covered = migrations
        .iter()
        .take_while(|migration| migration.version <= BASELINE_VERSION)
        .collect::<Vec<_>>();
    if covered.last().map(|migration| migration.version) != Some(BASELINE_VERSION) {
        return Err(StorageError::Backend(
            "migration baseline does not end at a registered migration".into(),
        ));
    }
    if !starts_empty(connection).storage()? {
        return Ok(0);
    }
    let version = BASELINE_VERSION as u32;
    crate::base::open_progress::observe(
        observer,
        crate::StorageOpenProgress::MigrationStarted(version),
    );
    let result = (|| {
        // A competing opener may have populated the database since the first
        // inspection. Recheck only after reserving the write transaction.
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        if !starts_empty(&tx).storage()? {
            return Ok(0);
        }
        // Defer FK enforcement until COMMIT so alphabetical seed inserts across
        // referencing tables succeed while still validating FKs before commit.
        tx.pragma_update(None, "defer_foreign_keys", true)
            .storage()?;
        tx.execute_batch(BASELINE_SQL).storage()?;
        for migration in &covered {
            super::record_applied(&tx, migration)?;
        }
        tx.commit().storage()?;
        Ok(covered.len())
    })();
    crate::base::open_progress::observe(
        observer,
        crate::StorageOpenProgress::MigrationBatchFinished {
            version,
            success: result.is_ok(),
            migrations_completed: result.as_ref().copied().unwrap_or(0) as u32,
        },
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::migrations::{
        MIGRATIONS, run, run_all, run_through, run_with_summary_observed,
    };

    /// Open an in-memory database with foreign keys enabled, matching production opens.
    fn open_in_memory_fk() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        conn
    }

    #[derive(Clone, Copy)]
    enum RenewedRender {
        /// Emit the SQL generator expression so `baseline.sql` draws fresh
        /// per-database values directly on insert.
        Expression,
        /// Mask renewed values to type- and length-matched zeros so two
        /// databases compare equal by everything they share.
        Zeroed,
    }

    fn dump_objects(connection: &Connection, kinds: &[&str], out: &mut String) {
        for kind in kinds {
            let mut statement = connection
                .prepare(
                    "SELECT name, sql FROM sqlite_schema
                     WHERE type = ?1 AND sql IS NOT NULL AND name NOT GLOB 'sqlite_*'
                     ORDER BY rowid",
                )
                .unwrap();
            let rows = statement
                .query_map([kind], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            for (name, sql) in rows {
                if LEDGER_TABLES.contains(&name.as_str()) {
                    continue;
                }
                out.push_str(&sql);
                out.push_str(";\n");
            }
        }
    }

    /// The schema and rows of `connection` as replayable SQL: tables, indexes,
    /// and views first, then seed rows (with renewed columns emitted as their
    /// generator expressions), then triggers so seed inserts never trip triggers.
    pub(super) fn dump(connection: &Connection) -> String {
        let mut out = String::from(
            "-- Generated by storage-sqlite migrations::baseline::tests::dump; do not edit.\n",
        );
        dump_objects(connection, &["table", "index", "view"], &mut out);
        out.push_str(&dump_rows(
            connection,
            |name| !LEDGER_TABLES.contains(&name),
            RenewedRender::Expression,
        ));
        dump_objects(connection, &["trigger"], &mut out);
        out
    }

    /// `INSERT` statements for every row of every table `keep` selects, plus
    /// `sqlite_sequence`, in a stable order.
    fn dump_rows(
        connection: &Connection,
        keep: impl Fn(&str) -> bool,
        renewed_render: RenewedRender,
    ) -> String {
        let mut tables = connection
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'table'
                 AND (name NOT GLOB 'sqlite_*' OR name = 'sqlite_sequence') ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        tables.retain(|name| keep(name));
        let mut out = String::new();
        for table in tables {
            let mut columns = connection
                .prepare(&format!(
                    "SELECT name FROM pragma_table_info('{table}') ORDER BY cid"
                ))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            // sqlite_sequence has no declared key; keep each row's rowid too.
            if table == "sqlite_sequence" {
                columns.insert(0, "rowid".to_owned());
            }
            for column in &columns {
                // quote() stops a text value at its first NUL, so such a seed
                // could not be reproduced from the file.
                let truncated: bool = connection
                    .query_row(
                        &format!(
                            "SELECT EXISTS (SELECT 1 FROM \"{table}\"
                             WHERE typeof(\"{column}\") = 'text' AND instr(\"{column}\", char(0)) > 0)"
                        ),
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(!truncated, "{table}.{column} holds text with a NUL");
            }
            // Rewritten in the SELECT, never stored via UPDATE: an update would
            // fire triggers and mutate the database being inspected.
            let quoted = columns
                .iter()
                .map(|column| {
                    let renewed = RENEWED_PER_DATABASE.iter().find(|entry| {
                        !LEDGER_TABLES.contains(&entry.table)
                            && entry.table == table
                            && entry.column == column
                    });
                    match (renewed, renewed_render) {
                        (Some(entry), RenewedRender::Expression) => {
                            let escaped = entry.expression.replace('\'', "''");
                            format!(
                                "CASE WHEN \"{column}\" IS NULL THEN 'NULL' ELSE '{escaped}' END"
                            )
                        }
                        (Some(_), RenewedRender::Zeroed) => format!(
                            "quote(CASE typeof(\"{column}\")
                                WHEN 'blob' THEN zeroblob(length(\"{column}\"))
                                WHEN 'integer' THEN 0 WHEN 'real' THEN 0.0 WHEN 'text' THEN ''
                                ELSE \"{column}\" END)"
                        ),
                        (None, _) => format!("quote(\"{column}\")"),
                    }
                })
                .collect::<Vec<_>>()
                .join(" || ',' || ");
            let names = columns
                .iter()
                .map(|column| format!("\"{column}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let mut rows = connection
                .prepare(&format!("SELECT {quoted} FROM \"{table}\" ORDER BY 1"))
                .unwrap();
            let values = rows
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            for value in values {
                out.push_str(&format!(
                    "INSERT INTO \"{table}\" ({names}) VALUES ({value});\n"
                ));
            }
        }
        out
    }

    /// Everything a migrated database holds that a later open can observe,
    /// including the ledger's versions and names but not its timestamps.
    fn observable_state(connection: &Connection) -> String {
        let mut schema = connection
            .prepare(
                "SELECT type || ' ' || name || ' ' || tbl_name || ' ' || coalesce(sql, '')
                 FROM sqlite_schema ORDER BY type, name",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        schema.push('\n');
        schema.push_str(&dump_rows(
            connection,
            |name| !LEDGER_TABLES.contains(&name),
            RenewedRender::Zeroed,
        ));
        let ledger = connection
            .prepare("SELECT version || ' ' || name FROM cgka_schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        let origin: i64 = connection
            .query_row("SELECT count(*) FROM cgka_database_origin", [], |row| {
                row.get(0)
            })
            .unwrap();
        let user_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        format!(
            "{schema}\n-- ledger\n{ledger}\n-- origin {origin}\n-- user_version {user_version}\n"
        )
    }

    /// The checked-in file is exactly what a full replay through
    /// `BASELINE_VERSION` dumps, and dumping itself never writes to the
    /// database. Set `MDK_WRITE_MIGRATION_BASELINE=1` to rewrite the file.
    #[test]
    fn baseline_file_matches_a_full_replay() {
        let mut conn = open_in_memory_fk();
        run_through(&mut conn, BASELINE_VERSION).unwrap();
        let changes_before = conn.total_changes();
        let replayed = dump(&conn);
        assert_eq!(conn.total_changes(), changes_before, "dump must not write");
        assert_eq!(dump(&conn), replayed, "dump must be deterministic");
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/base/migrations/baseline.sql");
        if std::env::var_os("MDK_WRITE_MIGRATION_BASELINE").is_some() {
            // The binary embeds the file it was built with; the next run compares.
            std::fs::write(&path, &replayed).unwrap();
            return;
        }
        if let Some((line, (file, replay))) = BASELINE_SQL
            .lines()
            .zip(replayed.lines())
            .enumerate()
            .find(|(_, (file, replay))| file != replay)
        {
            panic!(
                "baseline.sql line {} differs:\n file: {file}\n replay: {replay}",
                line + 1
            );
        }
        assert!(
            BASELINE_SQL == replayed,
            "baseline.sql differs from a full replay through {BASELINE_VERSION}; regenerate it as the module docs say"
        );
    }

    /// A fresh open through the baseline ends in the same observable state as
    /// replaying every registered migration, draws its own per-database values,
    /// and a second open applies nothing.
    #[test]
    fn fresh_baseline_open_matches_replaying_every_migration() {
        let mut replayed = open_in_memory_fk();
        run(&mut replayed, MIGRATIONS).unwrap();

        let mut fresh = open_in_memory_fk();
        assert_eq!(run_all(&mut fresh).unwrap(), MIGRATIONS.len());
        assert_same_state(&fresh, &replayed);
        assert_eq!(run_all(&mut fresh).unwrap(), 0);

        let mut second = open_in_memory_fk();
        assert_eq!(run_all(&mut second).unwrap(), MIGRATIONS.len());
        let first_epoch: Vec<u8> = fresh
            .query_row("SELECT store_epoch FROM chat_presentation_meta", [], |r| {
                r.get(0)
            })
            .unwrap();
        let second_epoch: Vec<u8> = second
            .query_row("SELECT store_epoch FROM chat_presentation_meta", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(first_epoch.len(), 16);
        assert_ne!(first_epoch, vec![0u8; 16]);
        assert_ne!(first_epoch, second_epoch);

        let violations: i64 = fresh
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(violations, 0);
        let integrity: String = fresh
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
    }

    /// Migrations registered after `BASELINE_VERSION` replay normally after the
    /// baseline commits, even when `BASELINE_VERSION` equals the current head.
    #[test]
    fn baseline_is_followed_by_later_migrations() {
        use crate::StorageOpenProgress::{
            MigrationBatchFinished, MigrationFinished, MigrationStarted,
        };

        let tail_version = MIGRATIONS.last().unwrap().version + 1;
        let mut extended = MIGRATIONS.to_vec();
        extended.push(Migration {
            version: tail_version,
            name: "9999_baseline_tail_probe",
            suspend_foreign_keys: &[],
            apply: |tx| {
                tx.execute_batch("CREATE TABLE baseline_tail_probe (id INTEGER PRIMARY KEY);")
                    .storage()
            },
        });

        let mut fresh = open_in_memory_fk();
        let progress = std::cell::RefCell::new(Vec::new());
        let observer = |value| progress.borrow_mut().push(value);
        assert_eq!(
            run_with_summary_observed(&mut fresh, &extended, true, Some(&observer)).unwrap(),
            extended.len()
        );

        let mut replayed = open_in_memory_fk();
        run(&mut replayed, &extended).unwrap();
        assert_same_state(&fresh, &replayed);

        let baseline = BASELINE_VERSION as u32;
        let covered_count = MIGRATIONS
            .iter()
            .filter(|migration| migration.version <= BASELINE_VERSION)
            .count() as u32;
        let tail = tail_version as u32;
        let progress = progress.into_inner();
        assert!(progress.contains(&MigrationStarted(baseline)));
        assert!(progress.contains(&MigrationBatchFinished {
            version: baseline,
            success: true,
            migrations_completed: covered_count,
        }));
        assert!(progress.contains(&MigrationStarted(tail)));
        assert!(progress.contains(&MigrationFinished {
            version: tail,
            success: true,
        }));
    }

    /// A failure while recording the ledger rolls the whole baseline back and
    /// progress reports it as failed.
    #[test]
    fn a_failed_ledger_write_rolls_back_the_baseline_and_reports_failure() {
        let mut conn = open_in_memory_fk();
        run_through(&mut conn, 0).unwrap();
        conn.execute_batch(&format!(
            "CREATE TEMP TRIGGER refuse_ledger BEFORE INSERT ON main.cgka_schema_migrations
             WHEN NEW.version = {BASELINE_VERSION}
             BEGIN SELECT RAISE(ABORT, 'ledger refused'); END;"
        ))
        .unwrap();
        let progress = std::cell::RefCell::new(Vec::new());
        let observer = |value| progress.borrow_mut().push(value);
        let err = apply(&mut conn, MIGRATIONS, Some(&observer)).unwrap_err();
        assert!(err.to_string().contains("ledger refused"), "{err}");
        assert!(starts_empty(&conn).unwrap());
        let version = BASELINE_VERSION as u32;
        assert_eq!(
            progress.into_inner(),
            vec![
                crate::StorageOpenProgress::MigrationStarted(version),
                crate::StorageOpenProgress::MigrationBatchFinished {
                    version,
                    success: false,
                    migrations_completed: 0,
                },
            ]
        );
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name = 'chat_presentation_meta'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
    }

    #[test]
    fn baseline_progress_allows_a_competing_opener_to_finish_first() {
        use crate::StorageOpenProgress::{MigrationBatchFinished, MigrationStarted};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("baseline.sqlite");
        let mut first = Connection::open(&path).unwrap();
        first.pragma_update(None, "foreign_keys", true).unwrap();
        run_through(&mut first, 0).unwrap();
        let version = BASELINE_VERSION as u32;
        let competing = std::cell::RefCell::new(None);
        let progress = std::cell::RefCell::new(Vec::new());
        let observer = |value| {
            progress.borrow_mut().push(value);
            if value == MigrationStarted(version) {
                let mut other = Connection::open(&path).unwrap();
                other.pragma_update(None, "foreign_keys", true).unwrap();
                other.busy_timeout(std::time::Duration::ZERO).unwrap();
                *competing.borrow_mut() = Some(apply(&mut other, MIGRATIONS, None));
            }
        };

        assert_eq!(apply(&mut first, MIGRATIONS, Some(&observer)).unwrap(), 0);
        assert_eq!(
            competing.into_inner().unwrap().unwrap(),
            MIGRATIONS
                .iter()
                .filter(|migration| migration.version <= BASELINE_VERSION)
                .count()
        );
        assert_eq!(
            progress.into_inner(),
            [
                MigrationStarted(version),
                MigrationBatchFinished {
                    version,
                    success: true,
                    migrations_completed: 0,
                },
            ]
        );
    }

    /// An empty ledger beside any other schema object is not a fresh
    /// database, so it keeps replaying migrations one by one.
    #[test]
    fn a_database_with_other_schema_never_takes_the_baseline() {
        for extra in [
            "CREATE TABLE unrelated (id INTEGER PRIMARY KEY)",
            "CREATE TABLE sqliteX_notes (id INTEGER PRIMARY KEY)",
            "CREATE INDEX ledger_names ON cgka_schema_migrations(name)",
        ] {
            let mut conn = open_in_memory_fk();
            run_through(&mut conn, 0).unwrap();
            conn.execute_batch(extra).unwrap();
            assert_eq!(apply(&mut conn, MIGRATIONS, None).unwrap(), 0, "{extra}");
            let ledger: i64 = conn
                .query_row("SELECT count(*) FROM cgka_schema_migrations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(ledger, 0, "{extra}");
        }
    }

    /// A database with any ledger row keeps replaying migrations one by one.
    #[test]
    fn partially_migrated_databases_never_take_the_baseline() {
        let mut conn = open_in_memory_fk();
        run_through(&mut conn, 1).unwrap();
        assert_eq!(apply(&mut conn, MIGRATIONS, None).unwrap(), 0);
        assert_eq!(run_all(&mut conn).unwrap(), MIGRATIONS.len() - 1);

        let mut replayed = open_in_memory_fk();
        run(&mut replayed, MIGRATIONS).unwrap();
        assert_same_state(&conn, &replayed);
    }

    /// Compare two databases line by line so a failure names what differs.
    fn assert_same_state(left: &Connection, right: &Connection) {
        let (left, right) = (observable_state(left), observable_state(right));
        for (line, (l, r)) in left.lines().zip(right.lines()).enumerate() {
            assert_eq!(l, r, "observable state line {} differs", line + 1);
        }
        assert_eq!(left.lines().count(), right.lines().count());
    }
}
