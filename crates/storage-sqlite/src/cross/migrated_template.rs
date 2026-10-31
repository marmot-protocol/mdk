//! A migrated in-memory account database for tests, copied instead of
//! replaying every migration for each store a test opens.
//!
//! nextest runs each test in its own process, so a template kept in memory
//! would be built again by every test. This one is built once per test binary,
//! by the same fresh open as [`open_account_in_memory`], and kept beside the
//! binary for the binary's other processes. A copy draws its own per-database
//! values ([`RENEWED_PER_DATABASE`]), so copies are as distinct as freshly
//! migrated databases; those values sit on both sides, so this lives in
//! `cross/`. Building or reading the template is best effort: on any failure
//! the open replays the migrations instead, which is slower but opens the same
//! database.

use crate::SqliteResultExt;
use crate::base::connection::{
    OpenedAccount, SqliteStorageOptions, apply_cipher_pragmas, ensure_private_db_files,
    finish_account_open, open_account_in_memory,
};
use cgka_traits::storage::StorageResult;
use rusqlite::backup::Backup;
use rusqlite::{Connection, OpenFlags};
use std::ffi::c_int;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

/// The values a fresh database draws for itself while migrating, as
/// (table, column, the statement that draws a new one). A migration that adds
/// one needs a line here; `two_fresh_databases_differ_only_in_renewed_values`
/// finds it.
const RENEWED_PER_DATABASE: &[(&str, &str, &str)] = &[
    (
        "chat_presentation_meta",
        "store_epoch",
        "UPDATE chat_presentation_meta SET store_epoch = randomblob(16)",
    ),
    (
        "cgka_schema_migrations",
        "applied_at_unix_seconds",
        "UPDATE cgka_schema_migrations \
         SET applied_at_unix_seconds = CAST(strftime('%s', 'now') AS INTEGER)",
    ),
];

const TEMPLATE_INFIX: &str = ".migrated-template-";

/// Open an in-memory account database with `options`, copied from this test
/// binary's migrated template.
pub(crate) fn open(options: SqliteStorageOptions) -> StorageResult<OpenedAccount> {
    match template_path() {
        Some(template) => open_with_template(&template, options),
        None => open_account_in_memory(options),
    }
}

/// Copy `template`, or replay the migrations and publish the result as
/// `template` when there is none yet.
fn open_with_template(
    template: &Path,
    options: SqliteStorageOptions,
) -> StorageResult<OpenedAccount> {
    if !template.exists() {
        let opened = open_account_in_memory(options)?;
        publish(&opened, template);
        return Ok(opened);
    }
    copy(template, &options)
        .and_then(|connection| finish_account_open(connection, options.clone(), None))
        .or_else(|_| open_account_in_memory(options))
}

/// The template's path: beside the test binary, named for this build of it,
/// so a rebuild never copies an older schema.
fn template_path() -> Option<PathBuf> {
    let binary = std::env::current_exe().ok()?;
    let metadata = std::fs::metadata(&binary).ok()?;
    let built = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let name = binary.file_name()?.to_str()?;
    Some(binary.with_file_name(format!(
        "{name}{TEMPLATE_INFIX}{built}-{}.sqlite",
        metadata.len()
    )))
}

/// Write `opened`, a freshly migrated database, as the template, then remove
/// the templates of earlier builds of this binary. Processes that start
/// together may each write one; every one is complete, and a rename that
/// loses the race leaves the winner in place.
fn publish(opened: &OpenedAccount, template: &Path) {
    let staging = template.with_extension(format!("{}.staging", std::process::id()));
    let written = (|| -> StorageResult<()> {
        let source = opened.connection.lock()?;
        ensure_private_db_files(&staging)?;
        let mut file = Connection::open(&staging).storage()?;
        Backup::new(&source, &mut file)
            .storage()?
            .run_to_completion(c_int::MAX, Duration::ZERO, None)
            .storage()
    })();
    if written.is_err() || std::fs::rename(&staging, template).is_err() {
        let _ = std::fs::remove_file(&staging);
        return;
    }
    remove_earlier_templates(template);
}

fn remove_earlier_templates(current: &Path) {
    let (Some(directory), Some(current_name)) = (
        current.parent(),
        current.file_name().and_then(|name| name.to_str()),
    ) else {
        return;
    };
    let Some(prefix) = current_name
        .find(TEMPLATE_INFIX)
        .map(|at| &current_name[..at + TEMPLATE_INFIX.len()])
    else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name != current_name && name.starts_with(prefix) && name.ends_with(".sqlite") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Copy the template into a new in-memory connection and draw its
/// per-database values.
fn copy(template: &Path, options: &SqliteStorageOptions) -> StorageResult<Connection> {
    let source = Connection::open_with_flags(
        template,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .storage()?;
    let mut connection = Connection::open_in_memory().storage()?;
    apply_cipher_pragmas(&connection, options)?;
    Backup::new(&source, &mut connection)
        .storage()?
        .run_to_completion(c_int::MAX, Duration::ZERO, None)
        .storage()?;
    drop(source);
    for (_, _, renew) in RENEWED_PER_DATABASE {
        connection.execute_batch(renew).storage()?;
    }
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;
    use std::collections::BTreeSet;

    fn options() -> SqliteStorageOptions {
        SqliteStorageOptions {
            cipher_memory_security: false,
            ..SqliteStorageOptions::default()
        }
    }

    fn replayed() -> SqliteAccountStorage {
        SqliteAccountStorage::in_memory_with_options(options()).unwrap()
    }

    fn from_template(template: &Path) -> SqliteAccountStorage {
        SqliteAccountStorage::from_opened(open_with_template(template, options()).unwrap())
    }

    /// A template in `dir` and a first copy of it.
    fn template_in(dir: &tempfile::TempDir) -> (PathBuf, SqliteAccountStorage) {
        let template = dir.path().join(format!("binary{TEMPLATE_INFIX}1-1.sqlite"));
        let first = from_template(&template);
        assert!(first.migration_summary().0 > 0, "no template yet: replay");
        assert!(template.exists(), "the replay was published");
        let copy = from_template(&template);
        (template, copy)
    }

    fn query<T: rusqlite::types::FromSql>(store: &SqliteAccountStorage, sql: &str) -> Vec<T> {
        let conn = store.lock().unwrap();
        let mut statement = conn.prepare(sql).unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn schema(store: &SqliteAccountStorage) -> Vec<String> {
        query(
            store,
            "SELECT type || ' ' || name || ' ' || coalesce(sql, '') FROM sqlite_master \
             ORDER BY type, name",
        )
    }

    fn store_epoch(store: &SqliteAccountStorage) -> Vec<u8> {
        query::<Vec<u8>>(store, "SELECT store_epoch FROM chat_presentation_meta")
            .pop()
            .unwrap()
    }

    /// Every (table, column) whose values differ between the two databases.
    fn differing_columns(
        left: &SqliteAccountStorage,
        right: &SqliteAccountStorage,
    ) -> BTreeSet<(String, String)> {
        let columns: Vec<String> = query(
            left,
            "SELECT m.name || char(31) || p.name \
             FROM sqlite_master AS m, pragma_table_info(m.name) AS p \
             WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'",
        );
        let values = |store: &SqliteAccountStorage, table: &str, column: &str| {
            let mut values: Vec<String> = query::<rusqlite::types::Value>(
                store,
                &format!("SELECT \"{column}\" FROM \"{table}\""),
            )
            .into_iter()
            .map(|value| format!("{value:?}"))
            .collect();
            values.sort();
            values
        };
        columns
            .iter()
            .filter_map(|entry| entry.split_once('\u{1f}'))
            .filter(|(table, column)| values(left, table, column) != values(right, table, column))
            .map(|(table, column)| (table.to_string(), column.to_string()))
            .collect()
    }

    fn renewed() -> BTreeSet<(String, String)> {
        RENEWED_PER_DATABASE
            .iter()
            .map(|(table, column, _)| (table.to_string(), column.to_string()))
            .collect()
    }

    #[test]
    fn two_fresh_databases_differ_only_in_renewed_values() {
        let differing = differing_columns(&replayed(), &replayed());
        assert!(
            differing.is_subset(&renewed()),
            "a migration draws a per-database value; renew it in RENEWED_PER_DATABASE: {:?}",
            differing.difference(&renewed()).collect::<Vec<_>>()
        );
        assert!(differing.contains(&("chat_presentation_meta".into(), "store_epoch".into())));
    }

    #[test]
    fn a_copy_is_the_database_a_replay_opens() {
        let dir = tempfile::tempdir().unwrap();
        let (_, copy) = template_in(&dir);
        let replay = replayed();
        assert_eq!(copy.migration_summary().0, 0, "the copy needs no migration");
        assert_eq!(schema(&copy), schema(&replay));
        for pragma in ["auto_vacuum", "page_size", "user_version", "application_id"] {
            let sql = format!("PRAGMA {pragma}");
            assert_eq!(
                query::<i64>(&copy, &sql),
                query::<i64>(&replay, &sql),
                "{pragma}"
            );
        }
        assert!(differing_columns(&copy, &replay).is_subset(&renewed()));
    }

    #[test]
    fn copies_draw_their_own_values_and_share_no_pages() {
        let dir = tempfile::tempdir().unwrap();
        let (template, first) = template_in(&dir);
        let second = from_template(&template);
        assert_ne!(store_epoch(&first), store_epoch(&second));

        first
            .lock()
            .unwrap()
            .execute_batch("CREATE TABLE template_copy_probe(value INTEGER)")
            .unwrap();
        let probe = "SELECT count(*) FROM sqlite_master WHERE name = 'template_copy_probe'";
        assert_eq!(query::<i64>(&first, probe), [1]);
        assert_eq!(
            query::<i64>(&second, probe),
            [0],
            "copies must not share pages"
        );
        let third = from_template(&template);
        assert_eq!(
            query::<i64>(&third, probe),
            [0],
            "writes must not reach the template"
        );
    }

    #[test]
    fn an_unreadable_template_falls_back_to_a_replay() {
        let dir = tempfile::tempdir().unwrap();
        let template = dir.path().join(format!("binary{TEMPLATE_INFIX}1-1.sqlite"));
        std::fs::write(&template, b"not a database").unwrap();
        let store = from_template(&template);
        assert!(store.migration_summary().0 > 0);
        assert_eq!(schema(&store), schema(&replayed()));
    }

    #[test]
    fn publishing_removes_only_earlier_templates_of_the_same_binary() {
        let dir = tempfile::tempdir().unwrap();
        let file = |name: &str| dir.path().join(name);
        for name in [
            "binary.migrated-template-1-1.sqlite",
            "binary.migrated-template-1-1.42.staging",
            "other.migrated-template-1-1.sqlite",
            "binary",
        ] {
            std::fs::write(file(name), b"").unwrap();
        }
        let current = file("binary.migrated-template-2-2.sqlite");
        let _ = from_template(&current);
        assert!(current.exists());
        assert!(!file("binary.migrated-template-1-1.sqlite").exists());
        for kept in [
            "binary.migrated-template-1-1.42.staging",
            "other.migrated-template-1-1.sqlite",
            "binary",
        ] {
            assert!(file(kept).exists(), "{kept}");
        }
    }

    #[test]
    fn in_memory_for_test_copies_this_binarys_template() {
        let _ = SqliteAccountStorage::in_memory_for_test().unwrap();
        let copy = SqliteAccountStorage::in_memory_for_test().unwrap();
        assert_eq!(copy.migration_summary().0, 0);
        assert!(template_path().unwrap().exists());
    }
}
