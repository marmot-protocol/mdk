//! Populated encrypted upgrades must not duplicate payload pages during account open.
use super::*;
use crate::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

fn encrypted_fixture() -> (tempfile::TempDir, Connection) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixture.sqlite");
    fs_private::ensure_private_db_files(&path).unwrap();
    let connection = Connection::open(path).unwrap();
    let key = SqlCipherKey::new("synthetic-upgrade-regression".to_owned()).unwrap();
    open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
    connection.execute_batch("PRAGMA foreign_keys=ON;
        CREATE TABLE attachment_acquisition(token BLOB PRIMARY KEY,state INTEGER,cancelled INTEGER DEFAULT 0,permission_paused INTEGER DEFAULT 0);
        INSERT INTO attachment_acquisition VALUES(x'01',1,0,0);").unwrap();
    ensure_migration_table(&connection).unwrap();
    (directory, connection)
}

fn pages(connection: &Connection) -> i64 {
    connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap()
}

#[test]
fn retained_upgrade_preserves_payload_pages_and_rollback() {
    let (_directory, mut connection) = encrypted_fixture();
    connection.execute_batch("CREATE TABLE retained_attachment_bytes(token BLOB PRIMARY KEY REFERENCES attachment_acquisition(token) ON DELETE CASCADE,bytes BLOB NOT NULL CHECK(length(bytes)<=536870912));
        INSERT INTO retained_attachment_bytes(rowid,token,bytes) VALUES(71,x'01',zeroblob(2097152));
        CREATE TABLE attachment_retention_usage(id INTEGER PRIMARY KEY,byte_count INTEGER);
        INSERT INTO attachment_retention_usage VALUES(1,2097152);
        CREATE TRIGGER attachment_bytes_added AFTER INSERT ON retained_attachment_bytes BEGIN SELECT 1; END;
        CREATE TRIGGER attachment_bytes_removed AFTER DELETE ON retained_attachment_bytes BEGIN SELECT 1; END;
        CREATE TRIGGER attachment_bytes_updated AFTER UPDATE OF bytes ON retained_attachment_bytes BEGIN SELECT 1; END;").unwrap();
    let before = pages(&connection);
    {
        let transaction = connection.transaction().unwrap();
        migration_0104_file_attachment_retention::apply(&transaction).unwrap();
        assert!(
            pages(&transaction) <= before + 16,
            "account open duplicated retained payload pages"
        );
        transaction.rollback().unwrap();
    }
    assert!(
        !connection
            .column_exists(None, "retained_attachment_bytes", "byte_len")
            .unwrap()
    );
    let transaction = connection.transaction().unwrap();
    migration_0104_file_attachment_retention::apply(&transaction).unwrap();
    transaction.commit().unwrap();
    let bytes: Vec<u8> = connection
        .query_row("SELECT bytes FROM retained_attachment_bytes", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(bytes, vec![0u8; 2097152]);
    assert!(pages(&connection) <= before + 16);
    connection
        .execute("DELETE FROM attachment_acquisition", [])
        .unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT byte_count FROM attachment_retention_usage",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn partial_upgrade_preserves_chunk_pages_and_restores_foreign_keys() {
    let (_directory, mut connection) = encrypted_fixture();
    let transaction = connection.transaction().unwrap();
    migration_0085_attachment_partials::apply(&transaction).unwrap();
    transaction.execute("INSERT INTO attachment_partial VALUES(x'01',zeroblob(32),zeroblob(32),'etag',4194304,4194304,100)",[]).unwrap();
    for index in 0..4 {
        transaction.execute("INSERT INTO attachment_partial_chunk VALUES(x'01',?1,zeroblob(1048576),zeroblob(32))",[index*1048576]).unwrap();
    }
    transaction.commit().unwrap();
    let before = pages(&connection);
    let migration = Migration {
        version: 105,
        name: "0105_file_attachment_partials",
        apply: migration_0105_file_attachment_partials::apply,
    };
    apply_migration(&mut connection, &migration).unwrap();
    assert!(
        pages(&connection) <= before + 16,
        "account open duplicated partial ciphertext pages"
    );
    assert!(
        connection
            .pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))
            .unwrap()
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT sum(length(bytes)) FROM attachment_partial_chunk",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        4194304
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
    connection
        .execute("DELETE FROM attachment_acquisition", [])
        .unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT reserved_bytes FROM attachment_partial_usage",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM attachment_partial_chunk", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
}

#[test]
fn failed_parent_rebuild_rolls_back_and_restores_foreign_key_enforcement() {
    let (_directory, mut connection) = encrypted_fixture();
    let transaction = connection.transaction().unwrap();
    migration_0085_attachment_partials::apply(&transaction).unwrap();
    transaction.execute("INSERT INTO attachment_partial VALUES(x'01',zeroblob(32),zeroblob(32),'etag',10,3,100)",[]).unwrap();
    transaction
        .execute(
            "INSERT INTO attachment_partial_chunk VALUES(x'01',0,x'010203',zeroblob(32))",
            [],
        )
        .unwrap();
    transaction.commit().unwrap();
    let migration = Migration {
        version: 105,
        name: "0105_file_attachment_partials",
        apply: |tx| {
            migration_0105_file_attachment_partials::apply(tx)?;
            Err(StorageError::Backend(
                "synthetic post-rebuild failure".into(),
            ))
        },
    };
    assert!(apply_migration(&mut connection, &migration).is_err());
    assert!(
        connection
            .pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))
            .unwrap()
    );
    assert_eq!(
        connection
            .query_row("SELECT bytes FROM attachment_partial_chunk", [], |r| r
                .get::<_, Vec<u8>>(0))
            .unwrap(),
        vec![1, 2, 3]
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM cgka_schema_migrations WHERE version=105",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    connection
        .execute("INSERT INTO attachment_acquisition VALUES(x'02',1,0,0)", [])
        .unwrap();
    let error=connection.execute("INSERT INTO attachment_partial VALUES(x'02',zeroblob(32),zeroblob(32),'etag',758000016,0,100)",[]).unwrap_err();
    assert!(matches!(error,rusqlite::Error::SqliteFailure(code,_) if code.extended_code == 275));
    connection
        .execute("DELETE FROM attachment_acquisition", [])
        .unwrap();
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM attachment_partial_chunk", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
}

#[test]
fn observer_faults_do_not_change_storage_results_and_progress_names_the_migration() {
    let root = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("synthetic-observation".to_owned()).unwrap();
    let progress = std::cell::RefCell::new(Vec::new());
    let observer = |value| {
        progress.borrow_mut().push(value);
    };
    let store = crate::SqliteAccountStorage::open_encrypted_observed(
        root.path().join("observed.sqlite"),
        &key,
        &observer,
    )
    .unwrap();
    assert!(
        progress
            .borrow()
            .contains(&crate::StorageOpenProgress::MigrationStarted(105))
    );
    assert!(
        progress
            .borrow()
            .contains(&crate::StorageOpenProgress::MigrationFinished {
                version: 105,
                success: true
            })
    );
    drop(store);
    let failed_observer = |_| panic!("synthetic observer fault");
    let store = crate::SqliteAccountStorage::open_encrypted_observed(
        root.path().join("observed.sqlite"),
        &key,
        &failed_observer,
    )
    .unwrap();
    assert_eq!(store.migration_summary().0, 0);
}

#[path = "media_upgrade_prior.rs"]
mod prior;

#[test]
fn published_media_schema_reopens_without_rewriting_or_reapplying() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("prior.sqlite");
    fs_private::ensure_private_db_files(&path).unwrap();
    let mut connection = Connection::open(&path).unwrap();
    let key = SqlCipherKey::new("synthetic-prior-store".to_owned()).unwrap();
    open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
    connection
        .execute_batch(include_str!("../../fixtures/account-v0.10.4.sql"))
        .unwrap();
    let prior: Vec<_> = MIGRATIONS
        .iter()
        .map(|m| Migration {
            version: m.version,
            name: m.name,
            apply: match m.version {
                104 => prior::retained,
                105 => prior::partial,
                _ => m.apply,
            },
        })
        .collect();
    run_with_summary(&mut connection, &prior).unwrap();
    let (group, message): (String, String) = connection
        .query_row(
            "SELECT group_id_hex,message_id_hex FROM app_events LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    connection.execute("INSERT INTO attachment_acquisition(token,group_id_hex,message_id_hex,attachment_index,source_message_id_hex,source_epoch,slot_json,plaintext_digest,state,due) VALUES(zeroblob(16),?1,?2,0,?2,1,'{}',zeroblob(32),3,NULL)",params![group,message]).unwrap();
    connection.execute("INSERT INTO retained_attachment_bytes(token,byte_len,bytes) VALUES(zeroblob(16),3,x'010203')",[]).unwrap();
    drop(connection);
    let reopened = crate::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(reopened.migration_summary().0, 0);
    let connection = reopened.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT bytes FROM retained_attachment_bytes WHERE token=zeroblob(16)",
                [],
                |r| r.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
        vec![1, 2, 3]
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT byte_count FROM attachment_retention_usage",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        3
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
}

#[test]
fn rebuild_rejects_invalid_references_before_committing_a_ledger_row() {
    let (_directory, mut connection) = encrypted_fixture();
    let transaction = connection.transaction().unwrap();
    migration_0085_attachment_partials::apply(&transaction).unwrap();
    transaction.commit().unwrap();
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute(
            "INSERT INTO attachment_partial_chunk VALUES(x'09',0,x'01',zeroblob(32))",
            [],
        )
        .unwrap();
    let migration = Migration {
        version: 105,
        name: "0105_file_attachment_partials",
        apply: migration_0105_file_attachment_partials::apply,
    };
    assert!(apply_migration(&mut connection, &migration).is_err());
    assert!(
        !connection
            .pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))
            .unwrap()
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM cgka_schema_migrations WHERE version=105",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM attachment_partial_chunk", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
}

#[test]
fn unwinding_rebuild_restores_enforcement_and_rolls_back_metadata() {
    let (_directory, mut connection) = encrypted_fixture();
    let transaction = connection.transaction().unwrap();
    migration_0085_attachment_partials::apply(&transaction).unwrap();
    transaction.commit().unwrap();
    let migration = Migration {
        version: 105,
        name: "0105_file_attachment_partials",
        apply: |tx| {
            migration_0105_file_attachment_partials::apply(tx)?;
            panic!("synthetic migration unwind");
        },
    };
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| apply_migration(
            &mut connection,
            &migration
        )))
        .is_err()
    );
    assert!(
        connection
            .pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))
            .unwrap()
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM cgka_schema_migrations WHERE version=105",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert!(
        !connection
            .table_exists(None, "attachment_partial_next")
            .unwrap()
    );
}
