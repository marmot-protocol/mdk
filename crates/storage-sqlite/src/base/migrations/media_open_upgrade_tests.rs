//! Populated encrypted upgrades must not duplicate payload pages during account open.
use super::*;
use crate::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

/// Create an owner-only encrypted fixture with a valid job parent and production cipher hardening.
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

/// Detect persistent payload duplication, including freed pages that a table replacement leaves behind.
fn pages(connection: &Connection) -> i64 {
    connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap()
}

/// Measure native SQLite allocation in a dedicated child so concurrent tests cannot affect its global counter.
#[test]
fn retained_mutations_do_not_materialize_old_payloads() {
    const CHILD: &str = "MDK_RETAINED_MUTATION_MEMORY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "base::migrations::media_open_upgrade_tests::retained_mutations_do_not_materialize_old_payloads",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated native-memory regression failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the child must execute the exact memory regression"
        );
        return;
    }
    let mib: i64 = std::env::var("MDK_RETAINED_MUTATION_MEMORY_MIB")
        .unwrap_or_else(|_| "16".to_owned())
        .parse()
        .unwrap();
    assert!((16..=512).contains(&mib));
    let body_len = mib * 1024 * 1024;
    let _trace = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::INFO)
            .finish(),
    );
    const MAX_EXTRA: i64 = 4 * 1024 * 1024;
    for declared in [true, false] {
        for cascade in [false, true] {
            let (_directory, mut connection) = encrypted_fixture();
            connection.execute_batch("PRAGMA cache_size=-512; PRAGMA secure_delete=ON;
                CREATE TABLE retained_attachment_bytes(token BLOB PRIMARY KEY REFERENCES attachment_acquisition(token) ON DELETE CASCADE,bytes BLOB NOT NULL CHECK(length(bytes)<=536870912));
                CREATE TABLE attachment_retention_usage(id INTEGER PRIMARY KEY,byte_count INTEGER);
                CREATE TRIGGER attachment_bytes_added AFTER INSERT ON retained_attachment_bytes BEGIN SELECT 1; END;
                CREATE TRIGGER attachment_bytes_removed AFTER DELETE ON retained_attachment_bytes BEGIN SELECT 1; END;
                CREATE TRIGGER attachment_bytes_updated AFTER UPDATE OF bytes ON retained_attachment_bytes BEGIN SELECT 1; END;").unwrap();
            connection
                .execute(
                    "INSERT INTO retained_attachment_bytes VALUES(x'01',zeroblob(?1))",
                    [body_len],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO attachment_retention_usage VALUES(1,?1)",
                    [body_len],
                )
                .unwrap();
            let transaction = connection.transaction().unwrap();
            migration_0104_file_attachment_retention::apply(&transaction).unwrap();
            transaction.commit().unwrap();
            if declared {
                connection
                    .execute(
                        "UPDATE retained_attachment_bytes SET byte_len=length(bytes)",
                        [],
                    )
                    .unwrap();
            }
            connection.execute_batch("PRAGMA shrink_memory").unwrap();
            let delete = if cascade {
                "DELETE FROM attachment_acquisition"
            } else {
                "DELETE FROM retained_attachment_bytes"
            };
            let transaction = connection.transaction().unwrap();
            let peak = native_sqlite_allocation_peak(|| {
                transaction.execute(delete, []).unwrap();
            });
            assert!(
                peak < MAX_EXTRA,
                "deletion materialized a retained body: declared={declared}, cascade={cascade}, extra_bytes={peak}"
            );
            tracing::info!(target: "storage_sqlite::mutation_memory", method = "retained_delete",
                mib, declared, cascade, extra_bytes = peak, "synthetic deletion allocation bound verified");
            transaction.rollback().unwrap();
            assert_eq!(
                connection
                    .query_row(
                        "SELECT byte_count FROM attachment_retention_usage",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                body_len
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT length(bytes) FROM retained_attachment_bytes",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                body_len
            );
            if !cascade {
                let transaction = connection.transaction().unwrap();
                let peak = native_sqlite_allocation_peak(|| {
                    transaction
                        .execute(
                            "UPDATE retained_attachment_bytes SET bytes=x'010203',byte_len=3",
                            [],
                        )
                        .unwrap();
                });
                assert!(
                    peak < MAX_EXTRA,
                    "replacement materialized the old retained body: declared={declared}, extra_bytes={peak}"
                );
                tracing::info!(target: "storage_sqlite::mutation_memory", method = "retained_replace",
                    mib, declared, extra_bytes = peak, "synthetic replacement allocation bound verified");
                assert_eq!(
                    transaction
                        .query_row(
                            "SELECT byte_count FROM attachment_retention_usage",
                            [],
                            |r| r.get::<_, i64>(0)
                        )
                        .unwrap(),
                    3
                );
                transaction.rollback().unwrap();
            }
            connection.execute(delete, []).unwrap();
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
    }
}

/// Reset the linked SQLCipher allocator high-water mark around one statement, excluding fixture construction.
fn native_sqlite_allocation_peak(operation: impl FnOnce()) -> i64 {
    // SAFETY: These SQLite status APIs take no pointers and are called only in the isolated single-test child.
    let baseline = unsafe { rusqlite::ffi::sqlite3_memory_used() };
    assert!(
        baseline > 0,
        "native SQLite allocation tracking must be enabled"
    );
    // SAFETY: Resetting this process-global counter is isolated from every other test process.
    unsafe { rusqlite::ffi::sqlite3_memory_highwater(1) };
    operation();
    // SAFETY: The same pointer-free status API reads the peak from the just-completed statement.
    unsafe { rusqlite::ffi::sqlite3_memory_highwater(0) }.saturating_sub(baseline)
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
        suspend_foreign_keys:
            crate::base::migrations::migration_0105_file_attachment_partials::SUSPEND_FOREIGN_KEYS,
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
        suspend_foreign_keys:
            crate::base::migrations::migration_0105_file_attachment_partials::SUSPEND_FOREIGN_KEYS,
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

/// Build either physical 0104 layout through its actual migration body, preserving the original fixture.
fn media_layout_fixture(
    published: bool,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    SqlCipherKey,
    Connection,
) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("prior.sqlite");
    fs_private::ensure_private_db_files(&path).unwrap();
    let mut connection = Connection::open(&path).unwrap();
    let key = SqlCipherKey::new("synthetic-prior-store".to_owned()).unwrap();
    open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
    connection
        .execute_batch(include_str!("../../../fixtures/account-v0.10.4.sql"))
        .unwrap();
    let prior: Vec<_> = MIGRATIONS
        .iter()
        .map(|m| Migration {
            version: m.version,
            name: m.name,
            suspend_foreign_keys: m.suspend_foreign_keys,
            apply: if published {
                match m.version {
                    104 => prior::retained,
                    105 => prior::partial,
                    _ => m.apply,
                }
            } else {
                m.apply
            },
        })
        .collect();
    run_with_summary(&mut connection, &prior).unwrap();
    (root, path, key, connection)
}

#[test]
fn published_media_schema_reopens_without_rewriting_or_reapplying() {
    let (_root, path, key, connection) = media_layout_fixture(true);
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

/// Legacy promotion uses the public byte-array ceiling on both layouts, before allocating a BLOB.
#[test]
fn physical_media_layouts_share_legacy_staging_ceiling() {
    for published in [false, true] {
        let (_root, _path, _key, connection) = media_layout_fixture(published);
        let (group, message): (String, String) = connection
            .query_row(
                "SELECT group_id_hex,message_id_hex FROM app_events LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let staged = [2u8; 16];
        let retained = [3u8; 16];
        connection.execute("INSERT INTO outgoing_attachment_uploads(token,group_id_hex,source_epoch,plaintext_digest,bytes,expires_at) VALUES(?1,?2,1,zeroblob(32),x'010203',1000)", params![staged,group]).unwrap();
        connection.execute("INSERT INTO attachment_acquisition(token,group_id_hex,message_id_hex,attachment_index,source_message_id_hex,source_epoch,slot_json,plaintext_digest,state,due) VALUES(?1,?2,?3,0,?3,1,'{}',zeroblob(32),3,NULL)",params![retained,group,message]).unwrap();
        crate::app::attachment_acquisition::copy_staged_body_for_test(
            &connection,
            &staged,
            &retained,
            3,
        )
        .unwrap();
        let before = connection.total_changes();
        let result = crate::app::attachment_acquisition::copy_staged_body_for_test(
            &connection,
            &staged,
            &[4u8; 16],
            crate::MAX_RETAINED_ATTACHMENT_BYTES as u64 + 1,
        );
        assert!(matches!(
            result,
            Err(cgka_traits::StorageError::InvalidAttachmentBody(
                "retained attachment exceeds byte-array storage bound"
            ))
        ));
        assert_eq!(connection.total_changes(), before);
        assert_eq!(
            connection
                .query_row(
                    "SELECT bytes FROM retained_attachment_bytes WHERE token=?1",
                    [retained],
                    |row| row.get::<_, Vec<u8>>(0)
                )
                .unwrap(),
            vec![1, 2, 3]
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT byte_count FROM attachment_retention_usage WHERE id=1",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            6
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }
}

/// An arbitrary migration version/table name can request FK-safe rebuilding while preserving the prior setting.
#[test]
fn declared_foreign_key_scope_preserves_children_and_original_mode() {
    for enabled in [false, true] {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER REFERENCES parent(id) ON DELETE CASCADE); INSERT INTO parent VALUES(1); INSERT INTO child VALUES(1);").unwrap();
        connection
            .pragma_update(None, "foreign_keys", enabled)
            .unwrap();
        let migration = Migration {
            version: 1,
            name: "synthetic_parent_rebuild",
            suspend_foreign_keys: &["child"],
            apply: |tx| {
                tx.execute_batch("CREATE TABLE replacement(id INTEGER PRIMARY KEY); INSERT INTO replacement SELECT * FROM parent; DROP TABLE parent; ALTER TABLE replacement RENAME TO parent;").storage()
            },
        };
        assert_eq!(run_with_summary(&mut connection, &[migration]).unwrap(), 1);
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM child", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
                .unwrap(),
            enabled
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }
}

/// A declared-table violation rolls back the body and ledger even when enforcement was originally disabled.
#[test]
fn declared_foreign_key_scope_rejects_orphans_and_restores_mode() {
    for enabled in [false, true] {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER REFERENCES parent(id) ON DELETE CASCADE); INSERT INTO parent VALUES(1); INSERT INTO child VALUES(1);").unwrap();
        connection
            .pragma_update(None, "foreign_keys", enabled)
            .unwrap();
        let migration = Migration {
            version: 1,
            name: "synthetic_invalid_rebuild",
            suspend_foreign_keys: &["child"],
            apply: |tx| tx.execute_batch("DELETE FROM parent;").storage(),
        };
        assert!(run_with_summary(&mut connection, &[migration]).is_err());
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM parent", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM child", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM cgka_schema_migrations", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
                .unwrap(),
            enabled
        );
    }
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
        suspend_foreign_keys:
            crate::base::migrations::migration_0105_file_attachment_partials::SUSPEND_FOREIGN_KEYS,
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
        suspend_foreign_keys:
            crate::base::migrations::migration_0105_file_attachment_partials::SUSPEND_FOREIGN_KEYS,
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
