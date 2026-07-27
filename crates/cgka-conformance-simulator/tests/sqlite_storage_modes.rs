use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use cgka_conformance_simulator::{ClientBuilder, HarnessStorageMode, TransportBus};
use cgka_traits::storage::{GroupStorage, StorageProvider};
use storage_sqlite::{
    SqlCipherHardening, SqlCipherKey, SqliteAccountStorage, SqliteStorageOptions,
    open_hardened_sqlcipher,
};

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

#[tokio::test]
async fn encrypted_file_restart_closes_reopens_and_hydrates_group_state() {
    let dir = tempfile::tempdir().expect("storage directory");
    let path = dir.path().join("alice.sqlite3");
    let key = SqlCipherKey::new("conformance explicit file key").expect("SQLCipher key");
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice"))
        .file_backed_storage(&path, key, SqliteStorageOptions::default())
        .attach(&bus);
    let member_id = alice.member_id();

    let (group_id, pending) = alice
        .create_group("file-backed", Vec::new(), Vec::new())
        .await;
    alice.confirm(pending).await;
    let before = alice
        .storage()
        .get_group(&group_id)
        .expect("group persisted before restart");

    alice.restart();

    assert_eq!(alice.member_id(), member_id);
    assert_eq!(alice.epoch(), before.epoch);
    assert_eq!(
        alice
            .storage()
            .get_group(&group_id)
            .expect("group persisted after restart"),
        before
    );
    assert_eq!(alice.database_path(), Some(path.as_path()));

    let bytes = std::fs::read(&path).expect("read encrypted database");
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "SQLCipher database must not expose a plaintext SQLite header"
    );

    let inspection = rusqlite::Connection::open(&path).expect("open inspection connection");
    let inspection_key =
        SqlCipherKey::new("conformance explicit file key").expect("inspection SQLCipher key");
    open_hardened_sqlcipher(&inspection, &inspection_key, SqlCipherHardening::default())
        .expect("key inspection connection");
    let journal_mode: String = inspection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("read journal mode");
    let synchronous: i64 = inspection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .expect("read synchronous mode");
    assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(synchronous, 2, "production default must be FULL");
}

#[tokio::test]
async fn encrypted_file_harness_write_retries_a_busy_writer() {
    let dir = tempfile::tempdir().expect("storage directory");
    let path = dir.path().join("busy.sqlite3");
    let options = SqliteStorageOptions {
        busy_timeout_ms: 50,
        ..SqliteStorageOptions::default()
    };
    let key = SqlCipherKey::new("conformance busy key").expect("SQLCipher key");
    let bus = TransportBus::ordered();
    let mut alice = ClientBuilder::new(pad32(b"alice-busy"))
        .file_backed_storage(&path, key, options.clone())
        .attach(&bus);

    let peer_key = SqlCipherKey::new("conformance busy key").expect("peer SQLCipher key");
    let peer = SqliteAccountStorage::open_encrypted_with_options(&path, &peer_key, options)
        .expect("peer storage opens");
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let blocker = thread::spawn(move || {
        peer.with_transaction(|_| -> Result<(), cgka_traits::StorageError> {
            ready_tx.send(()).expect("signal writer lock");
            release_rx.recv().expect("release writer lock");
            Ok(())
        })
        .expect("blocking transaction");
    });
    ready_rx.recv().expect("writer lock acquired");

    let releaser = thread::spawn(move || {
        thread::sleep(Duration::from_millis(120));
        release_tx.send(()).expect("release blocker");
    });
    let started = Instant::now();
    let key_package = alice.fresh_key_package().await;
    let elapsed = started.elapsed();

    releaser.join().expect("releaser exits");
    blocker.join().expect("blocker exits");
    assert!(!key_package.bytes().is_empty());
    assert!(
        elapsed >= Duration::from_millis(50),
        "operation must outlive the first busy timeout before retrying: {elapsed:?}"
    );
}

#[test]
fn storage_mode_parser_accepts_cli_names() {
    assert_eq!(
        HarnessStorageMode::parse("memory").expect("memory parses"),
        HarnessStorageMode::InMemorySqlite
    );
    assert_eq!(
        HarnessStorageMode::parse("file").expect("file parses"),
        HarnessStorageMode::TempFileBackedSqlite
    );
}
