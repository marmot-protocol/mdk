use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::*;
use crate::{
    AttachmentDemand, AttachmentHistoryEntry, SqlCipherKey, SqliteAccountStorage, StoredAppEvent,
};

const GROUP: &str = "abababababababababababababababab";
const NOW: u64 = 1_000;

struct Fixture {
    _dir: tempfile::TempDir,
    db: PathBuf,
    root: PathBuf,
    key: SqlCipherKey,
    storage: SqliteAccountStorage,
    store: MediaFileStore,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("session.sqlite");
        let root = dir.path().join("media");
        let key = SqlCipherKey::new(hex::encode([0x6b; 32])).unwrap();
        let storage = SqliteAccountStorage::open_encrypted(&db, &key).unwrap();
        let store = MediaFileStore::new(storage.clone(), &root);
        Self {
            _dir: dir,
            db,
            root,
            key,
            storage,
            store,
        }
    }

    /// Process death and restart: a fresh handle with no in-flight publishes.
    fn restart(&mut self) {
        self.storage.close().unwrap();
        self.storage = SqliteAccountStorage::open_encrypted(&self.db, &self.key).unwrap();
        self.store = MediaFileStore::new(self.storage.clone(), &self.root);
    }

    fn publish(&self, body: &[u8]) -> MediaPublishOutcome {
        self.store
            .publish_from_reader(
                MediaCategory::Retained,
                &mut Cursor::new(body),
                body.len() as u64,
                digest(body),
                NOW,
                &|| false,
            )
            .unwrap()
    }

    fn published(&self, body: &[u8]) -> MediaFileId {
        match self.publish(body) {
            MediaPublishOutcome::Published(id) => id,
            other => panic!("expected a new file, got {other:?}"),
        }
    }

    fn rows(&self) -> i64 {
        self.storage
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM media_files", [], |r| r.get(0))
            .unwrap()
    }

    fn files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let Ok(shards) = std::fs::read_dir(&self.root) else {
            return files;
        };
        for shard in shards {
            for file in std::fs::read_dir(shard.unwrap().path()).unwrap() {
                files.push(file.unwrap().path());
            }
        }
        files
    }

    fn read_all(&self, id: &MediaFileId) -> Option<Vec<u8>> {
        let mut reader = self.store.open_reader(id).unwrap()?;
        let mut body = Vec::new();
        reader.read_to_end(&mut body).unwrap();
        Some(body)
    }

    /// Sweeps to completion and returns the summed report.
    fn sweep(&self) -> MediaSweepReport {
        let mut total = MediaSweepReport::default();
        loop {
            let batch = self.store.sweep(2).unwrap();
            total.rows_checked += batch.rows_checked;
            total.files_checked += batch.files_checked;
            total.pending_removed += batch.pending_removed;
            total.orphans_unlinked += batch.orphans_unlinked;
            total.lost_marked += batch.lost_marked;
            if batch.complete {
                total.complete = true;
                return total;
            }
        }
    }

    /// A real attachment slot whose acquisition token can hold a reference.
    fn slot(&self, message: &str) -> Vec<u8> {
        let body_digest = [9; 32];
        let tag = vec![
            "imeta".to_owned(),
            "m image/png".to_owned(),
            format!("x {}", hex::encode(body_digest)),
        ];
        let conn = self.storage.lock().unwrap();
        conn.execute(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0) ON CONFLICT DO NOTHING",
            [GROUP],
        )
        .unwrap();
        drop(conn);
        self.storage
            .record_app_event(&StoredAppEvent {
                group_id_hex: GROUP.into(),
                message_id_hex: message.into(),
                source_message_id_hex: Some(message.into()),
                source_epoch: Some(1),
                direction: "received".into(),
                sender: "author".into(),
                plaintext: String::new(),
                kind: 9,
                tags: vec![tag.clone()],
                recorded_at: NOW,
                received_at: NOW,
                origin_commit_id: None,
                moderation_grant: false,
            })
            .unwrap();
        let selected = AttachmentHistoryEntry {
            emoji_tags: Vec::new(),
            message_id_hex: message.into(),
            attachment_index: 0,
            source_message_id_hex: message.into(),
            source_epoch: Some(1),
            sender: "author".into(),
            timeline_at: NOW,
            received_at: NOW,
            slot: serde_json::to_value(&tag).unwrap(),
        };
        assert!(matches!(
            self.storage
                .request_attachment_acquisition(GROUP, &selected, body_digest, NOW)
                .unwrap(),
            AttachmentDemand::Requested(_)
        ));
        self.storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT token FROM attachment_acquisition WHERE message_id_hex=?1",
                [message],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn attach(&self, token: &[u8], id: MediaFileId) {
        self.store.attach_reference(token, id).unwrap();
    }

    fn reset_store(&self) {
        self.storage
            .lock()
            .unwrap()
            .execute(
                "UPDATE chat_presentation_meta SET store_epoch=randomblob(16) WHERE id=1",
                [],
            )
            .unwrap();
    }
}

fn digest(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

fn body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + i / 509) as u8).collect()
}

/// A body source that must never be read.
struct Unread;

impl Read for Unread {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("a digest match must not read the body")
    }
}

#[test]
fn published_files_read_back_and_identical_content_is_reused() {
    let fixture = Fixture::new();
    let content = body(200_000);
    let id = fixture.published(&content);
    assert_eq!(
        fixture.store.file_state(&id).unwrap(),
        Some(MediaFileState::Ready)
    );
    assert_eq!(fixture.read_all(&id).unwrap(), content);
    let mut window = vec![0; 100];
    assert_eq!(
        fixture.store.read_at(&id, 70_000, &mut window).unwrap(),
        Some(100)
    );
    assert_eq!(window, content[70_000..70_100]);

    // Only the file's name is on disk; it reveals nothing about the content.
    let path = fixture.store.path(&id);
    assert_eq!(fixture.files(), vec![path.clone()]);
    assert_eq!(
        path.file_name().unwrap().to_str().unwrap(),
        hex::encode(id.as_bytes())
    );
    assert!(
        !std::fs::read(&path)
            .unwrap()
            .windows(32)
            .any(|w| w == &content[..32])
    );

    assert_eq!(
        fixture
            .store
            .publish_from_reader(
                MediaCategory::Retained,
                &mut Unread,
                content.len() as u64,
                digest(&content),
                NOW,
                &|| false,
            )
            .unwrap(),
        MediaPublishOutcome::Existing(id)
    );
    assert_eq!(fixture.rows(), 1);
}

#[cfg(unix)]
#[test]
fn media_directories_and_files_are_private_at_creation() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let id = fixture.published(b"private");
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&fixture.root), 0o700);
    assert_eq!(mode(fixture.store.path(&id).parent().unwrap()), 0o700);
    assert_eq!(mode(&fixture.store.path(&id)), 0o600);
}

#[test]
fn rejected_bodies_leave_no_row_and_no_file() {
    let fixture = Fixture::new();
    let content = body(100_000);
    let publish = |bytes: &[u8], declared: u64, cancelled: &dyn Fn() -> bool| {
        fixture.store.publish_from_reader(
            MediaCategory::Retained,
            &mut Cursor::new(bytes),
            declared,
            digest(&content),
            NOW,
            cancelled,
        )
    };
    let mut wrong = content.clone();
    wrong[5] ^= 1;
    assert!(matches!(
        publish(&wrong, wrong.len() as u64, &|| false),
        Err(StorageError::Corruption(_))
    ));
    assert!(publish(&content, content.len() as u64 - 1, &|| false).is_err());
    assert!(publish(&content[..10], content.len() as u64, &|| false).is_err());
    assert!(publish(&content, content.len() as u64, &|| true).is_err());
    assert_eq!(fixture.rows(), 0);
    assert!(fixture.files().is_empty());
    assert_eq!(fixture.sweep().pending_removed, 0);
}

/// Crash after step 1 of publish: a pending row and no file.
#[test]
fn crash_before_the_file_exists_drops_the_pending_row() {
    let mut fixture = Fixture::new();
    let (id, _key, in_flight) = fixture
        .store
        .insert_pending(MediaCategory::Retained, 5, &digest(b"bytes"), NOW)
        .unwrap();
    std::mem::forget(in_flight);
    fixture.restart();
    let report = fixture.sweep();
    assert_eq!((report.pending_removed, report.orphans_unlinked), (1, 0));
    assert_eq!(fixture.store.file_state(&id).unwrap(), None);
    assert_eq!(
        fixture.sweep(),
        MediaSweepReport {
            complete: true,
            ..Default::default()
        }
    );
}

/// Crash during step 2: a pending row and a partly written file.
#[test]
fn crash_mid_write_drops_the_row_and_the_partial_file() {
    let mut fixture = Fixture::new();
    let content = body(300_000);
    let (id, key, in_flight) = fixture
        .store
        .insert_pending(
            MediaCategory::Retained,
            content.len() as u64,
            &digest(&content),
            NOW,
        )
        .unwrap();
    fs_private::create_dir_all_private(&fixture.store.shard_dir(id.as_bytes()[0])).unwrap();
    let file = fs_private::create_new_private(&fixture.store.path(&id)).unwrap();
    let mut writer = MediaFileWriter::new(file, &key, id.as_bytes()).unwrap();
    writer.write_all(&content[..150_000]).unwrap();
    drop(writer);
    std::mem::forget(in_flight);
    fixture.restart();
    assert_eq!(fixture.files().len(), 1);
    let report = fixture.sweep();
    assert_eq!((report.pending_removed, report.orphans_unlinked), (1, 0));
    assert_eq!(fixture.rows(), 0);
    assert!(fixture.files().is_empty());
}

/// Crash after step 2, before the ready commit: a complete synced file whose
/// row is still pending is discarded, never adopted.
#[test]
fn crash_before_the_ready_commit_drops_the_complete_file() {
    let mut fixture = Fixture::new();
    let content = body(70_000);
    let (id, key, in_flight) = fixture
        .store
        .insert_pending(
            MediaCategory::Retained,
            content.len() as u64,
            &digest(&content),
            NOW,
        )
        .unwrap();
    fixture
        .store
        .write_body(
            &id,
            &key,
            &mut Cursor::new(&content),
            content.len() as u64,
            &digest(&content),
            &|| false,
        )
        .unwrap();
    std::mem::forget(in_flight);
    fixture.restart();
    assert_eq!(fixture.store.open_reader(&id).unwrap().map(|_| ()), None);
    let report = fixture.sweep();
    assert_eq!((report.pending_removed, report.orphans_unlinked), (1, 0));
    assert!(fixture.files().is_empty());
}

/// Crash after the ready commit: nothing to repair.
#[test]
fn crash_after_the_ready_commit_keeps_the_file() {
    let mut fixture = Fixture::new();
    let content = body(10_000);
    let id = fixture.published(&content);
    fixture.restart();
    assert_eq!(
        fixture.sweep(),
        MediaSweepReport {
            rows_checked: 1,
            files_checked: 1,
            complete: true,
            ..Default::default()
        }
    );
    assert_eq!(fixture.read_all(&id).unwrap(), content);
}

/// Crash between a key-first delete's commit and its unlink: a file with no
/// row is unlinked.
#[test]
fn crash_between_key_deletion_and_unlink_unlinks_the_orphan() {
    let mut fixture = Fixture::new();
    let id = fixture.published(b"orphan");
    fixture
        .storage
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM media_files WHERE id=?1",
            [id.as_bytes().as_slice()],
        )
        .unwrap();
    fixture.restart();
    let report = fixture.sweep();
    assert_eq!((report.pending_removed, report.orphans_unlinked), (0, 1));
    assert!(fixture.files().is_empty());
}

/// A ready row whose file vanished becomes lost, distinct from removal, and
/// its key is zeroed.
#[test]
fn missing_ready_files_are_marked_lost_by_reads_and_the_sweep() {
    let fixture = Fixture::new();
    let swept = fixture.published(b"swept");
    let read = fixture.published(b"read");
    std::fs::remove_file(fixture.store.path(&swept)).unwrap();
    std::fs::remove_file(fixture.store.path(&read)).unwrap();

    assert_eq!(fixture.store.read_at(&read, 0, &mut [0; 4]).unwrap(), None);
    assert_eq!(
        fixture.store.file_state(&read).unwrap(),
        Some(MediaFileState::Lost)
    );
    assert_eq!(fixture.sweep().lost_marked, 1);
    assert_eq!(
        fixture.store.file_state(&swept).unwrap(),
        Some(MediaFileState::Lost)
    );
    let zeroed: bool = fixture
        .storage
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*)=2 FROM media_files WHERE state=2 AND file_key=zeroblob(32)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(zeroed);
    // A lost file never blocks republishing the same content.
    assert!(matches!(
        fixture.publish(b"swept"),
        MediaPublishOutcome::Published(_)
    ));
}

#[test]
fn the_sweep_leaves_live_publishes_alone() {
    let fixture = Fixture::new();
    let (id, _key, in_flight) = fixture
        .store
        .insert_pending(MediaCategory::Retained, 1, &digest(b"x"), NOW)
        .unwrap();
    assert_eq!(fixture.sweep().pending_removed, 0);
    assert_eq!(
        fixture.store.file_state(&id).unwrap(),
        Some(MediaFileState::Pending)
    );
    drop(in_flight);
    assert_eq!(fixture.sweep().pending_removed, 1);
}

#[test]
fn the_sweep_ignores_names_it_did_not_create() {
    let fixture = Fixture::new();
    let id = fixture.published(b"kept");
    let shard = fixture.store.path(&id).parent().unwrap().to_path_buf();
    std::fs::write(shard.join("notes.txt"), b"foreign").unwrap();
    // A valid id in the wrong shard is not this store's file either.
    let misplaced = if id.as_bytes()[0] == 0 { "01" } else { "00" };
    std::fs::write(shard.join(format!("{misplaced}{}", "0".repeat(30))), b"x").unwrap();
    assert_eq!(fixture.sweep().orphans_unlinked, 0);
    assert_eq!(fixture.files().len(), 3);
}

#[test]
fn the_last_reference_deletes_the_key_before_the_file() {
    let fixture = Fixture::new();
    let first = fixture.slot("1".repeat(64).as_str());
    let second = fixture.slot("2".repeat(64).as_str());
    let content = body(1_000);
    let id = fixture.published(&content);
    fixture.attach(&first, id);
    fixture.attach(&second, id);

    // Erasing the key relies on secure_delete, which account databases enable.
    let secure_delete: i64 = fixture
        .storage
        .lock()
        .unwrap()
        .query_row("PRAGMA secure_delete", [], |r| r.get(0))
        .unwrap();
    assert_eq!(secure_delete, 1);

    assert!(fixture.store.remove_reference(&first).unwrap());
    assert_eq!(fixture.read_all(&id).unwrap(), content);
    assert!(fixture.store.remove_reference(&second).unwrap());
    assert_eq!(fixture.store.file_state(&id).unwrap(), None);
    assert!(fixture.files().is_empty());
    assert!(!fixture.store.remove_reference(&second).unwrap());
}

#[test]
fn references_require_ready_files_and_repointing_releases_the_old_file() {
    let fixture = Fixture::new();
    let token = fixture.slot("3".repeat(64).as_str());
    let (pending, _key, _in_flight) = fixture
        .store
        .insert_pending(MediaCategory::Retained, 1, &digest(b"p"), NOW)
        .unwrap();
    assert!(fixture.store.attach_reference(&token, pending).is_err());

    let old = fixture.published(b"old");
    let new = fixture.published(b"new");
    fixture.attach(&token, old);
    fixture.attach(&token, old);
    fixture.attach(&token, new);
    assert_eq!(fixture.store.file_state(&old).unwrap(), None);
    assert_eq!(fixture.sweep().orphans_unlinked, 1);
    assert_eq!(fixture.read_all(&new).unwrap(), b"new");
}

#[test]
fn deleting_an_acquisition_releases_its_file_through_the_cascade() {
    let fixture = Fixture::new();
    let token = fixture.slot("4".repeat(64).as_str());
    let id = fixture.published(b"cascade");
    fixture.attach(&token, id);
    fixture
        .storage
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM attachment_acquisition WHERE token=?1",
            [&token],
        )
        .unwrap();
    assert_eq!(fixture.store.file_state(&id).unwrap(), None);
    assert_eq!(fixture.sweep().orphans_unlinked, 1);
    assert!(fixture.files().is_empty());
}

#[test]
fn a_store_reset_destroys_every_key_and_supersedes_live_publishes() {
    let fixture = Fixture::new();
    let token = fixture.slot("5".repeat(64).as_str());
    let referenced = fixture.published(b"referenced");
    fixture.attach(&token, referenced);
    fixture.published(b"unreferenced");

    // The reset lands while a publish is streaming its body.
    struct ResetMidway<'a>(&'a Fixture, Cursor<Vec<u8>>);
    impl Read for ResetMidway<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.1.position() == 0 {
                self.0.reset_store();
            }
            {
                let len = out.len().min(1000);
                self.1.read(&mut out[..len])
            }
        }
    }
    let content = body(5_000);
    let outcome = fixture
        .store
        .publish_from_reader(
            MediaCategory::Retained,
            &mut ResetMidway(&fixture, Cursor::new(content.clone())),
            content.len() as u64,
            digest(&content),
            NOW,
            &|| false,
        )
        .unwrap();
    assert_eq!(outcome, MediaPublishOutcome::Superseded);
    assert_eq!(fixture.rows(), 0);
    assert_eq!(fixture.sweep().orphans_unlinked, 2);
    assert!(fixture.files().is_empty());
}

#[test]
fn terminal_close_stops_media_io_and_restart_reclaims_the_interrupted_publish() {
    let mut fixture = Fixture::new();
    let kept = fixture.published(b"kept");

    struct CloseMidway<'a>(&'a SqliteAccountStorage, Cursor<Vec<u8>>);
    impl Read for CloseMidway<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.1.position() > 0 {
                self.0.close().unwrap();
            }
            {
                let len = out.len().min(1000);
                self.1.read(&mut out[..len])
            }
        }
    }
    let content = body(5_000);
    let storage = fixture.storage.clone();
    let result = fixture.store.publish_from_reader(
        MediaCategory::Retained,
        &mut CloseMidway(&storage, Cursor::new(content.clone())),
        content.len() as u64,
        digest(&content),
        NOW,
        &|| false,
    );
    assert!(matches!(result, Err(StorageError::Closed(_))));
    assert!(matches!(
        fixture.store.read_at(&kept, 0, &mut [0; 1]),
        Err(StorageError::Closed(_))
    ));
    assert!(matches!(
        fixture.store.sweep(1),
        Err(StorageError::Closed(_))
    ));
    assert!(matches!(
        fixture.store.publish_from_reader(
            MediaCategory::Retained,
            &mut Unread,
            1,
            digest(b"x"),
            NOW,
            &|| false,
        ),
        Err(StorageError::Closed(_))
    ));
    assert!(matches!(
        fixture.store.remove_reference(b"t"),
        Err(StorageError::Closed(_))
    ));

    // The interrupted publish left its pending row and partial file behind.
    assert_eq!(fixture.files().len(), 2);
    let db = fixture.db.clone();
    let key = SqlCipherKey::new(hex::encode([0x6b; 32])).unwrap();
    fixture.storage = SqliteAccountStorage::open_encrypted(&db, &key).unwrap();
    fixture.store = MediaFileStore::new(fixture.storage.clone(), &fixture.root);
    let report = fixture.sweep();
    assert_eq!((report.pending_removed, report.orphans_unlinked), (1, 0));
    assert_eq!(fixture.files(), vec![fixture.store.path(&kept)]);
    assert_eq!(fixture.read_all(&kept).unwrap(), b"kept");
}

#[test]
fn a_corrupted_file_fails_verification_instead_of_returning_bytes() {
    let fixture = Fixture::new();
    let id = fixture.published(&body(1_000));
    let path = fixture.store.path(&id);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        fixture.store.read_at(&id, 0, &mut [0; 10]),
        Err(StorageError::Corruption(_))
    ));
    std::fs::write(&path, b"short").unwrap();
    assert!(matches!(
        fixture.store.open_reader(&id).map(|r| r.is_some()),
        Err(StorageError::Corruption(_))
    ));
}
