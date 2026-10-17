use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Cursor;
use std::path::PathBuf;

use media_store::conformance::{self, Harness};
use media_store::{
    CheckpointTarget, MEDIA_DIRECTORY, MediaStore, PromoteTarget, PublishOutcome, StageTarget,
};
use sha2::{Digest, Sha256};

use super::*;
use crate::{
    AttachmentAcquisition, AttachmentAssetRef, AttachmentDemand, AttachmentHistoryEntry,
    AttachmentPartialIdentity, SqlCipherKey, SqliteAccountStorage, StoredAppEvent,
};

const GROUP: &str = "abababababababababababababababab";
const NOW: u64 = 1_000;

struct SqliteHarness {
    dir: tempfile::TempDir,
    key: SqlCipherKey,
    storage: SqliteAccountStorage,
    slots: RefCell<HashMap<u32, (Vec<u8>, AttachmentAssetRef)>>,
    /// Each slot's claimed download attempt, for its checkpoint target.
    jobs: RefCell<HashMap<u32, AttachmentAcquisition>>,
    /// Each staging slot's sent message and outgoing upload token.
    uploads: RefCell<HashMap<u32, (String, Vec<u8>)>>,
}

impl SqliteHarness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new(hex::encode([0x6b; 32])).unwrap();
        let storage =
            SqliteAccountStorage::open_encrypted(dir.path().join("session.sqlite"), &key).unwrap();
        storage
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
                [GROUP],
            )
            .unwrap();
        Self {
            dir,
            key,
            storage,
            slots: RefCell::new(HashMap::new()),
            jobs: RefCell::new(HashMap::new()),
            uploads: RefCell::new(HashMap::new()),
        }
    }

    /// A real attachment slot (acquisition token) per test slot number.
    fn token(&self, slot: u32) -> Vec<u8> {
        if let Some((token, _)) = self.slots.borrow().get(&slot) {
            return token.clone();
        }
        let message = format!("{:064x}", slot + 1);
        let digest = [9; 32];
        let tag = vec![
            "imeta".to_owned(),
            "m image/png".to_owned(),
            format!("x {}", hex::encode(digest)),
        ];
        self.storage
            .app_storage()
            .record_app_event(&StoredAppEvent {
                group_id_hex: GROUP.into(),
                message_id_hex: message.clone(),
                source_message_id_hex: Some(message.clone()),
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
        let entry = AttachmentHistoryEntry {
            emoji_tags: Vec::new(),
            message_id_hex: message.clone(),
            attachment_index: 0,
            source_message_id_hex: message.clone(),
            source_epoch: Some(1),
            sender: "author".into(),
            timeline_at: NOW,
            received_at: NOW,
            slot: serde_json::to_value(&tag).unwrap(),
        };
        let AttachmentDemand::Requested(asset) = self
            .storage
            .app_storage()
            .request_attachment_acquisition(GROUP, &entry, digest, NOW)
            .unwrap()
        else {
            panic!("the slot's acquisition is requested");
        };
        let token: Vec<u8> = self
            .storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT token FROM attachment_acquisition WHERE message_id_hex=?1",
                [&message],
                |r| r.get(0),
            )
            .unwrap();
        self.slots.borrow_mut().insert(slot, (token.clone(), asset));
        token
    }

    /// `slot`'s claimed download attempt, claiming it on first use.
    fn job(&self, slot: u32) -> AttachmentAcquisition {
        if let Some(job) = self.jobs.borrow().get(&slot) {
            return job.clone();
        }
        self.token(slot);
        let asset = self.slots.borrow()[&slot].1.clone();
        let job = self
            .storage
            .app_storage()
            .claim_attachment_acquisition(&asset, NOW, NOW + 1_000)
            .unwrap()
            .expect("the slot's download is claimed");
        self.jobs.borrow_mut().insert(slot, job.clone());
        job
    }

    /// A sent message for staging slot `slot` and an outgoing upload bound
    /// to its attachment's source descriptor, created on first use.
    fn upload(&self, slot: u32) -> (String, Vec<u8>) {
        if let Some(upload) = self.uploads.borrow().get(&slot) {
            return upload.clone();
        }
        let message = format!("{:064x}", slot + 0x1000);
        let tag = vec![
            "imeta".to_owned(),
            "m image/png".to_owned(),
            format!("x {}", hex::encode([8; 32])),
        ];
        self.storage
            .app_storage()
            .record_app_event(&StoredAppEvent {
                group_id_hex: GROUP.into(),
                message_id_hex: message.clone(),
                source_message_id_hex: Some(message.clone()),
                source_epoch: Some(1),
                direction: "sent".into(),
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
        let token = self
            .storage
            .app_storage()
            .reserve_attachment_upload(GROUP, 1, NOW)
            .unwrap()
            .expect("an upload slot is free");
        self.storage
            .lock()
            .unwrap()
            .execute(
                "UPDATE outgoing_attachment_uploads SET slot_json=?2 WHERE token=?1",
                rusqlite::params![token, serde_json::to_string(&tag).unwrap()],
            )
            .unwrap();
        self.uploads
            .borrow_mut()
            .insert(slot, (message.clone(), token.clone()));
        (message, token)
    }

    fn sql(&self, sql: &str, param: &[u8]) {
        self.storage.lock().unwrap().execute(sql, [param]).unwrap();
    }
}

impl Harness for SqliteHarness {
    type Catalog = SqliteMediaCatalog;

    fn root(&self) -> PathBuf {
        self.dir.path().join(MEDIA_DIRECTORY)
    }

    fn catalog(&self) -> SqliteMediaCatalog {
        SqliteMediaCatalog::new(self.storage.app_storage())
    }

    fn target(&self, slot: u32) -> Box<dyn PublishTarget + '_> {
        Box::new(SlotPublication::new(
            self.storage.app_storage(),
            self.token(slot),
        ))
    }

    /// Deleting the acquisition, as removal and source invalidation do.
    fn supersede(&self, slot: u32) {
        self.sql(
            "DELETE FROM attachment_acquisition WHERE token=?1",
            &self.token(slot),
        );
    }

    fn release(&self, slot: u32) -> Vec<FileId> {
        self.storage
            .app_storage()
            .release_media_reference(&self.token(slot))
            .unwrap()
    }

    fn delete_row(&self, id: FileId) {
        self.sql("DELETE FROM media_files WHERE id=?1", id.as_bytes());
    }

    fn reset(&self) {
        self.storage
            .lock()
            .unwrap()
            .execute(
                "UPDATE chat_presentation_meta SET store_epoch=randomblob(16) WHERE id=1",
                [],
            )
            .unwrap();
    }

    fn restart(&mut self) {
        self.storage.close().unwrap();
        self.storage =
            SqliteAccountStorage::open_encrypted(self.dir.path().join("session.sqlite"), &self.key)
                .unwrap();
    }

    fn checkpoint(&self, slot: u32) -> Box<dyn CheckpointTarget + '_> {
        let identity = AttachmentPartialIdentity {
            ciphertext_digest: [1; 32],
            locator_digest: [2; 32],
            etag: "\"tag\"".into(),
            total: 100,
        };
        Box::new(self.storage.app_storage().attachment_checkpoint(
            &self.job(slot),
            identity,
            || NOW,
        ))
    }

    /// A worker restart requeues the claimed job; claiming it again starts
    /// a newer attempt and fences the old one.
    fn supersede_checkpoint(&self, slot: u32) {
        self.job(slot);
        self.jobs.borrow_mut().remove(&slot);
        self.storage
            .app_storage()
            .resume_attachment_acquisitions(NOW, 64)
            .unwrap();
        self.job(slot);
    }

    fn end_checkpoint(&self, slot: u32) {
        self.sql(
            "DELETE FROM attachment_partial WHERE token=?1",
            &self.token(slot),
        );
    }

    fn stage_target(&self, slot: u32) -> Box<dyn StageTarget + '_> {
        Box::new(
            self.storage
                .app_storage()
                .attachment_upload_stage(&self.upload(slot).1),
        )
    }

    fn promote_target(&self, slot: u32) -> Box<dyn PromoteTarget + '_> {
        let (message, token) = self.upload(slot);
        Box::new(self.storage.app_storage().attachment_upload_promotion(
            GROUP,
            &message,
            &token,
            || NOW,
        ))
    }

    /// Expiry, an abandoned send or group deletion: the upload row goes.
    fn end_stage_owner(&self, slot: u32) {
        self.sql(
            "DELETE FROM outgoing_attachment_uploads WHERE token=?1",
            &self.upload(slot).1,
        );
    }
}

#[test]
fn the_sqlcipher_catalog_passes_the_conformance_suite() {
    conformance::run_all(&SqliteHarness::new);
}

#[test]
fn deleting_a_key_relies_on_secure_delete() {
    let harness = SqliteHarness::new();
    let secure_delete: i64 = harness
        .storage
        .lock()
        .unwrap()
        .query_row("PRAGMA secure_delete", [], |r| r.get(0))
        .unwrap();
    assert_eq!(secure_delete, 1);
}

fn publish(
    harness: &SqliteHarness,
    store: &MediaStore<SqliteMediaCatalog>,
    slot: u32,
    body: &[u8],
) -> FileId {
    match store
        .publish(
            harness.target(slot).as_ref(),
            Category::Retained,
            &mut Cursor::new(body),
            body.len() as u64,
            Sha256::digest(body).into(),
            NOW,
            &|| false,
        )
        .unwrap()
    {
        PublishOutcome::Published(id) => id,
        other => panic!("expected a new file, got {other:?}"),
    }
}

#[test]
fn references_require_ready_files_and_repointing_releases_the_old_file() {
    let harness = SqliteHarness::new();
    let store = MediaStore::new(harness.root(), harness.catalog());
    let token = harness.token(9);
    let pending = FileId([3; 16]);
    harness
        .catalog()
        .insert_pending(&NewFile {
            id: pending,
            key: media_store::FileKey::from_bytes([1; 32]),
            category: Category::Retained,
            byte_len: 1,
            digest: [2; 32],
            created_at: NOW,
        })
        .unwrap();
    assert!(
        harness
            .storage
            .connection
            .with_transaction(|| {
                let conn = harness.storage.lock()?;
                attach_slot(&conn, &token, pending)
            })
            .is_err()
    );

    let old = publish(&harness, &store, 9, b"old");
    let new = publish(&harness, &store, 9, b"new");
    // The second publish re-pointed slot 9, releasing the old file's key.
    assert_eq!(store.file_state(&old).unwrap(), None);
    assert_eq!(store.file_state(&new).unwrap(), Some(FileState::Ready));
}
