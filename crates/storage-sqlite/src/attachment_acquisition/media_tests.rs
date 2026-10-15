use std::io::{Cursor, Read};

use media_store::{MEDIA_DIRECTORY, MediaError, MediaStore, PublishOutcome};

use super::*;
use crate::{AttachmentHistoryEntry, SqlCipherKey, SqliteMediaCatalog, StoredAppEvent};

const GROUP: &str = "abababababababababababababababab";
const NOW: u64 = 1_000;
const LEASE: u64 = 1_000_000;

struct Fixture {
    _dir: tempfile::TempDir,
    store: SqliteAccountStorage,
    media: MediaStore<SqliteMediaCatalog>,
}

fn body() -> Vec<u8> {
    (0..150_000_u32).map(|i| (i * 13 + i / 97) as u8).collect()
}

fn digest(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new(hex::encode([0x6b; 32])).unwrap();
        let store =
            SqliteAccountStorage::open_encrypted(dir.path().join("session.sqlite"), &key).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
                [GROUP],
            )
            .unwrap();
        let media = MediaStore::new(
            dir.path().join(MEDIA_DIRECTORY),
            SqliteMediaCatalog::new(store.clone()),
        );
        Self {
            _dir: dir,
            store,
            media,
        }
    }

    fn entry(message: &str, plaintext: &[u8]) -> (StoredAppEvent, AttachmentHistoryEntry) {
        let tag = vec![
            "imeta".to_owned(),
            "m application/octet-stream".to_owned(),
            format!("x {}", hex::encode(digest(plaintext))),
        ];
        let event = StoredAppEvent {
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
        };
        let entry = AttachmentHistoryEntry {
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
        (event, entry)
    }

    /// A recorded message with one attachment whose download is claimed.
    fn claimed(&self, message: &str, plaintext: &[u8]) -> AttachmentAcquisition {
        let (event, entry) = Self::entry(message, plaintext);
        self.store.record_app_event(&event).unwrap();
        let AttachmentDemand::Requested(reference) = self
            .store
            .request_attachment_acquisition(GROUP, &entry, digest(plaintext), NOW)
            .unwrap()
        else {
            panic!("attachment was not requested");
        };
        self.store
            .claim_attachment_acquisition(&reference, NOW, LEASE)
            .unwrap()
            .unwrap()
    }

    fn try_publish(
        &self,
        job: &AttachmentAcquisition,
        body: &mut dyn Read,
        len: u64,
    ) -> Result<PublishOutcome, MediaError> {
        self.media.publish(
            &self.store.attachment_publication(job, &|| NOW),
            Category::Retained,
            body,
            len,
            job.plaintext_digest().unwrap(),
            NOW,
            &|| false,
        )
    }

    fn publish(&self, job: &AttachmentAcquisition, plaintext: &[u8]) -> PublishOutcome {
        self.try_publish(job, &mut Cursor::new(plaintext), plaintext.len() as u64)
            .unwrap()
    }

    /// Reads the whole retained body the way the runtime does: locate it in
    /// the database, then read a media file through the store.
    fn read(&self, job: &AttachmentAcquisition) -> Option<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let window = match self
                .store
                .retained_attachment_read(
                    &job.reference,
                    NOW,
                    body.len() as u64,
                    MAX_ATTACHMENT_LOCAL_READ_BYTES,
                )
                .unwrap()?
            {
                RetainedAttachmentRead::Bytes(bytes) => bytes.to_vec(),
                RetainedAttachmentRead::MediaFile(id) => {
                    let mut window = vec![0; MAX_ATTACHMENT_LOCAL_READ_BYTES];
                    let read = self
                        .media
                        .read_at(&id, body.len() as u64, &mut window)
                        .unwrap()?;
                    window.truncate(read);
                    window
                }
            };
            if window.is_empty() {
                return Some(body);
            }
            body.extend_from_slice(&window);
        }
    }

    fn sweep(&self) {
        while !self.media.sweep(64).unwrap().complete {}
    }

    fn count(&self, table: &str) -> i64 {
        self.store
            .lock()
            .unwrap()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    fn media_files_on_disk(&self) -> usize {
        let root = self._dir.path().join(MEDIA_DIRECTORY);
        let Ok(shards) = std::fs::read_dir(root) else {
            return 0;
        };
        shards
            .map(|shard| std::fs::read_dir(shard.unwrap().path()).unwrap().count())
            .sum()
    }
}

#[test]
fn downloaded_bodies_are_retained_as_media_files_not_database_rows() {
    let fixture = Fixture::new();
    let content = body();
    let message = "1".repeat(64);
    let job = fixture.claimed(&message, &content);
    assert!(matches!(
        fixture.publish(&job, &content),
        PublishOutcome::Published(_)
    ));
    assert_eq!(fixture.read(&job).unwrap(), content);

    // No body, chunk or file-import row: only the key and the reference.
    assert_eq!(fixture.count("retained_attachment_bytes"), 0);
    assert_eq!(fixture.count("retained_attachment_chunks"), 0);
    assert_eq!(fixture.count("media_files"), 1);
    assert_eq!(fixture.count("media_file_refs"), 1);
    assert_eq!(fixture.media_files_on_disk(), 1);
    // The database-only read refuses a media body instead of hiding it.
    assert!(
        fixture
            .store
            .read_retained_attachment(&job.reference, NOW, 0, 16)
            .is_err()
    );

    let status = fixture
        .store
        .attachment_acquisition_status(&job.reference)
        .unwrap()
        .unwrap();
    assert_eq!(status.state, AttachmentAcquisitionState::Ready);
    assert_eq!(status.byte_count, content.len() as u64);
    let asset = fixture
        .store
        .retained_attachment_asset(GROUP, &message, &message, 0, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(asset.byte_count, content.len() as u64);
    let transfer = fixture
        .store
        .attachment_transfer_status(GROUP, &message, &message, 0, NOW, false)
        .unwrap()
        .unwrap();
    assert_eq!(transfer.state, AttachmentTransferState::Ready);
    // A retained media body is not "previously acquired": no re-download.
    assert!(
        !fixture
            .store
            .explicitly_retry_attachment(&job.reference, NOW)
            .unwrap()
    );
}

#[test]
fn the_retained_byte_budget_no_longer_gates_media_publication() {
    let fixture = Fixture::new();
    fixture
        .store
        .lock()
        .unwrap()
        .execute(
            "UPDATE attachment_retention_usage SET byte_count=?1 WHERE id=1",
            [i64::MAX / 2],
        )
        .unwrap();
    let content = body();
    let job = fixture.claimed(&"2".repeat(64), &content);
    assert!(matches!(
        fixture.publish(&job, &content),
        PublishOutcome::Published(_)
    ));
    assert_eq!(fixture.read(&job).unwrap(), content);
}

#[test]
fn a_body_that_fails_its_digest_is_invalid_and_leaves_nothing() {
    let fixture = Fixture::new();
    let content = body();
    let job = fixture.claimed(&"3".repeat(64), &content);
    let mut wrong = content.clone();
    wrong[7] ^= 1;
    let result = fixture.try_publish(&job, &mut Cursor::new(&wrong), wrong.len() as u64);
    assert!(
        matches!(result, Err(MediaError::InvalidBody(_))),
        "{result:?}"
    );
    assert_eq!(fixture.count("media_files"), 0);
    assert_eq!(fixture.media_files_on_disk(), 0);
}

#[test]
fn removal_during_the_write_supersedes_publication_and_keeps_nothing() {
    let fixture = Fixture::new();
    let content = body();
    let message = "4".repeat(64);
    let job = fixture.claimed(&message, &content);

    struct RemoveMidway<'a>(&'a Fixture, &'a str, Cursor<Vec<u8>>);
    impl Read for RemoveMidway<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.2.position() == 0 {
                assert!(
                    self.0
                        .store
                        .remove_local_attachment(GROUP, self.1, 0)
                        .unwrap()
                );
            }
            let len = out.len().min(10_000);
            self.2.read(&mut out[..len])
        }
    }
    let result = fixture
        .try_publish(
            &job,
            &mut RemoveMidway(&fixture, &message, Cursor::new(content.clone())),
            content.len() as u64,
        )
        .unwrap();
    assert_eq!(result, PublishOutcome::Superseded);
    assert_eq!(fixture.count("media_files"), 0);
    assert_eq!(fixture.media_files_on_disk(), 0);
}

#[test]
fn identical_content_is_attached_without_downloading_and_released_by_the_last_removal() {
    let fixture = Fixture::new();
    let content = body();
    let first_message = "5".repeat(64);
    let second_message = "6".repeat(64);
    let first = fixture.claimed(&first_message, &content);
    let PublishOutcome::Published(id) = fixture.publish(&first, &content) else {
        panic!("first publish wrote nothing");
    };

    // The check a worker makes before downloading.
    let second = fixture.claimed(&second_message, &content);
    assert_eq!(
        fixture
            .media
            .attach_existing(
                &fixture.store.attachment_publication(&second, &|| NOW),
                Category::Retained,
                &second.plaintext_digest().unwrap(),
            )
            .unwrap(),
        Some(PublishOutcome::Existing(id))
    );
    assert_eq!(fixture.read(&second).unwrap(), content);
    assert_eq!(fixture.media_files_on_disk(), 1);

    // Removing one slot keeps the shared file; the last removal deletes the
    // key, and the sweep unlinks the file.
    assert!(
        fixture
            .store
            .remove_local_attachment(GROUP, &first_message, 0)
            .unwrap()
    );
    assert_eq!(fixture.read(&second).unwrap(), content);
    assert!(
        fixture
            .store
            .remove_local_attachment(GROUP, &second_message, 0)
            .unwrap()
    );
    assert_eq!(fixture.count("media_files"), 0);
    fixture.sweep();
    assert_eq!(fixture.media_files_on_disk(), 0);
}

#[test]
fn a_digest_without_a_ready_file_downloads_as_usual() {
    let fixture = Fixture::new();
    let content = body();
    let job = fixture.claimed(&"7".repeat(64), &content);
    assert_eq!(
        fixture
            .media
            .attach_existing(
                &fixture.store.attachment_publication(&job, &|| NOW),
                Category::Retained,
                &job.plaintext_digest().unwrap(),
            )
            .unwrap(),
        None
    );
}

#[test]
fn legacy_database_bodies_stay_readable_beside_media_files() {
    let fixture = Fixture::new();
    let content = body();
    let legacy = fixture.claimed(&"8".repeat(64), &content);
    assert_eq!(
        fixture
            .store
            .complete_attachment_acquisition(&legacy, &content, NOW, u64::MAX / 2)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    let mut other = content.clone();
    other[0] ^= 1;
    let media = fixture.claimed(&"9".repeat(64), &other);
    assert!(matches!(
        fixture.publish(&media, &other),
        PublishOutcome::Published(_)
    ));
    assert_eq!(fixture.read(&legacy).unwrap(), content);
    assert_eq!(fixture.read(&media).unwrap(), other);
}
