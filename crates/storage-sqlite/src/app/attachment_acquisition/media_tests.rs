#[cfg(test)]
use crate::SqliteAccountStorage;
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
            SqliteMediaCatalog::new(store.app_storage()),
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
        self.store.app_storage().record_app_event(&event).unwrap();
        let AttachmentDemand::Requested(reference) = self
            .store
            .app_storage()
            .request_attachment_acquisition(GROUP, &entry, digest(plaintext), NOW)
            .unwrap()
        else {
            panic!("attachment was not requested");
        };
        self.store
            .app_storage()
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
            &self
                .store
                .app_storage()
                .attachment_publication(job, &|| NOW),
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
                .app_storage()
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
            .app_storage()
            .read_retained_attachment(&job.reference, NOW, 0, 16)
            .is_err()
    );

    let status = fixture
        .store
        .app_storage()
        .attachment_acquisition_status(&job.reference)
        .unwrap()
        .unwrap();
    assert_eq!(status.state, AttachmentAcquisitionState::Ready);
    assert_eq!(status.byte_count, content.len() as u64);
    let asset = fixture
        .store
        .app_storage()
        .retained_attachment_asset(GROUP, &message, &message, 0, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(asset.byte_count, content.len() as u64);
    let transfer = fixture
        .store
        .app_storage()
        .attachment_transfer_status(GROUP, &message, &message, 0, NOW, false)
        .unwrap()
        .unwrap();
    assert_eq!(transfer.state, AttachmentTransferState::Ready);
    // A retained media body is not "previously acquired": no re-download.
    assert!(
        !fixture
            .store
            .app_storage()
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
                        .app_storage()
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
                &fixture
                    .store
                    .app_storage()
                    .attachment_publication(&second, &|| NOW),
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
            .app_storage()
            .remove_local_attachment(GROUP, &first_message, 0)
            .unwrap()
    );
    assert_eq!(fixture.read(&second).unwrap(), content);
    assert!(
        fixture
            .store
            .app_storage()
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
                &fixture
                    .store
                    .app_storage()
                    .attachment_publication(&job, &|| NOW),
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
            .app_storage()
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

// Manage storage (mdk#2314 step 5) across both layouts.

const OTHER_GROUP: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

impl Fixture {
    /// A claimed download for `message` in `group`, received at `received`.
    fn claimed_in(
        &self,
        group: &str,
        message: &str,
        plaintext: &[u8],
        received: u64,
    ) -> AttachmentAcquisition {
        self.store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)
                 ON CONFLICT DO NOTHING",
                [group],
            )
            .unwrap();
        let (mut event, mut entry) = Self::entry(message, plaintext);
        event.group_id_hex = group.into();
        event.received_at = received;
        entry.received_at = received;
        self.store.app_storage().record_app_event(&event).unwrap();
        let AttachmentDemand::Requested(reference) = self
            .store
            .app_storage()
            .request_attachment_acquisition(group, &entry, digest(plaintext), NOW)
            .unwrap()
        else {
            panic!("attachment was not requested");
        };
        self.store
            .app_storage()
            .claim_attachment_acquisition(&reference, NOW, LEASE)
            .unwrap()
            .unwrap()
    }

    /// Retains `plaintext` in the legacy database layout.
    fn legacy(&self, job: &AttachmentAcquisition, plaintext: &[u8]) {
        assert_eq!(
            self.store
                .app_storage()
                .complete_attachment_acquisition(job, plaintext, NOW, u64::MAX / 2)
                .unwrap(),
            AttachmentPublishResult::Published
        );
    }
}

fn sized(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

/// Usage counts media-store files once and legacy bodies by the database
/// counter; listings order chats and attachments by bytes and page.
#[test]
fn storage_usage_and_listings_cover_both_layouts() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let big = sized(90_000, 1);
    let mid = sized(40_000, 2);
    let small = sized(5_000, 3);
    let first = fixture.claimed_in(GROUP, &"a".repeat(64), &big, NOW);
    assert!(matches!(
        fixture.publish(&first, &big),
        PublishOutcome::Published(_)
    ));
    let twin = fixture.claimed_in(OTHER_GROUP, &"b".repeat(64), &big, NOW);
    assert!(matches!(
        fixture.publish(&twin, &big),
        PublishOutcome::Existing(_)
    ));
    let legacy = fixture.claimed_in(OTHER_GROUP, &"c".repeat(64), &mid, NOW);
    fixture.legacy(&legacy, &mid);
    let tiny = fixture.claimed_in(GROUP, &"d".repeat(64), &small, NOW);
    assert!(matches!(
        fixture.publish(&tiny, &small),
        PublishOutcome::Published(_)
    ));

    let usage = app.attachment_storage_usage(NOW).unwrap();
    assert_eq!(
        usage.media_bytes,
        (big.len() + small.len()) as u64,
        "shared content counted once"
    );
    assert_eq!(usage.legacy_bytes, mid.len() as u64);
    assert_eq!(usage.attachment_count, 4);
    assert!(usage.database_bytes > 0);

    // Shared content counts in each chat that holds it.
    let chats = app.attachment_storage_by_chat(NOW, None, 8).unwrap();
    assert_eq!(
        chats
            .iter()
            .map(|chat| (
                chat.group_id_hex.as_str(),
                chat.bytes,
                chat.attachment_count
            ))
            .collect::<Vec<_>>(),
        vec![
            (OTHER_GROUP, (big.len() + mid.len()) as u64, 2),
            (GROUP, (big.len() + small.len()) as u64, 2),
        ]
    );
    let first_page = app.attachment_storage_by_chat(NOW, None, 1).unwrap();
    let rest = app
        .attachment_storage_by_chat(NOW, Some(&first_page[0].cursor()), 8)
        .unwrap();
    assert_eq!([first_page, rest].concat(), chats);

    let largest = app
        .largest_retained_attachments(NOW, None, None, 8)
        .unwrap();
    assert_eq!(
        largest
            .iter()
            .map(|entry| entry.byte_count)
            .collect::<Vec<_>>(),
        vec![
            big.len() as u64,
            big.len() as u64,
            mid.len() as u64,
            small.len() as u64
        ]
    );
    let mut paged = Vec::new();
    let mut after = None;
    loop {
        let page = app
            .largest_retained_attachments(NOW, None, after.as_ref(), 1)
            .unwrap();
        let Some(last) = page.last() else { break };
        after = Some(last.cursor());
        paged.extend(page);
    }
    assert_eq!(paged, largest);
    let in_group = app
        .largest_retained_attachments(NOW, Some(GROUP), None, 8)
        .unwrap();
    assert_eq!(in_group.len(), 2);
    assert!(in_group.iter().all(|entry| entry.group_id_hex == GROUP));
    assert!(
        app.largest_retained_attachments(NOW, None, None, 0)
            .is_err()
    );
    assert!(app.attachment_storage_by_chat(NOW, None, 257).is_err());
}

/// Bulk removal is explicit Remove: suppression recorded, bodies of both
/// layouts gone, released media files reported for an immediate unlink, and
/// a file another attachment still shares kept.
#[test]
fn bulk_removal_releases_files_and_respects_its_filters() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let shared = sized(60_000, 4);
    let old_media = fixture.claimed_in(GROUP, &"e".repeat(64), &shared, 100);
    let PublishOutcome::Published(shared_id) = fixture.publish(&old_media, &shared) else {
        panic!("published");
    };
    let new_twin = fixture.claimed_in(OTHER_GROUP, &"f".repeat(64), &shared, 5_000);
    assert!(matches!(
        fixture.publish(&new_twin, &shared),
        PublishOutcome::Existing(_)
    ));
    let own = sized(20_000, 5);
    let old_own = fixture.claimed_in(GROUP, &"1".repeat(64), &own, 200);
    let PublishOutcome::Published(own_id) = fixture.publish(&old_own, &own) else {
        panic!("published");
    };
    let legacy_body = sized(10_000, 6);
    let old_legacy = fixture.claimed_in(GROUP, &"2".repeat(64), &legacy_body, 300);
    fixture.legacy(&old_legacy, &legacy_body);
    let recent = sized(7_000, 7);
    let recent_job = fixture.claimed_in(GROUP, &"3".repeat(64), &recent, 9_000);
    assert!(matches!(
        fixture.publish(&recent_job, &recent),
        PublishOutcome::Published(_)
    ));

    // Received before 1,000 across the account: the three old attachments.
    let removal = app
        .remove_retained_attachments(NOW, None, Some(1_000))
        .unwrap();
    assert_eq!(removal.removed, 3);
    assert!(!removal.more);
    assert_eq!(
        removal.released_files,
        vec![own_id],
        "the shared file is still held"
    );
    assert_eq!(app.attachment_storage_usage(NOW).unwrap().legacy_bytes, 0);
    for job in [&old_media, &old_own, &old_legacy] {
        assert!(fixture.read(job).is_none());
    }
    assert_eq!(fixture.read(&new_twin).unwrap(), shared);
    assert_eq!(fixture.read(&recent_job).unwrap(), recent);
    let suppressed: i64 = fixture
        .store
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM attachment_removal_suppression",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(suppressed, 3, "removed attachments show as removed by you");
    fixture.media.unlink_released(&removal.released_files);
    assert!(
        !fixture.media.path(&own_id).exists(),
        "unlinked at once, not at the sweep"
    );
    assert!(fixture.media.path(&shared_id).exists());

    // One chat: its last holder releases the shared file.
    let chat = app
        .remove_retained_attachments(NOW, Some(OTHER_GROUP), None)
        .unwrap();
    assert_eq!(
        (chat.removed, chat.released_files.clone()),
        (1, vec![shared_id])
    );
    assert_eq!(
        fixture.read(&recent_job).unwrap(),
        recent,
        "other chats untouched"
    );
    assert_eq!(
        app.remove_retained_attachments(NOW, Some(OTHER_GROUP), None)
            .unwrap(),
        AttachmentRemoval::default()
    );
}

/// The single explicit Remove reports the media file it released.
#[test]
fn explicit_remove_reports_its_released_file() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let content = sized(30_000, 8);
    let job = fixture.claimed_in(GROUP, &"4".repeat(64), &content, NOW);
    let PublishOutcome::Published(id) = fixture.publish(&job, &content) else {
        panic!("published");
    };
    assert_eq!(
        app.remove_attachment_reference_releasing(&job.reference)
            .unwrap(),
        Some(vec![id])
    );
    assert_eq!(
        app.remove_attachment_reference_releasing(&job.reference)
            .unwrap(),
        None,
        "nothing left to remove"
    );
}

/// A file two attachments of one chat share counts once in that chat, while
/// two distinct files of equal length both count.
#[test]
fn a_chat_counts_each_stored_file_once() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let shared = sized(50_000, 10);
    let first = fixture.claimed_in(GROUP, &"5".repeat(64), &shared, NOW);
    assert!(matches!(
        fixture.publish(&first, &shared),
        PublishOutcome::Published(_)
    ));
    let second = fixture.claimed_in(GROUP, &"6".repeat(64), &shared, NOW);
    assert!(matches!(
        fixture.publish(&second, &shared),
        PublishOutcome::Existing(_)
    ));
    let same_len_a = sized(30_000, 11);
    let same_len_b = sized(30_000, 12);
    let a = fixture.claimed_in(GROUP, &"7".repeat(64), &same_len_a, NOW);
    assert!(matches!(
        fixture.publish(&a, &same_len_a),
        PublishOutcome::Published(_)
    ));
    let b = fixture.claimed_in(GROUP, &"8".repeat(64), &same_len_b, NOW);
    assert!(matches!(
        fixture.publish(&b, &same_len_b),
        PublishOutcome::Published(_)
    ));
    let chats = app.attachment_storage_by_chat(NOW, None, 8).unwrap();
    assert_eq!(chats.len(), 1);
    assert_eq!(
        chats[0].bytes,
        (shared.len() + same_len_a.len() + same_len_b.len()) as u64,
        "the shared file once, both equal-length files"
    );
    assert_eq!(chats[0].attachment_count, 4);
    assert_eq!(
        app.attachment_storage_usage(NOW).unwrap().media_bytes,
        chats[0].bytes
    );
}

/// An age bound past SQLite's integer range removes every received time,
/// including the largest storable one; a bound at that value does not.
#[test]
fn an_age_bound_past_the_integer_range_removes_everything() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let content = sized(4_000, 13);
    let job = fixture.claimed_in(GROUP, &"9".repeat(64), &content, i64::MAX as u64);
    assert!(matches!(
        fixture.publish(&job, &content),
        PublishOutcome::Published(_)
    ));
    assert_eq!(
        app.remove_retained_attachments(NOW, None, Some(i64::MAX as u64))
            .unwrap()
            .removed,
        0,
        "received at the bound is not before it"
    );
    assert_eq!(
        app.remove_retained_attachments(NOW, None, Some(u64::MAX))
            .unwrap()
            .removed,
        1
    );
}

// Moving legacy bodies into the media store (mdk#2314 step 6).

impl Fixture {
    /// Moves `body` into the store the way the runtime batch does, without
    /// its disk admission or the row drop.
    fn migrate(&self, body: &LegacyAttachmentBody) -> Result<PublishOutcome, MediaError> {
        let app = self.store.app_storage();
        self.migrate_from(body, &mut app.legacy_attachment_reader(body))
    }

    fn migrate_from(
        &self,
        body: &LegacyAttachmentBody,
        reader: &mut dyn Read,
    ) -> Result<PublishOutcome, MediaError> {
        let app = self.store.app_storage();
        self.media.publish(
            &app.legacy_attachment_publication(body),
            Category::Retained,
            reader,
            body.byte_len(),
            body.digest().unwrap(),
            NOW,
            &|| false,
        )
    }

    fn legacy_bodies(&self) -> Vec<LegacyAttachmentBody> {
        self.store
            .app_storage()
            .legacy_attachment_bodies(ATTACHMENT_ACQUISITION_BATCH_LIMIT)
            .unwrap()
    }

    /// Lets a test damage completed chunks, which triggers otherwise forbid.
    fn unlock_chunks(&self) {
        self.store
            .lock()
            .unwrap()
            .execute_batch(
                "DROP TRIGGER attachment_file_chunk_update_immutable;
                 DROP TRIGGER attachment_file_chunk_delete_immutable;",
            )
            .unwrap();
    }
}

/// Inline and chunked legacy bodies move into store files smallest first,
/// stay readable, and leave no rows or counted bytes behind.
#[test]
fn legacy_bodies_move_into_the_media_store_smallest_first() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let large = sized(200_000, 1);
    let small = sized(1_000, 2);
    let chunked = fixture.claimed(&"a".repeat(64), &large);
    fixture.legacy(&chunked, &large);
    let inline = fixture.claimed(&"b".repeat(64), &small);
    fixture.legacy(&inline, &small);
    assert_eq!(fixture.count("retained_attachment_files"), 1);
    assert_eq!(app.legacy_attachment_bytes().unwrap(), 201_000);
    assert_eq!(
        app.attachment_storage_usage(NOW).unwrap().migration,
        AttachmentMigrationState::Running {
            remaining_bytes: 201_000
        }
    );

    let bodies = fixture.legacy_bodies();
    assert_eq!(
        bodies
            .iter()
            .map(|body| body.byte_len())
            .collect::<Vec<_>>(),
        vec![1_000, 200_000]
    );
    for body in &bodies {
        assert!(body.media_file().is_none());
        assert!(matches!(
            fixture.migrate(body).unwrap(),
            PublishOutcome::Published(_)
        ));
        assert!(app.drop_migrated_legacy_body(body).unwrap());
    }

    assert!(fixture.legacy_bodies().is_empty());
    let usage = app.attachment_storage_usage(NOW).unwrap();
    assert_eq!(usage.migration, AttachmentMigrationState::NotNeeded);
    assert_eq!((usage.legacy_bytes, usage.media_bytes), (0, 201_000));
    for table in [
        "retained_attachment_bytes",
        "retained_attachment_files",
        "retained_attachment_chunks",
        "attachment_chunk_bodies",
    ] {
        assert_eq!(fixture.count(table), 0, "{table}");
    }
    assert_eq!(fixture.media_files_on_disk(), 2);
    assert_eq!(fixture.read(&chunked).unwrap(), large);
    assert_eq!(fixture.read(&inline).unwrap(), small);
}

/// A crash after the publish and before the drop leaves both copies. Reads
/// use the file, and the next batch sees it and only drops the rows.
#[test]
fn an_interrupted_move_reads_the_file_and_then_only_drops_the_rows() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let content = sized(90_000, 3);
    let job = fixture.claimed(&"c".repeat(64), &content);
    fixture.legacy(&job, &content);
    let PublishOutcome::Published(id) = fixture.migrate(&fixture.legacy_bodies()[0]).unwrap()
    else {
        panic!("not published");
    };

    let bodies = fixture.legacy_bodies();
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0].media_file(), Some(id));
    assert!(matches!(
        app.retained_attachment_read(&job.reference, NOW, 0, 16)
            .unwrap(),
        Some(RetainedAttachmentRead::MediaFile(read)) if read == id
    ));
    assert_eq!(fixture.read(&job).unwrap(), content);
    assert!(app.drop_migrated_legacy_body(&bodies[0]).unwrap());
    assert!(fixture.legacy_bodies().is_empty());
    assert_eq!(fixture.media_files_on_disk(), 1);
    assert_eq!(fixture.read(&job).unwrap(), content);
}

/// The drop is fenced on a ready file: rows whose move never published stay.
#[test]
fn rows_are_not_dropped_without_a_ready_file() {
    let fixture = Fixture::new();
    let content = sized(4_000, 4);
    let job = fixture.claimed(&"d".repeat(64), &content);
    fixture.legacy(&job, &content);
    let body = &fixture.legacy_bodies()[0];
    assert!(
        !fixture
            .store
            .app_storage()
            .drop_migrated_legacy_body(body)
            .unwrap()
    );
    assert_eq!(fixture.read(&job).unwrap(), content);
}

/// A legacy body that fails its digest, or whose chunks are missing, is
/// refused before anything is kept. Dropping it leaves its slot completed
/// without a body: unavailable, with download-again allowed.
#[test]
fn a_corrupt_legacy_body_is_refused_and_dropped_leaving_the_slot_unavailable() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let damaged = sized(200_000, 5);
    let truncated = sized(150_000, 6);
    let damaged_job = fixture.claimed(&"e".repeat(64), &damaged);
    fixture.legacy(&damaged_job, &damaged);
    let truncated_job = fixture.claimed(&"f".repeat(64), &truncated);
    fixture.legacy(&truncated_job, &truncated);
    fixture.unlock_chunks();
    let nonce = |job: &AttachmentAcquisition| -> Vec<u8> {
        fixture
            .store
            .lock()
            .unwrap()
            .query_row(
                "SELECT nonce FROM retained_attachment_files WHERE token=?1",
                [&job.reference.token],
                |row| row.get(0),
            )
            .unwrap()
    };
    let (damaged_nonce, truncated_nonce) = (nonce(&damaged_job), nonce(&truncated_job));
    let conn = fixture.store.lock().unwrap();
    conn.execute(
        "UPDATE retained_attachment_chunks SET bytes=zeroblob(length(bytes))
         WHERE token=?1 AND offset=0",
        [damaged_nonce],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM retained_attachment_chunks WHERE token=?1
         AND offset=(SELECT max(offset) FROM retained_attachment_chunks WHERE token=?1)",
        [truncated_nonce],
    )
    .unwrap();
    drop(conn);

    let bodies = fixture.legacy_bodies();
    let [truncated_body, damaged_body] = bodies.as_slice() else {
        panic!("two legacy bodies");
    };
    assert_eq!(
        fixture.migrate(damaged_body),
        Err(MediaError::InvalidBody("media body digest mismatch"))
    );
    let mut reader = app.legacy_attachment_reader(truncated_body);
    assert!(matches!(
        fixture.migrate_from(truncated_body, &mut reader),
        Err(MediaError::Io(_))
    ));
    assert!(reader.body_invalid());
    fixture.sweep();
    assert_eq!(fixture.media_files_on_disk(), 0);
    assert_eq!(fixture.count("media_files"), 0);

    for body in [truncated_body, damaged_body] {
        assert!(app.drop_corrupt_legacy_body(body).unwrap());
    }
    assert!(fixture.legacy_bodies().is_empty());
    assert_eq!(app.retained_attachment_byte_count().unwrap(), 0);
    for job in [&damaged_job, &truncated_job] {
        assert_eq!(fixture.read(job), None);
        assert_eq!(
            app.attachment_acquisition_status(&job.reference)
                .unwrap()
                .unwrap()
                .state,
            AttachmentAcquisitionState::Ready,
            "the slot keeps its completed acquisition without a body"
        );
    }
}

/// A removal while the body streams out supersedes the move: nothing is
/// kept, and the removal's cascade takes the rows.
#[test]
fn removal_during_a_move_supersedes_it_and_keeps_nothing() {
    struct RemovingReader<'a> {
        fixture: &'a Fixture,
        inner: LegacyBodyReader,
        removed: bool,
    }
    impl Read for RemovingReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let read = self.inner.read(out)?;
            if !self.removed {
                self.removed = true;
                self.fixture
                    .store
                    .app_storage()
                    .remove_retained_attachments(NOW, None, None)
                    .unwrap();
            }
            Ok(read)
        }
    }
    let fixture = Fixture::new();
    let content = sized(20_000, 7);
    let job = fixture.claimed(&"1".repeat(64), &content);
    fixture.legacy(&job, &content);
    let body = fixture.legacy_bodies().remove(0);
    let mut reader = RemovingReader {
        fixture: &fixture,
        inner: fixture.store.app_storage().legacy_attachment_reader(&body),
        removed: false,
    };
    assert_eq!(
        fixture.migrate_from(&body, &mut reader),
        Ok(PublishOutcome::Superseded)
    );
    fixture.sweep();
    assert_eq!(fixture.media_files_on_disk(), 0);
    assert!(fixture.legacy_bodies().is_empty());
}

/// A body whose content the store already holds attaches that file instead
/// of writing another copy.
#[test]
fn a_legacy_body_with_a_stored_twin_attaches_it() {
    let fixture = Fixture::new();
    let content = body();
    let media = fixture.claimed(&"2".repeat(64), &content);
    let PublishOutcome::Published(id) = fixture.publish(&media, &content) else {
        panic!("not published");
    };
    let legacy = fixture.claimed(&"3".repeat(64), &content);
    fixture.legacy(&legacy, &content);
    let body = fixture.legacy_bodies().remove(0);
    assert_eq!(fixture.migrate(&body), Ok(PublishOutcome::Existing(id)));
    assert!(
        fixture
            .store
            .app_storage()
            .drop_migrated_legacy_body(&body)
            .unwrap()
    );
    assert_eq!(fixture.media_files_on_disk(), 1);
    assert_eq!(fixture.read(&legacy).unwrap(), content);
}

/// A chunked import still in progress and a legacy outgoing upload are not
/// legacy bodies to move: they are neither listed nor counted, and stay.
#[test]
fn unfinished_imports_and_legacy_uploads_are_left_alone() {
    let fixture = Fixture::new();
    let app = fixture.store.app_storage();
    let content = sized(1_000, 8);
    let importing = fixture.claimed(&"4".repeat(64), &content);
    {
        let conn = fixture.store.lock().unwrap();
        conn.execute_batch("INSERT INTO attachment_chunk_bodies(nonce) VALUES(x'0102030405060708090a0b0c0d0e0f10')")
            .unwrap();
        conn.execute(
            "INSERT INTO retained_attachment_bytes(token,byte_len,bytes) VALUES(?1,0,x'')",
            [&importing.reference.token],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO retained_attachment_files(token,nonce,attempt,byte_len)
             VALUES(?1,x'0102030405060708090a0b0c0d0e0f10',zeroblob(16),500000)",
            [&importing.reference.token],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO outgoing_attachment_uploads(token,group_id_hex,source_epoch,plaintext_digest,bytes,expires_at)
             VALUES(zeroblob(16),?1,1,?2,?3,?4)",
            params![GROUP, digest(&content).as_slice(), content, i64::MAX],
        )
        .unwrap();
    }
    assert!(app.retained_attachment_byte_count().unwrap() > 0);
    assert!(fixture.legacy_bodies().is_empty());
    assert_eq!(app.legacy_attachment_bytes().unwrap(), 0);
    assert_eq!(
        app.attachment_storage_usage(NOW).unwrap().migration,
        AttachmentMigrationState::NotNeeded
    );
    assert_eq!(fixture.count("retained_attachment_files"), 1);
    assert_eq!(fixture.count("outgoing_attachment_uploads"), 1);
}
