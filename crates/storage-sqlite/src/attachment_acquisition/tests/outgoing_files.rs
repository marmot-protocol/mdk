//! File-backed outgoing staging and reader-based publication (#2175). Bodies
//! move through bounded incremental BLOB I/O and share the retention quota.
use super::*;
use std::io::{Cursor, Read};

fn sent(store: &SqliteAccountStorage, message: &str) {
    seed(store, message);
    let mut event = source(message);
    event.direction = "sent".into();
    store.record_app_event(&event).unwrap();
}

fn usage(store: &SqliteAccountStorage) -> u64 {
    store
        .lock()
        .unwrap()
        .query_row(
            "SELECT byte_count FROM attachment_retention_usage WHERE id=1",
            [],
            |r| nonnegative(r, 0),
        )
        .unwrap()
}

fn count(store: &SqliteAccountStorage, table: &str) -> i64 {
    store
        .lock()
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn stage(
    store: &SqliteAccountStorage,
    body: &[u8],
    len: u64,
    digest: [u8; 32],
    budget: u64,
    cancelled: &dyn Fn() -> bool,
) -> StorageResult<Vec<Vec<u8>>> {
    let mut reader = Cursor::new(body.to_vec());
    store.stage_attachment_upload_files(
        GROUP,
        3,
        &mut [AttachmentUploadSource {
            reader: &mut reader,
            len,
            digest,
        }],
        11,
        budget,
        cancelled,
    )
}

/// Counts every read so a test can prove chunks never exceed the staging bound.
struct Chunked<'a> {
    inner: Cursor<&'a [u8]>,
    largest: &'a std::cell::Cell<usize>,
}
impl Read for Chunked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.largest.set(self.largest.get().max(buf.len()));
        self.inner.read(buf)
    }
}

#[test]
fn file_staging_promotes_multi_chunk_body_with_bounded_reads_and_shared_quota() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "file");
    let body = (0..(3 * ATTACHMENT_STAGING_CHUNK_BYTES + 17))
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let largest = std::cell::Cell::new(0);
    let mut reader = Chunked {
        inner: Cursor::new(body.as_slice()),
        largest: &largest,
    };
    let tokens = store
        .stage_attachment_upload_files(
            GROUP,
            3,
            &mut [AttachmentUploadSource {
                reader: &mut reader,
                len: body.len() as u64,
                digest,
            }],
            11,
            u64::MAX / 4,
            &|| false,
        )
        .unwrap();
    assert!(largest.get() <= ATTACHMENT_STAGING_CHUNK_BYTES);
    assert_eq!(usage(&store), body.len() as u64);
    let parent_len: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT length(bytes) FROM outgoing_attachment_uploads WHERE token=?1",
            [&tokens[0]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        parent_len, 0,
        "file bodies never live in the mutable parent row"
    );
    store
        .bind_attachment_uploads(&tokens, &[(selected("file").slot, digest)])
        .unwrap();
    store
        .protect_attachment_uploads(GROUP, "file", &source("file").tags)
        .unwrap();
    assert_eq!(
        usage(&store),
        body.len() as u64,
        "binding never rewrites the body"
    );
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "file", 12, u64::MAX / 4)
            .unwrap(),
        1
    );
    assert_eq!(
        usage(&store),
        body.len() as u64,
        "promotion converts, never double charges"
    );
    assert_eq!(count(&store, "outgoing_attachment_upload_bodies"), 0);
    let asset = store
        .retained_attachment_asset(GROUP, "file", "source-file", 0, 12)
        .unwrap()
        .unwrap();
    assert_eq!(asset.byte_count, body.len() as u64);
    let mut copied = Vec::new();
    while copied.len() < body.len() {
        let chunk = store
            .read_retained_attachment(
                &asset.reference,
                12,
                copied.len() as u64,
                ATTACHMENT_STAGING_CHUNK_BYTES,
            )
            .unwrap()
            .unwrap();
        assert!(!chunk.is_empty());
        copied.extend_from_slice(&chunk);
    }
    assert_eq!(copied, body);
}

#[test]
fn file_staging_rolls_back_short_growing_mismatched_cancelled_and_over_quota_sources() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "reject");
    let len = BODY.len() as u64;
    let cancelled = std::cell::Cell::new(0);
    let cases: [(&str, StorageResult<Vec<Vec<u8>>>); 6] = [
        (
            "short",
            stage(&store, BODY, len + 1, digest(), 10000, &|| false),
        ),
        (
            "grown",
            stage(&store, BODY, len - 1, digest(), 10000, &|| false),
        ),
        (
            "mismatch",
            stage(&store, BODY, len, [7; 32], 10000, &|| false),
        ),
        (
            "quota",
            stage(&store, BODY, len, digest(), len - 1, &|| false),
        ),
        ("empty", stage(&store, b"", 0, digest(), 10000, &|| false)),
        (
            "cancelled",
            stage(&store, BODY, len, digest(), 10000, &|| {
                cancelled.set(cancelled.get() + 1);
                cancelled.get() > 1
            }),
        ),
    ];
    for (name, result) in cases {
        assert!(result.is_err(), "{name} must be refused");
    }
    assert_eq!(count(&store, "outgoing_attachment_uploads"), 0);
    assert_eq!(count(&store, "outgoing_attachment_upload_bodies"), 0);
    assert_eq!(usage(&store), 0);
    let oversized = {
        let mut reader = std::io::empty();
        store.stage_attachment_upload_files(
            GROUP,
            3,
            &mut [AttachmentUploadSource {
                reader: &mut reader,
                len: MAX_RETAINED_FILE_ATTACHMENT_BYTES + 1,
                digest: digest(),
            }],
            11,
            u64::MAX / 4,
            &|| false,
        )
    };
    assert!(
        oversized.is_err(),
        "the retained-table bound is checked before any write"
    );
}

#[test]
#[ignore = "opt-in 758 MB SQLCipher retention measurement; generated bounded input"]
fn generated_758_mb_reader_retention_is_available_above_legacy_array_limit() {
    const LEN: u64 = 758_000_000;
    let directory = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::open_encrypted(
        directory.path().join("large.sqlite"),
        &SqlCipherKey::new("synthetic-large-retention-test").unwrap(),
    )
    .unwrap();
    seed(&store, "large-retained");
    let mut hasher = Sha256::new();
    let buffer = [0x37; ATTACHMENT_STAGING_CHUNK_BYTES];
    let mut remaining = LEN;
    while remaining > 0 {
        let take = remaining.min(buffer.len() as u64) as usize;
        hasher.update(&buffer[..take]);
        remaining -= take as u64;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut event = source("large-retained");
    event.tags[0][2] = format!("x {}", hex::encode(digest));
    store.record_app_event(&event).unwrap();
    let mut entry = selected("large-retained");
    entry.slot = serde_json::to_value(&event.tags[0]).unwrap();
    let asset = match store
        .request_attachment_acquisition(GROUP, &entry, digest, 11)
        .unwrap()
    {
        AttachmentDemand::Requested(asset) => asset,
        other => panic!("unexpected demand: {other:?}"),
    };
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    struct Generated {
        remaining: u64,
        largest: usize,
    }
    impl Read for Generated {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.largest = self.largest.max(buf.len());
            let take = self.remaining.min(buf.len() as u64) as usize;
            buf[..take].fill(0x37);
            self.remaining -= take as u64;
            Ok(take)
        }
    }
    let mut reader = Generated {
        remaining: LEN,
        largest: 0,
    };
    assert_eq!(
        store
            .complete_attachment_acquisition_from_reader(
                &job,
                &mut reader,
                LEN,
                12,
                2 * 1024 * 1024 * 1024,
                &|| false
            )
            .unwrap(),
        AttachmentPublishResult::Published
    );
    assert!(reader.largest <= ATTACHMENT_STAGING_CHUNK_BYTES);
    assert_eq!(usage(&store), LEN);
    let asset_meta = store
        .retained_attachment_asset(GROUP, "large-retained", "source-large-retained", 0, 12)
        .unwrap()
        .unwrap();
    assert_eq!(asset_meta.byte_count, LEN);
    let tail = store
        .read_retained_attachment(&asset, 12, LEN - 17, 17)
        .unwrap()
        .unwrap();
    assert_eq!(tail.as_slice(), &[0x37; 17]);
    store.close().unwrap();
}

#[test]
fn corrupt_file_body_is_quarantined_and_released_without_publication() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "corrupt-file");
    let tokens = stage(&store, BODY, BODY.len() as u64, digest(), 10000, &|| false).unwrap();
    store
        .bind_attachment_uploads(&tokens, &[(selected("corrupt-file").slot, digest())])
        .unwrap();
    {
        let conn = store.lock().unwrap();
        let rowid: i64 = conn
            .query_row(
                "SELECT rowid FROM outgoing_attachment_upload_bodies WHERE token=?1",
                [&tokens[0]],
                |r| r.get(0),
            )
            .unwrap();
        let mut blob = conn
            .blob_open(
                "main",
                "outgoing_attachment_upload_bodies",
                "bytes",
                rowid,
                false,
            )
            .unwrap();
        blob.write_at(b"X", 0).unwrap();
        blob.close().unwrap();
    }
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "corrupt-file", 12, 10000)
            .unwrap(),
        0
    );
    assert_eq!(count(&store, "outgoing_attachment_upload_bodies"), 0);
    assert_eq!(count(&store, "retained_attachment_bytes"), 0);
    assert_eq!(usage(&store), 0);
}

#[test]
fn reader_publication_shares_fences_and_rolls_back_mismatch() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "received-file");
    let asset = request(&store, "received-file");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let wrong = b"private retained attachment plaintexX";
    assert!(
        store
            .complete_attachment_acquisition_from_reader(
                &job,
                &mut Cursor::new(&wrong[..]),
                wrong.len() as u64,
                12,
                10000,
                &|| false,
            )
            .is_err()
    );
    assert!(
        store
            .complete_attachment_acquisition_from_reader(
                &job,
                &mut Cursor::new(BODY),
                BODY.len() as u64,
                12,
                10000,
                &|| true,
            )
            .is_err()
    );
    assert_eq!(count(&store, "retained_attachment_bytes"), 0);
    assert_eq!(usage(&store), 0);
    assert_eq!(
        store
            .complete_attachment_acquisition_from_reader(
                &job,
                &mut Cursor::new(BODY),
                BODY.len() as u64,
                12,
                BODY.len() as u64 - 1,
                &|| false,
            )
            .unwrap(),
        AttachmentPublishResult::CapacityBlocked
    );
    seed(&store, "received-ok");
    let asset = request(&store, "received-ok");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition_from_reader(
                &job,
                &mut Cursor::new(BODY),
                BODY.len() as u64,
                12,
                10000,
                &|| false,
            )
            .unwrap(),
        AttachmentPublishResult::Published
    );
    assert_eq!(read(&store, &asset), BODY);
    assert_eq!(
        store
            .complete_attachment_acquisition_from_reader(
                &job,
                &mut Cursor::new(BODY),
                BODY.len() as u64,
                12,
                10000,
                &|| false,
            )
            .unwrap(),
        AttachmentPublishResult::Superseded,
        "a finished attempt cannot publish twice"
    );
}
