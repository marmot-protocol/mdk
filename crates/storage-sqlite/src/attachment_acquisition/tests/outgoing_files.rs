//! File-backed outgoing staging and reader-based publication (#2175). Bodies
//! move through protected chunks and share the retention quota.
use super::*;
use std::io::{Cursor, Read};

struct HeldReader {
    reader: Cursor<Vec<u8>>,
    entered: Option<std::sync::mpsc::Sender<()>>,
    release: std::sync::mpsc::Receiver<()>,
    hold_at: u64,
}

impl Read for HeldReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.reader.position() >= self.hold_at
            && let Some(entered) = self.entered.take()
        {
            entered.send(()).unwrap();
            self.release
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
        }
        self.reader.read(buffer)
    }
}

#[test]
fn held_file_import_allows_account_read_and_removal_without_publishing_bytes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "held-import");
    let asset = request(&store, "held-import");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let (entered, waiting) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let worker_store = store.clone();
    let import = std::thread::spawn(move || {
        let mut reader = HeldReader {
            reader: Cursor::new(BODY.to_vec()),
            entered: Some(entered),
            release: resume,
            hold_at: 0,
        };
        worker_store.complete_attachment_acquisition_from_reader(
            &job,
            &mut reader,
            BODY.len() as u64,
            12,
            10000,
            &|| false,
        )
    });
    waiting
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let probe_store = store.clone();
    let probe_asset = asset.clone();
    let (finished, done) = std::sync::mpsc::channel();
    let probe = std::thread::spawn(move || {
        assert!(count(&probe_store, "account_groups") > 0);
        assert_eq!(
            usage(&probe_store),
            BODY.len() as u64,
            "full quota is reserved"
        );
        assert!(
            probe_store
                .read_retained_attachment(&probe_asset, 12, 0, 10)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            probe_store
                .attachment_acquisition_status(&probe_asset)
                .unwrap()
                .unwrap()
                .byte_count,
            0
        );
        assert!(
            probe_store
                .remove_local_attachment(GROUP, "held-import", 0)
                .unwrap()
        );
        finished.send(()).unwrap();
    });
    let progressed = done.recv_timeout(std::time::Duration::from_secs(2)).is_ok();
    release.send(()).unwrap();
    let outcome = import.join().unwrap().unwrap();
    probe.join().unwrap();
    assert!(
        progressed,
        "account read and removal must finish before the reader resumes"
    );
    assert_eq!(outcome, AttachmentPublishResult::Superseded);
    assert_eq!(usage(&store), 0);
    assert_eq!(count(&store, "retained_attachment_chunks"), 0);
}

#[test]
fn replacement_attempt_preserves_its_bytes_when_old_import_resumes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "replace-import");
    let asset = request(&store, "replace-import");
    let old = store
        .claim_attachment_acquisition(&asset, 12, 13)
        .unwrap()
        .unwrap();
    let (entered, waiting) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let old_store = store.clone();
    let import = std::thread::spawn(move || {
        let mut reader = HeldReader {
            reader: Cursor::new(BODY.to_vec()),
            entered: Some(entered),
            release: resume,
            hold_at: 0,
        };
        old_store.complete_attachment_acquisition_from_reader(
            &old,
            &mut reader,
            BODY.len() as u64,
            12,
            10000,
            &|| false,
        )
    });
    waiting
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let replacement_store = store.clone();
    let replacement_asset = asset.clone();
    let (finished, done) = std::sync::mpsc::channel();
    let replacement = std::thread::spawn(move || {
        let new = replacement_store
            .claim_attachment_acquisition(&replacement_asset, 14, 100)
            .unwrap()
            .unwrap();
        assert_eq!(
            replacement_store
                .complete_attachment_acquisition_from_reader(
                    &new,
                    &mut Cursor::new(BODY),
                    BODY.len() as u64,
                    14,
                    10000,
                    &|| false
                )
                .unwrap(),
            AttachmentPublishResult::Published
        );
        finished.send(()).unwrap();
    });
    let progressed = done.recv_timeout(std::time::Duration::from_secs(2)).is_ok();
    release.send(()).unwrap();
    let outcome = import.join().unwrap().unwrap();
    replacement.join().unwrap();
    assert!(
        progressed,
        "expired import must not hold account transaction"
    );
    assert_eq!(outcome, AttachmentPublishResult::Superseded);
    assert_eq!(usage(&store), BODY.len() as u64);
    assert_eq!(
        store
            .read_retained_attachment(&asset, 14, 0, 100)
            .unwrap()
            .unwrap()
            .as_slice(),
        BODY
    );
}

#[test]
fn cancelled_staging_releases_committed_chunks_without_blocking_account_commands() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "stage-held");
    let body = vec![0x38; 2 * 1024 * 1024 + 17];
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let len = body.len() as u64;
    let (entered, waiting) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = cancelled.clone();
    let worker_store = store.clone();
    let staging = std::thread::spawn(move || {
        let mut reader = HeldReader {
            reader: Cursor::new(body),
            entered: Some(entered),
            release: resume,
            hold_at: 1024 * 1024,
        };
        worker_store.stage_attachment_upload_files(
            GROUP,
            3,
            &mut [AttachmentUploadSource {
                reader: &mut reader,
                len,
                digest,
            }],
            11,
            len,
            &|| stop.load(std::sync::atomic::Ordering::Acquire),
        )
    });
    waiting
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let probe_store = store.clone();
    let (finished, done) = std::sync::mpsc::channel();
    let probe = std::thread::spawn(move || {
        assert_eq!(count(&probe_store, "retained_attachment_chunks"), 16);
        assert_eq!(usage(&probe_store), len);
        // A real write as well as a read must proceed before the slow source.
        probe_store
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_groups SET pending_confirmation=0 WHERE group_id_hex=?1",
                [GROUP],
            )
            .unwrap();
        cancelled.store(true, std::sync::atomic::Ordering::Release);
        finished.send(()).unwrap();
    });
    let progressed = done.recv_timeout(std::time::Duration::from_secs(2)).is_ok();
    release.send(()).unwrap();
    assert!(staging.join().unwrap().is_err());
    probe.join().unwrap();
    assert!(progressed);
    assert_eq!(usage(&store), 0);
    assert_eq!(count(&store, "outgoing_attachment_uploads"), 0);
    assert_eq!(count(&store, "attachment_chunk_bodies"), 0);
    assert_eq!(count(&store, "retained_attachment_chunks"), 0);
}

#[test]
fn file_import_reads_across_chunk_boundaries_and_reopens_encrypted_storage() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chunked.sqlite");
    let key = SqlCipherKey::new("synthetic-chunk-reopen").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "chunked");
    let body = (0..(2 * 1024 * 1024 + 17))
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let mut event = source("chunked");
    event.tags[0][2] = format!("x {}", hex::encode(digest));
    store.record_app_event(&event).unwrap();
    let mut entry = selected("chunked");
    entry.slot = serde_json::to_value(&event.tags[0]).unwrap();
    let AttachmentDemand::Requested(asset) = store
        .request_attachment_acquisition(GROUP, &entry, digest, 11)
        .unwrap()
    else {
        panic!("expected demand")
    };
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition_from_reader(
                &job,
                &mut Cursor::new(&body),
                body.len() as u64,
                12,
                body.len() as u64,
                &|| false
            )
            .unwrap(),
        AttachmentPublishResult::Published
    );
    store.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(usage(&reopened), body.len() as u64);
    for (offset, limit) in [
        (0, 11),
        (65530, 30),
        (1024 * 1024 - 17, 40),
        (body.len() - 17, 100),
        (body.len(), 100),
    ] {
        let bytes = reopened
            .read_retained_attachment(&asset, 12, offset as u64, limit)
            .unwrap()
            .unwrap();
        assert_eq!(
            bytes.as_slice(),
            &body[offset..(offset + limit).min(body.len())]
        );
    }
    assert_eq!(
        reopened
            .retained_attachment_asset(GROUP, "chunked", "source-chunked", 0, 12)
            .unwrap()
            .unwrap()
            .byte_count,
        body.len() as u64
    );
    reopened
        .remove_local_attachment(GROUP, "chunked", 0)
        .unwrap();
    assert_eq!(usage(&reopened), 0);
    assert_eq!(count(&reopened, "attachment_chunk_bodies"), 0);
}

#[test]
fn shared_file_promotion_keeps_one_body_and_charges_each_source() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "file-a");
    sent(&store, "file-b");
    let tokens = stage(&store, BODY, BODY.len() as u64, digest(), 10000, &|| false).unwrap();
    store
        .bind_attachment_uploads(&tokens, &[(selected("file-a").slot, digest())])
        .unwrap();
    store
        .protect_attachment_uploads(GROUP, "file-a", &source("file-a").tags)
        .unwrap();
    store
        .protect_attachment_uploads(GROUP, "file-b", &source("file-b").tags)
        .unwrap();
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "file-a", 12, BODY.len() as u64)
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "file-a", 12, 2 * BODY.len() as u64)
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "file-b", 12, 2 * BODY.len() as u64)
            .unwrap(),
        1
    );
    assert_eq!(usage(&store), 2 * BODY.len() as u64);
    assert_eq!(count(&store, "retained_attachment_chunks"), 1);
    assert_eq!(count(&store, "attachment_chunk_bodies"), 1);
    assert!(
        store
            .lock()
            .unwrap()
            .execute("UPDATE retained_attachment_chunks SET bytes=bytes", [])
            .is_err(),
        "verified chunks are immutable"
    );
    store.remove_local_attachment(GROUP, "file-a", 0).unwrap();
    assert_eq!(usage(&store), BODY.len() as u64);
    assert_eq!(read(&store, &request(&store, "file-b")), BODY);
    store.remove_local_attachment(GROUP, "file-b", 0).unwrap();
    assert_eq!(usage(&store), 0);
    assert_eq!(count(&store, "attachment_chunk_bodies"), 0);
}

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
        started: Option<std::sync::mpsc::Sender<()>>,
    }
    impl Read for Generated {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if let Some(started) = self.started.take() {
                started.send(()).unwrap();
            }
            self.largest = self.largest.max(buf.len());
            let take = self.remaining.min(buf.len() as u64) as usize;
            buf[..take].fill(0x37);
            self.remaining -= take as u64;
            Ok(take)
        }
    }
    let (started, importing) = std::sync::mpsc::channel();
    let probe = store.clone();
    let account_read = std::thread::spawn(move || {
        importing
            .recv_timeout(std::time::Duration::from_secs(180))
            .unwrap();
        let start = std::time::Instant::now();
        assert!(count(&probe, "account_groups") > 0);
        start.elapsed()
    });
    let mut reader = Generated {
        remaining: LEN,
        largest: 0,
        started: Some(started),
    };
    let import_started = std::time::Instant::now();
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
    let import_time = import_started.elapsed();
    let account_read_wait = account_read.join().unwrap();
    println!(
        "large_retention_measurement bytes={LEN} import_ms={} concurrent_account_read_wait_ms={}",
        import_time.as_millis(),
        account_read_wait.as_millis()
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
        conn.execute_batch("DROP TRIGGER attachment_file_chunk_update_immutable;")
            .unwrap();
        conn.execute("UPDATE retained_attachment_chunks SET bytes=?2 WHERE token=(SELECT nonce FROM outgoing_attachment_upload_files WHERE token=?1) AND offset=0", params![tokens[0], vec![0u8;BODY.len()]]).unwrap();
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
    assert!(matches!(
        store.complete_attachment_acquisition_from_reader(
            &job,
            &mut Cursor::new(&wrong[..]),
            wrong.len() as u64,
            12,
            10000,
            &|| false,
        ),
        Err(StorageError::InvalidAttachmentBody(_))
    ));
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
