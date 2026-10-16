use super::*;
use crate::SqliteAccountStorage;

#[test]
fn attachment_jobs_are_provisioned_without_engine_or_network() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let count: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM attachment_acquisition", [], |row| {
            row.get(0)
        })
        .expect("account open must provision durable attachment jobs");
    assert_eq!(count, 0);
}

use crate::{SqlCipherKey, StoredAppEvent};

const GROUP: &str = "abababababababababababababababab";
const BODY: &[u8] = b"private retained attachment plaintext";
fn digest() -> [u8; 32] {
    Sha256::digest(BODY).into()
}
fn source(message: &str) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: GROUP.into(),
        message_id_hex: message.into(),
        source_message_id_hex: Some(format!("source-{message}")),
        source_epoch: Some(3),
        direction: "received".into(),
        sender: "author".into(),
        plaintext: "caption".into(),
        kind: 9,
        tags: vec![vec![
            "imeta".into(),
            "m image/png".into(),
            format!("x {}", hex::encode(digest())),
        ]],
        recorded_at: 10,
        received_at: 10,
        origin_commit_id: None,
        moderation_grant: false,
    }
}
/// Build the acquisition descriptor without gallery-only source metadata.
fn selected(message: &str) -> crate::AttachmentHistoryEntry {
    let event = source(message);
    crate::AttachmentHistoryEntry {
        emoji_tags: Vec::new(),
        message_id_hex: message.into(),
        attachment_index: 0,
        source_message_id_hex: event.source_message_id_hex.unwrap(),
        source_epoch: event.source_epoch,
        sender: event.sender,
        timeline_at: 10,
        received_at: 10,
        slot: serde_json::to_value(&event.tags[0]).unwrap(),
    }
}
fn seed(store: &SqliteAccountStorage, message: &str) {
    store.lock().unwrap().execute("INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0) ON CONFLICT DO NOTHING",[GROUP]).unwrap();
    store.record_app_event(&source(message)).unwrap();
}
fn request(store: &SqliteAccountStorage, message: &str) -> AttachmentAssetRef {
    match store
        .request_attachment_acquisition(GROUP, &selected(message), digest(), 11)
        .unwrap()
    {
        AttachmentDemand::Requested(r) => r,
        other => panic!("expected requested, got {other:?}"),
    }
}
fn publish(store: &SqliteAccountStorage, r: &AttachmentAssetRef) {
    let job = store
        .claim_attachment_acquisition(r, 12, 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 12, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
}
fn read(store: &SqliteAccountStorage, r: &AttachmentAssetRef) -> Vec<u8> {
    store
        .read_retained_attachment(r, 12, 0, 100)
        .unwrap()
        .unwrap()
        .to_vec()
}
/// The runtime's checkpoint flow without its wire file (mdk#2314 step 2b): a
/// zero offset begins a new checkpoint, and each write records the new
/// length once its bytes are durable in the wire file. `false` where the
/// attempt is fenced or the write does not extend this checkpoint.
fn checkpoint(
    store: &SqliteAccountStorage,
    job: &AttachmentAcquisition,
    identity: &AttachmentPartialIdentity,
    offset: u64,
    bytes: &[u8],
    now: u64,
) -> StorageResult<bool> {
    if offset == 0
        && store
            .begin_attachment_partial(job, identity, now)?
            .is_none()
    {
        return Ok(false);
    }
    let Some(part) = store.load_attachment_partial(job, now, u64::MAX, None)? else {
        return Ok(false);
    };
    if part.received != offset || part.identity != *identity {
        return Ok(false);
    }
    store.record_attachment_partial(
        job,
        identity,
        &part.wire_file,
        offset + bytes.len() as u64,
        now,
    )
}
fn sql(store: &SqliteAccountStorage, s: &str) {
    store.lock().unwrap().execute_batch(s).unwrap();
}

#[test]
fn attachment_jobs_and_bytes_survive_encrypted_reopen_and_fence_old_leases() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("attachment-test-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "one");
    let r = request(&store, "one");
    let old = store
        .claim_attachment_acquisition(&r, 11, 20)
        .unwrap()
        .unwrap();
    assert!(
        store
            .claim_attachment_acquisition(&r, 12, 30)
            .unwrap()
            .is_none()
    );
    assert_eq!(request(&store, "one"), r);
    store.close().unwrap();
    assert!(store.attachment_acquisition_status(&r).is_err());
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert!(
        store
            .due_attachment_acquisitions(19, 64)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.due_attachment_acquisitions(20, 1).unwrap(),
        vec![r.clone()]
    );
    let new = store
        .claim_attachment_acquisition(&r, 20, 30)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&old, BODY, 21, 10000)
            .unwrap(),
        AttachmentPublishResult::Superseded
    );
    assert!(!store.fail_attachment_acquisition(&old, Some(99)).unwrap());
    assert_eq!(
        store
            .complete_attachment_acquisition(&new, BODY, 21, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(read(&store, &r), BODY);
    let status = store.attachment_acquisition_status(&r).unwrap().unwrap();
    assert_eq!(status.state, AttachmentAcquisitionState::Ready);
    assert_eq!(status.attempts, 2);
    assert!(
        store
            .due_attachment_acquisitions(1000, 64)
            .unwrap()
            .is_empty()
    );
    let other = SqliteAccountStorage::in_memory().unwrap();
    assert!(
        other
            .read_retained_attachment(&r, 12, 0, 100)
            .unwrap()
            .is_none()
    );
    assert!(!other.retry_attachment_acquisition(&r, 12).unwrap());
    store.close().unwrap();
    let file = std::fs::read(&path).unwrap();
    assert!(!file.starts_with(b"SQLite format 3"));
    assert!(!file.windows(BODY.len()).any(|b| b == BODY));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn attachment_removal_survives_rebuild_revalidation_and_requires_explicit_download_again() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    seed(&store, "two");
    let one = request(&store, "one");
    let two = request(&store, "two");
    publish(&store, &one);
    publish(&store, &two);
    store.rebuild_message_timeline_for_group(GROUP).unwrap();
    assert_eq!(read(&store, &one), BODY);
    assert_eq!(read(&store, &two), BODY);
    assert!(
        !store
            .remove_local_attachment(GROUP, "one", u32::MAX)
            .unwrap()
    );
    assert!(store.remove_local_attachment(GROUP, "one", 0).unwrap());
    assert!(store.remove_local_attachment(GROUP, "one", 0).unwrap());
    store.rebuild_message_timeline_for_group(GROUP).unwrap();
    store
        .invalidate_app_event_by_message_id(GROUP, "one", "branch_selection_withdrawn")
        .unwrap();
    store.record_app_event(&source("one")).unwrap();
    assert_eq!(
        store
            .request_attachment_acquisition(GROUP, &selected("one"), digest(), 12)
            .unwrap(),
        AttachmentDemand::Suppressed
    );
    assert_eq!(read(&store, &two), BODY);
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        BODY.len() as u64
    );
    // Re-recording does not necessarily revalidate an invalidated raw event. Use
    // the same durable revalidation state transition before requesting again.
    sql(
        &store,
        "UPDATE app_events SET invalidated=0,invalidation_reason=NULL WHERE message_id_hex='one'",
    );
    store.rebuild_message_timeline_for_group(GROUP).unwrap();
    let AttachmentDemand::Requested(new) = store
        .request_attachment_download_again(GROUP, &selected("one"), digest(), 12)
        .unwrap()
    else {
        panic!("request")
    };
    assert_ne!(new, one);
    publish(&store, &new);
    assert_eq!(read(&store, &new), BODY);
    assert!(
        store
            .read_retained_attachment(&one, 12, 0, 100)
            .unwrap()
            .is_none()
    );
}

#[test]
fn attachment_invite_visibility_and_source_changes_gate_admission_and_completion() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    sql(&store, "UPDATE account_groups SET pending_confirmation=1");
    assert_eq!(
        store
            .request_attachment_acquisition(GROUP, &selected("one"), digest(), 11)
            .unwrap(),
        AttachmentDemand::Unavailable
    );
    sql(&store, "UPDATE account_groups SET pending_confirmation=0");
    let r = request(&store, "one");
    let job = store
        .claim_attachment_acquisition(&r, 11, 100)
        .unwrap()
        .unwrap();
    sql(&store, "UPDATE account_groups SET pending_confirmation=1");
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 12, 1000)
            .unwrap(),
        AttachmentPublishResult::Superseded
    );
    assert!(
        store
            .claim_attachment_acquisition(&r, 100, 200)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .due_attachment_acquisitions(101, 64)
            .unwrap()
            .is_empty()
    );
    sql(&store, "UPDATE account_groups SET pending_confirmation=0");
    assert!(store.retry_attachment_acquisition(&r, 11).unwrap());
    publish(&store, &r);
    sql(
        &store,
        "UPDATE message_timeline SET received_at=received_at+1",
    );
    assert_eq!(read(&store, &r), BODY);
    // Blocking hides local access without physically evicting retained bytes.
    sql(&store, "UPDATE attachment_history SET visible=0");
    assert!(
        store
            .read_retained_attachment(&r, 12, 0, 100)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        BODY.len() as u64
    );
    sql(&store, "UPDATE attachment_history SET visible=1");
    sql(
        &store,
        "UPDATE message_timeline SET media_json='{\"imeta\":[[\"imeta\",\"m audio/ogg\"]]}'",
    );
    assert!(store.attachment_acquisition_status(&r).unwrap().is_none());
    assert_eq!(store.retained_attachment_byte_count().unwrap(), 0);
}

#[test]
fn attachment_deletion_invalidation_and_expiry_erase_bytes_and_reject_late_results() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    seed(&store, "two");
    let r = request(&store, "one");
    publish(&store, &r);
    store
        .invalidate_app_event_by_message_id(GROUP, "one", "branch_selection_withdrawn")
        .unwrap();
    assert!(store.attachment_acquisition_status(&r).unwrap().is_none());
    assert_eq!(store.retained_attachment_byte_count().unwrap(), 0);
    let r = request(&store, "two");
    let job = store
        .claim_attachment_acquisition(&r, 11, 100)
        .unwrap()
        .unwrap();
    let mut deletion = source("deletion");
    deletion.kind = 5;
    deletion.tags = vec![vec!["e".into(), "two".into()]];
    store.record_app_event(&deletion).unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 12, 1000)
            .unwrap(),
        AttachmentPublishResult::Superseded
    );
    seed(&store, "three");
    let r = request(&store, "three");
    publish(&store, &r);
    sql(
        &store,
        "UPDATE app_events SET retention_expires_at=20 WHERE message_id_hex='three'",
    );
    assert!(
        store
            .read_retained_attachment(&r, 19, 0, 100)
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .read_retained_attachment(&r, 20, 0, 100)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.prune_expired_attachment_acquisitions(20, 1).unwrap(),
        1
    );
    assert_eq!(store.retained_attachment_byte_count().unwrap(), 0);
    assert_eq!(
        store
            .request_attachment_acquisition(GROUP, &selected("three"), digest(), 20)
            .unwrap(),
        AttachmentDemand::Unavailable
    );
    seed(&store, "four");
    let r = request(&store, "four");
    let job = store
        .claim_attachment_acquisition(&r, 11, 100)
        .unwrap()
        .unwrap();
    sql(
        &store,
        "UPDATE app_events SET retention_expires_at=12 WHERE message_id_hex='four'",
    );
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 12, 1000)
            .unwrap(),
        AttachmentPublishResult::Superseded
    );
}

#[test]
fn attachment_retry_deadlines_capacity_integrity_and_transaction_rollback() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    seed(&store, "two");
    let one = request(&store, "one");
    let two = request(&store, "two");
    publish(&store, &one);
    let job = store
        .claim_attachment_acquisition(&two, 11, 100)
        .unwrap()
        .unwrap();
    assert!(
        store
            .complete_attachment_acquisition(&job, b"wrong", 12, 10000)
            .is_err()
    );
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 12, BODY.len() as u64)
            .unwrap(),
        AttachmentPublishResult::CapacityBlocked
    );
    assert_eq!(read(&store, &one), BODY);
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        BODY.len() as u64
    );
    assert!(store.fail_attachment_acquisition(&job, Some(50)).unwrap());
    assert_eq!(request(&store, "two"), two);
    assert!(
        store
            .due_attachment_acquisitions(49, 64)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.due_attachment_acquisitions(50, 64).unwrap(),
        vec![two.clone()]
    );
    let job = store
        .claim_attachment_acquisition(&two, 50, 100)
        .unwrap()
        .unwrap();
    sql(
        &store,
        "CREATE TRIGGER fail_attachment_insert BEFORE INSERT ON retained_attachment_bytes BEGIN SELECT RAISE(ABORT,'injected'); END;",
    );
    assert!(
        store
            .complete_attachment_acquisition(&job, BODY, 51, 10000)
            .is_err()
    );
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        BODY.len() as u64
    );
    assert_eq!(
        store
            .attachment_acquisition_status(&two)
            .unwrap()
            .unwrap()
            .state,
        AttachmentAcquisitionState::Fetching
    );
    sql(&store, "DROP TRIGGER fail_attachment_insert");
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 51, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    let result: StorageResult<()> = store.connection.with_transaction(|| {
        store.remove_local_attachment(GROUP, "one", 0)?;
        Err(invalid("rollback"))
    });
    assert!(result.is_err());
    assert_eq!(read(&store, &one), BODY);
    assert_eq!(request(&store, "one"), one);
}

#[test]
fn attachment_local_reads_are_bounded_and_account_group_cleanup_is_authoritative() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let r = request(&store, "one");
    publish(&store, &r);
    let mut actual = Vec::new();
    for offset in (0..BODY.len()).step_by(3) {
        actual.extend_from_slice(
            &store
                .read_retained_attachment(&r, 12, offset as u64, 3)
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(actual, BODY);
    for limit in [0, MAX_ATTACHMENT_LOCAL_READ_BYTES + 1] {
        assert!(store.read_retained_attachment(&r, 12, 0, limit).is_err());
    }
    assert!(store.read_retained_attachment(&r, 12, u64::MAX, 1).is_err());
    // Group-list removal (e.g. retained left history) is not source deletion.
    sql(&store, "DELETE FROM account_groups");
    assert_eq!(read(&store, &r), BODY);
    assert!(store.remove_local_attachment(GROUP, "one", 0).unwrap());
    store.delete_local_group_data(GROUP).unwrap();
    let suppressed: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM attachment_removal_suppression",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(suppressed, 0);
    seed(&store, "one");
    let new = request(&store, "one");
    publish(&store, &new);
    sql(
        &store,
        "UPDATE chat_presentation_meta SET store_epoch=randomblob(16)",
    );
    assert!(
        store
            .read_retained_attachment(&new, 12, 0, 100)
            .unwrap()
            .is_none()
    );
    assert_eq!(store.retained_attachment_byte_count().unwrap(), 0);
    assert!(!format!("{new:?}").contains(GROUP));
}

#[test]
fn attachment_removal_during_download_fences_completion_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("attachment-test-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "one");
    let r = request(&store, "one");
    let job = store
        .claim_attachment_acquisition(&r, 11, 100)
        .unwrap()
        .unwrap();
    assert!(!format!("{job:?}").contains("image/png"));
    store.remove_local_attachment(GROUP, "one", 0).unwrap();
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    store.rebuild_message_timeline_for_group(GROUP).unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 12, 10000)
            .unwrap(),
        AttachmentPublishResult::Superseded
    );
    assert_eq!(
        store
            .request_attachment_acquisition(GROUP, &selected("one"), digest(), 12)
            .unwrap(),
        AttachmentDemand::Suppressed
    );
    assert_eq!(store.retained_attachment_byte_count().unwrap(), 0);
}

#[test]
fn attachment_job_candidate_pages_and_expiry_cleanup_use_bounded_indexes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for i in 0..70 {
        let id = format!("m-{i}");
        seed(&store, &id);
        request(&store, &id);
    }
    assert_eq!(store.due_attachment_acquisitions(12, 1).unwrap().len(), 1);
    assert_eq!(store.due_attachment_acquisitions(12, 64).unwrap().len(), 64);
    assert!(store.due_attachment_acquisitions(12, 65).is_err());
    let conn = store.lock().unwrap();
    for (query, index) in [
        (
            "EXPLAIN QUERY PLAN SELECT token FROM attachment_acquisition WHERE due<=?1 ORDER BY due,token LIMIT 64",
            "attachment_acquisition_due",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT token FROM attachment_acquisition WHERE expires_at<=?1 ORDER BY expires_at,token LIMIT 64",
            "attachment_acquisition_expiry",
        ),
    ] {
        let rows = conn
            .prepare(query)
            .unwrap()
            .query_map([12], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(rows.iter().any(|s| s.contains(index)), "{rows:?}");
    }
    drop(conn);
    sql(&store, "UPDATE app_events SET retention_expires_at=12");
    assert_eq!(
        store.prune_expired_attachment_acquisitions(12, 64).unwrap(),
        64
    );
    assert_eq!(
        store.prune_expired_attachment_acquisitions(12, 64).unwrap(),
        6
    );
}

#[test]
fn attachment_admission_rejects_source_changed_since_shared_parser_validation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let old = selected("one");
    sql(
        &store,
        "UPDATE message_timeline SET media_json='{\"imeta\":[[\"imeta\",\"m audio/ogg\"]]}'",
    );
    assert_eq!(
        store
            .request_attachment_acquisition(GROUP, &old, digest(), 11)
            .unwrap(),
        AttachmentDemand::Unavailable
    );
    assert!(
        store
            .due_attachment_acquisitions(12, 64)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn attachment_small_reads_do_not_materialize_the_whole_blob() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    seed(&store, "legacy");
    let bytes = vec![7u8; 2 * 1024 * 1024];
    let job = claim_body(&store, "one", &bytes);
    store
        .complete_attachment_acquisition(&job, &bytes, 12, 2 * bytes.len() as u64)
        .unwrap();
    // A large array row as upgraded databases still hold one: bound whole and
    // left at the migration's `byte_len=-1` sentinel, so sizing reads `bytes`.
    let legacy = claim_body(&store, "legacy", &bytes);
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "INSERT INTO retained_attachment_bytes(token,bytes) VALUES(?1,?2)",
            params![legacy.reference.token, bytes],
        )
        .unwrap();
        conn.execute(
            "UPDATE retained_attachment_bytes SET byte_len=-1 WHERE token=?1",
            [&legacy.reference.token],
        )
        .unwrap();
        conn.execute(
            "UPDATE attachment_acquisition SET state=3,due=NULL,attempt=NULL WHERE token=?1",
            [&legacy.reference.token],
        )
        .unwrap();
    }
    {
        let conn = store.lock().unwrap();
        // SAFETY: the guard exclusively owns this live connection. Lowering its
        // value-size limit makes full-value materialization fail deterministically.
        unsafe {
            rusqlite::ffi::sqlite3_limit(
                conn.handle(),
                rusqlite::ffi::SQLITE_LIMIT_LENGTH,
                64 * 1024,
            );
        }
    }
    // Sizing and a small read of the chunked body and of the legacy array row
    // (through `blob_open`) never build a whole-body value.
    for (message, job) in [("one", &job), ("legacy", &legacy)] {
        assert_eq!(
            store
                .retained_attachment_asset(GROUP, message, &format!("source-{message}"), 0, 12)
                .unwrap()
                .unwrap()
                .byte_count,
            bytes.len() as u64,
        );
        assert_eq!(
            store
                .read_retained_attachment(&job.reference, 12, 1024 * 1024, 17)
                .unwrap()
                .unwrap()
                .as_slice(),
            &[7; 17]
        );
    }
}

/// Request and claim one slot whose source declares `bytes` as its plaintext.
fn claim_body(store: &SqliteAccountStorage, message: &str, bytes: &[u8]) -> AttachmentAcquisition {
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    let mut event = source(message);
    event.tags[0][2] = format!("x {}", hex::encode(hash));
    store.record_app_event(&event).unwrap();
    let mut selection = selected(message);
    selection.slot = serde_json::to_value(&event.tags[0]).unwrap();
    let AttachmentDemand::Requested(reference) = store
        .request_attachment_acquisition(GROUP, &selection, hash, 11)
        .unwrap()
    else {
        panic!("missing demand")
    };
    store
        .claim_attachment_acquisition(&reference, 11, 100)
        .unwrap()
        .unwrap()
}

#[test]
fn attachment_publication_never_holds_more_than_one_chunk_in_a_sqlite_value() {
    const CHUNK: usize = ATTACHMENT_STAGING_CHUNK_BYTES;
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "array");
    seed(&store, "chunked");
    let array: Vec<u8> = (0..CHUNK).map(|i| (i % 251) as u8).collect();
    let chunked: Vec<u8> = (0..3 * CHUNK + 5).map(|i| (i % 241) as u8).collect();
    let array_job = claim_body(&store, "array", &array);
    let chunked_job = claim_body(&store, "chunked", &chunked);
    {
        let conn = store.lock().unwrap();
        // SAFETY: the guard exclusively owns this live connection. Any value
        // longer than one staging chunk, such as a whole-body zeroblob or
        // record, now fails deterministically instead of being allocated.
        unsafe {
            rusqlite::ffi::sqlite3_limit(
                conn.handle(),
                rusqlite::ffi::SQLITE_LIMIT_LENGTH,
                CHUNK as i32 + 1024,
            );
        }
    }
    for (job, body) in [(&array_job, &array), (&chunked_job, &chunked)] {
        assert_eq!(
            store
                .complete_attachment_acquisition(job, body, 12, 1 << 30)
                .unwrap(),
            AttachmentPublishResult::Published
        );
    }
    let (files, chunks): (i64, i64) = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT (SELECT count(*) FROM retained_attachment_files WHERE completed=1),
                    (SELECT count(*) FROM retained_attachment_chunks)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    // One staging chunk stays an array row; a larger body is one sealed file.
    assert_eq!((files, chunks), (1, 4));
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        (array.len() + chunked.len()) as u64
    );
    for (message, body) in [("array", &array), ("chunked", &chunked)] {
        let asset = store
            .retained_attachment_asset(GROUP, message, &format!("source-{message}"), 0, 12)
            .unwrap()
            .unwrap();
        assert_eq!(asset.byte_count, body.len() as u64);
        for (offset, len) in [(0, 17), (CHUNK - 6, 20), (body.len() - 3, 3)] {
            assert_eq!(
                store
                    .read_retained_attachment(&asset.reference, 12, offset as u64, len)
                    .unwrap()
                    .unwrap()
                    .as_slice(),
                &body[offset..(offset + len).min(body.len())]
            );
        }
    }
    assert!(store.remove_local_attachment(GROUP, "chunked", 0).unwrap());
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        array.len() as u64
    );
    let bodies: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT (SELECT count(*) FROM attachment_chunk_bodies)+(SELECT count(*) FROM retained_attachment_chunks)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bodies, 0);
}

#[test]
fn chunk_publication_failing_mid_body_commits_nothing() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let body: Vec<u8> = (0..3 * ATTACHMENT_STAGING_CHUNK_BYTES + 5)
        .map(|i| (i % 239) as u8)
        .collect();
    let job = claim_body(&store, "one", &body);
    sql(
        &store,
        "CREATE TEMP TRIGGER fail_second_chunk BEFORE INSERT ON main.retained_attachment_chunks
         WHEN NEW.offset>0 BEGIN SELECT RAISE(ABORT,'injected chunk failure'); END;",
    );
    assert!(
        store
            .complete_attachment_acquisition(&job, &body, 12, 1 << 30)
            .is_err()
    );
    let rows: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT (SELECT count(*) FROM retained_attachment_bytes)+(SELECT count(*) FROM retained_attachment_files)
                   +(SELECT count(*) FROM attachment_chunk_bodies)+(SELECT count(*) FROM retained_attachment_chunks)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0);
    assert_eq!(store.retained_attachment_byte_count().unwrap(), 0);
    // The rolled-back attempt still owns its lease and publishes once the
    // fault is gone.
    sql(&store, "DROP TRIGGER temp.fail_second_chunk");
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, &body, 12, 1 << 30)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        body.len() as u64
    );
}

#[test]
fn attachment_policy_park_resumes_on_readmission_but_terminal_failure_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("policy-park-test-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "one");
    let reference = request(&store, "one");
    sql(&store, "UPDATE account_groups SET pending_confirmation=1");
    assert!(
        store
            .claim_attachment_acquisition(&reference, 11, 20)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .due_attachment_acquisitions(11, 64)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .attachment_acquisition_status(&reference)
            .unwrap()
            .unwrap()
            .state,
        AttachmentAcquisitionState::Parked,
    );
    assert_eq!(
        store
            .request_attachment_acquisition(GROUP, &selected("one"), digest(), 11)
            .unwrap(),
        AttachmentDemand::Unavailable,
    );
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    sql(&store, "UPDATE account_groups SET pending_confirmation=0");
    assert_eq!(request(&store, "one"), reference);
    assert_eq!(
        store.due_attachment_acquisitions(11, 64).unwrap(),
        vec![reference.clone()]
    );
    let job = store
        .claim_attachment_acquisition(&reference, 11, 20)
        .unwrap()
        .unwrap();
    assert!(store.fail_attachment_acquisition(&job, None).unwrap());
    assert_eq!(request(&store, "one"), reference);
    assert!(
        store
            .due_attachment_acquisitions(11, 64)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .attachment_acquisition_status(&reference)
            .unwrap()
            .unwrap()
            .state,
        AttachmentAcquisitionState::Blocked
    );
    assert!(store.retry_attachment_acquisition(&reference, 12).unwrap());
    assert_eq!(
        store.due_attachment_acquisitions(12, 64).unwrap(),
        vec![reference]
    );
}

#[test]
fn attachment_background_demand_tracks_sources_and_acceptance() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let pending = || {
        store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM attachment_worker_demand", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
    };
    assert_eq!(pending(), 1);
    sql(
        &store,
        "DELETE FROM attachment_worker_demand;
        UPDATE account_groups SET pending_confirmation=1;",
    );
    seed(&store, "two");
    assert_eq!(pending(), 0, "pending invitations never auto-download");
    sql(&store, "UPDATE account_groups SET pending_confirmation=0;");
    assert_eq!(
        pending(),
        2,
        "acceptance discovers retained history without opening a screen"
    );
    sql(&store, "DELETE FROM app_events;");
    assert_eq!(pending(), 0);
}

#[test]
fn attachment_worker_acknowledgement_cannot_lose_source_updates_and_removal_stays_suppressed() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let first = store.attachment_worker_demands(1).unwrap().pop().unwrap();
    // A repair can recreate the same slot while the caller holds a work item.
    sql(
        &store,
        "UPDATE attachment_history SET timeline_at=timeline_at+1;",
    );
    store.acknowledge_attachment_worker_demand(&first).unwrap();
    let next = store.attachment_worker_demands(1).unwrap().pop().unwrap();
    assert_eq!(next.entry.source_epoch, Some(3));
    store.remove_local_attachment(GROUP, "one", 0).unwrap();
    assert_eq!(
        store
            .request_attachment_acquisition(GROUP, &next.entry, digest(), 11)
            .unwrap(),
        AttachmentDemand::Suppressed
    );
    store.acknowledge_attachment_worker_demand(&next).unwrap();
    assert!(store.attachment_worker_demands(32).unwrap().is_empty());
    // Routine account saves must not enqueue the whole retained history again.
    sql(&store, "UPDATE account_groups SET updated_at=updated_at+1;");
    assert!(store.attachment_worker_demands(32).unwrap().is_empty());
}

#[test]
fn attachment_worker_pending_demand_survives_encrypted_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("worker.sqlite");
    let key = SqlCipherKey::new("worker-restart-test").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    for i in 0..35 {
        seed(&store, &format!("{i:064x}"));
    }
    assert_eq!(store.attachment_worker_demands(32).unwrap().len(), 32);
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    for demand in store.attachment_worker_demands(32).unwrap() {
        store.acknowledge_attachment_worker_demand(&demand).unwrap();
    }
    assert_eq!(store.attachment_worker_demands(32).unwrap().len(), 3);
}

#[test]
fn attachment_startup_reclaims_only_abandoned_attempts_in_bounded_batches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resume.sqlite");
    let key = SqlCipherKey::new("resume-test").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    for name in ["active", "retry", "ready", "blocked"] {
        seed(&store, name);
    }
    let active = request(&store, "active");
    let old = store
        .claim_attachment_acquisition(&active, 12, 1200)
        .unwrap()
        .unwrap();
    let retry = request(&store, "retry");
    let job = store
        .claim_attachment_acquisition(&retry, 12, 1200)
        .unwrap()
        .unwrap();
    store.fail_attachment_acquisition(&job, Some(100)).unwrap();
    let ready = request(&store, "ready");
    publish(&store, &ready);
    let blocked = request(&store, "blocked");
    let job = store
        .claim_attachment_acquisition(&blocked, 12, 1200)
        .unwrap()
        .unwrap();
    store.fail_attachment_acquisition(&job, None).unwrap();
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(store.resume_attachment_acquisitions(13, 1).unwrap(), 1);
    assert_eq!(store.resume_attachment_acquisitions(13, 1).unwrap(), 0);
    assert_eq!(
        store.due_attachment_acquisitions(13, 64).unwrap(),
        vec![active.clone()]
    );
    assert_eq!(
        store
            .complete_attachment_acquisition(&old, BODY, 13, 10000)
            .unwrap(),
        AttachmentPublishResult::Superseded
    );
    let new = store
        .claim_attachment_acquisition(&active, 13, 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&new, BODY, 13, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    assert_eq!(
        store
            .attachment_acquisition_status(&retry)
            .unwrap()
            .unwrap()
            .due,
        Some(100)
    );
    assert_eq!(
        store
            .attachment_acquisition_status(&blocked)
            .unwrap()
            .unwrap()
            .state,
        AttachmentAcquisitionState::Blocked
    );
    assert_eq!(read(&store, &ready), BODY);
}

#[test]
fn attachment_partial_storage_is_provisioned_without_network() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let count: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM attachment_partial", [], |r| r.get(0))
        .expect("resumable acquisition needs a durable protected checkpoint store");
    assert_eq!(count, 0);
}

/// Worker admission as the app hands it to readmission: room for a download
/// of up to `limit` bytes less its recorded checkpoint, as one threshold.
fn admission(reserve: u64, free: u64, limit: u64) -> ReadmitAdmission {
    match free
        .checked_sub(reserve)
        .and_then(|available| media_store::DiskPolicy::checkpoint_needed(limit, available))
    {
        Some(needed) => ReadmitAdmission {
            checkpointed_at_least: needed,
            uncheckpointed: needed == 0,
        },
        None => ReadmitAdmission::NONE,
    }
}

fn partial_identity(total: u64) -> AttachmentPartialIdentity {
    AttachmentPartialIdentity {
        ciphertext_digest: [1; 32],
        locator_digest: [2; 32],
        etag: "\"v1\"".into(),
        total,
    }
}

fn partial_usage(store: &SqliteAccountStorage) -> u64 {
    store
        .lock()
        .unwrap()
        .query_row(
            "SELECT coalesce(sum(received),0) FROM attachment_partial",
            [],
            |r| nonnegative(r, 0),
        )
        .unwrap()
}
#[test]
fn attachment_partial_reopen_preserves_prefix_and_fences_old_attempts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.sqlite");
    let key = SqlCipherKey::new("partial-test-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "one");
    let asset = request(&store, "one");
    let old = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let identity = partial_identity(10);
    assert!(checkpoint(&store, &old, &identity, 0, b"abc", 12).unwrap());
    assert!(!checkpoint(&store, &old, &identity, 2, b"x", 12).unwrap());
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    store.resume_attachment_acquisitions(13, 64).unwrap();
    let job = store
        .claim_attachment_acquisition(&asset, 13, 100)
        .unwrap()
        .unwrap();
    assert!(!checkpoint(&store, &old, &identity, 3, b"old", 13).unwrap());
    assert!(
        !store
            .clear_attachment_partial(&old, 13, None)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .load_attachment_partial(&job, 13, 10, None)
            .unwrap()
            .unwrap()
            .received,
        3
    );
    assert!(checkpoint(&store, &job, &identity, 3, b"def", 13).unwrap());
    assert_eq!(
        store
            .load_attachment_partial(&job, 13, 10, None)
            .unwrap()
            .unwrap()
            .received,
        6
    );
    store.remove_local_attachment(GROUP, "one", 0).unwrap();
    assert_eq!(partial_usage(&store), 0);
    assert!(!checkpoint(&store, &job, &identity, 0, b"late", 13).unwrap());
}
/// A checkpoint append the database has no room to record (`SQLITE_FULL`)
/// reaches the media store as a full disk, which the app parks on, and the
/// store cuts the appended bytes off again: the recorded length and the
/// file both stay where they were.
#[test]
fn a_checkpoint_append_on_a_full_database_reports_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let media = media_store::MediaStore::new(
        dir.path().join(media_store::MEDIA_DIRECTORY),
        crate::SqliteMediaCatalog::new(store.clone()),
    );
    seed(&store, "full");
    let asset = request(&store, "full");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let target = store.attachment_checkpoint(&job, partial_identity(10), || 12);
    assert!(media.checkpoint_append(&target, 0, b"abc").unwrap());
    // Recording the length needs more pages than the database may grow.
    sql(
        &store,
        "CREATE TABLE filler(b BLOB);
         CREATE TRIGGER fill_on_record AFTER UPDATE OF received ON attachment_partial
         BEGIN INSERT INTO filler VALUES(zeroblob(1048576)); END;",
    );
    store.limit_database_pages_for_test(16).unwrap();
    assert_eq!(
        media.checkpoint_append(&target, 3, b"defg"),
        Err(media_store::MediaError::Capacity)
    );
    store.limit_database_pages_for_test(1 << 30).unwrap();
    let part = store
        .load_attachment_partial(&job, 12, 10, None)
        .unwrap()
        .unwrap();
    assert_eq!(part.received, 3);
    assert_eq!(
        std::fs::metadata(media.wire_path(&part.wire_file))
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn attachment_partial_record_rollback_and_terminal_cleanup() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let a = request(&store, "one");
    let job = store
        .claim_attachment_acquisition(&a, 12, 100)
        .unwrap()
        .unwrap();
    let identity = partial_identity(10);
    assert!(checkpoint(&store, &job, &identity, 0, b"abcdef", 12).unwrap());
    // A record that fails leaves the recorded length where it was.
    store.lock().unwrap().execute_batch("CREATE TRIGGER refuse_record BEFORE UPDATE OF received ON attachment_partial BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(checkpoint(&store, &job, &identity, 6, b"xyz", 12).is_err());
    assert_eq!(
        store
            .load_attachment_partial(&job, 12, 10, None)
            .unwrap()
            .unwrap()
            .received,
        6
    );
    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER refuse_record;")
        .unwrap();
    // A terminal failure releases the checkpoint row (its wire file follows
    // through the media sweep).
    store.fail_attachment_acquisition(&job, None).unwrap();
    assert_eq!(partial_usage(&store), 0);
    let rows: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM attachment_partial", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0);
}
#[test]
fn attachment_partial_expiry_is_bounded_and_shrinking_limit_discards() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for name in ["one", "two"] {
        seed(&store, name);
        let asset = request(&store, name);
        let job = store
            .claim_attachment_acquisition(&asset, 12, 100000)
            .unwrap()
            .unwrap();
        checkpoint(&store, &job, &partial_identity(10), 0, b"abc", 12).unwrap();
    }
    assert_eq!(store.prune_attachment_partials(86412, 1).unwrap(), 1);
    assert_eq!(store.prune_attachment_partials(86412, 1).unwrap(), 1);
    assert_eq!(partial_usage(&store), 0);
    seed(&store, "three");
    let asset = request(&store, "three");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    checkpoint(&store, &job, &partial_identity(10), 0, b"abc", 12).unwrap();
    assert!(
        store
            .load_attachment_partial(&job, 12, 9, None)
            .unwrap()
            .is_none()
    );
    assert_eq!(partial_usage(&store), 0);
}

#[test]
fn attachment_partial_locator_mismatch_does_not_discard_the_checkpoint() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let asset = request(&store, "one");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let identity = partial_identity(10);
    assert!(checkpoint(&store, &job, &identity, 0, b"abc", 12).unwrap());
    assert!(
        store
            .load_attachment_partial(&job, 12, 10, Some((&[1; 32], &[3; 32])))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        partial_usage(&store),
        3,
        "a mismatched locator must not discard the checkpoint"
    );
    assert_eq!(
        store
            .load_attachment_partial(&job, 12, 10, Some((&[1; 32], &[2; 32])))
            .unwrap()
            .unwrap()
            .received,
        3,
        "the matching locator resumes it"
    );
}

#[test]
fn attachment_partial_cleanup_is_locator_ciphertext_and_attempt_scoped() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let asset = request(&store, "one");
    let old = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let identity = partial_identity(10);
    assert!(checkpoint(&store, &old, &identity, 0, b"abc", 12).unwrap());
    for pair in [([1; 32], [3; 32]), ([4; 32], [2; 32])] {
        assert!(
            !store
                .clear_attachment_partial(&old, 12, Some((&pair.0, &pair.1)))
                .unwrap()
                .is_some()
        );
        assert_eq!(partial_usage(&store), 3);
    }
    store.resume_attachment_acquisitions(13, 64).unwrap();
    let current = store
        .claim_attachment_acquisition(&asset, 13, 100)
        .unwrap()
        .unwrap();
    assert!(
        !store
            .clear_attachment_partial(&old, 13, Some((&[1; 32], &[2; 32])))
            .unwrap()
            .is_some()
    );
    assert_eq!(partial_usage(&store), 3);
    assert!(
        store
            .clear_attachment_partial(&current, 13, Some((&[1; 32], &[2; 32])))
            .unwrap()
            .is_some()
    );
    assert_eq!(partial_usage(&store), 0);
}

#[test]
fn attachment_local_metadata_is_read_only_and_follows_byte_visibility() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let lookup = |now| {
        store
            .retained_attachment_asset(GROUP, "one", "source-one", 0, now)
            .unwrap()
    };
    assert!(lookup(12).is_none());
    assert!(
        store
            .due_attachment_acquisitions(12, 64)
            .unwrap()
            .is_empty()
    );
    let reference = request(&store, "one");
    assert!(lookup(12).is_none());
    publish(&store, &reference);
    let asset = lookup(12).expect("published bytes must be discoverable without requesting them");
    assert_eq!(asset.reference, reference);
    assert_eq!(asset.byte_count, BODY.len() as u64);
    assert!(
        store
            .retained_attachment_asset(GROUP, "one", "obsolete-source", 0, 12)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .retained_attachment_asset(GROUP, "one", "source-one", 1, 12)
            .unwrap()
            .is_none()
    );
    sql(&store, "UPDATE app_events SET retention_expires_at=20");
    assert!(lookup(19).is_some());
    assert!(lookup(20).is_none());
    assert!(
        store
            .read_retained_attachment(&reference, 20, 0, 1)
            .unwrap()
            .is_none()
    );
    sql(&store, "UPDATE app_events SET retention_expires_at=NULL");
    store.remove_local_attachment(GROUP, "one", 0).unwrap();
    assert!(lookup(12).is_none());
    assert!(
        store
            .read_retained_attachment(&reference, 12, 0, 1)
            .unwrap()
            .is_none()
    );
}

#[test]
fn attachment_asset_opaque_references_are_bounded_and_store_scoped() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let reference = request(&store, "one");
    publish(&store, &reference);
    let opaque = reference.to_opaque();
    assert_eq!(AttachmentAssetRef::from_opaque(&opaque).unwrap(), reference);
    for input in [
        "".to_owned(),
        "x".repeat(1000),
        opaque.replacen("1:", "2:", 1),
        opaque.replace(':', "/"),
        format!("{opaque}:extra"),
    ] {
        assert!(AttachmentAssetRef::from_opaque(&input).is_err());
    }
    let other = SqliteAccountStorage::in_memory().unwrap();
    assert!(
        other
            .read_retained_attachment(&reference, 12, 0, 1)
            .unwrap()
            .is_none()
    );
    sql(
        &store,
        "UPDATE chat_presentation_meta SET store_epoch=randomblob(16)",
    );
    assert!(
        store
            .read_retained_attachment(&reference, 12, 0, 1)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .retained_attachment_asset(GROUP, "one", "source-one", 0, 12)
            .unwrap()
            .is_none()
    );
}

#[test]
fn attachment_cancellation_is_durable_and_only_explicit_retry_readmits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cancel.db");
    let key = SqlCipherKey::new("cancel-restart-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "cancel");
    let reference = request(&store, "cancel");
    let old = store
        .claim_attachment_acquisition(&reference, 12, 100)
        .unwrap()
        .unwrap();
    assert!(
        store.cancel_attachment_acquisition(&reference).unwrap(),
        "cancel must persist user intent"
    );
    assert_eq!(
        store
            .complete_attachment_acquisition(&old, BODY, 13, 10000)
            .unwrap(),
        AttachmentPublishResult::Superseded
    );
    drop(store);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    request(&store, "cancel");
    store.resume_attachment_acquisitions(200, 64).unwrap();
    assert!(
        store
            .due_attachment_acquisitions(200, 64)
            .unwrap()
            .is_empty()
    );
    assert!(store.retry_attachment_acquisition(&reference, 201).unwrap());
    assert!(
        store
            .claim_attachment_acquisition(&reference, 201, 300)
            .unwrap()
            .is_some()
    );
}

fn policy(automatic: bool, limit: u64) -> AttachmentDownloadPolicy {
    AttachmentDownloadPolicy {
        automatic,
        retained_bytes: 10000,
        disk_reserve: 0,
        transfer_limit: limit,
    }
}
fn transfer(
    store: &SqliteAccountStorage,
    message: &str,
    automatic: bool,
) -> AttachmentTransferStatus {
    store
        .attachment_transfer_status(
            GROUP,
            message,
            &format!("source-{message}"),
            0,
            20,
            automatic,
        )
        .unwrap()
        .unwrap()
}
#[test]
fn cancellation_preserves_partial_until_expiry_and_never_removes_ready_bytes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "partial");
    let asset = request(&store, "partial");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    checkpoint(&store, &job, &partial_identity(10), 0, b"abc", 12).unwrap();
    assert_eq!(partial_usage(&store), 3);
    store.cancel_attachment_acquisition(&asset).unwrap();
    assert_eq!(partial_usage(&store), 3);
    assert_eq!(
        transfer(&store, "partial", true).state,
        AttachmentTransferState::Cancelled
    );
    store
        .set_attachment_download_policy(&policy(false, 64), 13)
        .unwrap();
    store
        .set_attachment_download_policy(&policy(true, 128), 14)
        .unwrap();
    assert_eq!(
        transfer(&store, "partial", true).state,
        AttachmentTransferState::Cancelled
    );
    assert!(
        store
            .attachment_transfer_candidates(20, 64, true)
            .unwrap()
            .is_empty()
    );
    store
        .prune_attachment_partials(12 + 24 * 3600 + 1, 64)
        .unwrap();
    assert_eq!(partial_usage(&store), 0);
    store.explicitly_retry_attachment(&asset, 20).unwrap();
    let job = store
        .claim_attachment_acquisition(&asset, 20, 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 21, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    assert!(!store.cancel_attachment_acquisition(&asset).unwrap());
    assert_eq!(
        transfer(&store, "partial", true).state,
        AttachmentTransferState::Ready
    );
    assert_eq!(
        &*store
            .read_retained_attachment(&asset, 21, 0, 100)
            .unwrap()
            .unwrap(),
        BODY
    );
}
#[test]
fn disabled_policy_fences_automatic_completion_but_preserves_promoted_explicit_work() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for m in ["automatic", "explicit"] {
        seed(&store, m);
    }
    let automatic = request(&store, "automatic");
    let explicit = request(&store, "explicit");
    let automatic_job = store
        .claim_attachment_acquisition(&automatic, 12, 100)
        .unwrap()
        .unwrap();
    let explicit_job = store
        .claim_attachment_acquisition(&explicit, 12, 100)
        .unwrap()
        .unwrap();
    // Promotion must preserve an already-running attempt, not start a duplicate.
    store.explicitly_retry_attachment(&explicit, 13).unwrap();
    store
        .set_attachment_download_policy(&policy(false, 64), 14)
        .unwrap();
    assert!(
        !store
            .attachment_transfer_is_active(&automatic_job, 15)
            .unwrap()
    );
    assert!(
        store
            .attachment_transfer_is_active(&explicit_job, 15)
            .unwrap()
    );
    assert_eq!(
        transfer(&store, "automatic", false).state,
        AttachmentTransferState::Paused
    );
    assert_eq!(
        store
            .complete_attachment_acquisition(&automatic_job, BODY, 15, 10000)
            .unwrap(),
        AttachmentPublishResult::Superseded
    );
    assert_eq!(
        store
            .complete_attachment_acquisition(&explicit_job, BODY, 15, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    assert!(
        store
            .attachment_transfer_candidates(20, 64, false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .attachment_download_policy(&policy(true, 100))
            .unwrap(),
        policy(false, 64)
    );
}
#[test]
fn cap_increase_readmits_size_failures_but_not_integrity_or_cancelled_work() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for m in ["size", "integrity", "cancel"] {
        seed(&store, m);
        let asset = request(&store, m);
        let job = store
            .claim_attachment_acquisition(&asset, 12, 100)
            .unwrap()
            .unwrap();
        match m {
            "size" => store.block_attachment_size_policy(&job, 64, 13).unwrap(),
            "integrity" => {
                store.fail_attachment_acquisition(&job, None).unwrap();
            }
            _ => {
                store.cancel_attachment_acquisition(&asset).unwrap();
            }
        }
    }
    store
        .set_attachment_download_policy(&policy(true, 64), 13)
        .unwrap();
    assert!(
        store
            .attachment_transfer_candidates(20, 64, true)
            .unwrap()
            .is_empty()
    );
    store
        .set_attachment_download_policy(&policy(true, 128), 14)
        .unwrap();
    assert_eq!(
        store.attachment_transfer_candidates(20, 64, true).unwrap(),
        vec![request(&store, "size")]
    );
    assert_eq!(
        transfer(&store, "integrity", true).state,
        AttachmentTransferState::Failed
    );
    assert_eq!(
        transfer(&store, "cancel", true).state,
        AttachmentTransferState::Cancelled
    );
}
#[test]
fn progress_is_monotonic_per_http_generation_and_fenced_by_attempt() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "progress");
    let asset = request(&store, "progress");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    assert!(
        store
            .update_attachment_progress(&job, 13, 1, 8, Some(12), true)
            .unwrap()
    );
    assert!(
        !store
            .update_attachment_progress(&job, 13, 1, 7, Some(12), false)
            .unwrap()
    );
    let first = transfer(&store, "progress", true);
    assert_eq!((first.attempt, first.received), (1, 8));
    assert!(
        store
            .update_attachment_progress(&job, 14, 1, 0, None, true)
            .unwrap()
    );
    assert!(
        store
            .update_attachment_progress(&job, 14, 1, 12, Some(12), false)
            .unwrap()
    );
    store.update_attachment_phase(&job, 15, 2).unwrap();
    let second = transfer(&store, "progress", true);
    assert_eq!((second.attempt, second.received), (2, 12));
    assert_eq!(second.state, AttachmentTransferState::VerifyingCiphertext);
    store.cancel_attachment_acquisition(&asset).unwrap();
    assert!(!store.update_attachment_phase(&job, 16, 4).unwrap());
    assert!(
        !store
            .update_attachment_progress(&job, 16, 1, 0, None, true)
            .unwrap()
    );
}
#[test]
fn explicit_then_recent_candidates_precede_backfill_and_invalid_policy_is_atomic() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for (m, t) in [("old", 1), ("new", 30), ("explicit", 2)] {
        seed(&store, m);
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE attachment_history SET received_at=?2 WHERE message_id_hex=?1",
                params![m, t],
            )
            .unwrap();
        request(&store, m);
    }
    let explicit = request(&store, "explicit");
    store.explicitly_retry_attachment(&explicit, 12).unwrap();
    assert_eq!(
        store.attachment_transfer_candidates(20, 64, true).unwrap(),
        vec![explicit, request(&store, "new"), request(&store, "old")]
    );
    store
        .set_attachment_download_policy(&policy(true, 64), 12)
        .unwrap();
    assert!(
        store
            .set_attachment_download_policy(&policy(false, 0), 13)
            .is_err()
    );
    assert_eq!(
        store
            .attachment_download_policy(&policy(false, 10))
            .unwrap(),
        policy(true, 64)
    );
}
#[test]
fn stale_download_again_does_not_clear_removal_and_valid_request_is_explicit() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "removed");
    request(&store, "removed");
    store.remove_local_attachment(GROUP, "removed", 0).unwrap();
    let mut stale = selected("removed");
    stale.source_epoch = Some(4);
    assert!(matches!(
        store
            .request_attachment_download_again(GROUP, &stale, digest(), 12)
            .unwrap(),
        AttachmentDemand::Unavailable
    ));
    assert_eq!(
        transfer(&store, "removed", true).state,
        AttachmentTransferState::Removed
    );
    let AttachmentDemand::Requested(asset) = store
        .request_attachment_download_again(GROUP, &selected("removed"), digest(), 13)
        .unwrap()
    else {
        panic!("request missing")
    };
    assert_eq!(
        store.attachment_transfer_candidates(20, 64, false).unwrap(),
        vec![asset]
    );
}

#[test]
fn attachment_promoted_explicit_transfer_retries_with_full_limit_after_old_cap() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "promoted");
    let asset = request(&store, "promoted");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    store.explicitly_retry_attachment(&asset, 13).unwrap();
    store.block_attachment_size_policy(&job, 64, 14).unwrap();
    assert_eq!(
        store.attachment_transfer_candidates(20, 64, false).unwrap(),
        vec![asset]
    );
    assert_eq!(
        transfer(&store, "promoted", false).state,
        AttachmentTransferState::Queued
    );
}

#[test]
fn attachment_retry_claim_resets_progress_before_any_response_body() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "retry-progress");
    let asset = request(&store, "retry-progress");
    let old = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    store
        .update_attachment_progress(&old, 13, 1, 8, Some(12), true)
        .unwrap();
    let previous = transfer(&store, "retry-progress", true);
    store.fail_attachment_acquisition(&old, Some(14)).unwrap();
    let current = store
        .claim_attachment_acquisition(&asset, 14, 100)
        .unwrap()
        .unwrap();
    let claimed = transfer(&store, "retry-progress", true);
    assert_eq!(claimed.state, AttachmentTransferState::Downloading);
    assert!(
        claimed.attempt > previous.attempt,
        "claim must identify the new attempt before HTTP starts"
    );
    assert_eq!((claimed.received, claimed.total), (0, None));
    store
        .update_attachment_progress(&current, 15, 1, 8, Some(12), true)
        .unwrap();
    let resumed = transfer(&store, "retry-progress", true);
    assert_eq!(
        resumed.attempt, claimed.attempt,
        "first body belongs to the claimed generation"
    );
    assert_eq!(resumed.received, 8);
    store
        .update_attachment_progress(&current, 16, 1, 0, None, true)
        .unwrap();
    assert!(
        transfer(&store, "retry-progress", true).attempt > resumed.attempt,
        "locator fallback explicitly resets generation"
    );
}

#[test]
fn attachment_policy_rejects_quota_smaller_than_admission_without_mutating() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let original = policy(true, 64);
    store.set_attachment_download_policy(&original, 12).unwrap();
    let mut invalid = original.clone();
    invalid.retained_bytes = 63;
    assert!(store.set_attachment_download_policy(&invalid, 13).is_err());
    assert_eq!(
        store.attachment_download_policy(&original).unwrap(),
        original
    );
}

#[test]
fn attachment_transfer_snapshot_does_not_take_the_writer_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.sqlite");
    let key = SqlCipherKey::new("snapshot test key").unwrap();
    let options = crate::SqliteStorageOptions {
        busy_timeout_ms: 0,
        ..Default::default()
    };
    let store =
        SqliteAccountStorage::open_encrypted_with_options(&path, &key, options.clone()).unwrap();
    seed(&store, "snapshot");
    request(&store, "snapshot");
    let other = SqliteAccountStorage::open_encrypted_with_options(&path, &key, options).unwrap();
    let conn = other.lock().unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let frame =
        store.attachment_transfer_snapshot(GROUP, &[("snapshot", "source-snapshot", 0)], 20, true);
    let single =
        store.attachment_transfer_status(GROUP, "snapshot", "source-snapshot", 0, 20, true);
    conn.execute_batch("ROLLBACK").unwrap();
    assert!(
        frame.is_ok(),
        "read snapshot must coexist with a separate WAL writer: {frame:?}"
    );
    assert!(
        single.is_ok(),
        "single read must coexist with a separate WAL writer: {single:?}"
    );
}

#[test]
fn attachment_transfer_candidates_seek_past_future_backoff() {
    use crate::query_work_test_support::{QUERY_MEASUREMENT, measure};
    let _guard = QUERY_MEASUREMENT.lock().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "future");
    let ready = request(&store, "future");
    store.lock().unwrap().execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<20000)
        INSERT INTO attachment_acquisition(token,group_id_hex,message_id_hex,attachment_index,source_message_id_hex,source_epoch,slot_json,plaintext_digest,due,explicit_request)
        SELECT randomblob(16),group_id_hex,message_id_hex,i,source_message_id_hex,source_epoch,slot_json,plaintext_digest,100000,1
        FROM attachment_acquisition CROSS JOIN n WHERE attachment_index=0;").unwrap();
    for automatic in [true, false] {
        store.explicitly_retry_attachment(&ready, 11).unwrap();
        let (result, steps) = measure(&store, || {
            store
                .attachment_transfer_candidates(20, 32, automatic)
                .unwrap()
        });
        assert_eq!(result, vec![ready.clone()]);
        assert!(
            steps < 500,
            "future backoff must be skipped by a range seek: {steps}"
        );
    }
}

#[test]
fn attachment_partial_forward_progress_resets_backoff_but_replay_does_not() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "slow");
    let asset = request(&store, "slow");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let identity = partial_identity(12);
    checkpoint(&store, &job, &identity, 0, b"abcd", 13).unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE attachment_acquisition SET attempts=9 WHERE token=?1",
            [&asset.token],
        )
        .unwrap();
    checkpoint(&store, &job, &identity, 0, b"abcd", 14).unwrap();
    assert_eq!(
        store
            .attachment_acquisition_status(&asset)
            .unwrap()
            .unwrap()
            .attempts,
        9
    );
    checkpoint(&store, &job, &identity, 4, b"ef", 15).unwrap();
    assert_eq!(
        store
            .attachment_acquisition_status(&asset)
            .unwrap()
            .unwrap()
            .attempts,
        1,
        "new resumable bytes must break a failure streak"
    );
}

#[test]
fn attachment_transfer_snapshot_reports_expiry_even_for_ready_rows() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "expiry");
    let asset = request(&store, "expiry");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    store
        .complete_attachment_acquisition(&job, BODY, 13, 1000)
        .unwrap();
    sql(&store, "UPDATE app_events SET retention_expires_at=25");
    let AttachmentTransferFrame {
        rows,
        next_expiry: next,
        ..
    } = store
        .attachment_transfer_snapshot(GROUP, &[("expiry", "source-expiry", 0)], 20, true)
        .unwrap();
    assert_eq!(
        rows[0].as_ref().unwrap().state,
        AttachmentTransferState::Ready
    );
    assert_eq!(next, Some(25));
    let AttachmentTransferFrame {
        rows,
        next_expiry: next,
        ..
    } = store
        .attachment_transfer_snapshot(GROUP, &[("expiry", "source-expiry", 0)], 25, true)
        .unwrap();
    assert!(rows[0].is_none());
    assert_eq!(next, None);
}

fn automatic_request(
    store: &SqliteAccountStorage,
    message: &str,
    allowed: bool,
) -> (Option<AttachmentTransferStatus>, bool) {
    store
        .request_automatic_attachment(
            GROUP,
            &selected(message),
            digest(),
            12,
            (
                &AttachmentDownloadPolicy {
                    automatic: true,
                    retained_bytes: 10000,
                    disk_reserve: 0,
                    transfer_limit: 100,
                },
                allowed,
            ),
        )
        .unwrap()
}

#[test]
fn automatic_demand_preserves_acquisition_history_after_authoritative_bytes_are_lost() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("automatic-history").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    for message in ["one", "two", "three", "four", "five", "six", "seven"] {
        seed(&store, message);
        let (state, queued) = automatic_request(&store, message, true);
        assert!(queued);
        publish(&store, &state.unwrap().reference.unwrap());
    }
    // Remove the authoritative SQLCipher bytes, not the Android presentation cache.
    sql(&store, "DELETE FROM retained_attachment_bytes");
    assert_eq!(store.retained_attachment_byte_count().unwrap(), 0);
    store.rebuild_message_timeline_for_group(GROUP).unwrap();
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    for _ in 0..10 {
        for message in ["one", "two", "three", "four", "five", "six", "seven"] {
            let (state, queued) = automatic_request(&store, message, true);
            assert!(!queued);
            assert_eq!(
                state.unwrap().state,
                AttachmentTransferState::PreviouslyAcquiredUnavailable
            );
        }
        assert!(
            store
                .attachment_transfer_candidates(1000, 64, true)
                .unwrap()
                .is_empty()
        );
    }
    let reference = request(&store, "one");
    assert!(store.explicitly_retry_attachment(&reference, 12).unwrap());
    publish(&store, &reference);
    assert_eq!(
        automatic_request(&store, "one", true).0.unwrap().state,
        AttachmentTransferState::Ready
    );
}

#[test]
fn automatic_demand_preserves_suppression_deadlines_and_policy() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    assert_eq!(
        automatic_request(&store, "one", false).0.unwrap().state,
        AttachmentTransferState::PolicyBlocked
    );
    assert!(
        store
            .due_attachment_acquisitions(12, 64)
            .unwrap()
            .is_empty()
    );
    let (status, queued) = automatic_request(&store, "one", true);
    assert!(queued);
    let reference = status.unwrap().reference.unwrap();
    let job = store
        .claim_attachment_acquisition(&reference, 12, 100)
        .unwrap()
        .unwrap();
    store.fail_attachment_acquisition(&job, Some(50)).unwrap();
    for _ in 0..10 {
        let (status, queued) = automatic_request(&store, "one", true);
        assert!(!queued);
        assert_eq!(status.unwrap().retry_at, Some(50));
    }
    store.cancel_attachment_acquisition(&reference).unwrap();
    assert_eq!(
        automatic_request(&store, "one", true).0.unwrap().state,
        AttachmentTransferState::Cancelled
    );
    store.remove_attachment_reference(&reference).unwrap();
    assert_eq!(
        automatic_request(&store, "one", true).0.unwrap().state,
        AttachmentTransferState::Removed
    );
}

#[test]
fn automatic_network_budget_survives_progress_reopen_and_repeated_demand() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("automatic-budget").unwrap();
    let mut store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "one");
    let reference = automatic_request(&store, "one", true)
        .0
        .unwrap()
        .reference
        .unwrap();
    for attempt in 0..4 {
        let now = 12 + attempt;
        let job = store
            .claim_attachment_acquisition(&reference, now, 100)
            .unwrap()
            .unwrap();
        assert!(store.begin_attachment_network_attempt(&job, now).unwrap());
        assert!(checkpoint(&store, &job, &partial_identity(100), attempt, b"x", now).unwrap());
        assert_eq!(
            store
                .attachment_acquisition_status(&reference)
                .unwrap()
                .unwrap()
                .attempts,
            1
        );
        store
            .fail_attachment_acquisition(&job, Some(now + 1))
            .unwrap();
        for _ in 0..10 {
            assert!(!automatic_request(&store, "one", true).1);
        }
        store.close().unwrap();
        store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        store.resume_attachment_acquisitions(now + 1, 64).unwrap();
    }
    assert!(
        store
            .claim_attachment_acquisition(&reference, 100, 200)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        automatic_request(&store, "one", true).0.unwrap().state,
        AttachmentTransferState::RetryExhausted
    );
    assert!(store.explicitly_retry_attachment(&reference, 100).unwrap());
    let job = store
        .claim_attachment_acquisition(&reference, 100, 200)
        .unwrap()
        .unwrap();
    assert!(store.begin_attachment_network_attempt(&job, 100).unwrap());
}

#[test]
fn automatic_completed_body_is_terminal_after_capacity_failure_or_process_death() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("automatic-receipt").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    for message in ["capacity", "crash"] {
        seed(&store, message);
        let reference = automatic_request(&store, message, true)
            .0
            .unwrap()
            .reference
            .unwrap();
        let job = store
            .claim_attachment_acquisition(&reference, 12, 100)
            .unwrap()
            .unwrap();
        assert!(store.mark_attachment_body_completed(&job, 12).unwrap());
        if message == "capacity" {
            assert_eq!(
                store
                    .complete_attachment_acquisition(&job, BODY, 12, 0)
                    .unwrap(),
                AttachmentPublishResult::CapacityBlocked
            );
        }
    }
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    store.resume_attachment_acquisitions(13, 64).unwrap();
    for message in ["capacity", "crash"] {
        let (status, queued) = automatic_request(&store, message, true);
        assert!(!queued);
        assert_eq!(
            status.unwrap().state,
            AttachmentTransferState::CompletedUnretained
        );
        assert!(
            store
                .retained_attachment_asset(GROUP, message, &format!("source-{message}"), 0, 13)
                .unwrap()
                .is_none()
        );
    }
    assert!(
        store
            .attachment_transfer_candidates(1000, 64, true)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn automatic_history_replacement_is_independent_but_slot_removal_stays_suppressed() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let original = request(&store, "one");
    publish(&store, &original);
    // Simulate an authoritative source-selection update, not another rendering.
    sql(
        &store,
        "UPDATE message_timeline SET source_message_id_hex='replacement',source_epoch=4 WHERE message_id_hex='one'",
    );
    let entry = store
        .attachment_control_entry(GROUP, "one", "replacement", 0, 12)
        .unwrap()
        .unwrap();
    let policy = AttachmentDownloadPolicy {
        automatic: true,
        retained_bytes: 10000,
        disk_reserve: 0,
        transfer_limit: 100,
    };
    let (status, queued) = store
        .request_automatic_attachment(GROUP, &entry, digest(), 12, (&policy, true))
        .unwrap();
    assert!(queued);
    let replacement = status.unwrap().reference.unwrap();
    assert_ne!(replacement, original);
    assert!(
        store
            .read_retained_attachment(&original, 12, 0, 100)
            .unwrap()
            .is_none()
    );
    store.remove_attachment_reference(&replacement).unwrap();
    sql(
        &store,
        "UPDATE message_timeline SET source_message_id_hex='third-source' WHERE message_id_hex='one'",
    );
    let entry = store
        .attachment_control_entry(GROUP, "one", "third-source", 0, 12)
        .unwrap()
        .unwrap();
    let (status, queued) = store
        .request_automatic_attachment(GROUP, &entry, digest(), 12, (&policy, true))
        .unwrap();
    assert!(!queued);
    assert_eq!(status.unwrap().state, AttachmentTransferState::Removed);
}

#[test]
fn automatic_request_can_readmit_eligible_parked_work_without_replacing_identity() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let reference = automatic_request(&store, "one", true)
        .0
        .unwrap()
        .reference
        .unwrap();
    sql(&store, "UPDATE attachment_acquisition SET state=5,due=NULL");
    assert!(!automatic_request(&store, "one", false).1);
    let (state, queued) = automatic_request(&store, "one", true);
    assert!(queued);
    let state = state.unwrap();
    assert_eq!(state.reference, Some(reference));
    assert_eq!(state.state, AttachmentTransferState::Queued);
}

#[test]
fn automatic_budget_does_not_invalidate_a_live_final_attempt() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let asset = automatic_request(&store, "one", true)
        .0
        .unwrap()
        .reference
        .unwrap();
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    for _ in 0..64 {
        assert!(store.begin_attachment_network_attempt(&job, 12).unwrap());
    }
    assert!(
        store
            .claim_attachment_acquisition(&asset, 13, 200)
            .unwrap()
            .is_none()
    );
    assert!(store.attachment_transfer_is_active(&job, 13).unwrap());
    assert!(store.mark_attachment_body_completed(&job, 13).unwrap());
    assert!(
        store
            .claim_attachment_acquisition(&asset, 13, 200)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 13, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
}

#[test]
fn automatic_retry_budget_also_bounds_failures_before_networking() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let asset = automatic_request(&store, "one", true)
        .0
        .unwrap()
        .reference
        .unwrap();
    for now in 12..16 {
        let job = store
            .claim_attachment_acquisition(&asset, now, 100)
            .unwrap()
            .unwrap();
        assert!(
            store
                .fail_attachment_acquisition(&job, Some(now + 1))
                .unwrap()
        );
        assert_eq!(request(&store, "one"), asset);
    }
    assert!(
        store
            .claim_attachment_acquisition(&asset, 16, 100)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        automatic_request(&store, "one", true).0.unwrap().state,
        AttachmentTransferState::RetryExhausted
    );
}

#[test]
fn automatic_permission_flaps_preserve_partial_and_do_not_spend_claim_budget() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let asset = automatic_request(&store, "one", true)
        .0
        .unwrap()
        .reference
        .unwrap();
    for round in 0..6 {
        let now = 100 + round * 60;
        let job = store
            .claim_attachment_acquisition(&asset, now, now + 180)
            .unwrap()
            .unwrap();
        assert!(store.begin_attachment_network_attempt(&job, now).unwrap());
        assert!(checkpoint(&store, &job, &partial_identity(100), 0, b"prefix", now).unwrap());
        store.pause_automatic_attachments(now + 1).unwrap();
        store.pause_automatic_attachments(now + 1).unwrap();
        assert!(
            !store
                .begin_attachment_network_attempt(&job, now + 1)
                .unwrap()
        );
        assert!(
            store
                .fail_attachment_acquisition(&job, Some(now + 20))
                .unwrap()
        );
        assert_eq!(partial_usage(&store), 6);
        assert_eq!(
            automatic_request(&store, "one", true).0.unwrap().state,
            AttachmentTransferState::Paused
        );
        assert!(!automatic_request(&store, "one", true).1);
        assert!(
            store
                .attachment_transfer_candidates(now + 1000, 64, true)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .resume_permitted_attachments(now + 2, [false; 4])
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .resume_permitted_attachments(now + 2, [true; 4])
                .unwrap(),
            1
        );
        assert!(
            store
                .claim_attachment_acquisition(&asset, now + 19, now + 180)
                .unwrap()
                .is_none()
        );
        let counters = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT acquisition_attempts,network_attempts FROM attachment_acquisition",
                [],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            )
            .unwrap();
        assert_eq!(counters, (0, (round + 1) as i64));
    }
    let job = store
        .claim_attachment_acquisition(&asset, 1000, 1200)
        .unwrap()
        .unwrap();
    assert!(store.mark_attachment_body_completed(&job, 1000).unwrap());
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 1000, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
}

#[test]
fn automatic_verified_publication_survives_revocation_in_either_receipt_order() {
    for receipt_first in [false, true] {
        for durable_policy in [false, true] {
            let store = SqliteAccountStorage::in_memory().unwrap();
            seed(&store, "one");
            let asset = automatic_request(&store, "one", true)
                .0
                .unwrap()
                .reference
                .unwrap();
            let job = store
                .claim_attachment_acquisition(&asset, 12, 100)
                .unwrap()
                .unwrap();
            if receipt_first {
                assert!(store.mark_attachment_body_completed(&job, 13).unwrap());
            }
            if durable_policy {
                store
                    .set_attachment_download_policy(&policy(false, 64), 14)
                    .unwrap();
            } else {
                store.pause_automatic_attachments(14).unwrap();
            }
            if !receipt_first {
                assert!(store.mark_attachment_body_completed(&job, 15).unwrap());
            }
            assert!(!store.begin_attachment_network_attempt(&job, 15).unwrap());
            assert_eq!(
                store
                    .complete_attachment_acquisition(&job, BODY, 15, 10000)
                    .unwrap(),
                AttachmentPublishResult::Published
            );
            assert_eq!(
                &*store
                    .read_retained_attachment(&asset, 15, 0, 100)
                    .unwrap()
                    .unwrap(),
                BODY
            );
        }
    }
}

#[test]
fn automatic_publication_receipt_does_not_override_cancel_or_removal() {
    for remove in [false, true] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, "one");
        let asset = automatic_request(&store, "one", true)
            .0
            .unwrap()
            .reference
            .unwrap();
        let job = store
            .claim_attachment_acquisition(&asset, 12, 100)
            .unwrap()
            .unwrap();
        assert!(store.mark_attachment_body_completed(&job, 13).unwrap());
        if remove {
            store.remove_attachment_reference(&asset).unwrap();
        } else {
            store.cancel_attachment_acquisition(&asset).unwrap();
        }
        assert_eq!(
            store
                .complete_attachment_acquisition(&job, BODY, 15, 10000)
                .unwrap(),
            AttachmentPublishResult::Superseded
        );
    }
}

#[test]
fn native_attachment_retry_and_retention_failures_do_not_acquire_host_limits() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let asset = request(&store, "one");
    for now in 12..22 {
        let job = store
            .claim_attachment_acquisition(&asset, now, 100)
            .unwrap()
            .unwrap();
        for _ in 0..8 {
            assert!(store.begin_attachment_network_attempt(&job, now).unwrap());
        }
        assert!(store.mark_attachment_body_completed(&job, now).unwrap());
        assert_eq!(
            store
                .complete_attachment_acquisition(&job, BODY, now, 0)
                .unwrap(),
            AttachmentPublishResult::CapacityBlocked
        );
        assert!(
            store
                .fail_attachment_acquisition(&job, Some(now + 1))
                .unwrap()
        );
        assert_eq!(
            transfer(&store, "one", true).state,
            AttachmentTransferState::RetryScheduled
        );
    }
    let job = store
        .claim_attachment_acquisition(&asset, 30, 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 30, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
}

#[test]
fn attachment_preparation_deferral_backs_off_then_fails_until_explicit_retry() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let asset = request(&store, "one");
    let status = |store: &SqliteAccountStorage| {
        store
            .attachment_acquisition_status(&asset)
            .unwrap()
            .unwrap()
    };
    let mut now = 11;
    for delay in [15, 30, 60, 120, 240] {
        assert!(!store.defer_attachment_preparation(&asset, now).unwrap());
        let deferred = status(&store);
        assert_eq!(deferred.state, AttachmentAcquisitionState::RetryScheduled);
        assert_eq!(deferred.due, Some(now + delay));
        assert_eq!(deferred.attempts, 0, "deferral is not a transfer attempt");
        // A job that is not yet due is left untouched.
        assert!(
            !store
                .defer_attachment_preparation(&asset, now + delay - 1)
                .unwrap()
        );
        assert_eq!(status(&store).due, Some(now + delay));
        now += delay;
    }
    assert!(store.defer_attachment_preparation(&asset, now).unwrap());
    assert_eq!(status(&store).state, AttachmentAcquisitionState::Blocked);
    assert_eq!(
        transfer(&store, "one", true).state,
        AttachmentTransferState::Failed
    );
    assert_eq!(request(&store, "one"), asset);
    assert!(
        store
            .due_attachment_acquisitions(u32::MAX.into(), 64)
            .unwrap()
            .is_empty()
    );
    // Explicit retry starts a fresh window; a claim also ends the streak.
    assert!(store.explicitly_retry_attachment(&asset, now).unwrap());
    for _ in 0..(MAX_PREPARATION_DEFERRALS - 1) {
        assert!(!store.defer_attachment_preparation(&asset, now).unwrap());
        now = status(&store).due.unwrap();
    }
    let job = store
        .claim_attachment_acquisition(&asset, now, now + 100)
        .unwrap()
        .unwrap();
    assert!(store.fail_attachment_acquisition(&job, Some(now)).unwrap());
    assert!(!store.defer_attachment_preparation(&asset, now).unwrap());
    assert_eq!(status(&store).due, Some(now + 15));
}

#[test]
fn automatic_transport_budget_counts_each_attempt_and_keeps_size_cause_visible() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let asset = automatic_request(&store, "one", true)
        .0
        .unwrap()
        .reference
        .unwrap();
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    for _ in 0..64 {
        assert!(store.begin_attachment_network_attempt(&job, 12).unwrap());
    }
    assert!(!store.begin_attachment_network_attempt(&job, 12).unwrap());
    store.block_attachment_size_policy(&job, 64, 12).unwrap();
    assert_eq!(
        transfer(&store, "one", true).state,
        AttachmentTransferState::PolicyBlocked
    );
    store
        .set_attachment_download_policy(&policy(true, 128), 13)
        .unwrap();
    assert!(
        store
            .claim_attachment_acquisition(&asset, 14, 100)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        transfer(&store, "one", true).state,
        AttachmentTransferState::RetryExhausted
    );
}

#[test]
fn attachment_permission_readmission_is_bounded_and_skips_denied_categories() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
            [GROUP],
        )
        .unwrap();
    for i in 0..70 {
        let message = format!("slot-{i:03}");
        let mut event = source(&message);
        for field in &mut event.tags[0] {
            if field.starts_with("m ") {
                *field = if i < 65 {
                    "m image/png"
                } else {
                    "m application/octet-stream"
                }
                .to_owned();
            }
        }
        store.record_app_event(&event).unwrap();
        let entry = store
            .attachment_control_entry(GROUP, &message, &format!("source-{message}"), 0, 12)
            .unwrap()
            .unwrap();
        let AttachmentDemand::Requested(asset) = store
            .request_attachment_acquisition(GROUP, &entry, digest(), 12)
            .unwrap()
        else {
            panic!("expected demand");
        };
        store.park_attachment_permission(&asset).unwrap();
    }
    assert!(
        store
            .attachment_transfer_candidates(1000, 64, true)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.resume_permitted_attachments(13, [false; 4]).unwrap(),
        0
    );
    assert_eq!(
        store
            .resume_permitted_attachments(13, [false, false, false, true])
            .unwrap(),
        5
    );
    assert_eq!(
        store
            .attachment_transfer_candidates(13, 64, true)
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        store.resume_permitted_attachments(13, [true; 4]).unwrap(),
        64
    );
    assert_eq!(
        store.resume_permitted_attachments(13, [true; 4]).unwrap(),
        1
    );
    assert_eq!(
        store.resume_permitted_attachments(13, [true; 4]).unwrap(),
        0
    );
}

#[test]
fn attachment_terminal_failure_clears_permission_pause() {
    for opted_in in [false, true] {
        for exhausted in [false, true] {
            let store = SqliteAccountStorage::in_memory().unwrap();
            seed(&store, "one");
            let asset = request(&store, "one");
            if opted_in {
                store.enable_attachment_automatic_history(&asset).unwrap();
            }
            let job = store
                .claim_attachment_acquisition(&asset, 12, 100)
                .unwrap()
                .unwrap();
            if exhausted {
                for _ in 0..64 {
                    assert!(store.begin_attachment_network_attempt(&job, 12).unwrap());
                }
            }
            store.pause_automatic_attachments(13).unwrap();
            // Cover hard failure and the exhausted-budget terminal arm.
            let retry = (opted_in && exhausted).then_some(30);
            assert!(store.fail_attachment_acquisition(&job, retry).unwrap());
            let paused: bool = store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT permission_paused FROM attachment_acquisition",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!paused);
            assert_eq!(
                transfer(&store, "one", true).state,
                if opted_in && exhausted {
                    AttachmentTransferState::RetryExhausted
                } else {
                    AttachmentTransferState::Failed
                }
            );
            assert_eq!(
                store.resume_permitted_attachments(40, [true; 4]).unwrap(),
                0
            );
            assert!(
                store
                    .due_attachment_acquisitions(40, 64)
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[test]
fn attachment_repeated_demand_does_not_rewrite_permission_category() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    request(&store, "one");
    let before = store.lock().unwrap().total_changes();
    request(&store, "one");
    assert_eq!(store.lock().unwrap().total_changes(), before);
}

#[test]
fn attachment_idle_permission_resume_is_read_only() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    request(&store, "one");
    store
        .lock()
        .unwrap()
        .execute_batch("PRAGMA query_only=ON")
        .unwrap();
    assert_eq!(
        store.resume_permitted_attachments(12, [true; 4]).unwrap(),
        0
    );
}

/// Free space beyond the reserve that readmits a job parked with `headroom`.
fn fits(headroom: u64) -> u64 {
    headroom + STORAGE_READMIT_MARGIN_BYTES
}
fn parked_headroom(store: &SqliteAccountStorage, asset: &AttachmentAssetRef) -> Option<i64> {
    column(store, asset, "storage_blocked_headroom")
}
fn column(store: &SqliteAccountStorage, asset: &AttachmentAssetRef, name: &str) -> Option<i64> {
    store
        .lock()
        .unwrap()
        .query_row(
            &format!("SELECT {name} FROM attachment_acquisition WHERE token=?1"),
            [&asset.token],
            |r| r.get(0),
        )
        .unwrap()
}
fn park(store: &SqliteAccountStorage, job: &AttachmentAcquisition, headroom: u64, now: u64) {
    assert!(store.block_attachment_storage(job, headroom, now).unwrap());
}
fn due(store: &SqliteAccountStorage, asset: &AttachmentAssetRef) -> Option<u64> {
    store
        .attachment_acquisition_status(asset)
        .unwrap()
        .unwrap()
        .due
}
/// Readmit with a transfer limit small enough that admission never interferes.
fn readmit(
    store: &SqliteAccountStorage,
    now: u64,
    reserve: u64,
    free: u64,
    automatic: bool,
) -> usize {
    store
        .readmit_storage_blocked_attachments(
            now,
            reserve,
            free,
            automatic,
            admission(reserve, free, 1),
        )
        .unwrap()
}

/// mdk#2239: a storage-parked job keeps its checkpoint, never rejoins the due
/// page on its own, readmits exactly when its recorded headroom plus the margin
/// fits below the free space, and clears on either retry path.
#[test]
fn storage_block_parks_until_space_or_retry_and_keeps_checkpoints() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for m in ["disk", "cancel", "size"] {
        seed(&store, m);
    }
    let asset = request(&store, "disk");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    checkpoint(&store, &job, &partial_identity(10), 0, b"abc", 12).unwrap();
    park(&store, &job, 8192, 12);
    assert!(
        !store.block_attachment_storage(&job, 8192, 12).unwrap(),
        "only the live attempt parks"
    );
    assert_eq!(
        transfer(&store, "disk", true).state,
        AttachmentTransferState::StorageBlocked
    );
    assert_eq!(transfer(&store, "disk", true).retry_at, None);
    assert_eq!(partial_usage(&store), 3, "checkpoints survive parking");
    assert!(
        store
            .attachment_transfer_candidates(20, 64, true)
            .unwrap()
            .is_empty()
    );
    // Cancelled and size-blocked work stays parked whatever the free space.
    let cancelled = request(&store, "cancel");
    let cancelled_job = store
        .claim_attachment_acquisition(&cancelled, 12, 100)
        .unwrap()
        .unwrap();
    store.cancel_attachment_acquisition(&cancelled).unwrap();
    assert!(
        !store
            .block_attachment_storage(&cancelled_job, 1, 12)
            .unwrap()
    );
    let sized = request(&store, "size");
    let sized_job = store
        .claim_attachment_acquisition(&sized, 12, 100)
        .unwrap()
        .unwrap();
    store
        .block_attachment_size_policy(&sized_job, 64, 13)
        .unwrap();
    assert_eq!(
        readmit(&store, 21, 1000, 1000 + fits(8192) - 1, true),
        0,
        "one byte short of the target plus margin keeps the job parked"
    );
    assert_eq!(readmit(&store, 21, 1000, 999, true), 0);
    assert_eq!(
        readmit(&store, 21, 1000, 1000 + fits(8192), false),
        0,
        "an automatic row waits for automatic acquisition to be enabled"
    );
    assert_eq!(readmit(&store, 21, 1000, 1000 + fits(8192), true), 1);
    assert_eq!(
        transfer(&store, "disk", true).state,
        AttachmentTransferState::Queued
    );
    assert_eq!(parked_headroom(&store, &asset), None);
    assert_eq!(
        store.attachment_transfer_candidates(21, 64, true).unwrap(),
        vec![asset.clone()],
        "a first park readmits without delay"
    );
    assert_eq!(partial_usage(&store), 3, "readmission keeps the prefix");
    assert_eq!(
        transfer(&store, "cancel", true).state,
        AttachmentTransferState::Cancelled
    );
    assert_eq!(
        transfer(&store, "size", true).state,
        AttachmentTransferState::PolicyBlocked
    );
    assert_eq!(
        readmit(&store, 23, 0, u64::MAX, true),
        0,
        "nothing else is storage-parked"
    );
    // A second and third park wait out the park streak before they are due
    // again, so a target that free space keeps crossing cannot drive a hot loop.
    let job = store
        .claim_attachment_acquisition(&asset, 24, 100)
        .unwrap()
        .unwrap();
    park(&store, &job, 8192, 24);
    assert_eq!(readmit(&store, 30, 0, fits(8192), true), 1);
    assert_eq!(due(&store, &asset), Some(45), "second park: 15 s");
    assert!(
        store
            .attachment_transfer_candidates(44, 64, true)
            .unwrap()
            .is_empty()
    );
    let job = store
        .claim_attachment_acquisition(&asset, 45, 100)
        .unwrap()
        .unwrap();
    park(&store, &job, 8192, 45);
    assert_eq!(readmit(&store, 50, 0, fits(8192), true), 1);
    assert_eq!(due(&store, &asset), Some(80), "third park: 30 s");
    // Checkpoint progress ends the park streak: the next park is immediate.
    let job = store
        .claim_attachment_acquisition(&asset, 80, 100)
        .unwrap()
        .unwrap();
    checkpoint(&store, &job, &partial_identity(10), 3, b"de", 80).unwrap();
    assert_eq!(column(&store, &asset, "storage_park_count"), Some(0));
    park(&store, &job, 8192, 80);
    assert_eq!(readmit(&store, 81, 0, fits(8192), true), 1);
    assert_eq!(due(&store, &asset), Some(81), "progress reset the streak");
    // Explicit retry readmits at once, clears the parked marker on both paths
    // and forgets earlier parks, so a user who freed space is not made to wait.
    let job = store
        .claim_attachment_acquisition(&asset, 81, 100)
        .unwrap()
        .unwrap();
    park(&store, &job, 8192, 81);
    let job = {
        assert_eq!(readmit(&store, 82, 0, fits(8192), true), 1);
        store
            .claim_attachment_acquisition(&asset, 97, 200)
            .unwrap()
            .unwrap()
    };
    park(&store, &job, 8192, 97);
    assert_eq!(column(&store, &asset, "storage_park_count"), Some(3));
    assert!(store.retry_attachment_acquisition(&asset, 98).unwrap());
    assert_eq!(
        transfer(&store, "disk", true).state,
        AttachmentTransferState::Queued
    );
    assert_eq!(parked_headroom(&store, &asset), None);
    assert_eq!(column(&store, &asset, "storage_park_count"), Some(0));
    let job = store
        .claim_attachment_acquisition(&asset, 98, 200)
        .unwrap()
        .unwrap();
    park(&store, &job, 8192, 98);
    assert_eq!(readmit(&store, 99, 0, fits(8192), true), 1);
    assert_eq!(
        due(&store, &asset),
        Some(99),
        "no inherited backoff after retry"
    );
    let job = store
        .claim_attachment_acquisition(&asset, 99, 200)
        .unwrap()
        .unwrap();
    park(&store, &job, 8192, 99);
    assert!(store.explicitly_retry_attachment(&asset, 100).unwrap());
    assert_eq!(
        transfer(&store, "disk", false).state,
        AttachmentTransferState::Queued
    );
    assert_eq!(parked_headroom(&store, &asset), None);
    assert_eq!(column(&store, &asset, "storage_park_count"), Some(0));
    assert_eq!(
        readmit(&store, 101, 0, u64::MAX, true),
        0,
        "retry cleared the parked marker"
    );
    // Retry racing readmission in either order leaves one queued row.
    let job = store
        .claim_attachment_acquisition(&asset, 101, 200)
        .unwrap()
        .unwrap();
    park(&store, &job, 8192, 101);
    assert_eq!(
        readmit(&store, 102, 0, fits(8192), false),
        1,
        "an explicitly retried row readmits while automatic work is disabled"
    );
    assert!(store.explicitly_retry_attachment(&asset, 102).unwrap());
    assert_eq!(
        store
            .attachment_acquisition_status(&asset)
            .unwrap()
            .unwrap()
            .state,
        AttachmentAcquisitionState::Queued
    );
    assert_eq!(parked_headroom(&store, &asset), None);
}

/// Readmission never outruns admission: a parked row whose target fits is left
/// parked while free space is still below the reserve plus two transfer
/// limits (worker admission), instead of being bounced back to a retry timer.
#[test]
fn storage_readmission_waits_for_admission_capacity() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "small");
    let asset = request(&store, "small");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    park(&store, &job, 1024, 12);
    let limit = 4 * 1024 * 1024;
    assert!(
        fits(1024) < 2 * limit,
        "the target fits before admission would"
    );
    assert_eq!(
        store
            .readmit_storage_blocked_attachments(
                13,
                1000,
                1000 + 2 * limit - 1,
                true,
                admission(1000, 1000 + 2 * limit - 1, limit)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        transfer(&store, "small", true).state,
        AttachmentTransferState::StorageBlocked
    );
    assert_eq!(
        store
            .readmit_storage_blocked_attachments(
                13,
                1000,
                1000 + 2 * limit,
                true,
                admission(1000, 1000 + 2 * limit, limit)
            )
            .unwrap(),
        1
    );
}

/// Readmission credits a parked row's checkpoint as worker admission does: a
/// job whose saved bytes cover most of the limit is readmitted with free
/// space below two transfer limits once its own discounted need fits, while a
/// row without a checkpoint keeps waiting for the whole two limits.
#[test]
fn storage_readmission_credits_the_saved_checkpoint() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "saved");
    let asset = request(&store, "saved");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let limit = 8 * 1024 * 1024;
    let saved = 6 * 1024 * 1024;
    let identity = partial_identity(limit);
    assert!(checkpoint(&store, &job, &identity, 0, &vec![7; saved as usize], 12).unwrap());
    park(&store, &job, 1024, 12);
    // Discounted admission: two limits less the checkpoint.
    let needed = 2 * limit - saved;
    assert!(needed < 2 * limit && fits(1024) < needed);
    assert_eq!(
        store
            .readmit_storage_blocked_attachments(
                13,
                1000,
                1000 + needed - 1,
                true,
                admission(1000, 1000 + needed - 1, limit)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .readmit_storage_blocked_attachments(
                13,
                1000,
                1000 + needed,
                true,
                admission(1000, 1000 + needed, limit)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        transfer(&store, "saved", true).state,
        AttachmentTransferState::Queued
    );
}

/// Admission filters parked rows before the page is limited: a full page of
/// higher-priority jobs that admission refuses (no checkpoint, so they need
/// two whole limits) cannot hide a lower-priority checkpointed job that fits.
#[test]
fn readmission_is_not_starved_by_a_page_admission_refuses() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let limit = 8 * 1024 * 1024;
    let saved = 6 * 1024 * 1024;
    let prioritize = |asset: &AttachmentAssetRef, priority: i64| {
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE attachment_acquisition SET priority_at=?2 WHERE token=?1",
                params![asset.token, priority],
            )
            .unwrap();
    };
    for index in 0..ATTACHMENT_ACQUISITION_BATCH_LIMIT {
        let message = format!("busy{index}");
        seed(&store, &message);
        let asset = request(&store, &message);
        let job = store
            .claim_attachment_acquisition(&asset, 12, 100)
            .unwrap()
            .unwrap();
        park(&store, &job, 1024, 12);
        prioritize(&asset, 100);
    }
    seed(&store, "saved");
    let asset = request(&store, "saved");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let identity = partial_identity(limit);
    assert!(checkpoint(&store, &job, &identity, 0, &vec![7; saved as usize], 12).unwrap());
    park(&store, &job, 1024, 12);
    prioritize(&asset, 0);
    // Room for the saved job's remaining checkpoint and store file only.
    let free = 1000 + 2 * limit - saved;
    let admission = admission(1000, free, limit);
    assert!(!admission.admits(None) && admission.admits(Some(saved)));
    assert_eq!(
        store
            .readmit_storage_blocked_attachments(13, 1000, free, true, admission)
            .unwrap(),
        1
    );
    assert_eq!(
        transfer(&store, "saved", true).state,
        AttachmentTransferState::Queued
    );
    assert_eq!(
        transfer(&store, "busy0", true).state,
        AttachmentTransferState::StorageBlocked
    );
}

/// Cancelling a storage-parked job clears its marker, so the kept prefix
/// expires and is pruned like any other cancelled checkpoint instead of
/// pinning quota forever.
#[test]
fn cancelled_storage_park_releases_its_prefix_on_expiry() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "parked");
    let asset = request(&store, "parked");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    checkpoint(&store, &job, &partial_identity(10), 0, b"abc", 12).unwrap();
    park(&store, &job, 8192, 12);
    store.cancel_attachment_acquisition(&asset).unwrap();
    assert_eq!(parked_headroom(&store, &asset), None);
    assert_eq!(
        transfer(&store, "parked", true).state,
        AttachmentTransferState::Cancelled
    );
    assert_eq!(readmit(&store, 13, 0, u64::MAX, true), 0);
    assert_eq!(
        partial_usage(&store),
        3,
        "cancellation keeps the prefix until expiry"
    );
    let later = 12 + 48 * 60 * 60;
    assert_eq!(store.prune_attachment_partials(later, 64).unwrap(), 1);
    assert_eq!(
        partial_usage(&store),
        0,
        "an expired cancelled prefix is reclaimed"
    );
}

/// Leaving the parked state through permission paths never leaves a stale
/// storage marker behind, so a later ordinary failure renders as `Failed`.
#[test]
fn permission_transitions_clear_the_storage_marker() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "paused");
    let asset = request(&store, "paused");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    store.pause_automatic_attachments(13).unwrap();
    park(&store, &job, 8192, 13);
    assert_eq!(
        parked_headroom(&store, &asset),
        None,
        "a permission-owned park carries no storage target"
    );
    assert_eq!(
        store.resume_permitted_attachments(40, [true; 4]).unwrap(),
        1
    );
    assert_eq!(parked_headroom(&store, &asset), None);
    let job = store
        .claim_attachment_acquisition(&asset, 41, 100)
        .unwrap()
        .unwrap();
    park(&store, &job, 8192, 41);
    assert_eq!(parked_headroom(&store, &asset), Some(8192));
    assert_eq!(readmit(&store, 42, 0, u64::MAX, true), 1);
    store.park_attachment_permission(&asset).unwrap();
    assert_eq!(parked_headroom(&store, &asset), None);
    assert_eq!(
        store.resume_permitted_attachments(43, [true; 4]).unwrap(),
        1
    );
    let now = due(&store, &asset).unwrap();
    assert_eq!(
        now, 43,
        "a permission-owned park does not count toward the park streak"
    );
    let job = store
        .claim_attachment_acquisition(&asset, now, now + 100)
        .unwrap()
        .unwrap();
    store.fail_attachment_acquisition(&job, None).unwrap();
    assert_eq!(
        transfer(&store, "paused", true).state,
        AttachmentTransferState::Failed,
        "a plain failure after a park is not a storage park"
    );
}

/// A storage park refunds the automatic-history claim it consumed: a row that
/// parks four times is still attempted, and its prefix is not discarded as
/// exhausted work.
#[test]
fn storage_parks_do_not_spend_the_automatic_history_budget() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "auto");
    let asset = request(&store, "auto");
    store.enable_attachment_automatic_history(&asset).unwrap();
    let mut now = 12;
    for _ in 0..4 {
        let job = store
            .claim_attachment_acquisition(&asset, now, now + 100)
            .unwrap()
            .expect("claim");
        park(&store, &job, 8192, now);
        assert_eq!(column(&store, &asset, "acquisition_attempts"), Some(0));
        now += 5000;
        assert_eq!(readmit(&store, now, 0, u64::MAX, true), 1);
        now = due(&store, &asset).unwrap();
    }
    assert_eq!(
        transfer(&store, "auto", true).state,
        AttachmentTransferState::Queued
    );
    assert!(
        store
            .claim_attachment_acquisition(&asset, now, now + 100)
            .unwrap()
            .is_some(),
        "readmitted work must be attempted"
    );
}

/// Each park records the need its own check proved, even below an earlier
/// park's, and readmissions are spaced by the park streak, 15 s doubling to an
/// hour, so a body that keeps starting over cannot refetch faster than that.
/// Explicit retry forgets the streak.
#[test]
fn repeated_parks_record_their_own_need_and_back_off() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "chunked");
    let asset = request(&store, "chunked");
    let mib = 1024 * 1024;
    let mut now = 12;
    let mut delays = vec![];
    for target in [445, 470, 460, 480, 485, 486, 487, 488, 489, 490, 491, 492] {
        let job = store
            .claim_attachment_acquisition(&asset, now, now + 100)
            .unwrap()
            .unwrap();
        assert!(
            store
                .block_attachment_storage(&job, target * mib, now)
                .unwrap()
        );
        assert_eq!(parked_headroom(&store, &asset), Some((target * mib) as i64));
        assert_eq!(readmit(&store, now, 0, fits(target * mib) - 1, true), 0);
        assert_eq!(readmit(&store, now, 0, fits(target * mib), true), 1);
        let next = due(&store, &asset).unwrap();
        delays.push(next - now);
        now = next;
    }
    assert_eq!(
        delays,
        [0, 15, 30, 60, 120, 240, 480, 960, 1920, 3600, 3600, 3600],
        "readmissions are spaced by the park streak, at most one an hour once it saturates"
    );
    let job = store
        .claim_attachment_acquisition(&asset, now, now + 100)
        .unwrap()
        .unwrap();
    assert!(store.block_attachment_storage(&job, 7 * mib, now).unwrap());
    assert!(store.retry_attachment_acquisition(&asset, now + 1).unwrap());
    assert_eq!(column(&store, &asset, "storage_park_count"), Some(0));
}

/// An explicit Retry of a job parked for longer than the idle expiry resumes
/// from its kept prefix through either retry API, instead of pruning it and
/// refetching the body from zero.
#[test]
fn retry_after_a_park_longer_than_a_day_keeps_the_prefix() {
    for explicit in [false, true] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, "parked");
        let asset = request(&store, "parked");
        let job = store
            .claim_attachment_acquisition(&asset, 12, 100)
            .unwrap()
            .unwrap();
        checkpoint(&store, &job, &partial_identity(10), 0, b"abc", 12).unwrap();
        park(&store, &job, 8192, 12);
        let later = 12 + 72 * 60 * 60;
        assert_eq!(
            store.prune_attachment_partials(later, 64).unwrap(),
            0,
            "parked prefixes are exempt"
        );
        if explicit {
            assert!(store.explicitly_retry_attachment(&asset, later).unwrap());
        } else {
            assert!(store.retry_attachment_acquisition(&asset, later).unwrap());
        }
        assert_eq!(
            store.prune_attachment_partials(later, 64).unwrap(),
            0,
            "the next tick prunes nothing once the row is queued"
        );
        let job = store
            .claim_attachment_acquisition(&asset, later, later + 100)
            .unwrap()
            .unwrap();
        assert_eq!(
            store
                .attachment_partial_extent(&job, later, (&[1; 32], &[2; 32]))
                .unwrap(),
            Some((10, 3)),
            "explicit={explicit}"
        );
        assert_eq!(
            store
                .load_attachment_partial(&job, later, 100, Some((&[1; 32], &[2; 32])))
                .unwrap()
                .unwrap()
                .received,
            3
        );
    }
}

/// A storage-parked prefix is kept for at most a week after its latest park:
/// past that it is pruned, while the row
/// stays parked and simply starts the body over when it is readmitted.
#[test]
fn storage_parked_prefixes_expire_after_the_maximum_parked_age() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "stale");
    let asset = request(&store, "stale");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    checkpoint(&store, &job, &partial_identity(10), 0, b"abc", 12).unwrap();
    park(&store, &job, 8192, 12);
    let reserved = |store: &SqliteAccountStorage| -> u64 {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT reserved_bytes FROM attachment_partial_usage WHERE id=1",
                [],
                |r| nonnegative(r, 0),
            )
            .unwrap()
    };
    // Wire checkpoints live outside SQLCipher and reserve no retained budget.
    assert_eq!(reserved(&store), 0);
    let limit = 12 + STORAGE_PARKED_PREFIX_MAX_AGE_SECONDS;
    assert_eq!(store.prune_attachment_partials(limit - 1, 64).unwrap(), 0);
    assert_eq!(partial_usage(&store), 3);
    assert_eq!(store.prune_attachment_partials(limit, 64).unwrap(), 1);
    assert_eq!(partial_usage(&store), 0);
    assert_eq!(reserved(&store), 0);
    assert_eq!(
        parked_headroom(&store, &asset),
        Some(8192),
        "the target is unchanged; a next attempt that needs more parks again"
    );
    assert_eq!(
        transfer(&store, "stale", true).state,
        AttachmentTransferState::StorageBlocked,
        "the row stays parked without its prefix"
    );
    assert_eq!(readmit(&store, limit, 0, u64::MAX, true), 1);
}

/// A permission-owned park does not advance the storage park streak,
/// cancellation clears it, and every park refunds the claim streak
/// so a later network failure backs off as if the parks never happened.
#[test]
fn storage_park_streak_counts_only_storage_owned_parks() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "streak");
    let asset = request(&store, "streak");
    for now in [12, 13] {
        let job = store
            .claim_attachment_acquisition(&asset, now, now + 100)
            .unwrap()
            .unwrap();
        assert_eq!(column(&store, &asset, "attempts"), Some(1));
        assert!(store.block_attachment_storage(&job, 8192, now).unwrap());
        assert_eq!(
            column(&store, &asset, "attempts"),
            Some(0),
            "the park refunds its claim"
        );
        assert_eq!(readmit(&store, now, 0, u64::MAX, true), 1);
        sql(&store, "UPDATE attachment_acquisition SET due=0");
    }
    assert_eq!(column(&store, &asset, "storage_park_count"), Some(2));
    let job = store
        .claim_attachment_acquisition(&asset, 14, 100)
        .unwrap()
        .unwrap();
    store.pause_automatic_attachments(14).unwrap();
    assert!(store.block_attachment_storage(&job, 1 << 20, 14).unwrap());
    assert_eq!(column(&store, &asset, "storage_park_count"), Some(2));
    assert_eq!(column(&store, &asset, "attempts"), Some(0));
    assert_eq!(
        store.resume_permitted_attachments(15, [true; 4]).unwrap(),
        1
    );
    sql(&store, "UPDATE attachment_acquisition SET due=0");
    // A network failure after the parks backs off from one claim, not four.
    let job = store
        .claim_attachment_acquisition(&asset, 15, 100)
        .unwrap()
        .unwrap();
    assert_eq!(column(&store, &asset, "attempts"), Some(1));
    store.fail_attachment_acquisition(&job, Some(30)).unwrap();
    store.cancel_attachment_acquisition(&asset).unwrap();
    assert_eq!(column(&store, &asset, "storage_park_count"), Some(0));
}

/// A verified-body shortage under a revoked automatic permission parks under
/// the permission owner: the row waits as `Paused`, keeps its prefix, and the
/// permission readmission path requeues it for a fresh capacity check.
#[test]
fn storage_block_under_permission_pause_stays_permission_owned() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "paused");
    let asset = request(&store, "paused");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    checkpoint(&store, &job, &partial_identity(10), 0, b"abc", 12).unwrap();
    store.pause_automatic_attachments(13).unwrap();
    park(&store, &job, 8192, 13);
    assert_eq!(
        transfer(&store, "paused", true).state,
        AttachmentTransferState::Paused
    );
    assert_eq!(partial_usage(&store), 3);
    assert_eq!(
        readmit(&store, 14, 0, u64::MAX, true),
        0,
        "permission, not space, owns the row"
    );
    assert_eq!(
        store.resume_permitted_attachments(40, [true; 4]).unwrap(),
        1
    );
    assert_eq!(
        transfer(&store, "paused", true).state,
        AttachmentTransferState::Queued
    );
    assert_eq!(partial_usage(&store), 3);
    let job = store
        .claim_attachment_acquisition(&asset, 41, 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        parked_headroom(&store, &asset),
        None,
        "a claim starts clean"
    );
    park(&store, &job, 8192, 41);
    assert_eq!(
        transfer(&store, "paused", true).state,
        AttachmentTransferState::StorageBlocked
    );
}

/// The 24-hour checkpoint expiry skips storage-parked jobs, and parking and
/// readmission refresh it, so a prefix kept through a park longer than a day
/// still loads for the readmitted attempt.
#[test]
fn storage_parked_checkpoints_are_exempt_from_idle_expiry() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for m in ["parked", "idle"] {
        seed(&store, m);
    }
    let parked = request(&store, "parked");
    let job = store
        .claim_attachment_acquisition(&parked, 12, 100)
        .unwrap()
        .unwrap();
    checkpoint(&store, &job, &partial_identity(10), 0, b"abc", 12).unwrap();
    park(&store, &job, 8192, 12);
    let idle = request(&store, "idle");
    let idle_job = store
        .claim_attachment_acquisition(&idle, 12, 100)
        .unwrap()
        .unwrap();
    checkpoint(&store, &idle_job, &partial_identity(10), 0, b"abcd", 12).unwrap();
    assert_eq!(partial_usage(&store), 7);
    let far_future = 12 + 48 * 60 * 60;
    assert_eq!(store.prune_attachment_partials(far_future, 64).unwrap(), 1);
    assert_eq!(partial_usage(&store), 3, "only the idle prefix expired");
    assert_eq!(readmit(&store, far_future, 0, u64::MAX, true), 1);
    let job = store
        .claim_attachment_acquisition(&parked, far_future, far_future + 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .attachment_partial_extent(&job, far_future + 1, (&[1; 32], &[2; 32]))
            .unwrap(),
        Some((10, 3)),
        "the kept checkpoint is usable by the readmitted attempt"
    );
    let restored = store
        .load_attachment_partial(&job, far_future + 1, 100, Some((&[1; 32], &[2; 32])))
        .unwrap()
        .unwrap();
    assert_eq!(restored.received, 3);
    store
        .fail_attachment_acquisition(&job, Some(far_future + 2))
        .unwrap();
    assert!(
        store
            .retry_attachment_acquisition(&parked, far_future + 2)
            .unwrap()
    );
    let much_later = far_future + 48 * 60 * 60;
    assert_eq!(store.prune_attachment_partials(much_later, 64).unwrap(), 1);
    assert_eq!(
        partial_usage(&store),
        0,
        "a retried job's prefix expires normally"
    );
}

/// A full database during publication is a capacity error that commits
/// nothing and leaves the attempt live, so the worker can park the job; once
/// room exists the same attempt publishes.
#[test]
fn publication_into_a_full_database_commits_nothing_and_reports_capacity() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "full");
    let asset = request(&store, "full");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let body: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let digest: [u8; 32] = Sha256::digest(&body).into();
    sql(
        &store,
        &format!(
            "UPDATE attachment_acquisition SET plaintext_digest=x'{}'",
            hex::encode(digest)
        ),
    );
    let job = {
        // Reclaim the attempt under the corrected digest.
        store.fail_attachment_acquisition(&job, Some(13)).unwrap();
        store
            .claim_attachment_acquisition(&asset, 13, 100)
            .unwrap()
            .unwrap()
    };
    store.limit_database_pages_for_test(0).unwrap();
    assert!(matches!(
        store.complete_attachment_acquisition(&job, &body, 13, 1 << 40),
        Err(StorageError::Capacity(_))
    ));
    assert_eq!(store.retained_attachment_byte_count().unwrap(), 0);
    assert!(
        store
            .read_retained_attachment(&asset, 13, 0, 10)
            .unwrap()
            .is_none()
    );
    assert!(store.attachment_transfer_is_active(&job, 13).unwrap());
    store.limit_database_pages_for_test(1 << 30).unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, &body, 14, 1 << 40)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        body.len() as u64
    );
}

/// On a database that cannot grow by a single page, a refused publication
/// still parks: the park rewrites fixed-size columns of an existing row and
/// the checkpoint's expiry, and needs no new page.
#[test]
fn storage_park_needs_no_new_page_after_a_full_publication() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "full");
    let asset = request(&store, "full");
    let body: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let digest: [u8; 32] = Sha256::digest(&body).into();
    sql(
        &store,
        &format!(
            "UPDATE attachment_acquisition SET plaintext_digest=x'{}'",
            hex::encode(digest)
        ),
    );
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    checkpoint(&store, &job, &partial_identity(10), 0, b"abc", 12).unwrap();
    store.limit_database_pages_for_test(0).unwrap();
    assert!(matches!(
        store.complete_attachment_acquisition(&job, &body, 13, 1 << 40),
        Err(StorageError::Capacity(_))
    ));
    assert!(
        store
            .block_attachment_storage(&job, 4 * body.len() as u64, 13)
            .unwrap(),
        "the park write fits without a new page"
    );
    assert_eq!(
        transfer(&store, "full", true).state,
        AttachmentTransferState::StorageBlocked
    );
    assert_eq!(partial_usage(&store), 3);
    store.limit_database_pages_for_test(1 << 30).unwrap();
}

/// The per-tick readmission probe is read-only while no parked row fits: no
/// write statement runs, so the common tick never takes the write lock. A
/// query-only connection proves it, since any write statement fails there.
#[test]
fn storage_readmission_probe_is_read_only_while_nothing_fits() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "probe");
    let asset = request(&store, "probe");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    park(&store, &job, 8192, 12);
    sql(&store, "PRAGMA query_only=1");
    assert_eq!(
        readmit(&store, 13, 0, fits(8192) - 1, true),
        0,
        "a target that does not fit is never written"
    );
    assert_eq!(
        readmit(&store, 13, 0, u64::MAX, false),
        0,
        "an automatic row is never written while automatic work is disabled"
    );
    assert!(
        store
            .readmit_storage_blocked_attachments(13, 0, u64::MAX, true, admission(0, u64::MAX, 1))
            .is_err(),
        "a row that fits does write, so the guard is effective"
    );
    sql(&store, "PRAGMA query_only=0");
    assert_eq!(readmit(&store, 13, 0, u64::MAX, true), 1);
}

/// A full database can refuse publication after the completed-body receipt.
/// Parking withdraws that receipt, so an automatic-history job readmits and is
/// attempted again instead of ending as an unretained completed body, and its
/// eventual completion ends the park streak.
#[test]
fn storage_park_after_a_receipt_keeps_automatic_history_attemptable() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "receipt");
    let asset = request(&store, "receipt");
    store.enable_attachment_automatic_history(&asset).unwrap();
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    assert!(store.mark_attachment_body_completed(&job, 12).unwrap());
    park(&store, &job, 8192, 12);
    assert_eq!(column(&store, &asset, "body_completed"), Some(0));
    assert_eq!(
        transfer(&store, "receipt", true).state,
        AttachmentTransferState::StorageBlocked
    );
    assert_eq!(readmit(&store, 13, 0, u64::MAX, true), 1);
    assert_eq!(
        transfer(&store, "receipt", true).state,
        AttachmentTransferState::Queued,
        "a withdrawn receipt is not an unretained completed body"
    );
    let job = store
        .claim_attachment_acquisition(&asset, 13, 100)
        .unwrap()
        .expect("readmitted work is attempted");
    park(&store, &job, 8192, 13);
    assert_eq!(column(&store, &asset, "storage_park_count"), Some(2));
    assert_eq!(readmit(&store, 14, 0, u64::MAX, true), 1);
    let due = due(&store, &asset).unwrap();
    let job = store
        .claim_attachment_acquisition(&asset, due, due + 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, due, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    assert_eq!(column(&store, &asset, "storage_park_count"), Some(0));
    assert_eq!(read(&store, &asset), BODY);
}

/// mdk#2241: a body of at most one staging chunk publishes as an array row that
/// declares `byte_len` on insert, so the insert trigger charges the quota
/// without rewriting the row.
#[test]
fn array_publication_declares_length_and_skips_the_trigger_rewrite() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "array");
    let asset = request(&store, "array");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let before = store.lock().unwrap().total_changes();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 12, 10000)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    // Exactly the row insert, the usage charge and the job state change: the
    // `byte_len<0` normalizing UPDATE in the insert trigger matched no row.
    assert_eq!(store.lock().unwrap().total_changes() - before, 3);
    let (byte_len, stored_len): (i64, i64) = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT byte_len,length(bytes) FROM retained_attachment_bytes WHERE token=?1",
            [&asset.token],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (byte_len, stored_len),
        (BODY.len() as i64, BODY.len() as i64)
    );
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        BODY.len() as u64
    );
    assert_eq!(read(&store, &asset), BODY);
    // The retired bind-the-whole-body form pays the trigger rewrite inside one
    // statement: insert, row rewrite and usage charge also count three, which
    // is the copy the publication path no longer makes.
    seed(&store, "legacy");
    let legacy = request(&store, "legacy");
    let before = store.lock().unwrap().total_changes();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO retained_attachment_bytes(token,bytes) VALUES(?1,?2)",
            params![legacy.token, BODY],
        )
        .unwrap();
    assert_eq!(store.lock().unwrap().total_changes() - before, 3);
}

mod outgoing;
mod outgoing_files;
mod promotion;
