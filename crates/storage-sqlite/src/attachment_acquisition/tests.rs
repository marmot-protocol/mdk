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
fn selected(message: &str) -> crate::AttachmentHistoryEntry {
    let event = source(message);
    crate::AttachmentHistoryEntry {
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
    let bytes = vec![7u8; 2 * 1024 * 1024];
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    let mut event = source("one");
    event.tags[0][2] = format!("x {}", hex::encode(hash));
    store.record_app_event(&event).unwrap();
    let mut selection = selected("one");
    selection.slot = serde_json::to_value(&event.tags[0]).unwrap();
    let AttachmentDemand::Requested(reference) = store
        .request_attachment_acquisition(GROUP, &selection, hash, 11)
        .unwrap()
    else {
        panic!("missing demand")
    };
    let job = store
        .claim_attachment_acquisition(&reference, 11, 100)
        .unwrap()
        .unwrap();
    store
        .complete_attachment_acquisition(&job, &bytes, 12, bytes.len() as u64)
        .unwrap();
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
    assert_eq!(
        store
            .retained_attachment_asset(GROUP, "one", "source-one", 0, 12)
            .unwrap()
            .unwrap()
            .byte_count,
        bytes.len() as u64,
    );
    assert_eq!(
        store
            .read_retained_attachment(&reference, 12, 1024 * 1024, 17)
            .unwrap()
            .unwrap()
            .as_slice(),
        &[7; 17]
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
            "SELECT coalesce(sum(length(bytes)),0) FROM attachment_partial_chunk",
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
    assert!(
        store
            .checkpoint_attachment_partial(&old, &identity, 0, b"abc", 12, 100)
            .unwrap()
    );
    assert!(
        !store
            .checkpoint_attachment_partial(&old, &identity, 2, b"x", 12, 100)
            .unwrap()
    );
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    store.resume_attachment_acquisitions(13, 64).unwrap();
    let job = store
        .claim_attachment_acquisition(&asset, 13, 100)
        .unwrap()
        .unwrap();
    assert!(
        !store
            .checkpoint_attachment_partial(&old, &identity, 3, b"old", 13, 100)
            .unwrap()
    );
    assert!(!store.clear_attachment_partial(&old, 13, None).unwrap());
    assert_eq!(
        store
            .load_attachment_partial(&job, 13, 10, None)
            .unwrap()
            .unwrap()
            .bytes,
        b"abc"
    );
    assert!(
        store
            .checkpoint_attachment_partial(&job, &identity, 3, b"def", 13, 100)
            .unwrap()
    );
    assert_eq!(
        store
            .load_attachment_partial(&job, 13, 10, None)
            .unwrap()
            .unwrap()
            .bytes,
        b"abcdef"
    );
    store.remove_local_attachment(GROUP, "one", 0).unwrap();
    assert_eq!(partial_usage(&store), 0);
    assert!(
        !store
            .checkpoint_attachment_partial(&job, &identity, 0, b"late", 13, 100)
            .unwrap()
    );
}
#[test]
fn attachment_partial_quota_rollback_corruption_and_terminal_cleanup() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    seed(&store, "two");
    let a = request(&store, "one");
    let b = request(&store, "two");
    let job = store
        .claim_attachment_acquisition(&a, 12, 100)
        .unwrap()
        .unwrap();
    let other = store
        .claim_attachment_acquisition(&b, 12, 100)
        .unwrap()
        .unwrap();
    let identity = partial_identity(10);
    assert!(
        store
            .checkpoint_attachment_partial(&job, &identity, 0, b"abcdef", 12, 10)
            .unwrap()
    );
    assert!(
        !store
            .checkpoint_attachment_partial(&other, &identity, 0, b"12345", 12, 10)
            .unwrap()
    );
    assert_eq!(partial_usage(&store), 6);
    store.lock().unwrap().execute_batch("CREATE TRIGGER refuse_checkpoint BEFORE INSERT ON attachment_partial_chunk BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(
        store
            .checkpoint_attachment_partial(&job, &identity, 6, b"xyz", 12, 100)
            .is_err()
    );
    assert_eq!(
        store
            .load_attachment_partial(&job, 12, 10, None)
            .unwrap()
            .unwrap()
            .bytes,
        b"abcdef"
    );
    store.lock().unwrap().execute_batch("DROP TRIGGER refuse_checkpoint; UPDATE attachment_partial_chunk SET bytes=x'010203040506';").unwrap();
    assert!(
        store
            .load_attachment_partial(&job, 12, 10, None)
            .unwrap()
            .is_none()
    );
    assert_eq!(partial_usage(&store), 0);
    assert!(
        store
            .checkpoint_attachment_partial(&job, &identity, 0, b"abc", 12, 100)
            .unwrap()
    );
    store.fail_attachment_acquisition(&job, None).unwrap();
    assert_eq!(partial_usage(&store), 0);
}
#[test]
fn attachment_partial_publication_accounts_other_partials_and_releases_own() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    seed(&store, "two");
    let a = request(&store, "one");
    let b = request(&store, "two");
    let job = store
        .claim_attachment_acquisition(&a, 12, 100)
        .unwrap()
        .unwrap();
    let other = store
        .claim_attachment_acquisition(&b, 12, 100)
        .unwrap()
        .unwrap();
    let identity = partial_identity(10);
    store
        .checkpoint_attachment_partial(&job, &identity, 0, b"123456", 12, 100)
        .unwrap();
    store
        .checkpoint_attachment_partial(&other, &identity, 0, b"123456", 12, 100)
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 12, BODY.len() as u64 + 5)
            .unwrap(),
        AttachmentPublishResult::CapacityBlocked
    );
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 12, BODY.len() as u64 + 10)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    assert_eq!(partial_usage(&store), 6);
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        BODY.len() as u64
    );
    store
        .invalidate_app_event_by_message_id(GROUP, "two", "branch_selection_withdrawn")
        .unwrap();
    assert_eq!(partial_usage(&store), 0);
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
        store
            .checkpoint_attachment_partial(&job, &partial_identity(10), 0, b"abc", 12, 100)
            .unwrap();
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
    store
        .checkpoint_attachment_partial(&job, &partial_identity(10), 0, b"abc", 12, 100)
        .unwrap();
    assert!(
        store
            .load_attachment_partial(&job, 12, 9, None)
            .unwrap()
            .is_none()
    );
    assert_eq!(partial_usage(&store), 0);
}

#[test]
fn attachment_partial_reservation_prevents_pressure_deadlock() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for name in ["a", "b", "new"] {
        seed(&store, name);
    }
    let a = request(&store, "a");
    let b = request(&store, "b");
    let new = request(&store, "new");
    let ja = store
        .claim_attachment_acquisition(&a, 12, 100)
        .unwrap()
        .unwrap();
    let jb = store
        .claim_attachment_acquisition(&b, 12, 100)
        .unwrap()
        .unwrap();
    let identity = partial_identity(10);
    for job in [&ja, &jb] {
        assert!(
            store
                .checkpoint_attachment_partial(job, &identity, 0, b"abc", 12, 20)
                .unwrap()
        );
    }
    assert_eq!(partial_usage(&store), 6);
    assert!(
        !store
            .attachment_acquisition_fits_budget(&new, 20, 20)
            .unwrap()
    );
    // A full reservation can resume even when the account budget is saturated,
    // including when its size is smaller than the policy's maximum transfer.
    assert!(
        store
            .attachment_acquisition_fits_budget(&a, 20, 20)
            .unwrap()
    );
    assert!(
        store
            .checkpoint_attachment_partial(&ja, &identity, 3, b"defghij", 12, 20)
            .unwrap()
    );
    // Deletion releases the reservation as well as the actual chunk bytes.
    store.remove_local_attachment(GROUP, "a", 0).unwrap();
    assert!(
        store
            .attachment_acquisition_fits_budget(&new, 10, 20)
            .unwrap()
    );
    store.remove_local_attachment(GROUP, "b", 0).unwrap();
    assert!(
        store
            .attachment_acquisition_fits_budget(&new, 20, 20)
            .unwrap()
    );
}

#[test]
fn attachment_partial_locator_mismatch_does_not_read_or_discard_chunks() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "one");
    let asset = request(&store, "one");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    let identity = partial_identity(10);
    assert!(
        store
            .checkpoint_attachment_partial(&job, &identity, 0, b"abc", 12, 100)
            .unwrap()
    );
    sql(
        &store,
        "UPDATE attachment_partial_chunk SET digest=zeroblob(32);",
    );
    assert!(
        store
            .load_attachment_partial(&job, 12, 10, Some((&[1; 32], &[3; 32])))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        partial_usage(&store),
        3,
        "mismatched locator must not scan even corrupt chunks"
    );
    assert!(
        store
            .load_attachment_partial(&job, 12, 10, Some((&[1; 32], &[2; 32])))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        partial_usage(&store),
        0,
        "matching locator verifies and discards corruption"
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
    assert!(
        store
            .checkpoint_attachment_partial(&old, &identity, 0, b"abc", 12, 100)
            .unwrap()
    );
    for pair in [([1; 32], [3; 32]), ([4; 32], [2; 32])] {
        assert!(
            !store
                .clear_attachment_partial(&old, 12, Some((&pair.0, &pair.1)))
                .unwrap()
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
    );
    assert_eq!(partial_usage(&store), 3);
    assert!(
        store
            .clear_attachment_partial(&current, 13, Some((&[1; 32], &[2; 32])))
            .unwrap()
    );
    assert_eq!(partial_usage(&store), 0);
    assert!(
        store
            .attachment_acquisition_fits_budget(&asset, 100, 100)
            .unwrap()
    );
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
