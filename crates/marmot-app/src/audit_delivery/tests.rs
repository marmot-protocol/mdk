use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::process::Command;

use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::recovery::FaultPoint;
use super::state::MAX_RANGE_BYTES;
use super::*;

fn profile() -> DestinationProfile {
    DestinationProfile::new("test-profile").unwrap()
}

fn store_with_segment(initial: &[u8]) -> (TempDir, JournalId, SegmentId, AuditDeliveryStore) {
    let temporary = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store =
        AuditDeliveryStore::create(temporary.path(), journal.clone(), profile()).unwrap();
    let path = store.segment_path(&segment).unwrap();
    fs_private::write_private(&path, initial).unwrap();
    store
        .register_segment(segment.clone(), SegmentStatus::Active)
        .unwrap();
    (temporary, journal, segment, store)
}

fn append(store: &AuditDeliveryStore, segment: &SegmentId, bytes: &[u8]) {
    let path = store.segment_path(segment).unwrap();
    let mut file = fs_private::open_private_append(&path).unwrap();
    file.write_all(bytes).unwrap();
    file.flush().unwrap();
}

fn reopen(root: &TempDir, journal: &JournalId) -> AuditDeliveryStore {
    AuditDeliveryStore::open(root.path(), journal.clone(), profile()).unwrap()
}

fn store_with_large_acknowledged_active_prefix()
-> (TempDir, JournalId, SegmentId, AuditDeliveryStore, Vec<u8>) {
    let (root, journal, segment, mut store) = store_with_segment(b"");
    let mut payload = Vec::new();
    for index in 0..9_u8 {
        payload.extend(std::iter::repeat_n(b'a' + index, 9_000));
        payload.push(b'\n');
    }
    append(&store, &segment, &payload);
    let first = store.prepare_next().unwrap().unwrap();
    assert_eq!(first.bodies().len(), 8);
    assert!(first.end_offset() > 64 * 1024);
    store.acknowledge(first.token()).unwrap();
    (root, journal, segment, store, payload)
}

fn persisted_recovery_events(root: &TempDir, journal: &JournalId) -> u64 {
    let state_path = root
        .path()
        .join("audit-delivery/v1")
        .join(journal.as_str())
        .join("state.json");
    serde_json::from_slice::<serde_json::Value>(&fs::read(state_path).unwrap()).unwrap()["health"]
        ["recovery_events"]
        .as_u64()
        .unwrap()
}

#[test]
fn j01_growing_file_does_not_expand_prepared_token() {
    let (_root, _journal, segment, mut store) = store_with_segment(b"{\"n\":1}\n{\"n\":2}\n");
    let prepared = store.prepare_next().unwrap().unwrap();
    append(&store, &segment, b"{\"n\":3}\n");
    assert_eq!(
        prepared.bodies(),
        &[b"{\"n\":1}".to_vec(), b"{\"n\":2}".to_vec()]
    );
    assert_eq!(
        store.recover_prepared().unwrap().unwrap().bodies(),
        prepared.bodies()
    );
}

#[test]
fn j02_acknowledged_prefix_is_not_resent() {
    let (_root, _journal, segment, mut store) = store_with_segment(b"one\ntwo\n");
    let first = store.prepare_next().unwrap().unwrap();
    let first_end = first.end_offset();
    store.acknowledge(first.token()).unwrap();
    append(&store, &segment, b"three\n");
    let second = store.prepare_next().unwrap().unwrap();
    assert_eq!(second.start_offset(), first_end);
    assert_eq!(second.bodies(), &[b"three".to_vec()]);
}

#[test]
fn sealed_segment_registered_prefix_is_hashed_once_while_draining() {
    let temporary = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store = AuditDeliveryStore::create(temporary.path(), journal, profile()).unwrap();
    let payload = (0..17)
        .map(|index| format!("record-{index}\n"))
        .collect::<String>();
    fs_private::write_private(&store.segment_path(&segment).unwrap(), payload.as_bytes()).unwrap();
    store
        .register_segment(segment, SegmentStatus::Sealed)
        .unwrap();

    let mut range_count = 0;
    while let Some(prepared) = store.prepare_next().unwrap() {
        range_count += 1;
        store.recover_prepared().unwrap().unwrap();
        store.acknowledge(prepared.token()).unwrap();
    }

    assert_eq!(range_count, 3);
    assert_eq!(store.registered_prefix_validation_count(), 1);
    assert_eq!(store.acknowledged_prefix_validation_count(), 1);
}

#[test]
fn acknowledge_revalidates_a_cached_snapshot_after_same_inode_rewrite() {
    let temporary = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store = AuditDeliveryStore::create(temporary.path(), journal, profile()).unwrap();
    let payload = (0..17)
        .map(|index| format!("record-{index:02}\n"))
        .collect::<String>();
    let path = store.segment_path(&segment).unwrap();
    fs_private::write_private(&path, payload.as_bytes()).unwrap();
    store
        .register_segment(segment, SegmentStatus::Sealed)
        .unwrap();

    let prepared = store.prepare_next().unwrap().unwrap();
    let generation = path.parent().unwrap().parent().unwrap();
    let state_before = fs::read(generation.join("state.json")).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    let mut rewritten = payload.into_bytes();
    let unread = rewritten
        .windows(b"record-10".len())
        .position(|window| window == b"record-10")
        .unwrap();
    rewritten[unread] = b'R';
    fs_private::write_private(&path, &rewritten).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);

    assert!(matches!(
        store.acknowledge(prepared.token()),
        Err(AuditDeliveryError::CorruptState)
    ));
    assert_eq!(
        fs::read(generation.join("state.json")).unwrap(),
        state_before
    );
}

#[test]
fn registration_is_refused_while_a_prepared_range_is_pending() {
    let (root, journal, _segment, mut store) = store_with_segment(b"one\n");
    store.prepare_next().unwrap().unwrap();
    let second = SegmentId::generate();
    fs_private::write_private(&store.segment_path(&second).unwrap(), b"two\n").unwrap();
    assert!(matches!(
        store.register_segment(second, SegmentStatus::Sealed),
        Err(AuditDeliveryError::PreparationPending)
    ));

    drop(store);
    let mut reopened = reopen(&root, &journal);
    let prepared = reopened.recover_prepared().unwrap().unwrap();
    reopened.acknowledge(prepared.token()).unwrap();
}

#[test]
fn sealing_allows_the_next_active_segment_to_be_registered() {
    let (_root, _journal, first, mut store) = store_with_segment(b"one\n");
    store.seal_active_segment(&first).unwrap();
    let second = SegmentId::generate();
    fs_private::write_private(&store.segment_path(&second).unwrap(), b"two\n").unwrap();
    store
        .register_segment(second, SegmentStatus::Active)
        .unwrap();

    let first_range = store.prepare_next().unwrap().unwrap();
    assert_eq!(first_range.bodies(), &[b"one".to_vec()]);
    store.acknowledge(first_range.token()).unwrap();
    let second_range = store.prepare_next().unwrap().unwrap();
    assert_eq!(second_range.bodies(), &[b"two".to_vec()]);
}

#[test]
fn prepare_skips_fully_acknowledged_sealed_history_before_live_validation() {
    let (root, journal, first, mut store) = store_with_segment(b"one\n");
    store.seal_active_segment(&first).unwrap();
    let second = SegmentId::generate();
    fs_private::write_private(&store.segment_path(&second).unwrap(), b"two\n").unwrap();
    store
        .register_segment(second, SegmentStatus::Active)
        .unwrap();

    let first_range = store.prepare_next().unwrap().unwrap();
    store.acknowledge(first_range.token()).unwrap();
    fs_private::write_private(&store.segment_path(&first).unwrap(), b"bad\n").unwrap();

    let second_range = store.prepare_next().unwrap().unwrap();
    assert_eq!(second_range.bodies(), &[b"two".to_vec()]);

    drop(store);
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::CorruptState)
    ));
}

#[test]
fn j03_j04_reopen_recovers_prepare_and_durable_ack() {
    let (root, journal, _segment, mut store) = store_with_segment(b"one\ntwo\n");
    let prepared = store.prepare_next().unwrap().unwrap();
    let digest = prepared.ordered_body_digest();
    drop(store);
    let mut store = reopen(&root, &journal);
    let recovered = store.recover_prepared().unwrap().unwrap();
    assert_eq!(recovered.ordered_body_digest(), digest);
    store.acknowledge(recovered.token()).unwrap();
    drop(store);
    assert!(reopen(&root, &journal).prepare_next().unwrap().is_none());
}

#[test]
fn j05_j06_publication_faults_preserve_recoverable_state_and_fence_uncertainty() {
    for fault in [FaultPoint::Write, FaultPoint::FileSync, FaultPoint::Rename] {
        let (root, journal, _segment, mut store) = store_with_segment(b"one\n");
        store.fail_next(fault);
        assert!(store.prepare_next().is_err());
        let mut recovered = reopen(&root, &journal);
        assert!(recovered.prepare_next().unwrap().is_some());
    }

    let (root, journal, _segment, mut store) = store_with_segment(b"one\n");
    store.fail_next(FaultPoint::DirectorySync);
    assert!(matches!(
        store.prepare_next(),
        Err(AuditDeliveryError::UncertainPublication { .. })
    ));
    assert!(matches!(
        store.prepare_next(),
        Err(AuditDeliveryError::RecoveryRequired)
    ));
    let recovered = reopen(&root, &journal);
    assert!(recovered.recover_prepared().unwrap().is_some());
}

#[test]
fn publication_faults_recover_only_unambiguous_create_and_registration_gaps() {
    let publication_faults = [
        FaultPoint::Write,
        FaultPoint::FileSync,
        FaultPoint::Rename,
        FaultPoint::DirectorySync,
    ];

    for fault in publication_faults {
        let root = tempfile::tempdir().unwrap();
        let journal = JournalId::generate();
        assert!(
            AuditDeliveryStore::create_failing(root.path(), journal.clone(), profile(), fault)
                .is_err()
        );
        drop(AuditDeliveryStore::open(root.path(), journal.clone(), profile()).unwrap());
        assert_eq!(persisted_recovery_events(&root, &journal), 1);
    }

    for fault in publication_faults {
        for matching_calls_to_skip in [0, 1] {
            let root = tempfile::tempdir().unwrap();
            let journal = JournalId::generate();
            let segment = SegmentId::generate();
            let mut store =
                AuditDeliveryStore::create(root.path(), journal.clone(), profile()).unwrap();
            fs_private::write_private(&store.segment_path(&segment).unwrap(), b"one\n").unwrap();
            store.fail_after(fault, matching_calls_to_skip);
            assert!(
                store
                    .register_segment(segment, SegmentStatus::Active)
                    .is_err()
            );
            assert!(AuditDeliveryStore::open(root.path(), journal, profile()).is_ok());
        }
    }

    for fault in publication_faults {
        let (root, journal, _segment, mut store) = store_with_segment(b"one\n");
        let prepared = store.prepare_next().unwrap().unwrap();
        store.fail_next(fault);
        assert!(store.acknowledge(prepared.token()).is_err());
        let reopened = reopen(&root, &journal);
        if fault == FaultPoint::DirectorySync {
            assert!(reopened.recover_prepared().unwrap().is_none());
        } else {
            assert!(reopened.recover_prepared().unwrap().is_some());
        }
    }
}

#[test]
fn manifestless_generation_with_payload_evidence_still_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    assert!(
        AuditDeliveryStore::create_failing(
            root.path(),
            journal.clone(),
            profile(),
            FaultPoint::Write,
        )
        .is_err()
    );
    let generation = root.path().join("audit-delivery/v1").join(journal.as_str());
    fs_private::write_private(&generation.join("segments/orphan.jsonl"), b"one\n").unwrap();

    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::IncompleteState)
    ));
    assert!(!generation.join("manifest.json").exists());
    assert!(!generation.join("state.json").exists());
}

#[test]
fn empty_generation_without_segments_recovers_the_create_gap() {
    let root = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let generation = root.path().join("audit-delivery/v1").join(journal.as_str());
    fs_private::create_dir_all_private(&generation).unwrap();

    drop(AuditDeliveryStore::open(root.path(), journal.clone(), profile()).unwrap());

    assert!(generation.join("segments").is_dir());
    assert_eq!(persisted_recovery_events(&root, &journal), 1);
}

#[test]
fn nonempty_generation_without_segments_still_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let generation = root.path().join("audit-delivery/v1").join(journal.as_str());
    fs_private::create_dir_all_private(&generation).unwrap();
    fs_private::write_private(&generation.join("unknown"), b"evidence").unwrap();

    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::IncompleteState)
    ));
    assert!(!generation.join("segments").exists());
}

#[test]
fn registration_gap_recovers_zero_cursor_without_skipping_payload() {
    let root = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store = AuditDeliveryStore::create(root.path(), journal.clone(), profile()).unwrap();
    fs_private::write_private(&store.segment_path(&segment).unwrap(), b"one\n").unwrap();
    store.fail_after(FaultPoint::Write, 1);
    assert!(
        store
            .register_segment(segment, SegmentStatus::Active)
            .is_err()
    );
    drop(store);

    let mut reopened = reopen(&root, &journal);
    assert_eq!(persisted_recovery_events(&root, &journal), 1);
    let prepared = reopened.prepare_next().unwrap().unwrap();
    assert_eq!(prepared.start_offset(), 0);
    assert_eq!(prepared.bodies(), &[b"one".to_vec()]);
}

#[test]
fn payload_sync_failure_never_persists_preparation() {
    let (root, journal, _segment, mut store) = store_with_segment(b"one\n");
    store.fail_next(FaultPoint::PayloadSync);
    assert!(store.prepare_next().is_err());
    assert!(
        reopen(&root, &journal)
            .recover_prepared()
            .unwrap()
            .is_none()
    );
}

#[test]
fn payload_sync_failure_never_publishes_registration_or_sealing() {
    let root = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store = AuditDeliveryStore::create(root.path(), journal, profile()).unwrap();
    fs_private::write_private(&store.segment_path(&segment).unwrap(), b"one\n").unwrap();
    store.fail_next(FaultPoint::PayloadSync);
    assert!(
        store
            .register_segment(segment.clone(), SegmentStatus::Active)
            .is_err()
    );
    store
        .register_segment(segment.clone(), SegmentStatus::Active)
        .unwrap();

    store.fail_next(FaultPoint::PayloadSync);
    assert!(store.seal_active_segment(&segment).is_err());
    store.seal_active_segment(&segment).unwrap();
}

#[test]
fn j07_stale_destination_generation_attempt_and_close_tokens_are_refused() {
    let (root, journal, _segment, mut store) = store_with_segment(b"one\n");
    let prepared = store.prepare_next().unwrap().unwrap();
    let old_token = prepared.token().clone();
    store.close();
    assert!(matches!(
        store.acknowledge(&old_token),
        Err(AuditDeliveryError::Closed)
    ));
    let mut reopened = reopen(&root, &journal);
    assert!(matches!(
        reopened.acknowledge(&old_token),
        Err(AuditDeliveryError::StaleToken)
    ));
    let current = reopened.recover_prepared().unwrap().unwrap();
    reopened.acknowledge(current.token()).unwrap();
    assert!(matches!(
        reopened.acknowledge(current.token()),
        Err(AuditDeliveryError::StaleToken)
    ));
    assert!(matches!(
        AuditDeliveryStore::open(
            root.path(),
            journal,
            DestinationProfile::new("other").unwrap()
        ),
        Err(AuditDeliveryError::CorruptState)
    ));
}

#[test]
fn j08_missing_truncated_unknown_and_replaced_state_fail_closed() {
    let (root, journal, _segment, _store) = store_with_segment(b"one\n");
    let state = root
        .path()
        .join("audit-delivery/v1")
        .join(journal.as_str())
        .join("state.json");
    fs_private::write_private(&state, b"{").unwrap();
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal.clone(), profile()),
        Err(AuditDeliveryError::CorruptState)
    ));

    let (root, journal, _segment, _store) = store_with_segment(b"one\n");
    let generation = root.path().join("audit-delivery/v1").join(journal.as_str());
    fs::remove_file(generation.join("state.json")).unwrap();
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::IncompleteState)
    ));

    let (root, journal, _segment, _store) = store_with_segment(b"one\n");
    let manifest = root
        .path()
        .join("audit-delivery/v1")
        .join(journal.as_str())
        .join("manifest.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    value["version"] = serde_json::json!(999);
    fs_private::write_private(&manifest, &serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::UnknownVersion)
    ));

    let (root, journal, segment, store) = store_with_segment(b"one\n");
    let path = store.segment_path(&segment).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(AuditDeliveryStore::open(root.path(), journal, profile()).is_err());

    let (root, journal, segment, store) = store_with_segment(b"one\n");
    fs_private::write_private(&store.segment_path(&segment).unwrap(), b"xxxx").unwrap();
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::CorruptState)
    ));
}

#[test]
fn live_prepare_and_seal_reject_replaced_segment_identity() {
    let (_root, _journal, segment, mut store) = store_with_segment(b"one\n");
    let path = store.segment_path(&segment).unwrap();
    let displaced = path.with_extension("original");
    fs::rename(&path, &displaced).unwrap();
    fs_private::write_private(&path, b"two\n").unwrap();
    assert!(matches!(
        store.prepare_next(),
        Err(AuditDeliveryError::CorruptState)
    ));
    assert!(matches!(
        store.seal_active_segment(&segment),
        Err(AuditDeliveryError::CorruptState)
    ));
    assert_eq!(fs::read(displaced).unwrap(), b"one\n");
}

#[test]
fn live_prepare_and_seal_reject_same_inode_registered_prefix_rewrite() {
    let (_root, _journal, segment, mut store) = store_with_segment(b"one\n");
    let path = store.segment_path(&segment).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    let generation = path.parent().unwrap().parent().unwrap();
    let manifest_before = fs::read(generation.join("manifest.json")).unwrap();
    let state_before = fs::read(generation.join("state.json")).unwrap();
    fs_private::write_private(&path, b"two\n").unwrap();
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);

    assert!(matches!(
        store.seal_active_segment(&segment),
        Err(AuditDeliveryError::CorruptState)
    ));
    assert!(matches!(
        store.prepare_next(),
        Err(AuditDeliveryError::CorruptState)
    ));
    assert_eq!(
        fs::read(generation.join("manifest.json")).unwrap(),
        manifest_before
    );
    assert_eq!(
        fs::read(generation.join("state.json")).unwrap(),
        state_before
    );

    let (root, journal, segment, store) = store_with_segment(b"one\n");
    let path = store.segment_path(&segment).unwrap();
    let generation = path.parent().unwrap().parent().unwrap();
    drop(store);
    let mut reopened = reopen(&root, &journal);
    let manifest_before = fs::read(generation.join("manifest.json")).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    fs_private::write_private(&path, b"two\n").unwrap();
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
    assert!(matches!(
        reopened.seal_active_segment(&segment),
        Err(AuditDeliveryError::CorruptState)
    ));
    assert_eq!(
        fs::read(generation.join("manifest.json")).unwrap(),
        manifest_before
    );

    let (_root, _journal, segment, mut store) = store_with_segment(b"one\n");
    store.seal_active_segment(&segment).unwrap();
    let path = store.segment_path(&segment).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    let generation = path.parent().unwrap().parent().unwrap();
    let manifest_before = fs::read(generation.join("manifest.json")).unwrap();
    let state_before = fs::read(generation.join("state.json")).unwrap();
    fs_private::write_private(&path, b"two\n").unwrap();
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
    assert!(matches!(
        store.prepare_next(),
        Err(AuditDeliveryError::CorruptState)
    ));
    assert_eq!(
        fs::read(generation.join("manifest.json")).unwrap(),
        manifest_before
    );
    assert_eq!(
        fs::read(generation.join("state.json")).unwrap(),
        state_before
    );
}

#[test]
fn acknowledged_commitment_rejects_rewrites_older_than_the_boundary() {
    let (_root, _journal, segment, mut store, mut payload) =
        store_with_large_acknowledged_active_prefix();
    let prepared = store.prepare_next().unwrap().unwrap();
    let path = store.segment_path(&segment).unwrap();
    let generation = path.parent().unwrap().parent().unwrap();
    let state_before = fs::read(generation.join("state.json")).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    payload[0] = b'z';
    fs_private::write_private(&path, &payload).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
    assert!(matches!(
        store.acknowledge(prepared.token()),
        Err(AuditDeliveryError::CorruptState)
    ));
    assert_eq!(
        fs::read(generation.join("state.json")).unwrap(),
        state_before
    );

    let (_root, _journal, segment, mut store, mut payload) =
        store_with_large_acknowledged_active_prefix();
    let path = store.segment_path(&segment).unwrap();
    let generation = path.parent().unwrap().parent().unwrap();
    let manifest_before = fs::read(generation.join("manifest.json")).unwrap();
    payload[0] = b'z';
    fs_private::write_private(&path, &payload).unwrap();
    assert!(matches!(
        store.seal_active_segment(&segment),
        Err(AuditDeliveryError::CorruptState)
    ));
    assert_eq!(
        fs::read(generation.join("manifest.json")).unwrap(),
        manifest_before
    );

    let (root, journal, segment, store, mut payload) =
        store_with_large_acknowledged_active_prefix();
    let path = store.segment_path(&segment).unwrap();
    drop(store);
    payload[0] = b'z';
    fs_private::write_private(&path, &payload).unwrap();
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::CorruptState)
    ));
}

#[test]
fn empty_registered_segment_replacement_fails_recovery() {
    let (root, journal, segment, store) = store_with_segment(b"");
    let path = store.segment_path(&segment).unwrap();
    drop(store);
    let displaced = path.with_extension("original");
    fs::rename(&path, &displaced).unwrap();
    fs_private::write_private(&path, b"").unwrap();
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::CorruptState)
    ));
}

#[test]
fn sealed_segment_growth_is_rejected_live_and_on_reopen() {
    let (_root, _journal, segment, mut store) = store_with_segment(b"one\n");
    store.seal_active_segment(&segment).unwrap();
    append(&store, &segment, b"two\n");
    assert!(matches!(
        store.prepare_next(),
        Err(AuditDeliveryError::CorruptState)
    ));

    let (root, journal, segment, mut store) = store_with_segment(b"one\n");
    store.seal_active_segment(&segment).unwrap();
    append(&store, &segment, b"two\n");
    drop(store);
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::CorruptState)
    ));
}

#[test]
fn j09_middle_change_in_prepared_range_is_detected() {
    let (_root, _journal, segment, mut store) = store_with_segment(b"aaaa\nbbbb\ncccc\n");
    store.prepare_next().unwrap().unwrap();
    fs_private::write_private(
        &store.segment_path(&segment).unwrap(),
        b"aaaa\nzzzz\ncccc\n",
    )
    .unwrap();
    assert!(matches!(
        store.recover_prepared(),
        Err(AuditDeliveryError::CorruptState)
    ));
}

#[test]
fn truncated_prepared_range_is_reported_as_corrupt() {
    let (_root, _journal, segment, mut store) = store_with_segment(b"");
    append(&store, &segment, b"one\n");
    store.prepare_next().unwrap().unwrap();
    OpenOptions::new()
        .write(true)
        .open(store.segment_path(&segment).unwrap())
        .unwrap()
        .set_len(0)
        .unwrap();
    assert!(matches!(
        store.recover_prepared(),
        Err(AuditDeliveryError::CorruptState)
    ));
}

#[test]
fn prepared_range_must_start_at_the_current_cursor() {
    let (root, journal, segment, mut store) = store_with_segment(b"one\n");
    let first = store.prepare_next().unwrap().unwrap();
    store.acknowledge(first.token()).unwrap();
    append(&store, &segment, b"two\n");
    store.prepare_next().unwrap().unwrap();
    drop(store);

    let state_path = root
        .path()
        .join("audit-delivery/v1")
        .join(journal.as_str())
        .join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    let mut digest = Sha256::new();
    digest.update(3_u64.to_be_bytes());
    digest.update(b"one");
    state["prepared"]["start_offset"] = serde_json::json!(0);
    state["prepared"]["end_offset"] = serde_json::json!(4);
    state["prepared"]["ordered_body_digest"] = serde_json::json!(hex::encode(digest.finalize()));
    fs_private::write_private(&state_path, &serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::CorruptState)
    ));
}

#[test]
fn j10_incomplete_tail_and_missing_newline_are_bounded_without_repair() {
    let (_root, _journal, segment, mut store) = store_with_segment(b"complete\nincomplete");
    let prepared = store.prepare_next().unwrap().unwrap();
    assert_eq!(prepared.bodies(), &[b"complete".to_vec()]);
    assert_eq!(
        fs::read(store.segment_path(&segment).unwrap()).unwrap(),
        b"complete\nincomplete"
    );

    let huge = vec![b'x'; 1024 * 1024 + 1];
    let temporary = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store = AuditDeliveryStore::create(temporary.path(), journal, profile()).unwrap();
    fs_private::write_private(&store.segment_path(&segment).unwrap(), &huge).unwrap();
    assert!(matches!(
        store.register_segment(segment, SegmentStatus::Active),
        Err(AuditDeliveryError::RangeTooLarge)
    ));

    let exact_limit = vec![b'x'; MAX_RANGE_BYTES];
    let temporary = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store = AuditDeliveryStore::create(temporary.path(), journal, profile()).unwrap();
    fs_private::write_private(&store.segment_path(&segment).unwrap(), &exact_limit).unwrap();
    assert!(matches!(
        store.register_segment(segment, SegmentStatus::Active),
        Err(AuditDeliveryError::RangeTooLarge)
    ));

    let repairable_tail = vec![b'x'; MAX_RANGE_BYTES - 1];
    let temporary = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store = AuditDeliveryStore::create(temporary.path(), journal, profile()).unwrap();
    fs_private::write_private(&store.segment_path(&segment).unwrap(), &repairable_tail).unwrap();
    store
        .register_segment(segment.clone(), SegmentStatus::Active)
        .unwrap();
    assert!(store.prepare_next().unwrap().is_none());
    append(&store, &segment, b"\n");
    store.seal_active_segment(&segment).unwrap();
    assert_eq!(
        store.prepare_next().unwrap().unwrap().bodies(),
        &[repairable_tail]
    );

    let (_root, _journal, _segment, mut store) = store_with_segment(b"incomplete");
    assert!(store.prepare_next().unwrap().is_none());

    let temporary = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store =
        AuditDeliveryStore::create(temporary.path(), journal.clone(), profile()).unwrap();
    fs_private::write_private(&store.segment_path(&segment).unwrap(), b"incomplete").unwrap();
    assert!(matches!(
        store.register_segment(segment.clone(), SegmentStatus::Sealed),
        Err(AuditDeliveryError::InvalidJsonl)
    ));
    store
        .register_segment(segment.clone(), SegmentStatus::Active)
        .unwrap();
    assert!(store.prepare_next().unwrap().is_none());
    assert!(matches!(
        store.seal_active_segment(&segment),
        Err(AuditDeliveryError::InvalidJsonl)
    ));
    drop(store);
    let mut reopened = reopen(&temporary, &journal);
    assert!(matches!(
        reopened.seal_active_segment(&segment),
        Err(AuditDeliveryError::InvalidJsonl)
    ));
    append(&reopened, &segment, b"\n");
    reopened.seal_active_segment(&segment).unwrap();
    let prepared = reopened.prepare_next().unwrap().unwrap();
    assert_eq!(prepared.bodies(), &[b"incomplete".to_vec()]);

    let temporary = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store = AuditDeliveryStore::create(temporary.path(), journal, profile()).unwrap();
    fs_private::write_private(&store.segment_path(&segment).unwrap(), &[0xf0, 0x9f]).unwrap();
    assert!(matches!(
        store.register_segment(segment.clone(), SegmentStatus::Active),
        Err(AuditDeliveryError::InvalidJsonl)
    ));
    fs_private::write_private(&store.segment_path(&segment).unwrap(), b"repaired\n").unwrap();
    store
        .register_segment(segment.clone(), SegmentStatus::Sealed)
        .unwrap();
    assert_eq!(
        store.prepare_next().unwrap().unwrap().bodies(),
        &[b"repaired".to_vec()]
    );

    let temporary = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let segment = SegmentId::generate();
    let mut store = AuditDeliveryStore::create(temporary.path(), journal, profile()).unwrap();
    fs_private::write_private(&store.segment_path(&segment).unwrap(), &[0xff, b'\n']).unwrap();
    assert!(matches!(
        store.register_segment(segment, SegmentStatus::Sealed),
        Err(AuditDeliveryError::InvalidJsonl)
    ));
}

#[test]
fn j11_exact_bodies_crlf_large_integer_and_conflicts_are_preserved() {
    let input = b"{ \"seq\":9007199254740993, \"x\":1 }\r\n{\"seq\":9007199254740993,\"x\":2}\n";
    let (_root, _journal, _segment, mut store) = store_with_segment(input);
    let prepared = store.prepare_next().unwrap().unwrap();
    assert_eq!(
        prepared.bodies()[0],
        b"{ \"seq\":9007199254740993, \"x\":1 }\r"
    );
    assert_eq!(prepared.bodies()[1], b"{\"seq\":9007199254740993,\"x\":2}");
    let mut expected = Sha256::new();
    for body in prepared.bodies() {
        expected.update((body.len() as u64).to_be_bytes());
        expected.update(body);
    }
    assert_eq!(
        prepared.ordered_body_digest().as_slice(),
        expected.finalize().as_slice()
    );
}

#[test]
fn j12_paths_collisions_and_modes_are_private() {
    assert!(JournalId::parse("../escape").is_err());
    assert!(SegmentId::parse("a/b").is_err());
    let (root, journal, segment, store) = store_with_segment(b"one\n");
    assert!(matches!(
        AuditDeliveryStore::create(root.path(), journal.clone(), profile()),
        Err(AuditDeliveryError::GenerationCollision)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::fs::symlink;
        let segment_path = store.segment_path(&segment).unwrap();
        let generation = segment_path.parent().unwrap().parent().unwrap();
        assert_eq!(
            fs::metadata(generation).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(store.segment_path(&segment).unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let symlink_segment = SegmentId::generate();
        let symlink_root = tempfile::tempdir().unwrap();
        let symlink_journal = JournalId::generate();
        let mut symlink_store =
            AuditDeliveryStore::create(symlink_root.path(), symlink_journal, profile()).unwrap();
        let outside = symlink_root.path().join("outside.jsonl");
        fs_private::write_private(&outside, b"outside\n").unwrap();
        symlink(
            &outside,
            symlink_store.segment_path(&symlink_segment).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            symlink_store.register_segment(symlink_segment, SegmentStatus::Active),
            Err(AuditDeliveryError::UnsafePath)
        ));
    }
}

#[test]
fn generation_and_segments_directory_symlinks_are_rejected() {
    use std::os::unix::fs::symlink;

    let (root, journal, _segment, store) = store_with_segment(b"one\n");
    let generation = root.path().join("audit-delivery/v1").join(journal.as_str());
    drop(store);
    let outside_generation = root.path().join("outside-generation");
    fs::rename(&generation, &outside_generation).unwrap();
    let manifest_before = fs::read(outside_generation.join("manifest.json")).unwrap();
    symlink(&outside_generation, &generation).unwrap();
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::UnsafePath)
    ));
    assert_eq!(
        fs::read(outside_generation.join("manifest.json")).unwrap(),
        manifest_before
    );

    let (root, journal, _segment, store) = store_with_segment(b"one\n");
    let generation = root.path().join("audit-delivery/v1").join(journal.as_str());
    drop(store);
    let segments = generation.join("segments");
    let outside_segments = root.path().join("outside-segments");
    fs::rename(&segments, &outside_segments).unwrap();
    let payload_before = fs::read_dir(&outside_segments).unwrap().count();
    symlink(&outside_segments, &segments).unwrap();
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::UnsafePath)
    ));
    assert_eq!(
        fs::read_dir(&outside_segments).unwrap().count(),
        payload_before
    );
}

#[test]
fn j13_metadata_size_is_bounded_before_decode() {
    let (root, journal, _segment, _store) = store_with_segment(b"one\n");
    let manifest = root
        .path()
        .join("audit-delivery/v1")
        .join(journal.as_str())
        .join("manifest.json");
    let file = OpenOptions::new().write(true).open(&manifest).unwrap();
    file.set_len(1024 * 1024 + 1).unwrap();
    assert!(matches!(
        AuditDeliveryStore::open(root.path(), journal, profile()),
        Err(AuditDeliveryError::MetadataTooLarge)
    ));

    let temporary = tempfile::tempdir().unwrap();
    let journal = JournalId::generate();
    let store = AuditDeliveryStore::create(temporary.path(), journal.clone(), profile()).unwrap();
    let generation = temporary
        .path()
        .join("audit-delivery/v1")
        .join(journal.as_str());
    let mut segments = Vec::new();
    let mut cursors = Vec::new();
    let empty_digest = hex::encode(Sha256::digest([]));
    let empty_acknowledged_digest =
        hex::encode(Sha256::digest(b"marmot-audit-delivery-acknowledged-v1"));
    for index in 0..256 {
        let id = format!("segment-{index}");
        let segment_id = SegmentId::parse(id.clone()).unwrap();
        let segment_path = store.segment_path(&segment_id).unwrap();
        fs_private::create_new_private(&segment_path).unwrap();
        let metadata = fs::metadata(&segment_path).unwrap();
        segments.push(serde_json::json!({
            "segment_id": id,
            "relative_name": format!("segments/segment-{index}.jsonl"),
            "status": "sealed",
            "registered_length": 0,
            "registered_digest": empty_digest.clone(),
            "file_identity": {
                "device": metadata.dev(),
                "inode": metadata.ino(),
            },
        }));
        cursors.push(serde_json::json!({
            "segment_id": format!("segment-{index}"),
            "acknowledged_end": 0,
            "boundary_digest": empty_digest.clone(),
            "acknowledged_digest": empty_acknowledged_digest.clone(),
        }));
    }
    fs_private::write_private(
        &generation.join("manifest.json"),
        &serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "journal_id": journal.as_str(),
            "segments": segments,
        }))
        .unwrap(),
    )
    .unwrap();
    fs_private::write_private(
        &generation.join("state.json"),
        &serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "journal_id": journal.as_str(),
            "destination_profile": "test-profile",
            "revision": 1,
            "cursors": cursors,
            "prepared": null,
            "health": {
                "status": "clean",
                "recovery_events": 0,
                "corruption_events": 0,
            },
        }))
        .unwrap(),
    )
    .unwrap();
    let mut store = reopen(&temporary, &journal);
    let before_manifest = fs::read(generation.join("manifest.json")).unwrap();
    let before_state = fs::read(generation.join("state.json")).unwrap();
    assert!(matches!(
        store.register_segment(SegmentId::generate(), SegmentStatus::Active),
        Err(AuditDeliveryError::SegmentLimit)
    ));
    assert_eq!(
        fs::read(generation.join("manifest.json")).unwrap(),
        before_manifest
    );
    assert_eq!(
        fs::read(generation.join("state.json")).unwrap(),
        before_state
    );
}

#[test]
fn j14_close_keeps_preparation_for_new_owner() {
    let (root, journal, _segment, mut store) = store_with_segment(b"one\n");
    let digest = store.prepare_next().unwrap().unwrap().ordered_body_digest();
    store.close();
    assert!(matches!(
        store.recover_prepared(),
        Err(AuditDeliveryError::Closed)
    ));
    assert_eq!(
        reopen(&root, &journal)
            .recover_prepared()
            .unwrap()
            .unwrap()
            .ordered_body_digest(),
        digest
    );
}

#[test]
fn operation_sequence_preserves_exact_accepted_and_pending_union() {
    let (root, journal, segment, mut store) = store_with_segment(b"a\nb\n");
    let first = store.prepare_next().unwrap().unwrap();
    let accepted = first.bodies().to_vec();
    drop(store);
    let mut store = reopen(&root, &journal);
    let recovered = store.recover_prepared().unwrap().unwrap();
    store.acknowledge(recovered.token()).unwrap();
    append(&store, &segment, b"c\n");
    let pending = store.prepare_next().unwrap().unwrap().bodies().to_vec();
    assert_eq!(
        [accepted, pending].concat(),
        [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
    );
}

#[test]
fn subprocess_exit_recovers_before_and_after_acknowledgement() {
    let (root, journal, _segment, store) = store_with_segment(b"a\nb\n");
    drop(store);
    run_crash_helper(root.path(), &journal, "prepare");
    assert!(
        reopen(&root, &journal)
            .recover_prepared()
            .unwrap()
            .is_some()
    );
    run_crash_helper(root.path(), &journal, "acknowledge");
    let mut reopened = reopen(&root, &journal);
    assert!(reopened.recover_prepared().unwrap().is_none());
    assert!(reopened.prepare_next().unwrap().is_none());
}

fn run_crash_helper(root: &std::path::Path, journal: &JournalId, action: &str) {
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("audit_delivery::tests::audit_delivery_crash_helper")
        .arg("--nocapture")
        .env("MARMOT_AUDIT_DELIVERY_CRASH_ROOT", root)
        .env("MARMOT_AUDIT_DELIVERY_CRASH_JOURNAL", journal.as_str())
        .env("MARMOT_AUDIT_DELIVERY_CRASH_ACTION", action)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn audit_delivery_crash_helper() {
    let Ok(root) = std::env::var("MARMOT_AUDIT_DELIVERY_CRASH_ROOT") else {
        return;
    };
    let journal =
        JournalId::parse(std::env::var("MARMOT_AUDIT_DELIVERY_CRASH_JOURNAL").unwrap()).unwrap();
    let action = std::env::var("MARMOT_AUDIT_DELIVERY_CRASH_ACTION").unwrap();
    let mut store = AuditDeliveryStore::open(root, journal, profile()).unwrap();
    match action.as_str() {
        "prepare" => {
            store.prepare_next().unwrap().unwrap();
        }
        "acknowledge" => {
            let prepared = store.recover_prepared().unwrap().unwrap();
            store.acknowledge(prepared.token()).unwrap();
        }
        _ => panic!("unknown crash-helper action"),
    }
    std::process::exit(0);
}
