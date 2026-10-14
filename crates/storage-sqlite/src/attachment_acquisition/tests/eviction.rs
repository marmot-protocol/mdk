//! Least-recently-used eviction when the retained budget is full.
use super::*;

/// Late enough that bodies used at the fixture's early times are unprotected.
const LATE: u64 = 10_000;
const LEN: u64 = BODY.len() as u64;

fn ready(store: &SqliteAccountStorage, message: &str, used_at: i64) -> AttachmentAssetRef {
    seed(store, message);
    let asset = request(store, message);
    publish(store, &asset);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE attachment_acquisition SET retained_used_at=?2 WHERE token=?1",
            params![asset.token, used_at],
        )
        .unwrap();
    asset
}

fn publish_at(
    store: &SqliteAccountStorage,
    asset: &AttachmentAssetRef,
    now: u64,
    budget: u64,
) -> AttachmentPublishResult {
    let job = store
        .claim_attachment_acquisition(asset, now, now + 100)
        .unwrap()
        .unwrap();
    store
        .complete_attachment_acquisition(&job, BODY, now, budget)
        .unwrap()
}

/// Whether the body is still stored. A local read would count as a use.
fn retained(store: &SqliteAccountStorage, asset: &AttachmentAssetRef) -> bool {
    store
        .lock()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM retained_attachment_bytes WHERE token=?1)",
            [&asset.token],
            |r| r.get(0),
        )
        .unwrap()
}

fn used_at(store: &SqliteAccountStorage, asset: &AttachmentAssetRef) -> i64 {
    store
        .lock()
        .unwrap()
        .query_row(
            "SELECT retained_used_at FROM attachment_acquisition WHERE token=?1",
            [&asset.token],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn publication_evicts_least_recently_used_bodies_first() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = ready(&store, "a", 100);
    let b = ready(&store, "b", 200);
    let c = ready(&store, "c", 300);
    // Reading b makes it the most recently used of the three.
    assert!(
        store
            .read_retained_attachment(&b, 5_000, 0, 100)
            .unwrap()
            .is_some()
    );
    assert_eq!(used_at(&store, &b), 5_000);
    let budget = 3 * LEN;
    seed(&store, "d");
    let d = request(&store, "d");
    assert_eq!(
        publish_at(&store, &d, LATE, budget),
        AttachmentPublishResult::Published
    );
    assert!(!retained(&store, &a), "the oldest body is released");
    assert!(retained(&store, &b) && retained(&store, &c) && retained(&store, &d));
    assert_eq!(store.retained_attachment_byte_count().unwrap(), budget);
    assert_eq!(used_at(&store, &d), LATE as i64);

    seed(&store, "e");
    let e = request(&store, "e");
    assert_eq!(
        publish_at(&store, &e, LATE, budget),
        AttachmentPublishResult::Published
    );
    assert!(!retained(&store, &c), "c was used before the read of b");
    assert!(retained(&store, &b) && retained(&store, &d) && retained(&store, &e));
    assert_eq!(store.retained_attachment_byte_count().unwrap(), budget);
}

#[test]
fn eviction_spares_recent_bodies_and_releases_nothing_when_it_cannot_fit() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let old = ready(&store, "old", 100);
    let recent = ready(&store, "recent", LATE as i64 - 60);
    let budget = 2 * LEN;
    seed(&store, "next");
    let next = request(&store, "next");
    assert_eq!(
        publish_at(&store, &next, LATE, budget),
        AttachmentPublishResult::Published
    );
    assert!(!retained(&store, &old));
    assert!(
        retained(&store, &recent),
        "a body used within the hour stays"
    );

    // Everything left is protected, so the publication is refused and no
    // body is released for it.
    seed(&store, "blocked");
    let blocked = request(&store, "blocked");
    assert_eq!(
        publish_at(&store, &blocked, LATE, budget),
        AttachmentPublishResult::CapacityBlocked
    );
    assert!(retained(&store, &recent) && retained(&store, &next));
    assert_eq!(store.retained_attachment_byte_count().unwrap(), budget);

    // Once the protection window has passed, the oldest-used body makes room.
    let later = LATE + ATTACHMENT_EVICTION_PROTECTION_SECONDS;
    assert_eq!(
        publish_at(&store, &blocked, later, budget),
        AttachmentPublishResult::Published
    );
    assert!(!retained(&store, &recent));
    assert!(retained(&store, &next));
}

#[test]
fn admission_counts_evictable_bodies_without_evicting() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let old = ready(&store, "old", 100);
    seed(&store, "new");
    let new = request(&store, "new");
    let budget = LEN + 10;
    assert!(
        store
            .attachment_acquisition_fits_budget(&new, 20, budget, LATE)
            .unwrap()
    );
    assert!(retained(&store, &old), "admission only checks");
    assert!(
        !store
            .attachment_acquisition_fits_budget(&new, 20, budget, 200)
            .unwrap(),
        "a protected body is not room"
    );
}

#[test]
fn checkpoint_reservation_evicts_for_the_complete_representation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let old = ready(&store, "old", 100);
    seed(&store, "large");
    let large = request(&store, "large");
    let job = store
        .claim_attachment_acquisition(&large, LATE, LATE + 100)
        .unwrap()
        .unwrap();
    assert!(
        store
            .checkpoint_attachment_partial(&job, &partial_identity(20), 0, b"abc", LATE, LEN + 10)
            .unwrap()
    );
    assert!(!retained(&store, &old));
    assert_eq!(store.retained_attachment_byte_count().unwrap(), 0);
}

#[test]
fn evicted_bodies_stay_unavailable_until_explicitly_requested_again() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let old = ready(&store, "old", 100);
    seed(&store, "new");
    let new = request(&store, "new");
    assert_eq!(
        publish_at(&store, &new, LATE, LEN),
        AttachmentPublishResult::Published
    );
    assert_eq!(
        transfer(&store, "old", true).state,
        AttachmentTransferState::PreviouslyAcquiredUnavailable
    );
    // Ordinary demand never re-arms an evicted body.
    assert_eq!(request(&store, "old"), old);
    assert_eq!(
        transfer(&store, "old", true).state,
        AttachmentTransferState::PreviouslyAcquiredUnavailable
    );
    assert!(
        store
            .attachment_transfer_candidates(LATE, 64, true)
            .unwrap()
            .is_empty()
    );
    // Download-again queues it from its original source.
    assert!(store.explicitly_retry_attachment(&old, LATE).unwrap());
    assert_eq!(
        transfer(&store, "old", true).state,
        AttachmentTransferState::Queued
    );
}

#[test]
fn evicting_a_chunked_file_releases_its_chunks_and_quota() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let body = vec![7u8; 3 * ATTACHMENT_STAGING_CHUNK_BYTES + 5];
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let mut event = source("file");
    event.tags[0][2] = format!("x {}", hex::encode(digest));
    store.lock().unwrap().execute("INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0) ON CONFLICT DO NOTHING",[GROUP]).unwrap();
    store.record_app_event(&event).unwrap();
    let mut entry = selected("file");
    entry.slot = serde_json::to_value(&event.tags[0]).unwrap();
    let AttachmentDemand::Requested(file) = store
        .request_attachment_acquisition(GROUP, &entry, digest, 11)
        .unwrap()
    else {
        panic!("expected requested");
    };
    let job = store
        .claim_attachment_acquisition(&file, 12, 100)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, &body, 12, u64::MAX)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    let chunks = |store: &SqliteAccountStorage| -> i64 {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT (SELECT count(*) FROM retained_attachment_chunks)+(SELECT count(*) FROM attachment_chunk_bodies)",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert!(chunks(&store) > 0, "the body is stored as a chunked file");
    assert_eq!(
        store.retained_attachment_byte_count().unwrap(),
        body.len() as u64
    );

    seed(&store, "new");
    let new = request(&store, "new");
    assert_eq!(
        publish_at(&store, &new, LATE, LEN),
        AttachmentPublishResult::Published
    );
    assert_eq!(chunks(&store), 0);
    assert_eq!(store.retained_attachment_byte_count().unwrap(), LEN);
}

#[test]
fn outgoing_staging_evicts_old_bodies() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let old = ready(&store, "old", 100);
    let tokens = store
        .stage_attachment_uploads(GROUP, 3, &[BODY], LATE, LEN + 10)
        .unwrap();
    assert_eq!(tokens.len(), 1);
    assert!(!retained(&store, &old));
}

#[test]
fn victim_scan_uses_the_retained_lru_index() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let plan: Vec<String> = store
        .lock()
        .unwrap()
        .prepare(&format!(
            "EXPLAIN QUERY PLAN {}",
            super::super::eviction::VICTIMS_SQL
        ))
        .unwrap()
        .query_map(params![0, 1], |r| r.get(3))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let plan = plan.join("\n");
    assert!(
        plan.contains("attachment_acquisition_retained_lru"),
        "{plan}"
    );
    assert!(!plan.contains("TEMP B-TREE"), "{plan}");
}
