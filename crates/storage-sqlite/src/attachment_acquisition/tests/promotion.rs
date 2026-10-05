//! Promotion invariants at the durable owner, using a controlled clock.
use super::*;

/// Durable counters and ownership compared across joins.
#[derive(Debug, PartialEq, Eq)]
struct Budget(i64, i64, i64, i64, i64, Option<i64>, Option<Vec<u8>>, i64);

/// Snapshot every retry/lease/body field which join is forbidden to reset.
fn budget(store: &SqliteAccountStorage, asset: &AttachmentAssetRef) -> Budget {
    store.lock().unwrap().query_row(
        "SELECT attempts,acquisition_attempts,network_attempts,body_completed,retry_not_before,due,attempt,progress_epoch FROM attachment_acquisition WHERE token=?1",
        [&asset.token], |r| Ok(Budget(r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
    ).unwrap()
}

/// Ten joins in every live state preserve all budgets, backoff and attempt ownership.
#[test]
fn explicit_join_preserves_queued_retry_and_fetching_budgets() {
    for state in [0, 1, 2] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, "join");
        let asset = request(&store, "join");
        store.lock().unwrap().execute(
            "UPDATE attachment_acquisition SET state=?2,due=100,attempt=CASE WHEN ?2=1 THEN randomblob(16) ELSE NULL END,attempts=2,automatic_history=1,acquisition_attempts=2,network_attempts=7,retry_not_before=100,progress_epoch=9 WHERE token=?1",
            params![asset.token,state],
        ).unwrap();
        let before = budget(&store, &asset);
        for now in 20..30 {
            assert_eq!(
                store
                    .request_explicit_attachment(GROUP, &selected("join"), digest(), now)
                    .unwrap(),
                AttachmentDemand::Requested(asset.clone())
            );
            assert_eq!(budget(&store, &asset), before);
            assert!(
                store
                    .attachment_transfer_candidates(now, 64, true)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                store
                    .claim_attachment_acquisition(&asset, now, 200)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(store.attachment_request_is_explicit(&asset).unwrap());
        assert_eq!(
            store
                .attachment_transfer_candidates(100, 64, false)
                .unwrap(),
            vec![asset]
        );
    }
}

/// A paused automatic job regains admission without bypassing its future backoff.
#[test]
fn permission_paused_promotion_preserves_backoff_and_counters() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "paused");
    let asset = request(&store, "paused");
    store.lock().unwrap().execute("UPDATE attachment_acquisition SET state=2,due=100,automatic_history=1,acquisition_attempts=2,network_attempts=7 WHERE token=?1",[&asset.token]).unwrap();
    store.park_attachment_permission(&asset).unwrap();
    assert!(store.promote_attachment_demand(&asset, 20).unwrap());
    let after = budget(&store, &asset);
    assert_eq!(after.1, 2);
    assert_eq!(after.2, 7);
    assert_eq!(after.4, 100);
    assert_eq!(after.5, Some(100));
    assert!(!store.promote_attachment_demand(&asset, 21).unwrap());
    assert!(
        store
            .attachment_transfer_candidates(99, 64, false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .attachment_transfer_candidates(100, 64, false)
            .unwrap(),
        vec![asset]
    );
}

/// Cancellation, completed bodies and exhaustion cannot be rearmed by joins.
#[test]
fn promotion_rejects_terminal_and_suppressed_sources() {
    for clause in [
        "cancelled=1,state=4,due=NULL",
        "state=4,due=NULL",
        "body_completed=1",
        "automatic_history=1,acquisition_attempts=4",
        "automatic_history=1,network_attempts=64",
        "state=5,permission_paused=0,due=NULL",
        "size_blocked_max=1",
    ] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, "terminal");
        let asset = request(&store, "terminal");
        store
            .lock()
            .unwrap()
            .execute(
                &format!("UPDATE attachment_acquisition SET {clause} WHERE token=?1"),
                [&asset.token],
            )
            .unwrap();
        let before = budget(&store, &asset);
        assert!(!store.promote_attachment_demand(&asset, 20).unwrap());
        assert_eq!(budget(&store, &asset), before);
        assert!(!store.attachment_request_is_explicit(&asset).unwrap());
    }
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "removed");
    let asset = request(&store, "removed");
    store.remove_attachment_reference(&asset).unwrap();
    assert!(!store.promote_attachment_demand(&asset, 20).unwrap());
    assert_eq!(
        store
            .request_explicit_attachment(GROUP, &selected("removed"), digest(), 20)
            .unwrap(),
        AttachmentDemand::Suppressed
    );
    let AttachmentDemand::Requested(recovered) = store
        .request_attachment_download_again(GROUP, &selected("removed"), digest(), 21)
        .unwrap()
    else {
        panic!("deliberate recovery")
    };
    assert!(store.attachment_request_is_explicit(&recovered).unwrap());
}

/// Source validity and account-store incarnation are checked inside promotion.
#[test]
fn promotion_rejects_expired_hidden_pending_and_foreign_sources() {
    for mutation in [
        "UPDATE attachment_acquisition SET expires_at=20",
        "UPDATE attachment_history SET visible=0",
        "UPDATE account_groups SET pending_confirmation=1",
        "UPDATE attachment_history SET source_epoch=4",
    ] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, "stale");
        let asset = request(&store, "stale");
        sql(&store, mutation);
        assert!(!store.promote_attachment_demand(&asset, 20).unwrap());
    }
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "foreign");
    let asset = request(&store, "foreign");
    assert!(
        !SqliteAccountStorage::in_memory()
            .unwrap()
            .promote_attachment_demand(&asset, 20)
            .unwrap()
    );
}

/// The tapped seventh item wins the next admission without preempting a live lease.
#[test]
fn seventh_backlog_promotion_preserves_single_owner_and_retry_positive_control() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let mut assets = Vec::new();
    for n in 0..7 {
        let name = format!("file-{n}");
        seed(&store, &name);
        assets.push(request(&store, &name));
    }
    let running = store
        .claim_attachment_acquisition(&assets[0], 12, 100)
        .unwrap()
        .unwrap();
    let before = budget(&store, &assets[0]);
    assert!(store.promote_attachment_demand(&assets[6], 20).unwrap());
    assert_eq!(
        store.attachment_transfer_candidates(20, 64, true).unwrap()[0],
        assets[6]
    );
    assert_eq!(budget(&store, &assets[0]), before);
    let tapped = store
        .claim_attachment_acquisition(&assets[6], 20, 100)
        .unwrap()
        .unwrap();
    assert!(
        store
            .claim_attachment_acquisition(&assets[6], 21, 100)
            .unwrap()
            .is_none()
    );
    assert!(store.attachment_transfer_is_active(&running, 21).unwrap());
    assert!(store.promote_attachment_demand(&assets[0], 21).unwrap());
    assert!(store.attachment_transfer_is_active(&running, 21).unwrap());
    store.cancel_attachment_acquisition(&assets[6]).unwrap();
    assert!(!store.promote_attachment_demand(&assets[6], 22).unwrap());
    assert!(!store.attachment_transfer_is_active(&tapped, 22).unwrap());
    assert!(store.explicitly_retry_attachment(&assets[6], 23).unwrap());
    assert_eq!(budget(&store, &assets[6]).1, 0);
}

/// Durable promotion survives restart without moving the retry deadline.
#[test]
fn promotion_survives_encrypted_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("promotion.sqlite");
    let key = SqlCipherKey::new("promotion-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "restart");
    let asset = request(&store, "restart");
    store.lock().unwrap().execute("UPDATE attachment_acquisition SET state=2,due=100,retry_not_before=100,automatic_history=1,acquisition_attempts=2,network_attempts=7 WHERE token=?1",[&asset.token]).unwrap();
    let before = budget(&store, &asset);
    assert!(store.promote_attachment_demand(&asset, 20).unwrap());
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(budget(&store, &asset), before);
    assert!(store.attachment_request_is_explicit(&asset).unwrap());
    assert!(
        store
            .attachment_transfer_candidates(99, 64, false)
            .unwrap()
            .is_empty()
    );
}

/// An already admitted final attempt may be promoted without funding another one.
#[test]
fn active_budget_ceiling_promotion_preserves_partials_and_progress() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "last");
    let asset = request(&store, "last");
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    store
        .checkpoint_attachment_partial(&job, &partial_identity(10), 0, b"abc", 12, 100)
        .unwrap();
    store.lock().unwrap().execute("UPDATE attachment_acquisition SET automatic_history=1,acquisition_attempts=4,network_attempts=64,progress_received=3,progress_total=10,progress_phase=1 WHERE token=?1",[&asset.token]).unwrap();
    let before = budget(&store, &asset);
    assert!(store.promote_attachment_demand(&asset, 20).unwrap());
    assert_eq!(budget(&store, &asset), before);
    assert_eq!(partial_usage(&store), 3);
    assert!(store.attachment_transfer_is_active(&job, 20).unwrap());
    assert!(!store.begin_attachment_network_attempt(&job, 20).unwrap());
}

/// Failure in the promotion write rolls back initial demand creation as well.
#[test]
fn initial_explicit_demand_rolls_back_on_promotion_failure() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "fresh");
    sql(
        &store,
        "CREATE TRIGGER fail_promotion BEFORE UPDATE OF explicit_request ON attachment_acquisition BEGIN SELECT RAISE(ABORT,'injected promotion failure'); END;",
    );
    assert!(
        store
            .request_explicit_attachment(GROUP, &selected("fresh"), digest(), 20)
            .is_err()
    );
    let count: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM attachment_acquisition", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

/// Relay echoes and timeline rebuilds cannot erase the persisted tapped order.
#[test]
fn explicit_priority_survives_same_source_reprojection() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "first");
    seed(&store, "second");
    let a = request(&store, "first");
    let b = request(&store, "second");
    assert!(store.promote_attachment_demand(&a, 20).unwrap());
    assert!(store.promote_attachment_demand(&b, 21).unwrap());
    sql(
        &store,
        "UPDATE attachment_history SET received_at=99 WHERE message_id_hex='first';",
    );
    assert_eq!(
        store.attachment_transfer_candidates(22, 64, true).unwrap(),
        vec![b, a]
    );
}

/// Revocation racing promotion cannot refund the final still-running claim.
#[test]
fn pause_promotion_race_keeps_live_claim_charged_in_both_orders() {
    for pause_first in [false, true] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store, "race");
        let asset = request(&store, "race");
        store.enable_attachment_automatic_history(&asset).unwrap();
        let job = store
            .claim_attachment_acquisition(&asset, 11, 100)
            .unwrap()
            .unwrap();
        sql(
            &store,
            "UPDATE attachment_acquisition SET acquisition_attempts=4,network_attempts=12",
        );
        if pause_first {
            store.pause_automatic_attachments(12).unwrap();
        }
        assert!(store.promote_attachment_demand(&asset, 13).unwrap());
        if !pause_first {
            store.pause_automatic_attachments(14).unwrap();
        }
        assert!(store.fail_attachment_acquisition(&job, Some(30)).unwrap());
        let (acquisitions, network): (u64, u64) = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT acquisition_attempts,network_attempts FROM attachment_acquisition",
                [],
                |r| Ok((nonnegative(r, 0)?, nonnegative(r, 1)?)),
            )
            .unwrap();
        assert_eq!((acquisitions, network), (4, 12));
        assert!(
            store
                .claim_attachment_acquisition(&asset, 100, 200)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            transfer(&store, "race", true).state,
            AttachmentTransferState::RetryExhausted
        );
    }
}
