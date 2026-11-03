//! Durable visit authority, pacing, stale results and torn-write protection.

use super::*;
use crate::{
    RecoveryCause, RecoveryCoverageProof, RecoveryCoverageSlice, SqlCipherKey,
    SqliteAccountStorage, StoredEpochBackfillIntent,
};

fn gap(app: &SqliteAppStorage) -> RecoveryDemandTicket {
    app.pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|d| d.cause == RecoveryCause::EpochGap)
        .unwrap()
        .ticket
}

#[test]
fn epoch_gap_visits_survive_reopen_and_fence_stale_or_duplicate_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::raw([0x41; 32]);
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    app.lock()
        .unwrap()
        .execute_batch("INSERT INTO cgka_groups (id,epoch,record) VALUES (x'0a',1,x'00');")
        .unwrap();
    let route = TransportReconciliationRoute::Group([1; 32]);
    let other = TransportReconciliationRoute::Group([2; 32]);
    let relay = "wss://relay.example";
    app.widen_recovery_coverage_goals(&[route.clone(), other.clone()], 100)
        .unwrap();
    for r in [&route, &other] {
        app.record_recovery_coverage(
            &[RecoveryCoverageSlice {
                route: r,
                relay,
                since_seconds: 100,
                until_seconds: 1000,
                proof: RecoveryCoverageProof::SweepSlice,
            }],
            1000,
        )
        .unwrap();
    }
    let intent = StoredEpochBackfillIntent {
        group_id_hex: "0a".into(),
        stalled_epoch: 1,
    };
    app.arm_epoch_backfill_intents(std::slice::from_ref(&intent))
        .unwrap();
    let ticket = gap(&app);
    let floors = [(route.clone(), 100)];
    let mark = app.recovery_coverage_mark().unwrap();
    app.lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_gap_visit BEFORE INSERT ON account_recovery_coverage_uncovers
         BEGIN SELECT RAISE(ABORT,'injected gap-visit uncover'); END;",
        )
        .unwrap();
    match app.begin_recovery_epoch_gap_retry(ticket, &floors, 1000) {
        Err(StorageError::Backend(message)) => {
            assert!(message.contains("injected gap-visit uncover"))
        }
        other => panic!("expected injected gap-visit failure, got {other:?}"),
    }
    assert_eq!(app.recovery_epoch_gap_retry(ticket).unwrap(), None);
    assert_eq!(app.recovery_coverage_mark().unwrap(), mark);
    assert!(
        app.recovery_coverage_covers(&route, &[relay.into()], 100, 1000)
            .unwrap()
    );
    app.lock()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_gap_visit")
        .unwrap();
    assert!(
        app.begin_recovery_epoch_gap_retry(ticket, &floors, 1000)
            .unwrap()
    );
    let started = app.recovery_coverage_mark().unwrap();
    assert!(
        !app.begin_recovery_epoch_gap_retry(ticket, &floors, 1000)
            .unwrap()
    );
    assert_eq!(app.recovery_coverage_mark().unwrap(), started);
    assert!(
        app.recovery_coverage_covers(&other, &[relay.into()], 100, 1000)
            .unwrap()
    );
    assert!(
        app.finish_recovery_epoch_gap_retry(ticket, 1, 1000, 30, false)
            .unwrap()
    );
    assert!(
        !app.finish_recovery_epoch_gap_retry(ticket, 1, 1001, 30, false)
            .unwrap()
    );
    drop(app);
    drop(store);

    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    assert_eq!(
        app.recovery_epoch_gap_retry(ticket).unwrap(),
        Some(RecoveryEpochGapRetry {
            visits: 1,
            in_progress: false,
            exhausted: false,
            next_retry_at_seconds: 1030,
        })
    );
    app.arm_epoch_backfill_intents(std::slice::from_ref(&intent))
        .unwrap();
    assert!(
        gap(&app) == ticket,
        "same-epoch polling cannot create fresh authority"
    );
    crate::app::account_recovery::arm_released_epoch_tx(&app.lock().unwrap(), &[0x0a], 1, 1001)
        .unwrap();
    let revised = gap(&app);
    assert!(revised != ticket);
    assert_eq!(app.recovery_epoch_gap_retry(ticket).unwrap(), None);
    assert_eq!(
        app.recovery_epoch_gap_retry(revised)
            .unwrap()
            .unwrap()
            .next_retry_at_seconds,
        1030,
        "a new receipt at the same epoch cannot reset pacing"
    );
    let ticket = revised;

    assert!(
        !app.begin_recovery_epoch_gap_retry(ticket, &floors, 1029)
            .unwrap()
    );
    assert!(
        app.begin_recovery_epoch_gap_retry(ticket, &floors, 1030)
            .unwrap()
    );
    let mark = app.recovery_coverage_mark().unwrap();
    drop(app);
    drop(store);

    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    assert_eq!(
        app.recovery_epoch_gap_retry(ticket)
            .unwrap()
            .unwrap()
            .visits,
        2
    );
    assert!(
        !app.begin_recovery_epoch_gap_retry(ticket, &floors, 1040)
            .unwrap()
    );
    assert_eq!(
        app.recovery_coverage_mark().unwrap(),
        mark,
        "restart resumes the visit, not its un-cover"
    );
    app.arm_epoch_backfill_intents(&[StoredEpochBackfillIntent {
        stalled_epoch: 2,
        ..intent.clone()
    }])
    .unwrap();
    let newer = gap(&app);
    assert!(newer != ticket);
    assert!(
        app.begin_recovery_epoch_gap_retry(newer, &floors, 1040)
            .unwrap()
    );
    assert!(
        !app.finish_recovery_epoch_gap_retry(ticket, 2, 1041, 60, false)
            .unwrap()
    );
    assert_eq!(
        app.recovery_epoch_gap_retry(newer).unwrap().unwrap().visits,
        1
    );
    assert!(
        app.finish_recovery_epoch_gap_retry(newer, 1, 1041, 30, true)
            .unwrap()
    );
    let notices = app.parked_group_recovery_obligations(&[0x0a]).unwrap();
    assert_eq!(notices.len(), 1);
    assert!(notices[0].ticket == newer);
    assert_eq!(notices[0].cause, RecoveryCause::EpochGap);
    assert!(
        !app.begin_recovery_epoch_gap_retry(newer, &floors, 9999)
            .unwrap()
    );

    crate::app::account_recovery::arm_released_epoch_tx(&app.lock().unwrap(), &[0x0a], 2, 1042)
        .unwrap();
    let revised = gap(&app);
    assert!(revised != newer);
    assert!(
        !app.begin_recovery_epoch_gap_retry(revised, &floors, 9999)
            .unwrap()
    );
    assert!(
        app.recovery_epoch_gap_retry(revised)
            .unwrap()
            .unwrap()
            .exhausted,
        "same-epoch receipt revisions cannot reset an exhausted budget"
    );
    app.rearm_all_recovery_units().unwrap();
    let explicit = gap(&app);
    assert!(explicit != newer);
    assert!(
        !app.finish_recovery_epoch_gap_retry(newer, 1, 9999, 30, true)
            .unwrap()
    );
    assert!(
        app.begin_recovery_epoch_gap_retry(explicit, &floors, 1050)
            .unwrap()
    );
    assert_eq!(
        app.recovery_epoch_gap_retry(explicit)
            .unwrap()
            .unwrap()
            .visits,
        1
    );
    app.clear_epoch_backfill_intents(&[StoredEpochBackfillIntent {
        stalled_epoch: 2,
        ..intent
    }])
    .unwrap();
    assert_eq!(
        app.recovery_epoch_gap_retry(explicit).unwrap(),
        None,
        "epoch recovery deletes its visit state"
    );
}
