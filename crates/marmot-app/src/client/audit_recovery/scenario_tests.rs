//! Recovery-owner and transport-cursor audit rows, driven through the real
//! owner seams (loss import at authorization, the inline executor's settled
//! passes, the notice publication seam and dismissal, and cursor commits),
//! then read back from the account's v5 audit file.
use std::sync::Arc;

use serde_json::Value;
use storage_sqlite::{RecoveryCause, RecoveryLossCause};

use super::recorded_v5_rows;
use crate::client::AppClient;
use crate::client::recovery::AttemptGrant;
use crate::tests::{
    ScriptedEosePump, ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
    scripted_eose_pump,
};
use crate::unix_now_seconds;

struct Fixture {
    _dir: tempfile::TempDir,
    _pump: ScriptedEosePump,
    app: crate::MarmotApp,
    client: AppClient,
    storage: storage_sqlite::SqliteAccountStorage,
}

/// One account with audit v5 enabled, one group and a checkpointed cursor,
/// so the only recovery debt is what a test adds.
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    let pump = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
    let mut state = app.load_state("alice").unwrap();
    state.last_transport_timestamp = Some(unix_now_seconds().saturating_sub(60));
    app.save_state(&state).unwrap();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    client.create_group("recovery audit", &[]).await.unwrap();
    let storage = app.account_storage("alice").unwrap();
    Fixture {
        _dir: dir,
        _pump: pump,
        app,
        client,
        storage,
    }
}

fn authorize(client: &mut AppClient) -> Option<AttemptGrant> {
    client
        .authorize_account_recovery(
            None,
            marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
        )
        .unwrap()
}

/// Every compared route's relays answer and certify nothing new.
fn quiet_routes() -> crate::client::sync::ScriptedComparisons {
    crate::client::sync::ScriptedComparisons::by_route(|_| {
        Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            Vec::new(),
        )))
    })
}

fn queue_loss_id(storage: &storage_sqlite::SqliteAccountStorage) -> [u8; 16] {
    storage
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|demand| demand.cause == RecoveryCause::QueueLoss)
        .expect("queue loss is pending")
        .ticket
        .id
}

fn of_obligation<'rows>(rows: &'rows [Value], reference: &Value) -> Vec<&'rows Value> {
    rows.iter()
        .filter(|row| &row["event"]["obligation_ref"] == reference)
        .collect()
}

#[tokio::test]
async fn loss_charged_at_authorization_records_its_cause_bound_and_count() {
    let mut fixture = fixture().await;
    let floor = unix_now_seconds().saturating_sub(30);
    // What the off-worker marker writer persists for a queue-loss generation.
    fixture
        .storage
        .record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), Some(floor))
        .unwrap();
    drop(authorize(&mut fixture.client));
    // The same generation grows: charged to the pending obligation.
    fixture
        .storage
        .record_account_delivery_loss_bounded("alice", 41, 5, unix_now_seconds(), Some(floor))
        .unwrap();
    drop(authorize(&mut fixture.client));
    // A notification lag whose REQ floor was unknown.
    fixture
        .storage
        .record_account_recovery_loss_bounded(
            "alice",
            RecoveryLossCause::NotificationConsumer,
            7,
            2,
            unix_now_seconds(),
            None,
        )
        .unwrap();
    drop(authorize(&mut fixture.client));

    let rows = recorded_v5_rows(&fixture.app, "recovery_need_changed");
    let queue = rows
        .iter()
        .filter(|row| row["event"]["cause"] == "queue_loss")
        .collect::<Vec<_>>();
    assert_eq!(queue.len(), 2, "one row per change, none per evaluation");
    assert_eq!(queue[0]["event"]["change"], "recorded");
    assert_eq!(queue[0]["event"]["bound"], "floor");
    assert_eq!(queue[0]["event"]["floor_secs"], floor);
    assert_eq!(queue[0]["event"]["charged"], 3);
    assert_eq!(queue[1]["event"]["change"], "joined");
    assert_eq!(
        queue[1]["event"]["charged"], 2,
        "only the newly charged count"
    );
    assert_eq!(
        queue[0]["event"]["obligation_ref"], queue[1]["event"]["obligation_ref"],
        "both changes name one obligation"
    );
    assert!(
        queue[1]["event"]["obligation_revision"].as_u64()
            > queue[0]["event"]["obligation_revision"].as_u64()
    );
    let raw = hex::encode(queue_loss_id(&fixture.storage));
    assert_ne!(queue[0]["event"]["obligation_ref"], raw.as_str());
    assert!(queue[0]["group_ref"].is_null(), "loss is account-scoped");

    let notification = rows
        .iter()
        .find(|row| row["event"]["cause"] == "notification_loss")
        .expect("the lag is recorded");
    assert_eq!(notification["event"]["change"], "recorded");
    assert_eq!(notification["event"]["bound"], "unbounded");
    assert!(notification["event"].get("floor_secs").is_none());
    assert_eq!(notification["event"]["charged"], 2);
}

#[tokio::test]
async fn quiet_passes_record_attempts_verdicts_parking_notice_and_dismissal() {
    let mut fixture = fixture().await;
    // No known start: every served comparison finishes, none can certify.
    fixture
        .storage
        .record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), None)
        .unwrap();
    let passes = storage_sqlite::RECOVERY_PARK_AFTER_QUIET_PASSES;
    let mut serials = Vec::new();
    for _ in 0..passes {
        let grant = authorize(&mut fixture.client).expect("a retryable pass is selected");
        serials.push(grant.reservation.attempt_serial);
        fixture.client.test_comparison_results = Some(quiet_routes());
        fixture
            .client
            .run_recovery_grant_for_test(grant)
            .await
            .unwrap();
        fixture
            .client
            .recovery_owner
            .test_advance_to_retry(&fixture.storage);
    }
    let id = queue_loss_id(&fixture.storage);

    let started = recorded_v5_rows(&fixture.app, "recovery_attempt_started");
    let finished = recorded_v5_rows(&fixture.app, "recovery_attempt_finished");
    assert_eq!(started.len(), serials.len());
    assert_eq!(finished.len(), serials.len());
    for ((start, finish), serial) in started.iter().zip(&finished).zip(&serials) {
        assert_eq!(start["event"]["attempt_serial"], *serial);
        assert_eq!(start["event"]["seam"], "maintenance");
        assert_eq!(start["event"]["scope"], "history");
        assert!(
            start["event"]["causes"]
                .as_array()
                .unwrap()
                .contains(&Value::from("queue_loss"))
        );
        assert_eq!(start["event"]["park_after_quiet_passes"], passes);
        assert!(
            !start["event"]["endpoint_refs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(finish["event"]["attempt_serial"], *serial);
        assert_eq!(
            start["event"]["record_context"]["operation_ref"],
            finish["event"]["record_context"]["operation_ref"],
            "start and finish share the attempt reference"
        );
        // Every route answered and finished its comparison, so each carries
        // a certificate for the frozen window; that alone is not the loss's
        // coverage, which has no lower bound.
        let compared = finish["event"]["routes_compared"].as_u64().unwrap();
        assert!(compared > 0);
        assert_eq!(finish["event"]["routes_certified"], compared);
        assert_eq!(finish["event"]["routes_uncertified"], 0);
        assert_eq!(finish["event"]["events_retrieved"], 0);
        assert_eq!(finish["event"]["events_retained"], 0);
    }
    // The first pass also compared the startup incremental history, which
    // its certificates satisfied; the loss's own passes were quiet.
    assert_eq!(finished[0]["event"]["outcome"], "progressed");
    assert!(
        finished[1..]
            .iter()
            .all(|finish| finish["event"]["outcome"] == "quiet")
    );
    let incremental = recorded_v5_rows(&fixture.app, "recovery_obligation_reassessed")
        .into_iter()
        .find(|row| row["event"]["cause"] == "incremental_history")
        .expect("the startup comparison is reassessed");
    assert_eq!(incremental["event"]["verdict"], "satisfied");
    assert_eq!(incremental["event"]["next_attempt"], "not_needed");
    assert_eq!(
        incremental["event"]["scopes_certified"],
        incremental["event"]["scopes_total"]
    );

    // Each pass reassessed the loss; the last one parked it.
    let loss_ref = recorded_v5_rows(&fixture.app, "recovery_need_changed")
        .into_iter()
        .find(|row| row["event"]["cause"] == "queue_loss")
        .expect("the loss was recorded")["event"]["obligation_ref"]
        .clone();
    let reassessed = recorded_v5_rows(&fixture.app, "recovery_obligation_reassessed");
    let loss = of_obligation(&reassessed, &loss_ref);
    assert_eq!(loss.len(), serials.len());
    for (index, row) in loss.iter().enumerate() {
        let parked = index + 1 == loss.len();
        assert_eq!(row["event"]["cause"], "queue_loss");
        assert_eq!(row["event"]["progress"], "quiet");
        assert_eq!(row["event"]["quiet_passes"], index as u64 + 1);
        assert_eq!(
            row["event"]["verdict"],
            if parked { "parked" } else { "deferred" }
        );
        assert_eq!(
            row["event"]["next_attempt"],
            if parked {
                "explicit_repair_only"
            } else {
                "paced_retry"
            }
        );
        assert_eq!(row["event"]["attempt_serial"], serials[index]);
    }

    // The publication seam shows the parked occurrence once.
    let notices = fixture.client.history_notices().unwrap();
    assert_eq!(notices.len(), 1);
    fixture.client.take_history_notice_changes();
    fixture.client.take_history_notice_changes();
    let shown = recorded_v5_rows(&fixture.app, "recovery_need_changed")
        .into_iter()
        .filter(|row| row["event"]["change"] == "notice_shown")
        .collect::<Vec<_>>();
    assert_eq!(shown.len(), 1, "a notice is shown once, not per seam");
    assert_eq!(shown[0]["event"]["obligation_ref"], loss_ref);
    assert_eq!(shown[0]["event"]["cause"], "queue_loss");

    assert!(
        fixture
            .client
            .dismiss_history_notice(&notices[0].notice_id)
            .unwrap()
    );
    let dismissed = recorded_v5_rows(&fixture.app, "recovery_need_changed")
        .into_iter()
        .filter(|row| row["event"]["change"] == "notice_dismissed")
        .collect::<Vec<_>>();
    assert_eq!(dismissed.len(), 1);
    assert_eq!(dismissed[0]["event"]["obligation_ref"], loss_ref);
    assert_eq!(
        fixture
            .storage
            .recovery_obligation_status(id)
            .unwrap()
            .unwrap()
            .state,
        storage_sqlite::RecoveryObligationState::Retired
    );

    // New loss reopens the retired obligation.
    fixture
        .storage
        .record_account_delivery_loss_bounded("alice", 42, 1, unix_now_seconds(), None)
        .unwrap();
    drop(authorize(&mut fixture.client));
    let resumed = recorded_v5_rows(&fixture.app, "recovery_need_changed")
        .into_iter()
        .filter(|row| row["event"]["change"] == "resumed")
        .collect::<Vec<_>>();
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0]["event"]["obligation_ref"], loss_ref);
    assert_eq!(resumed[0]["event"]["charged"], 1);
}

#[tokio::test]
async fn a_parked_obligation_that_completes_records_closed() {
    let mut fixture = fixture().await;
    fixture
        .storage
        .record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), None)
        .unwrap();
    fixture
        .client
        .synchronize_recovery_loss(&fixture.storage)
        .unwrap();
    let id = queue_loss_id(&fixture.storage);
    crate::client::history_notices::park_recovery_for_test(&fixture.storage, id);
    fixture.client.take_history_notice_changes();
    // Stand-in for an explicit deep repair's qualified coverage: storage
    // satisfies the parked obligation. The notice seam then sees it leave.
    assert!(crate::client::history_notices::settle_recovery_for_test(
        &fixture.storage,
        id,
        true
    ));
    fixture.client.take_history_notice_changes();
    let changes = recorded_v5_rows(&fixture.app, "recovery_need_changed")
        .into_iter()
        .filter(|row| row["event"]["cause"] == "queue_loss")
        .map(|row| row["event"]["change"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(changes, ["recorded", "notice_shown", "closed"]);
}

#[tokio::test]
async fn new_loss_during_a_pass_supersedes_it() {
    let mut fixture = fixture().await;
    fixture
        .storage
        .record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), None)
        .unwrap();
    let grant = authorize(&mut fixture.client).expect("loss selects a grant");
    fixture.client.test_comparison_results = Some(quiet_routes());
    // New loss while the pass runs moves the obligation to a newer revision.
    fixture
        .storage
        .record_account_delivery_loss_bounded("alice", 41, 9, unix_now_seconds(), None)
        .unwrap();
    fixture
        .client
        .run_recovery_grant_for_test(grant)
        .await
        .unwrap();
    // The job's stability check imports the newer loss before admission, so
    // the grant no longer owns its debt: nothing is admitted or settled.
    let finished = recorded_v5_rows(&fixture.app, "recovery_attempt_finished");
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0]["event"]["outcome"], "superseded");
    assert!(
        recorded_v5_rows(&fixture.app, "recovery_obligation_reassessed").is_empty(),
        "a pass that settled nothing records no verdicts"
    );
    let loss_ref = recorded_v5_rows(&fixture.app, "recovery_need_changed")
        .into_iter()
        .find(|row| row["event"]["cause"] == "queue_loss")
        .unwrap()["event"]["obligation_ref"]
        .clone();
    let joined = recorded_v5_rows(&fixture.app, "recovery_need_changed")
        .into_iter()
        .filter(|row| row["event"]["change"] == "joined")
        .collect::<Vec<_>>();
    assert_eq!(
        joined.len(),
        1,
        "the stability check's import is itself recorded"
    );
    assert_eq!(joined[0]["event"]["charged"], 6);
    assert_eq!(joined[0]["event"]["obligation_ref"], loss_ref);
}

#[test]
fn cursor_rows_record_settled_advances_and_only_large_live_promotions() {
    crate::tests::run_composed_app_runtime_test("recovery-audit-cursor", || async {
        let mut fixture = crate::tests::LiveCursorFixture::open_audited().await;
        let cursor_before = fixture.cursor_before;
        // A live promotion within the rebuild lookback writes no row.
        crate::tests::inject_epoch_gap_probe(
            &fixture.app,
            fixture.probe(cursor_before + 60, "near"),
        )
        .await;
        fixture.wait_for_queue_depth(1).await;
        fixture.ingest_next_live_delivery().await;
        assert_eq!(fixture.persisted(), Some(cursor_before + 60));
        assert!(recorded_v5_rows(&fixture.app, "transport_cursor_advanced").is_empty());

        // One past the lookback does.
        crate::tests::inject_epoch_gap_probe(
            &fixture.app,
            fixture.probe(cursor_before + 4_000, "far"),
        )
        .await;
        fixture.wait_for_queue_depth(1).await;
        fixture.ingest_next_live_delivery().await;
        assert_eq!(fixture.persisted(), Some(cursor_before + 4_000));
        let rows = recorded_v5_rows(&fixture.app, "transport_cursor_advanced");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["event"]["trigger"], "live_promotion");
        assert_eq!(rows[0]["event"]["cursor_before_secs"], cursor_before + 60);
        assert_eq!(rows[0]["event"]["cursor_after_secs"], cursor_before + 4_000);
        assert_eq!(rows[0]["event"]["lookback_secs"], 120);

        // A delivery only that promotion exposed is spilled, and counted.
        let exposed = fixture
            .delivery(fixture.probe(cursor_before + 1_000, "exposed"))
            .await;
        fixture
            .app
            .relay_plane
            .route_account_delivery_for_test(exposed);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while fixture.client.adapter.delivery_loss_blocks_cursor() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the spill write becomes durable");

        // A drain checkpoint records its advance with that count.
        fixture.client.state.last_transport_timestamp = Some(cursor_before + 5_000);
        fixture
            .client
            .checkpoint_sync_prefix(&mut crate::SyncSummary::default(), false, 0)
            .await
            .unwrap_or_else(|_| panic!("the checkpoint saves"));
        let rows = recorded_v5_rows(&fixture.app, "transport_cursor_advanced");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["event"]["trigger"], "drain_checkpoint");
        assert_eq!(
            rows[1]["event"]["cursor_before_secs"],
            cursor_before + 4_000
        );
        assert_eq!(rows[1]["event"]["cursor_after_secs"], cursor_before + 5_000);
        assert_eq!(rows[1]["event"]["spilled_below_floor"], 1);
        assert_eq!(rows[1]["event"]["spilled_queue_full"], 0);
        assert_eq!(rows[1]["event"]["queue_dropped"], 0);
        assert!(rows.iter().all(|row| row["group_ref"].is_null()));
    });
}

/// Explicit full-history repair whose comparison certifies the whole retained
/// window closes its request (`BelowRetentionWindow`). The window certificate
/// is progress, not quiet, and the close is its own verdict, never coverage.
#[tokio::test]
async fn explicit_repair_below_the_window_records_a_searched_pass_and_its_close() {
    let mut fixture = fixture().await;
    fixture.client.test_comparison_results = Some(quiet_routes());
    let failure = fixture.client.repair_full_history().await.unwrap_err();
    assert_eq!(
        failure.source.full_history_repair_incomplete(),
        Some((
            crate::FullHistoryRepairIncompleteReason::BelowRetentionWindow,
            false
        ))
    );

    let requested = recorded_v5_rows(&fixture.app, "recovery_need_changed")
        .into_iter()
        .find(|row| row["event"]["cause"] == "explicit_history")
        .expect("the request is recorded");
    assert_eq!(requested["event"]["change"], "recorded");
    assert_eq!(requested["event"]["bound"], "unbounded");
    let explicit_ref = requested["event"]["obligation_ref"].clone();

    let started = recorded_v5_rows(&fixture.app, "recovery_attempt_started");
    let pass = started
        .iter()
        .find(|row| row["event"]["seam"] == "explicit_catch_up")
        .expect("the repair's pass started");
    let finished = recorded_v5_rows(&fixture.app, "recovery_attempt_finished")
        .into_iter()
        .find(|row| row["event"]["attempt_serial"] == pass["event"]["attempt_serial"])
        .expect("the repair's pass finished");
    assert_eq!(
        finished["event"]["outcome"], "progressed",
        "a certified window was searched, which is progress"
    );

    let reassessed = recorded_v5_rows(&fixture.app, "recovery_obligation_reassessed");
    let explicit = of_obligation(&reassessed, &explicit_ref);
    assert_eq!(explicit.len(), 1);
    assert_eq!(explicit[0]["event"]["verdict"], "closed_below_window");
    assert_eq!(explicit[0]["event"]["next_attempt"], "not_needed");
    assert_eq!(explicit[0]["event"]["progress"], "window_certified");
    assert_eq!(
        explicit[0]["event"]["scopes_certified"], 0,
        "an unbounded goal is never covered"
    );
    // Settlement closed it, so the caller's own close found nothing to record.
    assert!(
        recorded_v5_rows(&fixture.app, "recovery_need_changed")
            .iter()
            .all(|row| row["event"]["change"] != "closed_below_window")
    );
}
