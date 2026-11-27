//! The account worker's sign-in slot read (mdk#3466 PR 2): a check's read
//! runs beside the writer, and its continuation on it. The client's tests
//! (`tests/sign_ins.rs`) own the snapshot rule, the look and what the read
//! writes. These own what only the worker decides: the read the scheduled
//! check and a host check share, the host check's place and its bound,
//! maintenance paused under a read, and the client replacement and worker
//! exits a read can meet.
//!
//! Sign-in checks run only with device groups on, which these tests turn
//! on.

use marmot_observability::PerformanceRecorder;

use super::sign_in_reads::{Settled, SignInReads};
use super::writer_hold_tests::{
    HostCall, SETTLE, all_answered, deliver, foreign_group_event, none_answered, sample, send,
    until,
};
use super::*;

/// Alice with device groups on and one group. Her published KeyPackage
/// gives her a slot, which a check reads. Her runtime's first maintenance
/// tick starts the scheduled check, whose read waits on the relays until
/// `release` is notified.
pub(super) struct HeldRead {
    pub(super) app: MarmotApp,
    pub(super) account: marmot_account::AccountSummary,
    pub(super) relay: Arc<ScriptedPushRelayClient>,
    pub(super) runtime: crate::MarmotAppRuntime,
    pub(super) telemetry: PerformanceRecorder,
    pub(super) group: GroupId,
    pub(super) release: Arc<tokio::sync::Notify>,
}

fn device_groups_app(dir: &tempfile::TempDir, relay: Arc<ScriptedPushRelayClient>) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::white_noise()
            .with_allow_loopback_relay_endpoints(true)
            .with_device_groups(true),
    )
    .with_test_relay_client(relay)
}

pub(super) async fn held_scheduled_read(dir: &tempfile::TempDir) -> HeldRead {
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = device_groups_app(dir, relay.clone());
    crate::tests::remember_test_member_inbox(&app, &account.account_id_hex, "wss://relay.example");
    let group = {
        let mut client = app.client("alice").await.unwrap();
        client.publish_key_package().await.unwrap();
        client
            .create_group("other", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members")
    };
    let (entered, release) = relay.hold_next_slot_read();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let telemetry = runtime.shared_services().observer.performance().clone();
    runtime.reconcile_accounts().await.unwrap();
    timeout(SETTLE, entered.notified())
        .await
        .expect("the first maintenance tick checks for sign-ins");
    HeldRead {
        app,
        account,
        relay,
        runtime,
        telemetry,
        group,
        release,
    }
}

type HostCheck = tokio::task::JoinHandle<Result<Vec<crate::UnrecognizedSignIn>, AppError>>;

/// The host's sign-in check, on its own task. The worker takes it before
/// the send after it answers: it takes commands in order, and a send names
/// a group, so a waiting check doesn't keep it back.
async fn host_check(runtime: &crate::MarmotAppRuntime, group: &GroupId) -> HostCheck {
    let check = {
        let runtime = runtime.clone();
        tokio::spawn(async move { runtime.check_sign_ins("alice").await })
    };
    all_answered(vec![send(runtime, group)]).await;
    check
}

/// An account read, which names no group.
fn account_read(runtime: &crate::MarmotAppRuntime) -> HostCall {
    let runtime = runtime.clone();
    tokio::spawn(async move { runtime.unrecognized_sign_ins("alice").await.map(drop) })
}

pub(super) fn baseline_taken(app: &MarmotApp) -> bool {
    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .sign_in_baseline()
        .unwrap()
        .is_some()
}

/// S1 and S5: a host check during the scheduled read joins it and keeps its
/// place. While it waits, an account command waits behind it, a send to a
/// group answers and a delivery is ingested. One read answers the check,
/// and then the account command runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_check_waits_on_the_scheduled_read_in_its_place() {
    let dir = tempfile::tempdir().unwrap();
    let HeldRead {
        app,
        account,
        runtime,
        telemetry,
        group,
        release,
        ..
    } = held_scheduled_read(&dir).await;
    let check = host_check(&runtime, &group).await;
    let waiting = vec![account_read(&runtime)];
    let receives = sample(&telemetry, RuntimeOp::WorkerUnitDelivery);
    deliver(&app, &account, &group, &foreign_group_event(&app, &group));
    all_answered(vec![send(&runtime, &group)]).await;
    until(
        "the worker ingests a delivery while the check waits",
        || sample(&telemetry, RuntimeOp::WorkerUnitDelivery).started > receives.started,
    )
    .await;
    // The account read was sent before that send answered, so the worker
    // has taken it, and keeps it behind the check.
    none_answered(&waiting, "a waiting host check");
    assert!(!check.is_finished());

    release.notify_one();
    let listed = timeout(SETTLE, check).await.unwrap().unwrap().unwrap();
    assert!(listed.is_empty());
    all_answered(waiting).await;
    assert_eq!(
        sample(&telemetry, RuntimeOp::SignInSlotRead).started,
        1,
        "the scheduled check and the host check share one read"
    );
    assert!(baseline_taken(&app));
    runtime.shutdown_and_close().await.unwrap();
}

/// S6: commands parked behind a waiting host check are bounded. At the
/// bound the worker takes no more host commands, so callers wait to be
/// admitted and none is dropped, while its own subscription retry still
/// runs. Once the check is answered, every parked and waiting command is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parked_commands_are_bounded_and_the_worker_still_retries() {
    let dir = tempfile::tempdir().unwrap();
    let HeldRead {
        relay,
        runtime,
        group,
        release,
        ..
    } = held_scheduled_read(&dir).await;
    // A group whose subscription the relays refuse arms the worker's own
    // retry, which keeps sending until a relay accepts it.
    relay.refuse_group_subscribes(true);
    let unsubscribed = runtime
        .create_group("alice", "unsubscribed", &[], None)
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let check = host_check(&runtime, &group).await;
    let lane = runtime.accounts().worker_lane("alice").await.unwrap();
    let parked = (0..sign_in_reads::PARKED_LIMIT + lane.commands.max_capacity() + 4)
        .map(|_| account_read(&runtime))
        .collect::<Vec<_>>();
    until("the host channel fills at the bound", || {
        lane.commands.account_capacity() == 0
    })
    .await;

    relay.refuse_group_subscribes(false);
    until("the worker's own retry runs at the bound", || {
        relay
            .accepted_subscriptions()
            .iter()
            .any(|subscription| subscription.carries_group(&unsubscribed))
    })
    .await;
    // The worker has turned since the channel filled, and took no host
    // command from it.
    assert_eq!(lane.commands.account_capacity(), 0);
    none_answered(&parked, "a waiting host check at its bound");
    assert!(!check.is_finished());

    release.notify_one();
    timeout(SETTLE, check).await.unwrap().unwrap().unwrap();
    all_answered(parked).await;
    runtime.shutdown_and_close().await.unwrap();
}

/// S4: a scheduled read that returns while maintenance is paused gives
/// today's outcome. A scheduled check doesn't run while maintenance is
/// paused, so the continuation records nothing and leaves the schedule,
/// and the next pass after maintenance resumes reads again. Run on the
/// worker's reads directly, so the continuation's turn is known.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scheduled_read_returning_while_maintenance_is_paused_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = device_groups_app(&dir, relay);
    crate::tests::remember_test_member_inbox(&app, &account.account_id_hex, "wss://relay.example");
    let mut client = app.client("alice").await.unwrap();
    client.publish_key_package().await.unwrap();
    client.detach_sign_in_reads();
    let mut reads = SignInReads::default();

    client.drive_sign_ins().await;
    assert!(reads.adopt(&mut client).is_none());
    assert!(reads.is_running(), "a due check starts a read");
    client.pause_maintenance();
    let read = reads.next().await;
    assert!(matches!(
        reads.settle(&mut client, read).await,
        Settled::Quiet
    ));
    assert!(!reads.is_running());
    assert!(!baseline_taken(&app));

    client.resume_maintenance();
    client.drive_sign_ins().await;
    assert!(reads.adopt(&mut client).is_none());
    assert!(reads.is_running(), "the check is still due");
    let read = reads.next().await;
    assert!(matches!(
        reads.settle(&mut client, read).await,
        Settled::Quiet
    ));
    assert!(baseline_taken(&app));
}

/// L1: a client replacement drops the held read, and the host check waiting
/// on it keeps its place. The next client reads again and answers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_replacement_reads_again_for_a_waiting_host_check() {
    let dir = tempfile::tempdir().unwrap();
    let HeldRead {
        runtime,
        telemetry,
        group,
        release,
        ..
    } = held_scheduled_read(&dir).await;
    let check = host_check(&runtime, &group).await;
    let mut events = runtime.subscribe();
    runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_consumer_exit_for_test();
    timeout(SETTLE, async {
        loop {
            match events.recv().await {
                Ok(MarmotAppEvent::AccountError(error))
                    if error.message.starts_with("runtime receive failed") =>
                {
                    break;
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    panic!("runtime events closed before the failed receive")
                }
            }
        }
    })
    .await
    .expect("the consumer exit fails the worker's receive");
    // The next client reads again. The relay plane coalesces its slot
    // fetch with the one the dropped read began, which the relays still
    // hold; once they answer, the next client's read answers the check.
    until("the next client reads again for the waiting check", || {
        sample(&telemetry, RuntimeOp::SignInSlotRead).started == 2
    })
    .await;
    assert!(!check.is_finished());
    release.notify_one();
    let listed = timeout(SETTLE, check)
        .await
        .expect("the next client's read answers the waiting check")
        .unwrap()
        .unwrap();
    assert!(listed.is_empty());
    runtime.shutdown_and_close().await.unwrap();
}

/// L2, shutdown: a held read doesn't keep the worker from returning, and the
/// host check waiting on it gets the error a queued command gets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_ends_a_held_read_and_its_waiting_host_check() {
    let dir = tempfile::tempdir().unwrap();
    let HeldRead { runtime, group, .. } = held_scheduled_read(&dir).await;
    let check = host_check(&runtime, &group).await;
    timeout(SETTLE, runtime.shutdown_and_close())
        .await
        .expect("shutdown ends the held read")
        .unwrap();
    assert!(timeout(SETTLE, check).await.unwrap().unwrap().is_err());
}

/// L2, sign-out: a held read doesn't hold the sign-out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_out_ends_a_held_read() {
    let dir = tempfile::tempdir().unwrap();
    let HeldRead { runtime, .. } = held_scheduled_read(&dir).await;
    timeout(
        SETTLE,
        runtime.sign_out(
            "alice",
            crate::SignOutOptions {
                delete_key_packages: false,
            },
        ),
    )
    .await
    .expect("sign-out ends the held read")
    .unwrap();
    runtime.shutdown_and_close().await.unwrap();
}

/// L2, unlink: a held read doesn't hold the device's removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlinking_ends_a_held_read() {
    let dir = tempfile::tempdir().unwrap();
    let HeldRead { runtime, .. } = held_scheduled_read(&dir).await;
    timeout(SETTLE, runtime.accounts().unlink_device_for_test("alice"))
        .await
        .expect("unlinking ends the held read")
        .unwrap();
    runtime.shutdown_and_close().await.unwrap();
}

/// L2, a worker aborted at shutdown's timeout: its reads drop with it, and a
/// dropped read ends its task, as the read the worker once awaited inline
/// ended with it. Run on the worker's reads directly, since the abort drops
/// them without `end`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_read_ends_its_task() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = device_groups_app(&dir, relay.clone());
    crate::tests::remember_test_member_inbox(&app, &account.account_id_hex, "wss://relay.example");
    let mut client = app.client("alice").await.unwrap();
    let telemetry = PerformanceRecorder::default();
    client.runtime_telemetry = Some(telemetry.clone());
    client.publish_key_package().await.unwrap();
    client.detach_sign_in_reads();
    let (entered, _release) = relay.hold_next_slot_read();
    let mut reads = SignInReads::default();

    client.drive_sign_ins().await;
    assert!(reads.adopt(&mut client).is_none());
    timeout(SETTLE, entered.notified())
        .await
        .expect("the read reaches the relays");
    assert_eq!(sample(&telemetry, RuntimeOp::SignInSlotRead).in_flight, 1);
    drop(reads);
    until("the dropped read's task ends", || {
        sample(&telemetry, RuntimeOp::SignInSlotRead).in_flight == 0
    })
    .await;
}

/// A nudge during a read brings the check after it forward, as it did while
/// the read held the worker: the read may have started before what nudged
/// it. A maintenance pass during the read joins it and leaves the nudge for
/// the first pass after the continuation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nudge_during_a_read_brings_the_next_check_forward() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = device_groups_app(&dir, relay.clone());
    crate::tests::remember_test_member_inbox(&app, &account.account_id_hex, "wss://relay.example");
    let mut client = app.client("alice").await.unwrap();
    client.publish_key_package().await.unwrap();
    client.detach_sign_in_reads();
    let (entered, release) = relay.hold_next_slot_read();
    let mut reads = SignInReads::default();

    client.drive_sign_ins().await;
    assert!(reads.adopt(&mut client).is_none());
    timeout(SETTLE, entered.notified())
        .await
        .expect("the read reaches the relays");
    app.sign_in_nudges.nudge(&account.account_id_hex);
    client.drive_sign_ins().await;
    assert!(reads.adopt(&mut client).is_none());
    release.notify_one();
    let read = reads.next().await;
    assert!(matches!(
        reads.settle(&mut client, read).await,
        Settled::Quiet
    ));
    assert!(baseline_taken(&app));

    // A pass a minute on from that check runs the next one.
    client
        .sign_in_schedule
        .rewind(std::time::Duration::from_secs(61));
    client.drive_sign_ins().await;
    assert!(reads.adopt(&mut client).is_none());
    assert!(
        reads.is_running(),
        "the nudge brought the next check forward"
    );
}

/// While a host sign-in check holds `PARKED_LIMIT` account-wide commands and
/// fills the account-wide channel, group-scoped commands must still proceed
/// promptly without head-of-line blocking (mdk#3801).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_commands_proceed_when_parked_limit_is_reached_during_sign_in_check() {
    let dir = tempfile::tempdir().unwrap();
    let HeldRead {
        runtime,
        group,
        release,
        ..
    } = held_scheduled_read(&dir).await;
    let check = host_check(&runtime, &group).await;
    let lane = runtime.accounts().worker_lane("alice").await.unwrap();
    let parked = (0..sign_in_reads::PARKED_LIMIT + lane.commands.max_capacity() + 4)
        .map(|_| account_read(&runtime))
        .collect::<Vec<_>>();
    // Wait until the worker has parked PARKED_LIMIT account commands and the
    // account channel has filled behind them.
    until("the account channel fills at PARKED_LIMIT", || {
        lane.commands.account_capacity() == 0
    })
    .await;

    // A group-scoped command must still succeed promptly even while account
    // admissions are paused at PARKED_LIMIT.
    timeout(Duration::from_secs(5), send(&runtime, &group))
        .await
        .expect("group send must not starve when PARKED_LIMIT is reached")
        .unwrap()
        .unwrap();
    none_answered(&parked, "parked account commands stay behind CheckSignIns");
    assert!(!check.is_finished());

    release.notify_one();
    timeout(SETTLE, check).await.unwrap().unwrap().unwrap();
    all_answered(parked).await;
    runtime.shutdown_and_close().await.unwrap();
}
