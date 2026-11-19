//! An idle account with device groups on runs session maintenance only when
//! a device-group pass has work: at its own stored time, or 15 s after the
//! last run while it owes work with no time (mdk#3265). Before, device
//! groups kept the 15 s retry owed on every account, linked or not.

use super::*;
use crate::RuntimePerformanceOperation as RuntimeOp;

/// How long each test watches an idle account.
const IDLE_MINUTES: u64 = 10;

/// How many times `operation` has completed in `runtime`.
fn completed(runtime: &MarmotAppRuntime, operation: RuntimeOp) -> u64 {
    runtime
        .app_performance_snapshot()
        .runtime_operations
        .into_iter()
        .find(|snapshot| snapshot.operation == operation)
        .expect("every runtime operation is exported")
        .completed
}

/// Whether `operation` is running in `runtime` now.
fn in_flight(runtime: &MarmotAppRuntime, operation: RuntimeOp) -> bool {
    runtime
        .app_performance_snapshot()
        .runtime_operations
        .into_iter()
        .any(|snapshot| snapshot.operation == operation && snapshot.in_flight > 0)
}

/// Moves the worker's clock on by one 15 s tick and waits until the tick
/// ran and no maintenance run is in flight.
async fn idle_tick(runtime: &MarmotAppRuntime) {
    let ticks = completed(runtime, RuntimeOp::WorkerMaintenance);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(15)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(60), async {
        while completed(runtime, RuntimeOp::WorkerMaintenance) == ticks
            || in_flight(runtime, RuntimeOp::WorkerMaintenanceDue)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("an idle tick completes");
}

/// Starts `runtime`'s accounts, lets their startup maintenance settle, then
/// watches [`IDLE_MINUTES`] of idle ticks. Returns, for each maintenance
/// run in that window, how many seconds into it the run came.
async fn idle_maintenance_runs(runtime: &MarmotAppRuntime) -> Vec<u64> {
    runtime.reconcile_accounts().await.unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        while completed(runtime, RuntimeOp::WorkerMaintenanceDue) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the worker runs maintenance as it opens");
    // Startup work can owe a retry or two: settle until four ticks in a row
    // run no maintenance, or give up and let the window below show it.
    let mut quiet = 0;
    for _ in 0..12 {
        let before = completed(runtime, RuntimeOp::WorkerMaintenanceDue);
        idle_tick(runtime).await;
        quiet = if completed(runtime, RuntimeOp::WorkerMaintenanceDue) == before {
            quiet + 1
        } else {
            0
        };
        if quiet == 4 {
            break;
        }
    }
    let mut runs = Vec::new();
    for tick in 1..=IDLE_MINUTES * 4 {
        let before = completed(runtime, RuntimeOp::WorkerMaintenanceDue);
        idle_tick(runtime).await;
        let after = completed(runtime, RuntimeOp::WorkerMaintenanceDue);
        runs.extend(std::iter::repeat_n(tick * 15, (after - before) as usize));
    }
    runs
}

/// An account that is not linked, with device groups on, runs no
/// maintenance for ten idle minutes: it has no chat, so no component
/// recheck, and its sign-in check is hours away. Device groups kept its
/// 15 s retry owed, so it ran every 15 s.
#[tokio::test(flavor = "current_thread")]
async fn an_unlinked_account_runs_no_idle_maintenance() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = device_group_app_on(&dir, relay, MarmotDeployment::white_noise());
    assert!(app.device_groups_enabled());
    let runtime = MarmotAppRuntime::new(app);
    let runs = idle_maintenance_runs(&runtime).await;
    runtime.shutdown().await;
    assert_eq!(
        runs,
        Vec::<u64>::new(),
        "an idle unlinked account runs no maintenance for {IDLE_MINUTES} minutes"
    );
}

/// A linked account whose device group is settled runs no maintenance for
/// ten idle minutes but the device group's 10-minute component recheck: its
/// heartbeat went out at link time and is next due in an hour, and its
/// small-state broadcast in a day. Device groups kept its 15 s retry owed.
///
/// The devices link on a multi-threaded runtime, as their fixtures need;
/// the phone's runtime then starts on a single-threaded one whose clock the
/// test moves.
#[test]
fn a_settled_linked_account_runs_no_idle_maintenance() {
    let setup = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (dirs, relay) = setup.block_on(async {
        let (devices, _) = boxed(settled_linked_devices).await;
        let Devices {
            _dirs,
            relay,
            phone_app,
            laptop_app,
            phone,
            laptop,
            ..
        } = devices;
        drop((phone, laptop));
        phone_app.close_storage().unwrap();
        laptop_app.close_storage().unwrap();
        (_dirs, relay)
    });
    drop(setup);
    let idle = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let runs = idle.block_on(async {
        let phone_app = device_group_app_on(&dirs[0], relay, MarmotDeployment::white_noise());
        let runtime = MarmotAppRuntime::new(phone_app);
        let runs = idle_maintenance_runs(&runtime).await;
        runtime.shutdown().await;
        runs
    });
    assert!(
        runs.len() <= 1,
        "an idle settled linked account runs only its 10-minute component recheck \
         in {IDLE_MINUTES} minutes, not maintenance at {runs:?} s"
    );
}

/// A linked account whose device-group work comes due runs it then: its
/// next heartbeat, an hour after the last, goes out at that second, not at
/// the next 15 s retry. Real time: the worker reads due times as wall
/// seconds, which a paused clock never reaches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_linked_accounts_heartbeat_goes_out_when_it_is_due() {
    let (devices, group) = boxed(settled_linked_devices).await;
    let Devices {
        _dirs,
        phone_app,
        phone,
        laptop,
        ..
    } = devices;
    drop((phone, laptop));
    let runtime = MarmotAppRuntime::new(phone_app.clone());
    runtime.reconcile_accounts().await.unwrap();
    // Counted from the end of the worker's first maintenance run, just past
    // one 15 s retry step from either its start or its end: unless that run
    // took 9 s or more, the retry after it comes 9 s or more late.
    tokio::time::timeout(Duration::from_secs(60), async {
        while completed(&runtime, RuntimeOp::WorkerMaintenanceDue) == 0
            || in_flight(&runtime, RuntimeOp::WorkerMaintenanceDue)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the worker runs maintenance as it opens");
    let storage = phone_app.account_storage("alice").unwrap().app_storage();
    let due = crate::unix_now_seconds() + 16;
    storage
        .put_device_heartbeat_sent(Some(&storage_sqlite::DeviceHeartbeatSent {
            group_id_hex: hex::encode(group.as_slice()),
            sent_at: due - crate::client::device_heartbeats::HEARTBEAT_INTERVAL_SECS,
        }))
        .unwrap();
    // A command the worker serves re-reads when maintenance is next due.
    runtime.pause_maintenance("alice").await.unwrap();
    runtime.resume_maintenance("alice").await.unwrap();
    let sent = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(sent) = storage.device_heartbeat_sent().unwrap()
                && sent.sent_at >= due
            {
                break sent.sent_at;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    runtime.shutdown().await;
    let sent = sent.expect("the heartbeat goes out");
    assert!(
        sent <= due + 5,
        "the heartbeat due at {due} goes out then, not {} s later at a retry",
        sent - due
    );
}
