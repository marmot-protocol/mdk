//! Which host reads the account worker answers while it is inside a long
//! unit, and which wait for the unit to end (mdk#3273 PR 0). These tests pin
//! today's behaviour: a change of the read-path plan that moves a read changes
//! its row here on purpose.
//!
//! Every read the plan classifies goes down the account's real lane, in one
//! FIFO, while a barrier or a held relay publish keeps the worker inside the
//! unit. The unit's `read_queue_behind_<unit>` series must count each of them.

use futures::future::{BoxFuture, join_all};
use marmot_observability::{PerformanceRecorder, RuntimePerformanceSnapshot};

use super::*;

const SETTLE: Duration = Duration::from_secs(10);

/// What a unit that serves reads from a snapshot (startup sync, an explicit
/// catch-up, a convergence pass) does with a read today.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InSnapshotUnit {
    /// Answered from the snapshot the unit took when it started.
    Snapshot,
    /// Answered `NotReady` at once; the conversation window retries it.
    NotReady,
    /// Waits in the worker's FIFO until the unit ends.
    Waits,
}

struct Probe {
    read: &'static str,
    in_snapshot_unit: InSnapshotUnit,
    response: Box<dyn Pending>,
}

/// A read's response, of whatever type.
trait Pending: Send {
    /// Whether the worker has answered the read yet.
    fn answered(&mut self) -> bool;
    /// Resolves once the worker answers the read.
    fn answer(self: Box<Self>) -> BoxFuture<'static, ()>;
}

struct PendingResponse<T> {
    response: oneshot::Receiver<T>,
    answered: bool,
}

impl<T: Send + 'static> Pending for PendingResponse<T> {
    fn answered(&mut self) -> bool {
        if !self.answered {
            match self.response.try_recv() {
                Ok(_) => self.answered = true,
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    panic!("the worker dropped a host read unanswered")
                }
            }
        }
        self.answered
    }

    fn answer(self: Box<Self>) -> BoxFuture<'static, ()> {
        let PendingResponse { response, answered } = *self;
        Box::pin(async move {
            if !answered {
                response
                    .await
                    .expect("the worker dropped a host read unanswered");
            }
        })
    }
}

/// One command per read the plan classifies, each replying through `lane`.
/// The probes all record under one class: the class a host wrapper picks is
/// not what these tests pin, the unit series is.
fn host_reads(
    lane: &WorkerLane,
    telemetry: &PerformanceRecorder,
    group: &GroupId,
) -> Vec<(Probe, AccountWorkerCommand)> {
    macro_rules! reads {
        ($($in_unit:ident $variant:ident { $($field:ident: $value:expr),* $(,)? })+) => {
            vec![$({
                let (respond, response) = lane.read_reply(telemetry, ReadClass::R1);
                (
                    Probe {
                        read: stringify!($variant),
                        in_snapshot_unit: InSnapshotUnit::$in_unit,
                        response: Box::new(PendingResponse { response, answered: false }),
                    },
                    AccountWorkerCommand::$variant { $($field: $value,)* respond },
                )
            }),+]
        };
    }
    let group_id = || group.clone();
    reads! {
        Snapshot Members { group_id: group_id() }
        Snapshot MemberIdsPage { group_ids: vec![group_id()] }
        Snapshot GroupMlsState { group_id: group_id() }
        Snapshot GroupRoster { group_id: group_id() }
        Snapshot QuarantinedGroups {}
        NotReady CaptureConversation {
            queued: None,
            group_id: group_id(),
            query: Default::default(),
            store_epoch: Vec::new(),
            observer: None,
        }
        Waits PreparedGroupImageStatus { upload_id: "probe".into() }
        Waits PreparedGroupImages {}
        Waits StartedFresh {}
        Waits ChatHistoryImports {}
        Waits HistoryImportProvenance { group_id: group_id(), event_id: "00".repeat(32) }
        Waits GroupCommitDelivery { group_id: group_id() }
        Waits KeyPackageMaintenanceStatus {}
        Waits DurablyOwnedKeyPackages {}
        Waits PeriodicMaintenancePolicy {}
        Waits MaintenanceStatus { group_id: group_id() }
        Waits PendingWelcomeDeliveries {}
        Waits AccountDevicesActivation { group_id: group_id() }
        Waits GroupAppComponent { group_id: group_id(), component_id: 0 }
        Waits GroupPushDebugInfo { group_id: group_id() }
        Waits ExporterSecret { group_id: group_id(), label: "probe".into(), length: 32 }
        Waits SafeExportSecret { group_id: group_id(), component_id: 0 }
        Waits LinkedDevices {}
        Waits UnrecognizedSignIns {}
        Waits RemovedDeviceLeftoverChats {}
        Waits CompromiseWarning {}
        Waits KeyPackageRefreshOverdue {}
        Waits BackupSettings {}
        Waits ChatsClosedToLinkedDevices {}
        Waits BackupHistoryAvailability { group_id: group_id() }
        Waits BackupRestoreStatus {}
        Waits WatchBackupRestore {}
        Waits BuildMediaImetaTag {
            group_id: group_id(),
            reference: MediaAttachmentReference {
                locators: Vec::new(),
                ciphertext_sha256: "00".repeat(32),
                plaintext_sha256: "00".repeat(32),
                nonce_hex: "00".repeat(12),
                file_name: "probe.png".into(),
                media_type: "image/png".into(),
                version: "probe".into(),
                source_epoch: 0,
                source_epoch_identity: None,
                dim: None,
                thumbhash: None,
            },
        }
        Waits HistoryNotices {}
        Waits GroupRecoveryStatus { group_id: group_id() }
        Waits AccountRecoveryStatus {}
    }
}

fn sample(telemetry: &PerformanceRecorder, operation: RuntimeOp) -> RuntimePerformanceSnapshot {
    telemetry
        .snapshot()
        .runtime_operations
        .into_iter()
        .find(|sample| sample.operation == operation)
        .unwrap()
}

/// The probes sent while one unit was held, and its series before them.
struct HeldUnit {
    behind: RuntimeOp,
    before: RuntimePerformanceSnapshot,
    probes: Vec<Probe>,
}

impl HeldUnit {
    /// Once the unit ends, the worker answers every read, and the unit's
    /// series has nothing left in flight.
    async fn all_answered(self, telemetry: &PerformanceRecorder) {
        let total = self.probes.len() as u64;
        timeout(
            SETTLE,
            join_all(self.probes.into_iter().map(|probe| probe.response.answer())),
        )
        .await
        .unwrap_or_else(|_| panic!("every read is answered once {:?} ends", self.behind));
        let after = sample(telemetry, self.behind);
        assert_eq!(after.completed - self.before.completed, total);
        assert_eq!(after.cancelled, self.before.cancelled);
        assert_eq!(after.in_flight, 0);
    }
}

/// Sends every probe down `lane` while the worker is held inside a unit
/// that serves reads from a snapshot, then a snapshot read whose answer
/// proves the worker took up each probe before it. Checks which reads the
/// unit answered and what its series counted.
async fn probe_held_snapshot_unit(
    lane: &WorkerLane,
    telemetry: &PerformanceRecorder,
    group: &GroupId,
    behind: RuntimeOp,
) -> HeldUnit {
    let before = sample(telemetry, behind);
    let mut probes = Vec::new();
    for (probe, command) in host_reads(lane, telemetry, group) {
        lane.commands.send(command).await.unwrap();
        probes.push(probe);
    }
    let (respond, fence) = ReadReply::unobserved();
    lane.commands
        .send(AccountWorkerCommand::QuarantinedGroups { respond })
        .await
        .unwrap();
    timeout(SETTLE, fence)
        .await
        .unwrap_or_else(|_| panic!("a held {behind:?} answers snapshot reads"))
        .unwrap()
        .unwrap();

    let answered = probes
        .iter_mut()
        .map(|probe| (probe.read, probe.response.answered()))
        .collect::<Vec<_>>();
    let expected = probes
        .iter()
        .map(|probe| (probe.read, probe.in_snapshot_unit != InSnapshotUnit::Waits))
        .collect::<Vec<_>>();
    assert_eq!(answered, expected, "the reads a held {behind:?} answers");

    let total = probes.len() as u64;
    let waiting = expected.iter().filter(|(_, answered)| !answered).count() as u64;
    let held = sample(telemetry, behind);
    assert_eq!(held.started - before.started, total);
    assert_eq!(held.completed - before.completed, total - waiting);
    assert_eq!(held.not_ready - before.not_ready, 1);
    assert_eq!(held.in_flight - before.in_flight, waiting);
    HeldUnit {
        behind,
        before,
        probes,
    }
}

/// Startup sync, an explicit catch-up and a send, each held in turn on one
/// account. Startup sync and the catch-up answer five reads from their
/// snapshot and the conversation capture with `NotReady`; every other read
/// waits for the unit to end. A send answers nothing: the worker takes no
/// command until its relays answer, so the lane fills and a ninth read cannot
/// even be admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_reads_wait_behind_held_worker_units() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let group = {
        let mut client = app.client("alice").await.unwrap();
        client.create_group("held reads", &[]).await.unwrap()
    };
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let telemetry = runtime.shared_services().observer.performance().clone();

    let startup = Arc::new(tokio::sync::Barrier::new(2));
    runtime
        .shared_services()
        .set_next_startup_sync_barrier(startup.clone());
    runtime.reconcile_accounts().await.unwrap();
    timeout(SETTLE, startup.wait())
        .await
        .expect("the worker reaches startup sync");
    let lane = runtime.accounts().worker_lane("alice").await.unwrap();
    let held = probe_held_snapshot_unit(
        &lane,
        &telemetry,
        &group,
        RuntimeOp::ReadQueueBehindStartupSync,
    )
    .await;
    startup.wait().await;
    held.all_answered(&telemetry).await;

    let catch_up = Arc::new(tokio::sync::Barrier::new(2));
    runtime
        .shared_services()
        .set_next_catch_up_barrier(&account.account_id_hex, catch_up.clone());
    let catching_up = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.catch_up_accounts().await }
    });
    timeout(SETTLE, catch_up.wait())
        .await
        .expect("the explicit catch-up reaches its hold");
    // A host read through its public wrapper records its class and the unit.
    let class_before = sample(&telemetry, RuntimeOp::ReadQueueR3);
    let unit_before = sample(&telemetry, RuntimeOp::ReadQueueBehindCatchUp);
    timeout(SETTLE, runtime.group_members("alice", &group))
        .await
        .expect("a held catch-up answers members from its snapshot")
        .unwrap();
    let class_after = sample(&telemetry, RuntimeOp::ReadQueueR3);
    let unit_after = sample(&telemetry, RuntimeOp::ReadQueueBehindCatchUp);
    assert_eq!(class_after.successes - class_before.successes, 1);
    assert_eq!(unit_after.successes - unit_before.successes, 1);
    let held =
        probe_held_snapshot_unit(&lane, &telemetry, &group, RuntimeOp::ReadQueueBehindCatchUp)
            .await;
    catch_up.wait().await;
    timeout(SETTLE, catching_up)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    held.all_answered(&telemetry).await;

    relay.block_next_publish();
    let sending = tokio::spawn({
        let runtime = runtime.clone();
        let group = group.clone();
        async move {
            runtime
                .send_message("alice", &group, b"held send".to_vec())
                .await
        }
    });
    timeout(SETTLE, relay.wait_for_blocked_publish())
        .await
        .expect("the send reaches its relays");
    assert_eq!(sample(&telemetry, RuntimeOp::SendExecution).in_flight, 1);
    let before = sample(&telemetry, RuntimeOp::ReadQueueBehindSend);
    let mut probes = Vec::new();
    let mut unadmitted = Vec::new();
    for (probe, command) in host_reads(&lane, &telemetry, &group) {
        probes.push(probe);
        match lane.commands.try_send(command) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(command)) => unadmitted.push(command),
            Err(mpsc::error::TrySendError::Closed(_)) => panic!("the worker stopped"),
        }
    }
    assert_eq!(
        probes.len() - unadmitted.len(),
        lane.commands.max_capacity(),
        "a send awaiting its relays takes no command, so only the lane's slots admit"
    );
    let answered = probes
        .iter_mut()
        .filter_map(|probe| probe.response.answered().then_some(probe.read))
        .collect::<Vec<_>>();
    assert!(answered.is_empty(), "a held send answered {answered:?}");
    let held = sample(&telemetry, RuntimeOp::ReadQueueBehindSend);
    assert_eq!(held.started - before.started, probes.len() as u64);
    assert_eq!(held.in_flight - before.in_flight, probes.len() as u64);
    // The rest wait for a slot, as a host read would.
    let admitting = tokio::spawn({
        let commands = lane.commands.clone();
        async move {
            for command in unadmitted {
                commands.send(command).await.unwrap();
            }
        }
    });
    relay.release_publish();
    timeout(SETTLE, sending)
        .await
        .expect("the released send finishes")
        .unwrap()
        .unwrap();
    timeout(SETTLE, admitting).await.unwrap().unwrap();
    HeldUnit {
        behind: RuntimeOp::ReadQueueBehindSend,
        before,
        probes,
    }
    .all_answered(&telemetry)
    .await;
    runtime.shutdown_and_close().await.unwrap();
}

/// A scheduled convergence pass answers the same reads from its snapshot as
/// startup sync and an explicit catch-up; every other read waits for the
/// pass to end.
// Pauses the clock, which needs the current-thread runtime.
#[tokio::test(flavor = "current_thread")]
#[cfg(feature = "test-policy-overrides")]
async fn host_reads_wait_behind_a_held_convergence_pass() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(100)
            .with_dev_scheduled_convergence_delay_ms(60_000),
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let telemetry = runtime.shared_services().observer.performance().clone();
    runtime.reconcile_accounts().await.unwrap();
    runtime.publish_key_package("bob").await.unwrap();
    let group = runtime
        .create_group(
            "alice",
            "held reads",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap();
    runtime.catch_up_accounts().await.unwrap();
    runtime
        .update_group_profile("alice", &group, Some("changed".into()), None)
        .await
        .unwrap();
    // Bob's inbound commit arms a durable pass.
    use cgka_traits::storage::ConvergencePassStorage;
    let storage = app.account_storage("bob").unwrap();
    timeout(Duration::from_secs(30), async {
        while storage.convergence_pass(&group).unwrap().is_none() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the inbound commit arms a convergence pass");
    // Only Bob's worker is held; Alice's publications are done.
    runtime
        .accounts()
        .workers
        .lock()
        .await
        .remove(&alice.account_id_hex)
        .unwrap()
        .shutdown()
        .await;
    let lane = runtime.accounts().worker_lane("bob").await.unwrap();
    let pass = Arc::new(tokio::sync::Barrier::new(2));
    runtime
        .shared_services()
        .set_next_scheduled_convergence_barrier(pass.clone());
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(120)).await;
    tokio::time::resume();
    timeout(Duration::from_secs(30), pass.wait())
        .await
        .expect("the due pass reaches its hold");
    let held = probe_held_snapshot_unit(
        &lane,
        &telemetry,
        &group,
        RuntimeOp::ReadQueueBehindConvergence,
    )
    .await;
    pass.wait().await;
    held.all_answered(&telemetry).await;
    runtime.shutdown_and_close().await.unwrap();
}
