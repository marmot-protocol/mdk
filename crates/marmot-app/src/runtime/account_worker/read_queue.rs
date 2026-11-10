//! How long host reads wait on the account worker (mdk#3273 PR 0).
//!
//! Every host read the read-path plan classifies (R1–R9) carries a
//! [`ReadReply`] to the worker instead of a bare oneshot sender. Its wait, from
//! just before channel admission until the worker takes it up, is recorded in
//! its class's `read_queue_r<n>` series. A read enqueued while the worker is
//! inside one of the plan's long units records the same wait in that unit's
//! `read_queue_behind_<unit>` series too. Recording only observes: nothing here
//! changes when or how the worker serves a read.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use marmot_observability::{Observation, Outcome as TelemetryOutcome, PerformanceRecorder};
use tokio::sync::{mpsc, oneshot};

use super::AccountWorkerCommand;
use crate::RuntimePerformanceOperation as RuntimeOp;

/// The read classes of the read-path plan (mdk#3273, "Which reads, and what
/// they need"), sorted by what a read needs from the writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadClass {
    /// Prepared group images: app rows plus the in-flight upload set.
    R1,
    /// Device-group history reads (mdk#2628).
    R2,
    /// Durable engine facts behind memory gates.
    R3,
    /// Facts that need a hydrated group.
    R4,
    /// Exporter secrets.
    R5,
    /// The device roster and its side effects (mdk#2628).
    R6,
    /// Backup-restore status, already a watch.
    R7,
    /// The media imeta tag, which syncs with the network first.
    R8,
    /// Recovery state.
    R9,
}

impl ReadClass {
    const fn operation(self) -> RuntimeOp {
        match self {
            Self::R1 => RuntimeOp::ReadQueueR1,
            Self::R2 => RuntimeOp::ReadQueueR2,
            Self::R3 => RuntimeOp::ReadQueueR3,
            Self::R4 => RuntimeOp::ReadQueueR4,
            Self::R5 => RuntimeOp::ReadQueueR5,
            Self::R6 => RuntimeOp::ReadQueueR6,
            Self::R7 => RuntimeOp::ReadQueueR7,
            Self::R8 => RuntimeOp::ReadQueueR8,
            Self::R9 => RuntimeOp::ReadQueueR9,
        }
    }
}

/// The long units of worker work the read-path plan names: the worker can be
/// inside one for seconds while host reads queue behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum WorkerUnit {
    StartupSync = 1,
    CatchUp,
    Convergence,
    WelcomeFanout,
    Repair,
    /// A message send awaiting its relays.
    Send,
    /// An invite or a create, KeyPackage resolution included, until its reply.
    InviteOrCreate,
    Maintenance,
}

impl WorkerUnit {
    /// In discriminant order, so `ALL[n - 1]` is the unit stored as `n`.
    const ALL: [Self; 8] = [
        Self::StartupSync,
        Self::CatchUp,
        Self::Convergence,
        Self::WelcomeFanout,
        Self::Repair,
        Self::Send,
        Self::InviteOrCreate,
        Self::Maintenance,
    ];

    const fn operation(self) -> RuntimeOp {
        match self {
            Self::StartupSync => RuntimeOp::ReadQueueBehindStartupSync,
            Self::CatchUp => RuntimeOp::ReadQueueBehindCatchUp,
            Self::Convergence => RuntimeOp::ReadQueueBehindConvergence,
            Self::WelcomeFanout => RuntimeOp::ReadQueueBehindWelcomeFanout,
            Self::Repair => RuntimeOp::ReadQueueBehindRepair,
            Self::Send => RuntimeOp::ReadQueueBehindSend,
            Self::InviteOrCreate => RuntimeOp::ReadQueueBehindInviteOrCreate,
            Self::Maintenance => RuntimeOp::ReadQueueBehindMaintenance,
        }
    }
}

/// Which long unit one account worker is inside, if any. The worker sets it;
/// a host read samples it once, when it is enqueued. One relaxed atomic per
/// unit and per read, so the worker's hot paths pay nothing per delivery.
#[derive(Debug, Default)]
pub(crate) struct WorkerUnitGauge(AtomicU8);

impl WorkerUnitGauge {
    /// Be inside `unit` until the guard drops, which restores the unit it
    /// interrupted: a Welcome fanout runs inside its create or invite.
    pub(crate) fn enter(&self, unit: WorkerUnit) -> WorkerUnitGuard<'_> {
        let previous = self.0.swap(unit as u8, Ordering::Relaxed);
        WorkerUnitGuard {
            gauge: self,
            previous,
        }
    }

    fn current(&self) -> Option<WorkerUnit> {
        let unit = usize::from(self.0.load(Ordering::Relaxed));
        WorkerUnit::ALL.get(unit.checked_sub(1)?).copied()
    }
}

pub(crate) struct WorkerUnitGuard<'a> {
    gauge: &'a WorkerUnitGauge,
    previous: u8,
}

impl Drop for WorkerUnitGuard<'_> {
    fn drop(&mut self) {
        self.gauge.0.store(self.previous, Ordering::Relaxed);
    }
}

/// An account worker's command lane, with the gauge of what that worker is doing.
#[derive(Clone, Debug)]
pub(crate) struct WorkerLane {
    pub(crate) commands: mpsc::Sender<AccountWorkerCommand>,
    unit: Arc<WorkerUnitGauge>,
}

impl WorkerLane {
    pub(crate) fn new(
        commands: mpsc::Sender<AccountWorkerCommand>,
        unit: Arc<WorkerUnitGauge>,
    ) -> Self {
        Self { commands, unit }
    }

    /// The reply half of one host read of `class` on this lane, whose wait
    /// starts now. Create it just before sending the read.
    pub(crate) fn read_reply<T>(
        &self,
        telemetry: &PerformanceRecorder,
        class: ReadClass,
    ) -> (ReadReply<T>, oneshot::Receiver<T>) {
        let (reply, response) = oneshot::channel();
        let wait = ReadWait {
            class: telemetry.observe(class.operation()),
            behind: self
                .unit
                .current()
                .map(|unit| telemetry.observe(unit.operation())),
        };
        (
            ReadReply {
                reply,
                wait: Some(wait),
            },
            response,
        )
    }
}

/// A test lane for a fake worker: its gauge never leaves idle.
#[cfg(test)]
impl From<mpsc::Sender<AccountWorkerCommand>> for WorkerLane {
    fn from(commands: mpsc::Sender<AccountWorkerCommand>) -> Self {
        Self::new(commands, Arc::default())
    }
}

/// The reply half of one host read, with the observations of its wait on the
/// worker. Dropping it unanswered (worker shutdown, a reconnect rejection)
/// records the wait as cancelled.
#[derive(Debug)]
pub(crate) struct ReadReply<T> {
    reply: oneshot::Sender<T>,
    wait: Option<ReadWait>,
}

#[derive(Debug)]
struct ReadWait {
    class: Observation,
    behind: Option<Observation>,
}

impl<T> ReadReply<T> {
    /// A reply that observes nothing, for tests that hand-build commands.
    #[cfg(test)]
    pub(crate) fn unobserved() -> (Self, oneshot::Receiver<T>) {
        let (reply, response) = oneshot::channel();
        (Self { reply, wait: None }, response)
    }

    /// The worker takes the read up: its wait ends here, as cancelled when
    /// the caller has already gone.
    pub(crate) fn dispatched(&mut self) {
        let outcome = if self.reply.is_closed() {
            TelemetryOutcome::Cancelled
        } else {
            TelemetryOutcome::Success
        };
        self.finish_wait(outcome);
    }

    fn finish_wait(&mut self, outcome: TelemetryOutcome) {
        if let Some(wait) = self.wait.take() {
            wait.class.finish(outcome);
            if let Some(behind) = wait.behind {
                behind.finish(outcome);
            }
        }
    }

    /// Answer the read, ending its wait if dispatch has not. An answer that
    /// takes work where the worker took the read up goes through
    /// [`Self::send_with`] instead, so that work is not counted as waiting.
    pub(crate) fn send(mut self, value: T) -> Result<(), T> {
        self.dispatched();
        self.reply.send(value)
    }

    /// Answer the read where the worker took it up without dispatching it,
    /// from a snapshot or a hydration: the wait ends before `answer` runs.
    pub(crate) fn send_with(mut self, answer: impl FnOnce() -> T) -> Result<(), T> {
        self.dispatched();
        self.reply.send(answer())
    }

    /// Answer without running the read, because the worker cannot serve it
    /// now: its wait ends as not ready, or cancelled if the caller has gone.
    pub(crate) fn send_not_ready(mut self, value: T) -> Result<(), T> {
        let outcome = if self.reply.is_closed() {
            TelemetryOutcome::Cancelled
        } else {
            TelemetryOutcome::NotReady
        };
        self.finish_wait(outcome);
        self.reply.send(value)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.reply.is_closed()
    }
}

/// A worker command's reply half: a bare oneshot sender, or a host read's
/// [`ReadReply`].
pub(crate) trait WorkerReply<T> {
    fn send_reply(self, value: T) -> Result<(), T>;
}

impl<T> WorkerReply<T> for oneshot::Sender<T> {
    fn send_reply(self, value: T) -> Result<(), T> {
        self.send(value)
    }
}

impl<T> WorkerReply<T> for ReadReply<T> {
    fn send_reply(self, value: T) -> Result<(), T> {
        self.send(value)
    }
}

/// Lists the commands whose reply is a [`ReadReply`], so the worker can end a
/// read's wait when it takes the read up and before the read runs. Each listed
/// variant must carry its reply as `respond: ReadReply<_>`; the arm does not
/// compile otherwise.
macro_rules! host_reads {
    ($($variant:ident),+ $(,)?) => {
        impl AccountWorkerCommand {
            /// End a host read's queue wait as the worker takes it up.
            pub(super) fn read_dispatched(&mut self) {
                match self {
                    $(Self::$variant { respond, .. } => respond.dispatched(),)+
                    _ => {}
                }
            }
        }
    };
}

host_reads!(
    PreparedGroupImageStatus,
    PreparedGroupImages,
    StartedFresh,
    ChatHistoryImports,
    HistoryImportProvenance,
    Members,
    MemberIdsPage,
    GroupRoster,
    GroupCommitDelivery,
    KeyPackageMaintenanceStatus,
    DurablyOwnedKeyPackages,
    PeriodicMaintenancePolicy,
    MaintenanceStatus,
    QuarantinedGroups,
    PendingWelcomeDeliveries,
    GroupMlsState,
    AccountDevicesActivation,
    GroupAppComponent,
    GroupPushDebugInfo,
    CaptureConversation,
    ExporterSecret,
    SafeExportSecret,
    LinkedDevices,
    UnrecognizedSignIns,
    RemovedDeviceLeftoverChats,
    CompromiseWarning,
    KeyPackageRefreshOverdue,
    BackupSettings,
    ChatsClosedToLinkedDevices,
    BackupHistoryAvailability,
    BackupRestoreStatus,
    WatchBackupRestore,
    BuildMediaImetaTag,
    HistoryNotices,
    GroupRecoveryStatus,
    AccountRecoveryStatus,
);

#[cfg(test)]
mod tests {
    use super::*;

    /// An answer computed where the worker takes a read up is the read's own
    /// work: its wait, and the unit's, end before the answer runs.
    #[test]
    fn send_with_ends_the_wait_before_the_answer_runs() {
        let telemetry = PerformanceRecorder::default();
        let (commands, _receiver) = mpsc::channel::<AccountWorkerCommand>(1);
        let lane = WorkerLane::new(commands, Arc::default());
        let _unit = lane.unit.enter(WorkerUnit::CatchUp);
        let in_flight = |operation| {
            telemetry
                .snapshot()
                .runtime_operations
                .into_iter()
                .find(|sample| sample.operation == operation)
                .unwrap()
                .in_flight
        };
        let waits = || {
            (
                in_flight(RuntimeOp::ReadQueueR3),
                in_flight(RuntimeOp::ReadQueueBehindCatchUp),
            )
        };
        let (respond, mut response) = lane.read_reply(&telemetry, ReadClass::R3);
        assert_eq!(waits(), (1, 1));
        respond.send_with(waits).unwrap();
        assert_eq!(response.try_recv().unwrap(), (0, 0));
    }

    /// A read the worker cannot serve now ends as not ready, unless its caller
    /// has already gone: then it ends as cancelled, in both series.
    #[test]
    fn a_not_ready_answer_to_a_gone_caller_is_cancelled() {
        let telemetry = PerformanceRecorder::default();
        let (commands, _receiver) = mpsc::channel::<AccountWorkerCommand>(1);
        let lane = WorkerLane::new(commands, Arc::default());
        let _unit = lane.unit.enter(WorkerUnit::StartupSync);
        let (respond, waiting) = lane.read_reply(&telemetry, ReadClass::R4);
        respond.send_not_ready(()).unwrap();
        drop(waiting);
        let (respond, gone) = lane.read_reply(&telemetry, ReadClass::R4);
        drop(gone);
        assert!(respond.send_not_ready(()).is_err());
        let snapshot = telemetry.snapshot().runtime_operations;
        for operation in [
            RuntimeOp::ReadQueueR4,
            RuntimeOp::ReadQueueBehindStartupSync,
        ] {
            let sample = snapshot
                .iter()
                .find(|sample| sample.operation == operation)
                .unwrap();
            assert_eq!(
                (sample.not_ready, sample.cancelled, sample.in_flight),
                (1, 1, 0),
                "{operation:?}"
            );
        }
    }
}
