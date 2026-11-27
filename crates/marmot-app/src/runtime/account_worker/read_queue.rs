//! How long host work waits on the account worker, and how long the worker's
//! units take (mdk#3273 PR 0, step 3 PR 0).
//!
//! Every host read the read-path plan classifies (R1–R9) carries a
//! [`ReadReply`] to the worker instead of a bare oneshot sender. Its wait, from
//! just before channel admission until the worker takes it up, is recorded in
//! its class's `read_queue_r<n>` series. A read enqueued while the worker is
//! inside one of the plan's long units records the same wait in that unit's
//! `read_queue_behind_<unit>` series too.
//!
//! A host mutation enqueued while the worker is inside a long unit carries the
//! same wait in its [`QueuedCommand`], recorded in `mutation_queue_behind_<unit>`.
//! Each unit the worker runs records its duration in `worker_unit_<kind>`, and
//! once more in `worker_unit_<kind>_over_budget` when it outlasts the engine's
//! budget for its kind. Recording only observes: nothing here changes when or
//! how the worker serves a command.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use marmot_observability::{Observation, Outcome as TelemetryOutcome, PerformanceRecorder};
use tokio::sync::{mpsc, oneshot};

use super::AccountWorkerCommand;
use crate::RuntimePerformanceOperation as RuntimeOp;
use crate::client::read_state::ReadStateReader;
#[cfg(test)]
use crate::client::read_state::read_state_channel;

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

    const fn mutation_operation(self) -> RuntimeOp {
        match self {
            Self::StartupSync => RuntimeOp::MutationQueueBehindStartupSync,
            Self::CatchUp => RuntimeOp::MutationQueueBehindCatchUp,
            Self::Convergence => RuntimeOp::MutationQueueBehindConvergence,
            Self::WelcomeFanout => RuntimeOp::MutationQueueBehindWelcomeFanout,
            Self::Repair => RuntimeOp::MutationQueueBehindRepair,
            Self::Send => RuntimeOp::MutationQueueBehindSend,
            Self::InviteOrCreate => RuntimeOp::MutationQueueBehindInviteOrCreate,
            Self::Maintenance => RuntimeOp::MutationQueueBehindMaintenance,
        }
    }

    const fn kind(self) -> UnitKind {
        match self {
            Self::StartupSync => UnitKind::StartupSync,
            Self::CatchUp => UnitKind::CatchUp,
            Self::Convergence => UnitKind::Convergence,
            Self::WelcomeFanout => UnitKind::WelcomeFanout,
            Self::Repair => UnitKind::Repair,
            Self::Send => UnitKind::Send,
            Self::InviteOrCreate => UnitKind::InviteOrCreate,
            Self::Maintenance => UnitKind::Maintenance,
        }
    }
}

tokio::task_local! {
    /// The recorder of the account worker whose task this is.
    static ACCOUNT_WORKER: PerformanceRecorder;
}

/// Run `worker` as an account worker's task, whose waits
/// [`observe_on_account_worker`] observes.
pub(crate) async fn run_as_account_worker<F: std::future::Future>(
    telemetry: PerformanceRecorder,
    worker: F,
) -> F::Output {
    ACCOUNT_WORKER.scope(telemetry, worker).await
}

/// A span of `operation` for a wait the account worker's own task starts,
/// inside whichever unit it is running; none for a wait any other task
/// starts, a lane's or a host call's. Tokio does not carry the scope into
/// spawned tasks.
pub(crate) fn observe_on_account_worker(operation: RuntimeOp) -> Option<Observation> {
    ACCOUNT_WORKER
        .try_with(|telemetry| telemetry.observe(operation))
        .ok()
}

/// The engine's cooperative budgets for one unit of work
/// (`cgka_engine::message_processor::FOREGROUND_DEFERRED_PEEL_BUDGET_MS` and
/// `BACKGROUND_CONVERGENCE_BUDGET_MS`), which the over-budget counts judge
/// against. marmot-app reaches the engine only through the session, so the
/// values are restated here and a test keeps them equal.
const FOREGROUND_UNIT_BUDGET: Duration = Duration::from_millis(250);
const BACKGROUND_UNIT_BUDGET: Duration = Duration::from_millis(500);

/// Every kind of worker unit with a duration series: the gauge's long units,
/// and the short ones it does not show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnitKind {
    StartupSync,
    CatchUp,
    Convergence,
    WelcomeFanout,
    Repair,
    Send,
    InviteOrCreate,
    Maintenance,
    /// One delivery batch the worker receives and ingests: a received
    /// delivery, or a turn of native admission that has a ready frame.
    Delivery,
    /// One turn of the account's recovery runner, served on the worker.
    RunnerTurn,
}

impl UnitKind {
    /// The kind's duration series and its over-budget count.
    const fn operations(self) -> (RuntimeOp, RuntimeOp) {
        match self {
            Self::StartupSync => (
                RuntimeOp::WorkerUnitStartupSync,
                RuntimeOp::WorkerUnitStartupSyncOverBudget,
            ),
            Self::CatchUp => (
                RuntimeOp::WorkerUnitCatchUp,
                RuntimeOp::WorkerUnitCatchUpOverBudget,
            ),
            Self::Convergence => (
                RuntimeOp::WorkerUnitConvergence,
                RuntimeOp::WorkerUnitConvergenceOverBudget,
            ),
            Self::WelcomeFanout => (
                RuntimeOp::WorkerUnitWelcomeFanout,
                RuntimeOp::WorkerUnitWelcomeFanoutOverBudget,
            ),
            Self::Repair => (
                RuntimeOp::WorkerUnitRepair,
                RuntimeOp::WorkerUnitRepairOverBudget,
            ),
            Self::Send => (
                RuntimeOp::WorkerUnitSend,
                RuntimeOp::WorkerUnitSendOverBudget,
            ),
            Self::InviteOrCreate => (
                RuntimeOp::WorkerUnitInviteOrCreate,
                RuntimeOp::WorkerUnitInviteOrCreateOverBudget,
            ),
            Self::Maintenance => (
                RuntimeOp::WorkerUnitMaintenance,
                RuntimeOp::WorkerUnitMaintenanceOverBudget,
            ),
            Self::Delivery => (
                RuntimeOp::WorkerUnitDelivery,
                RuntimeOp::WorkerUnitDeliveryOverBudget,
            ),
            Self::RunnerTurn => (
                RuntimeOp::WorkerUnitRunnerTurn,
                RuntimeOp::WorkerUnitRunnerTurnOverBudget,
            ),
        }
    }

    /// A send, an invite and a create run for a waiting host caller, so they
    /// get the foreground budget; everything else is background work.
    const fn budget(self) -> Duration {
        match self {
            Self::Send | Self::InviteOrCreate => FOREGROUND_UNIT_BUDGET,
            _ => BACKGROUND_UNIT_BUDGET,
        }
    }
}

/// One unit's span: how long the worker stays in it. It ends when dropped,
/// and a unit that outlasted its kind's budget is counted over budget too.
pub(crate) struct UnitTiming {
    telemetry: PerformanceRecorder,
    kind: UnitKind,
    observation: Option<Observation>,
    started: Instant,
}

impl UnitTiming {
    fn start(telemetry: &PerformanceRecorder, kind: UnitKind) -> Self {
        Self {
            telemetry: telemetry.clone(),
            kind,
            observation: Some(telemetry.observe(kind.operations().0)),
            started: Instant::now(),
        }
    }
}

impl UnitTiming {
    /// End the unit's span after `elapsed` in it. A span ends once.
    fn end(&mut self, elapsed: Duration) {
        let Some(observation) = self.observation.take() else {
            return;
        };
        observation.finish(TelemetryOutcome::Success);
        if elapsed > self.kind.budget() {
            self.telemetry.record_runtime(
                self.kind.operations().1,
                elapsed,
                TelemetryOutcome::Success,
            );
        }
    }
}

impl Drop for UnitTiming {
    fn drop(&mut self) {
        self.end(self.started.elapsed());
    }
}

/// Which long unit one account worker is inside, if any. The worker sets it;
/// a host read or mutation samples it once, when it is enqueued. One relaxed
/// atomic per unit and per command, so the worker's hot paths pay nothing per
/// delivery. A gauge built with a recorder also times each unit.
#[derive(Debug, Default)]
pub(crate) struct WorkerUnitGauge {
    unit: AtomicU8,
    telemetry: Option<PerformanceRecorder>,
}

impl WorkerUnitGauge {
    /// A gauge that times the units its worker enters into `telemetry`.
    pub(crate) fn recording(telemetry: PerformanceRecorder) -> Self {
        Self {
            unit: AtomicU8::default(),
            telemetry: Some(telemetry),
        }
    }

    /// Be inside `unit` until the guard drops, which restores the unit it
    /// interrupted and ends the unit's span.
    pub(crate) fn enter(&self, unit: WorkerUnit) -> WorkerUnitGuard<'_> {
        let previous = self.unit.swap(unit as u8, Ordering::Relaxed);
        WorkerUnitGuard {
            gauge: self,
            previous,
            _timing: self.time(unit.kind()),
        }
    }

    /// Time one short unit the gauge does not show, until the timing drops.
    pub(crate) fn time(&self, kind: UnitKind) -> Option<UnitTiming> {
        self.telemetry
            .as_ref()
            .map(|telemetry| UnitTiming::start(telemetry, kind))
    }

    fn current(&self) -> Option<WorkerUnit> {
        let unit = usize::from(self.unit.load(Ordering::Relaxed));
        WorkerUnit::ALL.get(unit.checked_sub(1)?).copied()
    }

    /// The wait of a host mutation enqueued now: none for a read, which
    /// carries its own, or for a catch-up, which `catch_up_requested` and
    /// `catch_up_coalesced` already time, or while no long unit runs.
    fn mutation_wait(&self, command: &AccountWorkerCommand) -> QueueWait {
        let Some(telemetry) = &self.telemetry else {
            return QueueWait(None);
        };
        if command.is_host_read() || matches!(command, AccountWorkerCommand::CatchUp { .. }) {
            return QueueWait(None);
        }
        QueueWait(
            self.current()
                .map(|unit| telemetry.observe(unit.mutation_operation())),
        )
    }
}

pub(crate) struct WorkerUnitGuard<'a> {
    gauge: &'a WorkerUnitGauge,
    previous: u8,
    _timing: Option<UnitTiming>,
}

impl Drop for WorkerUnitGuard<'_> {
    fn drop(&mut self) {
        self.gauge.unit.store(self.previous, Ordering::Relaxed);
    }
}

/// A command on its way to the worker, with the wait of a host mutation
/// enqueued while the worker was inside a long unit. The wait ends when the
/// worker takes the command up, whatever it answers; a command a unit keeps
/// for later keeps its wait. Dropping one untaken (worker shutdown, a
/// reconnect rejection) records the wait as cancelled.
pub(crate) struct QueuedCommand {
    command: AccountWorkerCommand,
    wait: QueueWait,
    seq: u64,
}

/// The wait half of a [`QueuedCommand`], apart from its command while the
/// worker decides whether to serve it or keep it.
pub(crate) struct QueueWait(Option<Observation>);

impl QueueWait {
    /// The worker takes the command up: its wait ends here.
    pub(crate) fn take_up(self) {
        if let Some(wait) = self.0 {
            wait.finish(TelemetryOutcome::Success);
        }
    }
}

impl QueuedCommand {
    /// A command whose wait nothing observes: the worker's own sends.
    pub(crate) fn unobserved(command: AccountWorkerCommand) -> Self {
        Self {
            command,
            wait: QueueWait(None),
            seq: 0,
        }
    }

    pub(crate) fn command(&self) -> &AccountWorkerCommand {
        &self.command
    }

    pub(crate) fn into_parts(self) -> (AccountWorkerCommand, QueueWait) {
        (self.command, self.wait)
    }

    pub(crate) fn from_parts(command: AccountWorkerCommand, wait: QueueWait) -> Self {
        Self {
            command,
            wait,
            seq: 0,
        }
    }

    /// The worker takes the command up to run it: its wait ends here, before
    /// it runs.
    pub(crate) fn take_up(self) -> AccountWorkerCommand {
        self.wait.take_up();
        self.command
    }

    /// Let `serve` answer the command where it waits. A command `serve` hands
    /// back stays queued with its wait; one it answers is taken up.
    pub(crate) fn serve_or_keep(
        self,
        serve: impl FnOnce(AccountWorkerCommand) -> Option<AccountWorkerCommand>,
    ) -> Option<Self> {
        let Self { command, wait, seq } = self;
        match serve(command) {
            Some(command) => Some(Self { command, wait, seq }),
            None => {
                wait.take_up();
                None
            }
        }
    }
}

/// The host's split command receivers for an account worker: group-scoped
/// commands (`host_group`) and account-wide commands (`host_account`).
/// Splitting the two lets the worker pause account-wide admissions at
/// [`super::sign_in_reads::PARKED_LIMIT`] without head-of-line blocking
/// group-scoped commands (mdk#3801).
pub(crate) struct HostCommandReceivers {
    group: mpsc::Receiver<QueuedCommand>,
    account: mpsc::Receiver<QueuedCommand>,
}

/// What an account worker receives: the host's commands (split into
/// group-scoped and account-wide channels with sequence-ordered FIFO merge
/// when both are admitted), and the commands its own timers send (its push
/// and subscription retries) on a channel of their own. Its own come first,
/// and only the host's can be held back, so a worker that takes no more host
/// commands still runs its own retries (mdk#3466, mdk#3801).
pub(crate) struct WorkerInbox {
    host_group: mpsc::Receiver<QueuedCommand>,
    host_account: mpsc::Receiver<QueuedCommand>,
    peek_group: Option<QueuedCommand>,
    peek_account: Option<QueuedCommand>,
    host_group_closed: bool,
    host_account_closed: bool,
    own: mpsc::Receiver<QueuedCommand>,
}

impl WorkerInbox {
    /// The inbox over a real worker's split host channels, and the worker's
    /// own sender.
    pub(crate) fn new_host(host: HostCommandReceivers) -> (Self, WorkerCommands) {
        let (sender, own) = mpsc::channel(8);
        (
            Self {
                host_group: host.group,
                host_account: host.account,
                peek_group: None,
                peek_account: None,
                host_group_closed: false,
                host_account_closed: false,
                own,
            },
            WorkerCommands::unobserved(sender),
        )
    }

    /// The inbox over a single host channel (used by unit tests), and the
    /// worker's own sender.
    #[cfg(test)]
    pub(crate) fn new(host: mpsc::Receiver<QueuedCommand>) -> (Self, WorkerCommands) {
        let (sender, own) = mpsc::channel(8);
        let (_closed_account_tx, host_account) = mpsc::channel(1);
        (
            Self {
                host_group: host,
                host_account,
                peek_group: None,
                peek_account: None,
                host_group_closed: false,
                host_account_closed: true,
                own,
            },
            WorkerCommands::unobserved(sender),
        )
    }

    fn poll_admitted_peeks(&mut self, admit_group: bool, admit_account: bool) {
        if admit_group && self.peek_group.is_none() && !self.host_group_closed {
            match self.host_group.try_recv() {
                Ok(command) => self.peek_group = Some(command),
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => self.host_group_closed = true,
            }
        }
        if admit_account && self.peek_account.is_none() && !self.host_account_closed {
            match self.host_account.try_recv() {
                Ok(command) => self.peek_account = Some(command),
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => self.host_account_closed = true,
            }
        }
    }

    fn take_ready_peek(&mut self, admit_group: bool, admit_account: bool) -> Option<QueuedCommand> {
        match (
            admit_group && self.peek_group.is_some(),
            admit_account && self.peek_account.is_some(),
        ) {
            (true, true) => {
                let group_seq = self.peek_group.as_ref().expect("checked").seq;
                let account_seq = self.peek_account.as_ref().expect("checked").seq;
                if group_seq <= account_seq {
                    self.peek_group.take()
                } else {
                    self.peek_account.take()
                }
            }
            (true, false) => self.peek_group.take(),
            (false, true) => self.peek_account.take(),
            (false, false) => None,
        }
    }

    /// The next command, the worker's own first. `None` once the host's
    /// channels have closed and hold nothing.
    pub(crate) async fn recv(&mut self) -> Option<QueuedCommand> {
        self.recv_admitting(true, true).await
    }

    /// The next command; group-scoped host commands only when `admit_group`,
    /// account-wide host commands only when `admit_account`. Pending while
    /// both host channels are held back and the worker sends itself nothing.
    pub(crate) async fn recv_admitting(
        &mut self,
        admit_group: bool,
        admit_account: bool,
    ) -> Option<QueuedCommand> {
        loop {
            if let Ok(command) = self.own.try_recv() {
                return Some(command);
            }
            self.poll_admitted_peeks(admit_group, admit_account);
            if let Some(command) = self.take_ready_peek(admit_group, admit_account) {
                return Some(command);
            }
            let wait_group = admit_group && !self.host_group_closed;
            let wait_account = admit_account && !self.host_account_closed;
            if (admit_group || admit_account) && !wait_group && !wait_account {
                // Every admitted host channel is closed and drained.
                return None;
            }
            tokio::select! {
                biased;
                Some(command) = self.own.recv() => return Some(command),
                command = self.host_group.recv(), if wait_group => {
                    match command {
                        Some(command) => self.peek_group = Some(command),
                        None => self.host_group_closed = true,
                    }
                }
                command = self.host_account.recv(), if wait_account => {
                    match command {
                        Some(command) => self.peek_account = Some(command),
                        None => self.host_account_closed = true,
                    }
                }
                // Held back, with the worker's own channel closed (a test's
                // inbox): nothing can come.
                else => std::future::pending().await,
            }
        }
    }

    pub(crate) fn try_recv(&mut self) -> Result<QueuedCommand, mpsc::error::TryRecvError> {
        self.try_recv_admitting(true, true)
    }

    pub(crate) fn try_recv_admitting(
        &mut self,
        admit_group: bool,
        admit_account: bool,
    ) -> Result<QueuedCommand, mpsc::error::TryRecvError> {
        if let Ok(command) = self.own.try_recv() {
            return Ok(command);
        }
        if !admit_group && !admit_account {
            return Err(mpsc::error::TryRecvError::Empty);
        }
        self.poll_admitted_peeks(admit_group, admit_account);
        if let Some(command) = self.take_ready_peek(admit_group, admit_account) {
            return Ok(command);
        }
        let open_group = admit_group && !self.host_group_closed;
        let open_account = admit_account && !self.host_account_closed;
        if !open_group && !open_account {
            Err(mpsc::error::TryRecvError::Disconnected)
        } else {
            Err(mpsc::error::TryRecvError::Empty)
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.own.len()
            + usize::from(self.peek_group.is_some())
            + self.host_group.len()
            + usize::from(self.peek_account.is_some())
            + self.host_account.len()
    }

    /// Whether no command the worker would take now is waiting: its own, and
    /// each host channel it currently admits.
    pub(crate) fn is_empty_admitting(&self, admit_group: bool, admit_account: bool) -> bool {
        self.own.is_empty()
            && (!admit_group || (self.peek_group.is_none() && self.host_group.is_empty()))
            && (!admit_account || (self.peek_account.is_none() && self.host_account.is_empty()))
    }
}

/// A test's receiver as an inbox whose worker sends itself nothing.
#[cfg(test)]
impl From<mpsc::Receiver<QueuedCommand>> for WorkerInbox {
    fn from(host: mpsc::Receiver<QueuedCommand>) -> Self {
        Self::new(host).0
    }
}

/// An account worker's command sender. A host mutation sent through it while
/// the worker is inside a long unit carries its wait to the worker.
#[derive(Clone)]
pub(crate) struct WorkerCommands {
    group: mpsc::Sender<QueuedCommand>,
    account: mpsc::Sender<QueuedCommand>,
    next_seq: Arc<std::sync::atomic::AtomicU64>,
    gauge: Option<Arc<WorkerUnitGauge>>,
}

impl std::fmt::Debug for WorkerCommands {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerCommands").finish_non_exhaustive()
    }
}

impl WorkerCommands {
    /// Split host channels (`buffer` slots each for group-scoped and
    /// account-wide commands), whose mutations sample `gauge` when enqueued.
    pub(crate) fn host_channel(
        buffer: usize,
        gauge: Arc<WorkerUnitGauge>,
    ) -> (Self, HostCommandReceivers) {
        let (group_tx, group_rx) = mpsc::channel(buffer);
        let (account_tx, account_rx) = mpsc::channel(buffer);
        (
            Self {
                group: group_tx,
                account: account_tx,
                next_seq: Arc::new(std::sync::atomic::AtomicU64::new(1)),
                gauge: Some(gauge),
            },
            HostCommandReceivers {
                group: group_rx,
                account: account_rx,
            },
        )
    }

    /// A single-channel observed sender, used by unit tests.
    #[cfg(test)]
    pub(crate) fn observed(
        sender: mpsc::Sender<QueuedCommand>,
        gauge: Arc<WorkerUnitGauge>,
    ) -> Self {
        Self {
            group: sender.clone(),
            account: sender,
            next_seq: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            gauge: Some(gauge),
        }
    }

    /// The worker's own sender, for the commands it sends itself.
    pub(crate) fn unobserved(sender: mpsc::Sender<QueuedCommand>) -> Self {
        Self {
            group: sender.clone(),
            account: sender,
            next_seq: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            gauge: None,
        }
    }

    fn sender_for(&self, command: &AccountWorkerCommand) -> &mpsc::Sender<QueuedCommand> {
        if command.waits_behind_sign_in_check() {
            &self.account
        } else {
            &self.group
        }
    }

    fn mutation_wait(&self, command: &AccountWorkerCommand) -> QueueWait {
        match &self.gauge {
            Some(gauge) => gauge.mutation_wait(command),
            None => QueueWait(None),
        }
    }

    fn next_sequence(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) async fn send(
        &self,
        command: AccountWorkerCommand,
    ) -> Result<(), mpsc::error::SendError<AccountWorkerCommand>> {
        let wait = self.mutation_wait(&command);
        let sender = self.sender_for(&command);
        match sender.reserve().await {
            Ok(permit) => {
                let seq = self.next_sequence();
                permit.send(QueuedCommand { command, wait, seq });
                Ok(())
            }
            Err(_) => Err(mpsc::error::SendError(command)),
        }
    }

    /// Hands an unadmitted command back, as `mpsc::Sender::try_send` does.
    #[expect(
        clippy::result_large_err,
        reason = "keeps the shape of tokio's try_send, which returns the unsent command"
    )]
    pub(crate) fn try_send(
        &self,
        command: AccountWorkerCommand,
    ) -> Result<(), mpsc::error::TrySendError<AccountWorkerCommand>> {
        let sender = self.sender_for(&command);
        match sender.try_reserve() {
            Ok(permit) => {
                let wait = self.mutation_wait(&command);
                let seq = self.next_sequence();
                permit.send(QueuedCommand { command, wait, seq });
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(())) => {
                Err(mpsc::error::TrySendError::Full(command))
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                Err(mpsc::error::TrySendError::Closed(command))
            }
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.group.is_closed() || self.account.is_closed()
    }

    pub(crate) async fn closed(&self) {
        tokio::select! {
            _ = self.group.closed() => {}
            _ = self.account.closed() => {}
        }
    }
}

#[cfg(test)]
impl WorkerCommands {
    pub(crate) fn same_channel(&self, other: &Self) -> bool {
        self.group.same_channel(&other.group) && self.account.same_channel(&other.account)
    }

    pub(crate) fn max_capacity(&self) -> usize {
        if self.group.same_channel(&self.account) {
            self.group.max_capacity()
        } else {
            self.group.max_capacity() + self.account.max_capacity()
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        if self.group.same_channel(&self.account) {
            self.group.capacity()
        } else {
            self.group.capacity() + self.account.capacity()
        }
    }

    pub(crate) fn account_capacity(&self) -> usize {
        self.account.capacity()
    }

    pub(crate) async fn reserve_many(
        &self,
        n: usize,
    ) -> Result<mpsc::PermitIterator<'_, QueuedCommand>, mpsc::error::SendError<()>> {
        self.group.reserve_many(n).await
    }
}

/// A worker's command channel for a test that drives the worker's own
/// receiving code: an unobserved sender, and the raw receiver.
#[cfg(test)]
pub(crate) fn test_worker_queue(buffer: usize) -> (WorkerCommands, mpsc::Receiver<QueuedCommand>) {
    let (sender, receiver) = mpsc::channel(buffer);
    (WorkerCommands::unobserved(sender), receiver)
}

/// A fake worker's command channel: an unobserved sender, and a receiver
/// that yields each command taken up as it arrives.
#[cfg(test)]
pub(crate) fn test_worker_channel(buffer: usize) -> (WorkerCommands, TestWorkerReceiver) {
    let (sender, receiver) = mpsc::channel(buffer);
    (
        WorkerCommands::unobserved(sender),
        TestWorkerReceiver(receiver),
    )
}

#[cfg(test)]
pub(crate) struct TestWorkerReceiver(mpsc::Receiver<QueuedCommand>);

#[cfg(test)]
impl TestWorkerReceiver {
    pub(crate) async fn recv(&mut self) -> Option<AccountWorkerCommand> {
        self.0.recv().await.map(QueuedCommand::take_up)
    }

    pub(crate) fn try_recv(&mut self) -> Result<AccountWorkerCommand, mpsc::error::TryRecvError> {
        self.0.try_recv().map(QueuedCommand::take_up)
    }
}

/// An account worker's command lane, with the gauge of what that worker is doing.
#[derive(Clone, Debug)]
pub(crate) struct WorkerLane {
    pub(crate) commands: WorkerCommands,
    unit: Arc<WorkerUnitGauge>,
    /// The worker's published read state, A, which the account reads answer
    /// from without a queue wait (mdk#3273).
    pub(crate) read_state: ReadStateReader,
}

impl WorkerLane {
    pub(crate) fn new(
        commands: WorkerCommands,
        unit: Arc<WorkerUnitGauge>,
        read_state: ReadStateReader,
    ) -> Self {
        Self {
            commands,
            unit,
            read_state,
        }
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

/// A test lane for a fake worker: its gauge never leaves idle, and it never
/// publishes A, so every read is sent to it.
#[cfg(test)]
impl From<WorkerCommands> for WorkerLane {
    fn from(commands: WorkerCommands) -> Self {
        Self::new(commands, Arc::default(), read_state_channel().1)
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
    /// The worker answers through its `reply`, which publishes A first
    /// (mdk#3273).
    pub(crate) fn send(mut self, value: T) -> Result<(), T> {
        self.dispatched();
        self.reply.send(value)
    }

    /// Answer the read where the worker took it up without dispatching it:
    /// the wait ends before `answer` runs.
    #[cfg(test)]
    fn send_with(mut self, answer: impl FnOnce() -> T) -> Result<(), T> {
        self.dispatched();
        self.reply.send(answer())
    }

    /// Answer the read with a published version of A, which the answer
    /// carries: the version just published, or while a long unit holds the
    /// client, the latest one from before it (mdk#3273 PR 4).
    pub(crate) fn send_from_published(mut self, answer: impl FnOnce() -> T) -> Result<(), T> {
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
    /// The answer itself. The worker sends it through its `reply`, which
    /// publishes A first (mdk#3273).
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

            /// Whether this is a host read, which carries its own wait.
            fn is_host_read(&self) -> bool {
                matches!(self, $(Self::$variant { .. })|+)
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
    GroupCoMembers,
    MemberIdsPage,
    GroupRoster,
    HydrateGroups,
    GroupCommitDelivery,
    GroupChangesNotDelivered,
    GroupPendingCommit,
    KeyPackageMaintenanceStatus,
    DurablyOwnedKeyPackages,
    PeriodicMaintenancePolicy,
    MaintenanceStatus,
    QuarantinedGroups,
    PendingWelcomeDeliveries,
    InviteDeliveries,
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
        let (commands, _receiver) = test_worker_channel(1);
        let lane = WorkerLane::from(commands);
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

    /// A group read's hydration request ends its wait as the worker takes it
    /// up, before it hydrates anything, as the hydration phase ends it
    /// (mdk#3273 PR 4).
    #[test]
    fn a_hydration_request_ends_its_wait_when_taken_up() {
        let telemetry = PerformanceRecorder::default();
        let (commands, _receiver) = test_worker_channel(1);
        let lane = WorkerLane::from(commands);
        let in_flight = || {
            telemetry
                .snapshot()
                .runtime_operations
                .into_iter()
                .find(|sample| sample.operation == RuntimeOp::ReadQueueR3)
                .unwrap()
                .in_flight
        };
        let (respond, _response) = lane.read_reply(&telemetry, ReadClass::R3);
        let mut command = AccountWorkerCommand::HydrateGroups {
            group_ids: Vec::new(),
            respond,
        };
        assert_eq!(in_flight(), 1);
        command.read_dispatched();
        assert_eq!(in_flight(), 0, "taking the request up ends its wait");
    }

    /// A read the worker cannot serve now ends as not ready, unless its caller
    /// has already gone: then it ends as cancelled, in both series.
    #[test]
    fn a_not_ready_answer_to_a_gone_caller_is_cancelled() {
        let telemetry = PerformanceRecorder::default();
        let (commands, _receiver) = test_worker_channel(1);
        let lane = WorkerLane::from(commands);
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

    fn sample(
        telemetry: &PerformanceRecorder,
        operation: RuntimeOp,
    ) -> marmot_observability::RuntimePerformanceSnapshot {
        telemetry
            .snapshot()
            .runtime_operations
            .into_iter()
            .find(|sample| sample.operation == operation)
            .unwrap()
    }

    /// The over-budget counts judge a unit against the engine's own budgets
    /// for one unit of work.
    #[test]
    fn unit_budgets_are_the_engines() {
        use cgka_engine::message_processor::{
            BACKGROUND_CONVERGENCE_BUDGET_MS, FOREGROUND_DEFERRED_PEEL_BUDGET_MS,
        };
        assert_eq!(
            FOREGROUND_UNIT_BUDGET,
            Duration::from_millis(FOREGROUND_DEFERRED_PEEL_BUDGET_MS)
        );
        assert_eq!(
            BACKGROUND_UNIT_BUDGET,
            Duration::from_millis(BACKGROUND_CONVERGENCE_BUDGET_MS)
        );
    }

    /// Every unit counts once in its kind's series when it ends, and once
    /// more over budget only past its kind's budget: a send at 250 ms is in
    /// budget and at 251 ms over, a catch-up still in budget at 500 ms.
    #[test]
    fn a_unit_past_its_budget_is_counted_over_budget() {
        let telemetry = PerformanceRecorder::default();
        let gauge = WorkerUnitGauge::recording(telemetry.clone());
        for (kind, elapsed, over) in [
            (UnitKind::Send, 250, false),
            (UnitKind::Send, 251, true),
            (UnitKind::InviteOrCreate, 251, true),
            (UnitKind::CatchUp, 500, false),
            (UnitKind::Delivery, 501, true),
        ] {
            let (series, over_budget) = kind.operations();
            let before = (sample(&telemetry, series), sample(&telemetry, over_budget));
            let mut timing = gauge.time(kind).expect("a recording gauge times units");
            assert_eq!(sample(&telemetry, series).in_flight, before.0.in_flight + 1);
            timing.end(Duration::from_millis(elapsed));
            drop(timing);
            assert_eq!(
                sample(&telemetry, series).successes - before.0.successes,
                1,
                "{kind:?} at {elapsed} ms ends once"
            );
            assert_eq!(
                sample(&telemetry, over_budget).successes - before.1.successes,
                u64::from(over),
                "{kind:?} at {elapsed} ms"
            );
        }
        assert!(
            WorkerUnitGauge::default().time(UnitKind::Send).is_none(),
            "a gauge without a recorder times nothing"
        );
    }

    /// Entering a long unit times it until the guard drops.
    #[test]
    fn an_entered_unit_is_timed_until_its_guard_drops() {
        let telemetry = PerformanceRecorder::default();
        let gauge = WorkerUnitGauge::recording(telemetry.clone());
        let unit = gauge.enter(WorkerUnit::Repair);
        assert_eq!(sample(&telemetry, RuntimeOp::WorkerUnitRepair).in_flight, 1);
        drop(unit);
        let ended = sample(&telemetry, RuntimeOp::WorkerUnitRepair);
        assert_eq!((ended.in_flight, ended.successes), (0, 1));
    }

    /// A host mutation sent while the worker is inside a long unit waits in
    /// that unit's mutation series until the worker takes it up, through a
    /// unit that keeps it for later. A read carries its own wait, a
    /// catch-up is timed by its own series, and nothing waits while no unit
    /// runs or on the worker's own sender.
    #[tokio::test]
    async fn a_mutation_sent_inside_a_unit_waits_until_taken_up() {
        let telemetry = PerformanceRecorder::default();
        let gauge = Arc::new(WorkerUnitGauge::recording(telemetry.clone()));
        let (sender, mut receiver) = mpsc::channel(8);
        let commands = WorkerCommands::observed(sender.clone(), gauge.clone());
        let in_flight = || sample(&telemetry, RuntimeOp::MutationQueueBehindSend).in_flight;
        let mutation = || {
            let (respond, _) = oneshot::channel();
            AccountWorkerCommand::Drain { respond }
        };

        commands.send(mutation()).await.unwrap();
        assert_eq!(in_flight(), 0, "no unit runs");
        receiver.recv().await.unwrap().take_up();

        let unit = gauge.enter(WorkerUnit::Send);
        commands.send(mutation()).await.unwrap();
        let (respond, _) = ReadReply::unobserved();
        commands
            .send(AccountWorkerCommand::StartedFresh { respond })
            .await
            .unwrap();
        let (respond, _) = oneshot::channel();
        commands
            .send(AccountWorkerCommand::CatchUp { respond })
            .await
            .unwrap();
        WorkerCommands::unobserved(sender)
            .send(mutation())
            .await
            .unwrap();
        assert_eq!(in_flight(), 1, "only the host mutation waits");
        drop(unit);
        assert_eq!(in_flight(), 1, "the wait lasts past the unit");

        let kept = receiver
            .recv()
            .await
            .unwrap()
            .serve_or_keep(Some)
            .expect("the unit keeps the command");
        assert_eq!(in_flight(), 1, "a kept command keeps its wait");
        kept.take_up();
        let ended = sample(&telemetry, RuntimeOp::MutationQueueBehindSend);
        assert_eq!((ended.in_flight, ended.successes), (0, 1));
        while let Ok(queued) = receiver.try_recv() {
            queued.take_up();
        }
        let after = sample(&telemetry, RuntimeOp::MutationQueueBehindSend);
        assert_eq!((after.started, after.in_flight), (1, 0));
    }
}
