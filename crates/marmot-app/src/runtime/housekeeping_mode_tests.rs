//! Background housekeeping mode through the account worker's own paths
//! (mdk#2923 PR P): the maintenance tick and a presentation wake each reach
//! held jobs and are refused alike, the mode survives a worker reopen, and
//! held work runs once on returning to Normal and once per backstop.
// Each test pauses the clock, which needs the current-thread runtime.
use super::*;
use crate::housekeeping_mode::{Admit, HousekeepingJob as Job};
use crate::{BACKGROUND_BACKSTOP, HousekeepingMode};

/// What a presentation wake or a media completion reaches: the attachment
/// and avatar passes.
const PASS_JOBS: [Job; 4] = [
    Job::PruneSweeps,
    Job::MediaSweep,
    Job::AvatarIdentities,
    Job::AvatarAcquisition,
];
/// What the tick alone reaches. Compaction is reached only while it is due,
/// which an idle fresh account never is; the attachment tests cover it.
const TICK_JOBS: [Job; 3] = [
    Job::ContentBackfill,
    Job::LegacyPromotion,
    Job::HousekeepingBatch,
];

/// Alice's running worker, with the runtime's counters.
struct Worker {
    dir: tempfile::TempDir,
    app: MarmotApp,
    runtime: MarmotAppRuntime,
    account_id_hex: String,
}

impl Worker {
    /// Starts Alice's worker and lets its startup housekeeping settle.
    async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let app = MarmotApp::with_relays(dir.path(), vec![]);
        let account = app
            .account_home()
            .create_account("alice")
            .expect("create alice");
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.accounts().reconcile().await.expect("alice starts");
        let worker = Self {
            dir,
            app,
            runtime,
            account_id_hex: account.account_id_hex,
        };
        worker.wait_for_tick_after(0).await;
        // One more tick may still finish startup work.
        worker.tick().await;
        worker
    }

    /// How many `operation` spans have started.
    fn started(&self, operation: RuntimeOp) -> u64 {
        startup_stage_snapshot(&self.runtime, operation).started
    }

    /// How many `operation` spans have completed.
    fn completed(&self, operation: RuntimeOp) -> u64 {
        startup_stage_snapshot(&self.runtime, operation).completed
    }

    /// How many of `job`'s entry checks decided `admit`.
    fn decisions(&self, job: Job, admit: Admit) -> usize {
        self.app.housekeeping_modes.decisions("alice", job, admit)
    }

    /// How many times `job` was let run, held work's catch-ups included.
    fn ran(&self, job: Job) -> usize {
        self.decisions(job, Admit::Run) + self.decisions(job, Admit::RunOnce)
    }

    /// Lets the worker's passes and the blocking work they spawn finish.
    async fn settle() {
        for _ in 0..200 {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Waits until more than `ticks` maintenance ticks have completed, then
    /// settles.
    async fn wait_for_tick_after(&self, ticks: u64) {
        timeout(ACCOUNT_OPEN_TEST_DEADLINE, async {
            while self.completed(RuntimeOp::WorkerMaintenance) <= ticks {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a maintenance tick completes");
        Self::settle().await;
    }

    /// Advances the clock by `by` and runs the one tick that fires.
    async fn advance(&self, by: Duration) {
        let ticks = self.completed(RuntimeOp::WorkerMaintenance);
        tokio::time::pause();
        tokio::time::advance(by).await;
        tokio::time::resume();
        self.wait_for_tick_after(ticks).await;
    }

    /// Runs the next maintenance tick.
    async fn tick(&self) {
        self.advance(Duration::from_secs(15)).await;
    }

    /// Housekeeping batches and media sweeps started so far.
    fn housekeeping_spans(&self) -> [u64; 2] {
        [
            RuntimeOp::WorkerMaintenanceHousekeepingBatch,
            RuntimeOp::WorkerMediaSweep,
        ]
        .map(|operation| self.started(operation))
    }

    /// Sets Alice's housekeeping mode through the runtime.
    fn set_mode(&self, mode: HousekeepingMode) {
        self.runtime
            .set_housekeeping_mode("alice", mode)
            .expect("set the housekeeping mode");
    }
}

/// In Background, a presentation wake (which sets the attachment and avatar
/// passes due, as a media completion does) and the maintenance tick both
/// reach every held job and are refused: nothing held runs, no housekeeping
/// batch or media sweep starts, and each hold counts as `housekeeping_held`.
#[tokio::test(flavor = "current_thread")]
async fn background_mode_refuses_held_work_from_a_wake_and_the_tick() {
    let worker = Worker::start().await;
    worker.set_mode(HousekeepingMode::Background);
    let ran = Job::ALL.map(|job| worker.ran(job));
    let spans = worker.housekeeping_spans();
    let counted = worker.completed(RuntimeOp::HousekeepingHeld);

    let ticks = worker.completed(RuntimeOp::WorkerMaintenance);
    let held = PASS_JOBS.map(|job| worker.decisions(job, Admit::Hold));
    worker.app.presentation_signals.wake();
    Worker::settle().await;
    assert_eq!(
        worker.completed(RuntimeOp::WorkerMaintenance),
        ticks,
        "no tick ran, so these were the wake's passes"
    );
    for (job, held) in PASS_JOBS.into_iter().zip(held) {
        assert!(
            worker.decisions(job, Admit::Hold) > held,
            "{job:?} on a wake"
        );
    }

    let held = Job::ALL.map(|job| worker.decisions(job, Admit::Hold));
    worker.tick().await;
    for (job, held) in Job::ALL.into_iter().zip(held) {
        if PASS_JOBS.contains(&job) || TICK_JOBS.contains(&job) {
            assert!(
                worker.decisions(job, Admit::Hold) > held,
                "{job:?} on a tick"
            );
        }
    }

    assert_eq!(Job::ALL.map(|job| worker.ran(job)), ran, "nothing held ran");
    assert_eq!(worker.housekeeping_spans(), spans, "nothing held started");
    assert!(worker.completed(RuntimeOp::HousekeepingHeld) > counted);
    worker.runtime.shutdown().await;
}

/// Returning to Normal runs each held job once, even with nothing owed: the
/// switch's wake runs the passes' jobs, the next tick the rest, and the tick
/// after runs none of them again.
#[tokio::test(flavor = "current_thread")]
async fn returning_to_normal_runs_each_held_job_once() {
    let worker = Worker::start().await;
    worker.set_mode(HousekeepingMode::Background);
    worker.tick().await;
    let [batches, sweeps] = worker.housekeeping_spans();

    worker.set_mode(HousekeepingMode::Normal);
    Worker::settle().await;
    for job in PASS_JOBS {
        assert_eq!(
            worker.decisions(job, Admit::RunOnce),
            1,
            "{job:?} on the wake"
        );
    }
    worker.tick().await;
    for job in PASS_JOBS.into_iter().chain(TICK_JOBS) {
        assert_eq!(worker.decisions(job, Admit::RunOnce), 1, "{job:?}");
    }
    assert_eq!(
        worker.housekeeping_spans(),
        [batches + 1, sweeps + 1],
        "one catch-up batch and one catch-up sweep, though nothing is owed"
    );

    worker.tick().await;
    for job in PASS_JOBS.into_iter().chain(TICK_JOBS) {
        assert_eq!(worker.decisions(job, Admit::RunOnce), 1, "{job:?} once");
    }
    assert_eq!(worker.housekeeping_spans(), [batches + 1, sweeps + 1]);
    worker.runtime.shutdown().await;
}

/// The mode belongs to the runtime, not the worker: a reopened worker is
/// still in Background, so even its ownership sweep is held. A cold start
/// is Normal.
#[tokio::test(flavor = "current_thread")]
async fn the_housekeeping_mode_survives_a_worker_reopen() {
    let worker = Worker::start().await;
    worker.set_mode(HousekeepingMode::Background);
    let spans = worker.housekeeping_spans();
    let held = worker.decisions(Job::MediaSweep, Admit::Hold);
    let ticks = worker.completed(RuntimeOp::WorkerMaintenance);

    worker
        .runtime
        .restart_account(&worker.account_id_hex)
        .await
        .expect("restart alice");
    assert_eq!(
        worker.runtime.housekeeping_mode("alice").unwrap(),
        HousekeepingMode::Background
    );
    worker.wait_for_tick_after(ticks).await;
    assert!(
        worker.decisions(Job::MediaSweep, Admit::Hold) > held,
        "the new worker's ownership sweep was held"
    );
    assert_eq!(worker.housekeeping_spans(), spans, "nothing held started");
    worker.runtime.shutdown().await;

    let cold = MarmotApp::with_relays(worker.dir.path(), vec![]);
    assert_eq!(cold.housekeeping_mode("alice"), HousekeepingMode::Normal);
}

/// Held work still runs once per backstop interval in Background: the tick
/// after the interval runs each held job once, and the tick after that holds
/// them again.
#[tokio::test(flavor = "current_thread")]
async fn background_mode_runs_held_work_once_per_backstop() {
    let worker = Worker::start().await;
    worker.set_mode(HousekeepingMode::Background);
    worker.tick().await;
    let [batches, sweeps] = worker.housekeeping_spans();

    worker.advance(BACKGROUND_BACKSTOP).await;
    for job in PASS_JOBS.into_iter().chain(TICK_JOBS) {
        assert_eq!(worker.decisions(job, Admit::RunOnce), 1, "{job:?}");
    }
    assert_eq!(worker.housekeeping_spans(), [batches + 1, sweeps + 1]);

    let held = Job::ALL.map(|job| worker.decisions(job, Admit::Hold));
    worker.tick().await;
    for job in PASS_JOBS.into_iter().chain(TICK_JOBS) {
        assert_eq!(worker.decisions(job, Admit::RunOnce), 1, "{job:?} once");
    }
    assert!(
        Job::ALL
            .map(|job| worker.decisions(job, Admit::Hold))
            .into_iter()
            .zip(held)
            .any(|(now, before)| now > before),
        "held again after the backstop run"
    );
    assert_eq!(worker.housekeeping_spans(), [batches + 1, sweeps + 1]);
    worker.runtime.shutdown().await;
}
