//! The account worker's own deadlines (mdk#2923 step B). Every job the
//! maintenance tick used to run, other than session maintenance, runs when
//! an event wakes it or a deadline comes, not on every maintenance tick. Recovery and post-join re-arm at [`RETRY_WHILE_OWED`], the tick's
//! old cadence, while they still have work, and with none they rest until a
//! wake. A pass arms the deadline its data gives (see [`Schedule::arm`]).
//!
//! The 15 s tick stays only as a watchdog until PR C removes it: a job that
//! has work due with no wake pending and no deadline within 15 s is a missed
//! wake. The watchdog counts it, logs once per job per worker ownership, and
//! wakes the job for the worker's next turn, so a missed wake costs at most
//! one tick, as before.
use std::time::Duration;
use tokio::time::Instant;

/// How soon a job that still has work after it ran runs again: the
/// maintenance tick's cadence, so nothing waits longer than it did.
pub(super) const RETRY_WHILE_OWED: Duration = Duration::from_secs(15);

/// The longest the worker sleeps toward a wall-clock time before it looks
/// again. Its clock stops while the device is suspended and wall time does
/// not, so a longer sleep could wake long after the time it aimed at.
pub(super) const LONGEST_WALL_SLEEP: Duration = Duration::from_secs(15 * 60);

/// When, by the worker's clock, to look again for work due at unix second
/// `at`: then, or in at most [`LONGEST_WALL_SLEEP`], so a suspend delays it
/// by no more than that once the device runs again.
pub(super) fn wall_deadline(at: u64, now_wall: u64, now: Instant) -> Instant {
    now + Duration::from_secs(at.saturating_sub(now_wall)).min(LONGEST_WALL_SLEEP)
}

/// Work the schedule drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Job {
    /// The recovery seam (`refresh_recovery_at_seam`).
    Recovery,
    /// Post-join history collection (`advance_post_join_maintenance_subscriptions`).
    PostJoin,
    /// The attachment pass (`attachments::schedule`).
    AttachmentPass,
    /// The avatar pass (identity avatars and avatar acquisition).
    AvatarPass,
    /// The chat presentation pass.
    PresentationPass,
    /// Publishing app-owned local submissions (its own wake and retry).
    LocalSubmission,
    /// The content-report backfill, until it finishes.
    ContentBackfill,
    /// Legacy message promotion, until it finishes.
    LegacyPromotion,
    /// Device pairing timers, while pairing state exists.
    DevicePairing,
    /// The one-time compaction and the housekeeping batch.
    Housekeeping,
    /// The KeyPackage maintenance catch-up.
    KeyPackageCatchUp,
    /// Push join windows, owed announces and repair asks.
    Push,
    /// History uploads, fetches, backup passes and restores.
    HistoryDispatch,
}

impl Job {
    pub(super) const ALL: [Self; 13] = [
        Self::Recovery,
        Self::PostJoin,
        Self::AttachmentPass,
        Self::AvatarPass,
        Self::PresentationPass,
        Self::LocalSubmission,
        Self::ContentBackfill,
        Self::LegacyPromotion,
        Self::DevicePairing,
        Self::Housekeeping,
        Self::KeyPackageCatchUp,
        Self::Push,
        Self::HistoryDispatch,
    ];

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Recovery => "recovery",
            Self::PostJoin => "post_join",
            Self::AttachmentPass => "attachment_pass",
            Self::AvatarPass => "avatar_pass",
            Self::PresentationPass => "presentation_pass",
            Self::LocalSubmission => "local_submission",
            Self::ContentBackfill => "content_backfill",
            Self::LegacyPromotion => "legacy_promotion",
            Self::DevicePairing => "device_pairing",
            Self::Housekeeping => "housekeeping",
            Self::KeyPackageCatchUp => "key_package_catch_up",
            Self::Push => "push",
            Self::HistoryDispatch => "history_dispatch",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Default)]
struct JobState {
    /// An event created work for it; it runs on the worker's next turn.
    woken: bool,
    /// When it runs again on its own, by the worker's clock.
    deadline: Option<Instant>,
    /// When it runs again on its own, in unix seconds, for work whose time
    /// is stored as wall time: the worker looks again at least every
    /// [`LONGEST_WALL_SLEEP`] and runs it once wall time reaches it.
    wall: Option<u64>,
    /// A missed wake was logged for it under this worker.
    missed_logged: bool,
}

/// The deadlines and pending wakes of one account worker's jobs.
#[derive(Debug)]
pub(super) struct Schedule {
    jobs: [JobState; Job::ALL.len()],
}

impl Schedule {
    /// A worker that just opened runs each job once: what an earlier process
    /// left owed is rebuilt from the data, then each job arms its own deadline.
    pub(super) fn opened() -> Self {
        Self {
            jobs: std::array::from_fn(|_| JobState {
                woken: true,
                ..JobState::default()
            }),
        }
    }

    fn state(&mut self, job: Job) -> &mut JobState {
        &mut self.jobs[job.index()]
    }

    fn get(&self, job: Job) -> &JobState {
        &self.jobs[job.index()]
    }

    /// An event created work for `job`.
    pub(super) fn wake(&mut self, job: Job) {
        self.state(job).woken = true;
    }

    /// `job` ran, from the schedule or from a seam that runs it inline. It
    /// runs again after [`RETRY_WHILE_OWED`] while it still has work, and
    /// otherwise only on a wake.
    pub(super) fn ran(&mut self, job: Job, still_owed: bool, now: Instant) {
        let state = self.state(job);
        state.woken = false;
        state.deadline = still_owed.then(|| now + RETRY_WHILE_OWED);
        state.wall = None;
    }

    /// `job` runs next at `at` on its own, or only on a wake when `None`. A
    /// pass arms what its data gives after a run that left nothing to repeat
    /// at once.
    pub(super) fn arm(&mut self, job: Job, at: Option<Instant>) {
        self.arm_timed(job, at, None, 0, Instant::now());
    }

    /// [`Self::arm`] for a time stored as wall time, unix second `at`. One
    /// already past retries in 15 s, so work due but not taken waits for its
    /// retry, not a busy loop.
    pub(super) fn arm_wall(&mut self, job: Job, at: Option<u64>, now_wall: u64, now: Instant) {
        self.arm_timed(job, None, at, now_wall, now);
    }

    /// `job` runs next at the earlier of `at`, by the worker's clock, and
    /// `wall`, a unix second; `None` for both waits for a wake.
    pub(super) fn arm_timed(
        &mut self,
        job: Job,
        at: Option<Instant>,
        wall: Option<u64>,
        now_wall: u64,
        now: Instant,
    ) {
        let (at, wall) = match wall {
            Some(wall) if wall <= now_wall => {
                let retry = now + RETRY_WHILE_OWED;
                (Some(at.map_or(retry, |at| at.min(retry))), None)
            }
            wall => (at, wall),
        };
        let state = self.state(job);
        state.woken = false;
        state.deadline = at;
        state.wall = wall;
    }

    /// When the worker next has a job to run, or to look again: now for a
    /// woken one, else the earliest deadline, a wall time at most
    /// [`LONGEST_WALL_SLEEP`] ahead. `None` when every job rests.
    pub(super) fn next_at(&self, now: Instant, now_wall: u64) -> Option<Instant> {
        Job::ALL
            .into_iter()
            .filter_map(|job| {
                let state = self.get(job);
                if state.woken {
                    return Some(now);
                }
                let wall = state.wall.map(|at| wall_deadline(at, now_wall, now));
                state.deadline.into_iter().chain(wall).min()
            })
            .min()
    }

    /// Whether an event woke `job` and it has not run since.
    #[cfg(test)]
    pub(super) fn woken(&self, job: Job) -> bool {
        self.get(job).woken
    }

    /// Whether `job` has a wake or a deadline pending.
    pub(super) fn pending(&self, job: Job) -> bool {
        let state = self.get(job);
        state.woken || state.deadline.is_some() || state.wall.is_some()
    }

    /// Whether `job` should run now.
    pub(super) fn due(&self, job: Job, now: Instant, now_wall: u64) -> bool {
        let state = self.get(job);
        state.woken
            || state.deadline.is_some_and(|deadline| deadline <= now)
            || state.wall.is_some_and(|wall| wall <= now_wall)
    }

    /// The watchdog's check: `job` has work (`owed`), yet no wake is
    /// pending and neither its deadline nor its wall time runs it within
    /// [`RETRY_WHILE_OWED`]. A job that always arms some deadline (an hourly
    /// floor, a backup pass) would otherwise hide a missed wake behind it. A
    /// wall time compares with wall time, so one a suspend delayed is no
    /// miss. Returns whether that is a missed wake, and whether it is the
    /// first under this worker, which the caller logs.
    pub(super) fn missed(
        &mut self,
        job: Job,
        owed: bool,
        now: Instant,
        now_wall: u64,
    ) -> Option<bool> {
        let state = self.state(job);
        if !owed
            || state.woken
            || state
                .deadline
                .is_some_and(|deadline| deadline <= now + RETRY_WHILE_OWED)
            || state
                .wall
                .is_some_and(|wall| wall <= now_wall.saturating_add(RETRY_WHILE_OWED.as_secs()))
        {
            return None;
        }
        Some(!std::mem::replace(&mut state.missed_logged, true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wall clock the tests read, in unix seconds.
    const WALL: u64 = 1_000_000;

    /// An opened worker runs each job once; one that still has work re-arms
    /// 15 s later, and one with none rests until a wake.
    #[test]
    fn a_job_reruns_after_15_s_while_owed_and_rests_otherwise() {
        let now = Instant::now();
        let mut schedule = Schedule::opened();
        assert_eq!(schedule.next_at(now, WALL), Some(now));
        assert!(Job::ALL.into_iter().all(|job| schedule.due(job, now, WALL)));
        for job in Job::ALL {
            if !matches!(job, Job::Recovery | Job::PostJoin) {
                schedule.arm(job, None);
            }
        }

        schedule.ran(Job::Recovery, true, now);
        schedule.ran(Job::PostJoin, false, now);
        assert!(!schedule.due(Job::Recovery, now, WALL));
        assert!(!schedule.due(Job::PostJoin, now, WALL));
        assert_eq!(
            schedule.next_at(now, WALL),
            Some(now + Duration::from_secs(15))
        );
        assert!(schedule.due(Job::Recovery, now + Duration::from_secs(15), WALL));
        assert!(!schedule.due(Job::PostJoin, now + Duration::from_secs(3600), WALL));

        schedule.ran(Job::Recovery, false, now);
        assert_eq!(schedule.next_at(now, WALL), None, "every job rests");
        schedule.wake(Job::PostJoin);
        assert_eq!(schedule.next_at(now, WALL), Some(now));
        assert!(schedule.due(Job::PostJoin, now, WALL));
    }

    /// The watchdog counts a job with work and nothing pending to run it,
    /// and logs only the first such miss per job; a pending wake or deadline
    /// is not a miss, nor is a job with no work.
    #[test]
    fn a_missed_wake_is_owed_work_with_nothing_pending() {
        let now = Instant::now();
        let mut schedule = Schedule::opened();
        assert_eq!(
            schedule.missed(Job::Recovery, true, now, WALL),
            None,
            "woken"
        );
        schedule.ran(Job::Recovery, true, now);
        assert_eq!(
            schedule.missed(Job::Recovery, true, now, WALL),
            None,
            "armed"
        );
        schedule.ran(Job::Recovery, false, now);
        assert_eq!(
            schedule.missed(Job::Recovery, false, now, WALL),
            None,
            "no work"
        );
        assert_eq!(schedule.missed(Job::Recovery, true, now, WALL), Some(true));
        assert_eq!(schedule.missed(Job::Recovery, true, now, WALL), Some(false));
        assert_eq!(
            schedule.missed(Job::PostJoin, true, now, WALL),
            None,
            "still woken"
        );
    }

    /// Work due now behind a far deadline, such as an hourly floor, is a
    /// missed wake: nothing runs it within 15 s. A deadline within 15 s is
    /// not.
    #[test]
    fn owed_work_behind_a_far_deadline_is_a_missed_wake() {
        let now = Instant::now() + Duration::from_secs(3600);
        let mut schedule = Schedule::opened();
        schedule.ran(Job::Recovery, true, now);
        // Its retry is 15 s after `now`: an hour before, it is far off.
        let hour_before = now - Duration::from_secs(3600);
        assert_eq!(
            schedule.missed(Job::Recovery, true, hour_before, WALL),
            Some(true)
        );
        assert_eq!(schedule.missed(Job::Recovery, true, now, WALL), None);
    }

    /// Work stored as wall time runs once wall time reaches it, not before,
    /// and the worker looks again at least every 15 minutes, so a suspend
    /// delays it by no more than that.
    #[test]
    fn wall_time_work_runs_when_wall_time_reaches_it() {
        let now = Instant::now();
        let mut schedule = Schedule::opened();
        for job in Job::ALL {
            schedule.arm(job, None);
        }
        schedule.arm_wall(Job::HistoryDispatch, Some(WALL + 3_600), WALL, now);
        assert_eq!(schedule.next_at(now, WALL), Some(now + LONGEST_WALL_SLEEP));
        assert!(!schedule.due(Job::HistoryDispatch, now + LONGEST_WALL_SLEEP, WALL + 900));
        // An hour asleep: the worker's clock moved 15 minutes, wall time an
        // hour.
        assert!(schedule.due(Job::HistoryDispatch, now + LONGEST_WALL_SLEEP, WALL + 3_600));
        // One already past retries in 15 s, never at once.
        schedule.arm_wall(Job::HistoryDispatch, Some(WALL - 5), WALL, now);
        assert!(!schedule.due(Job::HistoryDispatch, now, WALL));
        assert_eq!(schedule.next_at(now, WALL), Some(now + RETRY_WHILE_OWED));
    }

    /// The watchdog compares a wall time with wall time: work a suspend
    /// delayed past its wall time is no missed wake, while owed work whose
    /// wall time is far off is one.
    #[test]
    fn a_suspend_delayed_wall_time_is_no_missed_wake() {
        let now = Instant::now();
        let mut schedule = Schedule::opened();
        schedule.arm_wall(Job::AvatarPass, Some(WALL + 3_600), WALL, now);
        // Woke an hour later by wall time, 15 minutes by the worker's clock.
        assert_eq!(
            schedule.missed(
                Job::AvatarPass,
                true,
                now + LONGEST_WALL_SLEEP,
                WALL + 3_600
            ),
            None
        );
        assert_eq!(
            schedule.missed(Job::AvatarPass, true, now, WALL),
            Some(true)
        );
    }
}
