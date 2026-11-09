//! The account worker's own deadlines (mdk#2923 step B). Recovery and
//! post-join work, and the attachment, avatar and presentation passes, run
//! when an event wakes them or a deadline comes, not on every maintenance
//! tick. Recovery and post-join re-arm at [`RETRY_WHILE_OWED`], the tick's
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
}

impl Job {
    pub(super) const ALL: [Self; 5] = [
        Self::Recovery,
        Self::PostJoin,
        Self::AttachmentPass,
        Self::AvatarPass,
        Self::PresentationPass,
    ];

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Recovery => "recovery",
            Self::PostJoin => "post_join",
            Self::AttachmentPass => "attachment_pass",
            Self::AvatarPass => "avatar_pass",
            Self::PresentationPass => "presentation_pass",
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
    /// When it runs again on its own.
    deadline: Option<Instant>,
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
    }

    /// `job` runs next at `at` on its own, or only on a wake when `None`. A
    /// pass arms what its data gives after a run that left nothing to repeat
    /// at once.
    pub(super) fn arm(&mut self, job: Job, at: Option<Instant>) {
        let state = self.state(job);
        state.woken = false;
        state.deadline = at;
    }

    /// When the worker next has a job to run: now for a woken one, else the
    /// earliest deadline. `None` when every job rests.
    pub(super) fn next_at(&self, now: Instant) -> Option<Instant> {
        Job::ALL
            .into_iter()
            .filter_map(|job| {
                let state = self.get(job);
                if state.woken {
                    Some(now)
                } else {
                    state.deadline
                }
            })
            .min()
    }

    /// Whether `job` should run now.
    pub(super) fn due(&self, job: Job, now: Instant) -> bool {
        let state = self.get(job);
        state.woken || state.deadline.is_some_and(|deadline| deadline <= now)
    }

    /// The watchdog's check: `job` has work (`owed`), yet no wake is
    /// pending and no deadline runs it within [`RETRY_WHILE_OWED`]. A job
    /// that always arms some deadline (an hourly floor, a backup pass) would
    /// otherwise hide a missed wake behind it. Returns whether that is a
    /// missed wake, and whether it is the first under this worker, which the
    /// caller logs.
    pub(super) fn missed(&mut self, job: Job, owed: bool, now: Instant) -> Option<bool> {
        let state = self.state(job);
        if !owed
            || state.woken
            || state
                .deadline
                .is_some_and(|deadline| deadline <= now + RETRY_WHILE_OWED)
        {
            return None;
        }
        Some(!std::mem::replace(&mut state.missed_logged, true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An opened worker runs each job once; one that still has work re-arms
    /// 15 s later, and one with none rests until a wake.
    #[test]
    fn a_job_reruns_after_15_s_while_owed_and_rests_otherwise() {
        let now = Instant::now();
        let mut schedule = Schedule::opened();
        assert_eq!(schedule.next_at(now), Some(now));
        assert!(Job::ALL.into_iter().all(|job| schedule.due(job, now)));
        for pass in [Job::AttachmentPass, Job::AvatarPass, Job::PresentationPass] {
            schedule.arm(pass, None);
        }

        schedule.ran(Job::Recovery, true, now);
        schedule.ran(Job::PostJoin, false, now);
        assert!(!schedule.due(Job::Recovery, now));
        assert!(!schedule.due(Job::PostJoin, now));
        assert_eq!(schedule.next_at(now), Some(now + Duration::from_secs(15)));
        assert!(schedule.due(Job::Recovery, now + Duration::from_secs(15)));
        assert!(!schedule.due(Job::PostJoin, now + Duration::from_secs(3600)));

        schedule.ran(Job::Recovery, false, now);
        assert_eq!(schedule.next_at(now), None, "every job rests");
        schedule.wake(Job::PostJoin);
        assert_eq!(schedule.next_at(now), Some(now));
        assert!(schedule.due(Job::PostJoin, now));
    }

    /// The watchdog counts a job with work and nothing pending to run it,
    /// and logs only the first such miss per job; a pending wake or deadline
    /// is not a miss, nor is a job with no work.
    #[test]
    fn a_missed_wake_is_owed_work_with_nothing_pending() {
        let now = Instant::now();
        let mut schedule = Schedule::opened();
        assert_eq!(schedule.missed(Job::Recovery, true, now), None, "woken");
        schedule.ran(Job::Recovery, true, now);
        assert_eq!(schedule.missed(Job::Recovery, true, now), None, "armed");
        schedule.ran(Job::Recovery, false, now);
        assert_eq!(schedule.missed(Job::Recovery, false, now), None, "no work");
        assert_eq!(schedule.missed(Job::Recovery, true, now), Some(true));
        assert_eq!(schedule.missed(Job::Recovery, true, now), Some(false));
        assert_eq!(
            schedule.missed(Job::PostJoin, true, now),
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
            schedule.missed(Job::Recovery, true, hour_before),
            Some(true)
        );
        assert_eq!(schedule.missed(Job::Recovery, true, now), None);
    }
}
