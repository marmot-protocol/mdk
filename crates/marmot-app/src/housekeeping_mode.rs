//! Per-account background housekeeping mode (mdk#2923 PR P).
//!
//! A host that keeps the app connected in the background (Android's
//! keep-connected service) sets an account to [`HousekeepingMode::Background`]
//! while it is backgrounded. That holds housekeeping only: cleanup of
//! finished or expired work, which can wait until the app is in use again.
//! Messaging keeps running. Receives, sends, downloads, notifications, the
//! KeyPackage lifecycle, recovery of already-prepared publications, the
//! recovery runner and push windows are never held, and nor is anything an
//! in-flight send or download depends on (upload promotion and recovery,
//! download admission and readmission). This is not network suspension
//! (mdk#2600), and it is not `pause_maintenance`, which keeps its own
//! contract: no new protocol maintenance preparation.
//!
//! The mode is process-local and owned by the runtime's [`crate::MarmotApp`],
//! keyed by account label, so it survives a worker or client reopen. A cold
//! start is [`HousekeepingMode::Normal`]; the host sets the mode again after
//! start. Each held job checks [`HousekeepingGate::admit`] at its own entry,
//! so every path that reaches it (the tick, a presentation wake, a media
//! completion) is refused alike.
//!
//! Held work still runs once every [`BACKGROUND_BACKSTOP`] in Background, so
//! expired pruning, compaction and WAL truncation cannot be held without
//! limit on an install that never returns to the foreground. Switching back
//! to Normal runs each held job once.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Whether an account's housekeeping runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HousekeepingMode {
    /// Housekeeping runs as maintenance finds it due.
    #[default]
    Normal,
    /// The app is in the background: housekeeping is held, apart from the
    /// [`BACKGROUND_BACKSTOP`] run. Messaging is unaffected.
    Background,
}

/// How often held housekeeping still runs in [`HousekeepingMode::Background`].
pub const BACKGROUND_BACKSTOP: Duration = Duration::from_secs(12 * 60 * 60);

/// One kind of housekeeping that [`HousekeepingMode::Background`] holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum HousekeepingJob {
    /// Expired partial downloads, orphaned uploads and expired acquisitions.
    PruneSweeps,
    /// The media store's orphan and lost-file sweep.
    MediaSweep,
    /// Keep-media, legacy body and avatar moves, reclaim, WAL truncate and
    /// the compaction check.
    HousekeepingBatch,
    /// The one-time compaction itself.
    Compaction,
    /// Resolving which avatars to acquire.
    AvatarIdentities,
    /// Downloading avatars.
    AvatarAcquisition,
    /// The content-report backfill.
    ContentBackfill,
    /// Legacy message format promotion.
    LegacyPromotion,
}

impl HousekeepingJob {
    pub(crate) const ALL: [Self; 8] = [
        Self::PruneSweeps,
        Self::MediaSweep,
        Self::HousekeepingBatch,
        Self::Compaction,
        Self::AvatarIdentities,
        Self::AvatarAcquisition,
        Self::ContentBackfill,
        Self::LegacyPromotion,
    ];
}

/// What a held job's entry check decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Admit {
    /// Run as the job's own schedule finds it due.
    Run,
    /// Run once now even if the job's schedule finds nothing owed: the
    /// account just returned to Normal, or the Background backstop is due.
    RunOnce,
    /// Held in Background.
    Hold,
}

impl Admit {
    pub(crate) fn runs(self) -> bool {
        self != Self::Hold
    }
}

#[derive(Default)]
struct AccountHousekeeping {
    mode: HousekeepingMode,
    /// When each job last ran in Background, or when Background began.
    last_run: HashMap<HousekeepingJob, tokio::time::Instant>,
    /// Jobs owed one run since the account returned to Normal.
    catch_up: HashSet<HousekeepingJob>,
}

/// An account label, a job and what its entry check decided.
#[cfg(test)]
type DecisionKey = (String, HousekeepingJob, Admit);

/// Every account's housekeeping mode, shared by the app's clones.
#[derive(Clone, Default)]
pub(crate) struct HousekeepingModes {
    accounts: Arc<Mutex<HashMap<String, AccountHousekeeping>>>,
    /// Every entry check's decision, per account and job, for tests.
    #[cfg(test)]
    decisions: Arc<Mutex<HashMap<DecisionKey, usize>>>,
}

impl HousekeepingModes {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, AccountHousekeeping>> {
        self.accounts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn mode(&self, label: &str) -> HousekeepingMode {
        self.lock()
            .get(label)
            .map_or_else(Default::default, |account| account.mode)
    }

    /// Sets `label`'s mode. Entering Background starts every job's backstop
    /// clock; returning to Normal owes each job one run.
    pub(crate) fn set(&self, label: &str, mode: HousekeepingMode) {
        let mut accounts = self.lock();
        let account = accounts.entry(label.to_owned()).or_default();
        if account.mode == mode {
            return;
        }
        account.mode = mode;
        match mode {
            HousekeepingMode::Background => {
                let now = tokio::time::Instant::now();
                account.catch_up.clear();
                account.last_run = HousekeepingJob::ALL.iter().map(|job| (*job, now)).collect();
            }
            HousekeepingMode::Normal => {
                account.last_run.clear();
                account.catch_up = HousekeepingJob::ALL.into_iter().collect();
            }
        }
    }

    /// Forgets `label`, as its account's other caches are when it goes.
    pub(crate) fn forget(&self, label: &str) {
        self.lock().remove(label);
    }

    /// The entry check for `job` on `label`. Never blocks.
    pub(crate) fn admit(&self, label: &str, job: HousekeepingJob) -> Admit {
        let admit = self.decide(label, job);
        #[cfg(test)]
        {
            *self
                .decisions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entry((label.to_owned(), job, admit))
                .or_default() += 1;
        }
        admit
    }

    /// How many entry checks for `job` on `label` decided `admit`.
    #[cfg(test)]
    pub(crate) fn decisions(&self, label: &str, job: HousekeepingJob, admit: Admit) -> usize {
        self.decisions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&(label.to_owned(), job, admit))
            .copied()
            .unwrap_or_default()
    }

    fn decide(&self, label: &str, job: HousekeepingJob) -> Admit {
        let mut accounts = self.lock();
        let Some(account) = accounts.get_mut(label) else {
            return Admit::Run;
        };
        match account.mode {
            HousekeepingMode::Normal => {
                if account.catch_up.remove(&job) {
                    Admit::RunOnce
                } else {
                    Admit::Run
                }
            }
            HousekeepingMode::Background => {
                let now = tokio::time::Instant::now();
                let last = account.last_run.entry(job).or_insert(now);
                if now.saturating_duration_since(*last) >= BACKGROUND_BACKSTOP {
                    *last = now;
                    Admit::RunOnce
                } else {
                    Admit::Hold
                }
            }
        }
    }
}

/// A held job's entry check for one account, with the counter it records a
/// hold in.
pub(crate) struct HousekeepingGate {
    modes: HousekeepingModes,
    label: String,
    telemetry: Option<marmot_observability::PerformanceRecorder>,
}

impl HousekeepingGate {
    pub(crate) fn new(
        modes: HousekeepingModes,
        label: impl Into<String>,
        telemetry: Option<marmot_observability::PerformanceRecorder>,
    ) -> Self {
        Self {
            modes,
            label: label.into(),
            telemetry,
        }
    }

    /// Whether `job` runs now; a hold is counted as
    /// `housekeeping_held`.
    pub(crate) fn admit(&self, job: HousekeepingJob) -> Admit {
        let admit = self.modes.admit(&self.label, job);
        if admit == Admit::Hold
            && let Some(telemetry) = &self.telemetry
        {
            telemetry.record_runtime(
                crate::RuntimePerformanceOperation::HousekeepingHeld,
                Duration::ZERO,
                marmot_observability::Outcome::Success,
            );
        }
        admit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Background holds every job; returning to Normal owes each one run
    /// once; an account never set runs as Normal.
    #[test]
    fn background_holds_and_normal_runs_each_job_once() {
        let modes = HousekeepingModes::default();
        for job in HousekeepingJob::ALL {
            assert_eq!(modes.admit("alice", job), Admit::Run, "{job:?}");
        }
        modes.set("alice", HousekeepingMode::Background);
        for job in HousekeepingJob::ALL {
            assert_eq!(modes.admit("alice", job), Admit::Hold, "{job:?}");
        }
        assert_eq!(modes.admit("bob", HousekeepingJob::MediaSweep), Admit::Run);
        modes.set("alice", HousekeepingMode::Normal);
        for job in HousekeepingJob::ALL {
            assert_eq!(modes.admit("alice", job), Admit::RunOnce, "{job:?}");
            assert_eq!(modes.admit("alice", job), Admit::Run, "{job:?} runs once");
        }
    }

    /// In Background each held job still runs once per backstop interval,
    /// and only once (paused clock).
    #[tokio::test(start_paused = true)]
    async fn background_runs_each_held_job_once_per_backstop() {
        let modes = HousekeepingModes::default();
        modes.set("alice", HousekeepingMode::Background);
        tokio::time::advance(BACKGROUND_BACKSTOP - Duration::from_secs(1)).await;
        assert_eq!(
            modes.admit("alice", HousekeepingJob::PruneSweeps),
            Admit::Hold
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        for job in HousekeepingJob::ALL {
            assert_eq!(modes.admit("alice", job), Admit::RunOnce, "{job:?}");
            assert_eq!(modes.admit("alice", job), Admit::Hold, "{job:?} once");
        }
        tokio::time::advance(BACKGROUND_BACKSTOP).await;
        assert_eq!(
            modes.admit("alice", HousekeepingJob::Compaction),
            Admit::RunOnce
        );
    }

    /// Setting the same mode again changes nothing: it neither restarts the
    /// backstop clock nor owes another catch-up.
    #[tokio::test(start_paused = true)]
    async fn setting_the_same_mode_again_changes_nothing() {
        let modes = HousekeepingModes::default();
        modes.set("alice", HousekeepingMode::Background);
        tokio::time::advance(BACKGROUND_BACKSTOP).await;
        modes.set("alice", HousekeepingMode::Background);
        assert_eq!(
            modes.admit("alice", HousekeepingJob::MediaSweep),
            Admit::RunOnce
        );
    }
}
