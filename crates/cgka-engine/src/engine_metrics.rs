//! Engine-side diagnostic telemetry for post-settle convergence reorgs.
//!
//! Realises phase 3 of the measurement model in
//! `docs/marmot-architecture/relay-delivery-telemetry.md`
//! (§"Validation: post-settle reorg rate"). It closes the quiescence loss
//! function by measuring how often a group *settled too early*: a canonical
//! branch that was applied and observed while [`ConvergenceStatus::Settled`],
//! later superseded by a branch that forks *below* the previously-applied tip
//! (a reorg) rather than extending it (a normal forward advance).
//!
//! `observed_reorg_rate = post_settle_reorgs / settles` is the only direct
//! evidence that a chosen `settlement_quiescence_ms` is too low. This facility
//! exports the raw counters; the rate is derived by the consumer.
//!
//! ## Diagnostic only
//!
//! Like the transport adapter's telemetry, this MUST NEVER feed convergence or
//! branch selection. It only observes settle outcomes after the engine has
//! already committed to a branch.
//!
//! ## Privacy (`docs/marmot-architecture/overview/observability.md`)
//!
//! The per-group last-applied record is in-memory only and keyed by
//! [`GroupId`]; it never reaches a snapshot. [`EngineMetricsSnapshot`] carries
//! only counts and fixed-bucket histograms (milliseconds for lateness, commits
//! for rewind depth) — no group ids, epochs, branch ids, or member ids. All
//! timing is local-monotonic, never Nostr `created_at`.

use std::collections::HashMap;

use cgka_traits::types::GroupId;

use crate::canonicalization::ConvergenceStatus;

/// Upper bounds, in milliseconds, of the `reorg_lateness_ms` histogram buckets.
///
/// Identical fine-grained edges to the transport adapter's delivery-spread
/// histogram (`transport-nostr-adapter/src/telemetry.rs`): the lateness
/// distribution is read with the same percentile lens and feeds the same
/// quiescence value, so the buckets must line up across the two halves of the
/// loss function. A sample lands in the first bucket whose bound it does not
/// exceed; samples above the last bound fall into a dedicated overflow bucket.
const LATENESS_BUCKET_BOUNDS_MS: [u64; 24] = [
    1, 2, 5, 10, 20, 30, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 7500,
    10000, 15000, 20000, 30000,
];

/// Upper bounds, in commits, of the `reorg_rewind_depth` histogram buckets.
///
/// A rewind is `previous_applied_tip - new_fork_epoch` and is bounded by the
/// group's `max_rewind_commits` (default 5), so small commit counts dominate;
/// the higher edges leave headroom for groups that negotiate a deeper horizon.
const REWIND_DEPTH_BUCKET_BOUNDS: [u64; 10] = [1, 2, 3, 4, 5, 6, 8, 10, 16, 32];

/// Fixed-bucket histogram over `u64` samples (milliseconds for lateness,
/// commits for rewind depth).
///
/// Mirrors the adapter's `DurationHistogram` bucketing: a sample is counted in
/// the first bucket whose bound it does not exceed, and anything past the last
/// bound is counted as overflow.
#[derive(Clone, Debug)]
struct BucketHistogram {
    bounds: &'static [u64],
    counts: Vec<u64>,
    overflow: u64,
}

impl BucketHistogram {
    fn new(bounds: &'static [u64]) -> Self {
        Self {
            bounds,
            counts: vec![0; bounds.len()],
            overflow: 0,
        }
    }

    fn record(&mut self, sample: u64) {
        for (idx, bound) in self.bounds.iter().enumerate() {
            if sample <= *bound {
                self.counts[idx] += 1;
                return;
            }
        }
        self.overflow += 1;
    }

    fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            buckets: self
                .bounds
                .iter()
                .zip(self.counts.iter())
                .map(|(bound, count)| HistogramBucket {
                    upper_bound: *bound,
                    count: *count,
                })
                .collect(),
            overflow_count: self.overflow,
        }
    }
}

/// One bucket of a fixed-bucket histogram.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistogramBucket {
    /// Inclusive upper bound of the bucket (milliseconds or commits, per the
    /// owning histogram).
    pub upper_bound: u64,
    /// Number of samples whose value fell in this bucket.
    pub count: u64,
}

/// Aggregate fixed-bucket histogram snapshot.
///
/// Counts and bucket bounds only: no group ids, epochs, branch ids, or
/// payload-derived values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistogramSnapshot {
    /// Buckets by ascending upper bound.
    pub buckets: Vec<HistogramBucket>,
    /// Samples whose value exceeded the largest bucket bound.
    pub overflow_count: u64,
}

impl HistogramSnapshot {
    /// Total number of samples across all buckets and the overflow.
    pub fn sample_count(&self) -> u64 {
        self.buckets.iter().map(|bucket| bucket.count).sum::<u64>() + self.overflow_count
    }

    /// Approximate `percentile` (0.0..=1.0), returned as the upper bound of the
    /// bucket the percentile falls in. `None` when there are no samples, and
    /// `None` for the overflow region (the value is only known to exceed the
    /// largest bound).
    ///
    /// For `reorg_lateness_ms` a high percentile is the empirical correction to
    /// add on top of the cross-relay-spread floor when choosing
    /// `settlement_quiescence_ms`.
    pub fn approx_percentile(&self, percentile: f64) -> Option<u64> {
        let total = self.sample_count();
        if total == 0 {
            return None;
        }
        let target = ((percentile.clamp(0.0, 1.0) * total as f64).ceil() as u64).max(1);
        let mut cumulative = 0;
        for bucket in &self.buckets {
            cumulative += bucket.count;
            if cumulative >= target {
                return Some(bucket.upper_bound);
            }
        }
        // Remaining samples are in the overflow region: wider than measured.
        None
    }
}

/// Per-group record of the last branch the engine applied to canonical state.
///
/// In-memory only and keyed by [`GroupId`] in [`EngineMetrics`], so no group id
/// reaches a snapshot. The `settled_since_apply` flag gates reorg classification
/// on the spec rule "the superseded branch was observed in a `Settled` pass":
/// superseding a branch the application was never told about is ordinary
/// pre-settle convergence, not a premature settle.
#[derive(Clone, Debug)]
struct LastAppliedBranch {
    /// Tip epoch of the applied branch (the "previously-applied tip").
    tip_epoch: u64,
    /// Content-derived id of the applied branch.
    branch_id: String,
    /// Local-monotonic time of the settle that applied this branch.
    settled_at_ms: u64,
    /// Whether this branch was applied during a `Settled` pass.
    settled_since_apply: bool,
}

/// Engine-side post-settle reorg telemetry recorder.
///
/// Held by `Engine<S>` and incremented at the convergence apply site. Exposed
/// to callers as an [`EngineMetricsSnapshot`] via `Engine::engine_metrics`.
/// Diagnostic only; never an input to convergence or branch selection.
#[derive(Clone, Debug)]
pub struct EngineMetrics {
    /// Settle episodes: times a group reached `Settled` and applied a branch,
    /// summed across groups. Denominator of `observed_reorg_rate`.
    settles: u64,
    /// Settles later superseded by a branch diverging below the applied tip.
    /// Numerator of `observed_reorg_rate`.
    post_settle_reorgs: u64,
    /// `previous_applied_tip - new_fork_epoch` per reorg, in commits.
    reorg_rewind_depth: BucketHistogram,
    /// Local time from the superseded settle to the reorg, in milliseconds —
    /// the extra quiescence that would have prevented the reorg.
    reorg_lateness_ms: BucketHistogram,
    /// Per-group last-applied branch, in-memory only (never snapshotted).
    last_applied: HashMap<GroupId, LastAppliedBranch>,
}

impl Default for EngineMetrics {
    fn default() -> Self {
        Self {
            settles: 0,
            post_settle_reorgs: 0,
            reorg_rewind_depth: BucketHistogram::new(&REWIND_DEPTH_BUCKET_BOUNDS),
            reorg_lateness_ms: BucketHistogram::new(&LATENESS_BUCKET_BOUNDS_MS),
            last_applied: HashMap::new(),
        }
    }
}

impl EngineMetrics {
    /// Record an applied canonical selection and classify it as a forward
    /// advance or a post-settle reorg.
    ///
    /// Called at the convergence apply site after the engine sets the selected
    /// branch stable. `status` is the pass's convergence status, the
    /// `selected_*` values describe the applied branch, and `now_ms` is a
    /// local-monotonic timestamp.
    ///
    /// A settle is counted whenever a branch is applied while `Settled`. It is
    /// classified as a **post-settle reorg** when there is a prior branch that
    ///
    /// - was itself observed in a `Settled` pass (else the application was never
    ///   told, so superseding it is normal convergence), and
    /// - differs from the new branch, and
    /// - the new branch forks *strictly below* the prior applied tip (forking
    ///   *at* the tip extends it — a forward advance, not a rewind).
    ///
    /// Anything else (first settle, forward advance, idempotent re-selection,
    /// or a re-selection while still `Resolving`) updates the per-group record
    /// without counting a reorg.
    ///
    /// Diagnostic only: this never influences convergence or branch selection.
    pub fn note_applied_selection(
        &mut self,
        group_id: &GroupId,
        status: ConvergenceStatus,
        selected_fork_epoch: u64,
        selected_tip: u64,
        selected_branch_id: &str,
        now_ms: u64,
    ) {
        let settled = status == ConvergenceStatus::Settled;
        if settled {
            self.settles += 1;
        }

        if settled
            && let Some(prior) = self.last_applied.get(group_id)
            && prior.settled_since_apply
            && selected_branch_id != prior.branch_id
            && selected_fork_epoch < prior.tip_epoch
        {
            let rewind_depth = prior.tip_epoch - selected_fork_epoch;
            let lateness_ms = now_ms.saturating_sub(prior.settled_at_ms);
            self.post_settle_reorgs += 1;
            self.reorg_rewind_depth.record(rewind_depth);
            self.reorg_lateness_ms.record(lateness_ms);
        }

        self.last_applied.insert(
            group_id.clone(),
            LastAppliedBranch {
                tip_epoch: selected_tip,
                branch_id: selected_branch_id.to_string(),
                settled_at_ms: now_ms,
                settled_since_apply: settled,
            },
        );
    }

    /// Aggregate, privacy-safe snapshot for diagnostics and quiescence tuning.
    pub fn snapshot(&self) -> EngineMetricsSnapshot {
        EngineMetricsSnapshot {
            settles: self.settles,
            post_settle_reorgs: self.post_settle_reorgs,
            reorg_rewind_depth: self.reorg_rewind_depth.snapshot(),
            reorg_lateness_ms: self.reorg_lateness_ms.snapshot(),
        }
    }
}

/// Aggregate engine telemetry snapshot.
///
/// Counts and millisecond/commit histograms only, summed across all groups: no
/// group ids, epochs, branch ids, or member ids in any field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineMetricsSnapshot {
    /// Settle episodes summed across groups (denominator).
    pub settles: u64,
    /// Post-settle reorgs summed across groups (numerator).
    pub post_settle_reorgs: u64,
    /// Rewind depth per reorg, in commits.
    pub reorg_rewind_depth: HistogramSnapshot,
    /// Lateness per reorg, in local-monotonic milliseconds.
    pub reorg_lateness_ms: HistogramSnapshot,
}

impl EngineMetricsSnapshot {
    /// `post_settle_reorgs / settles`, the fraction of settles that turned out
    /// premature. `None` when no settle has been observed yet.
    pub fn observed_reorg_rate(&self) -> Option<f64> {
        (self.settles > 0).then(|| self.post_settle_reorgs as f64 / self.settles as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gid(byte: u8) -> GroupId {
        GroupId::new(vec![byte; 32])
    }

    const SETTLED: ConvergenceStatus = ConvergenceStatus::Settled;
    const RESOLVING: ConvergenceStatus = ConvergenceStatus::Resolving;

    #[test]
    fn first_settle_is_not_a_reorg() {
        let mut metrics = EngineMetrics::default();
        // No prior record for this group: establishing the first applied
        // branch is never a reorg.
        metrics.note_applied_selection(&gid(1), SETTLED, 0, 1, "branch-a", 100);

        let snap = metrics.snapshot();
        assert_eq!(snap.settles, 1);
        assert_eq!(snap.post_settle_reorgs, 0);
        assert_eq!(snap.reorg_rewind_depth.sample_count(), 0);
        assert_eq!(snap.reorg_lateness_ms.sample_count(), 0);
        assert_eq!(snap.observed_reorg_rate(), Some(0.0));
    }

    #[test]
    fn forward_advance_is_not_a_reorg() {
        let mut metrics = EngineMetrics::default();
        // Settle tip 1 (forked at 0).
        metrics.note_applied_selection(&gid(1), SETTLED, 0, 1, "branch-a", 100);
        // Advance to tip 2 by a branch that forks *at* the prior tip (1): it
        // extends the applied branch rather than rewinding it.
        metrics.note_applied_selection(&gid(1), SETTLED, 1, 2, "branch-a-b", 200);

        let snap = metrics.snapshot();
        assert_eq!(snap.settles, 2);
        assert_eq!(snap.post_settle_reorgs, 0);
        assert_eq!(snap.reorg_rewind_depth.sample_count(), 0);
    }

    #[test]
    fn post_settle_reorg_is_counted_with_depth_and_lateness() {
        let mut metrics = EngineMetrics::default();
        // Settle tip 2 via a commit forked at epoch 1.
        metrics.note_applied_selection(&gid(1), SETTLED, 1, 2, "branch-a", 100);
        // A late competing commit forks at epoch 1 too but is a different
        // branch and the selection flips: it forks below the prior tip (2), so
        // it rewinds the previously-applied tip → post-settle reorg.
        metrics.note_applied_selection(&gid(1), SETTLED, 1, 2, "branch-b", 350);

        let snap = metrics.snapshot();
        assert_eq!(snap.settles, 2);
        assert_eq!(snap.post_settle_reorgs, 1);
        assert_eq!(snap.observed_reorg_rate(), Some(0.5));

        // Rewind depth = previous_applied_tip (2) - new_fork_epoch (1) = 1.
        assert_eq!(snap.reorg_rewind_depth.sample_count(), 1);
        let depth_bucket = snap
            .reorg_rewind_depth
            .buckets
            .iter()
            .find(|bucket| bucket.upper_bound == 1)
            .expect("depth-1 bucket");
        assert_eq!(depth_bucket.count, 1);

        // Lateness = 350 - 100 = 250ms, which lands in the <=300ms bucket.
        assert_eq!(snap.reorg_lateness_ms.sample_count(), 1);
        let lateness_bucket = snap
            .reorg_lateness_ms
            .buckets
            .iter()
            .find(|bucket| bucket.upper_bound == 300)
            .expect("300ms bucket");
        assert_eq!(lateness_bucket.count, 1);
    }

    #[test]
    fn deeper_reorg_records_a_larger_rewind_depth() {
        let mut metrics = EngineMetrics::default();
        // Settle a three-commit branch: tip 3, forked at 0.
        metrics.note_applied_selection(&gid(1), SETTLED, 0, 3, "branch-a", 100);
        // A late branch forked at epoch 0 supersedes it: rewind depth 3 - 0 = 3.
        metrics.note_applied_selection(&gid(1), SETTLED, 0, 3, "branch-b", 1_400);

        let snap = metrics.snapshot();
        assert_eq!(snap.post_settle_reorgs, 1);
        let depth_bucket = snap
            .reorg_rewind_depth
            .buckets
            .iter()
            .find(|bucket| bucket.upper_bound == 3)
            .expect("depth-3 bucket");
        assert_eq!(depth_bucket.count, 1);
        // Lateness 1300ms lands in the <=1500ms bucket.
        assert_eq!(snap.reorg_lateness_ms.approx_percentile(1.0), Some(1500));
    }

    #[test]
    fn idempotent_reselection_of_same_branch_is_not_a_reorg() {
        let mut metrics = EngineMetrics::default();
        metrics.note_applied_selection(&gid(1), SETTLED, 1, 2, "branch-a", 100);
        // Re-converging and re-selecting the *same* branch (e.g. after a late
        // losing commit) is a settle but not a reorg.
        metrics.note_applied_selection(&gid(1), SETTLED, 1, 2, "branch-a", 200);

        let snap = metrics.snapshot();
        assert_eq!(snap.settles, 2);
        assert_eq!(snap.post_settle_reorgs, 0);
    }

    #[test]
    fn resolving_phase_reselection_is_not_counted() {
        let mut metrics = EngineMetrics::default();
        // Settle a branch (the application is told).
        metrics.note_applied_selection(&gid(1), SETTLED, 1, 2, "branch-a", 100);
        // A re-selection while still Resolving, before the application was told
        // anything, is normal convergence: it counts neither a settle nor a
        // reorg even though it diverges below the prior tip.
        metrics.note_applied_selection(&gid(1), RESOLVING, 0, 2, "branch-b", 200);

        let snap = metrics.snapshot();
        assert_eq!(snap.settles, 1);
        assert_eq!(snap.post_settle_reorgs, 0);
        assert_eq!(snap.reorg_rewind_depth.sample_count(), 0);
        assert_eq!(snap.reorg_lateness_ms.sample_count(), 0);
    }

    #[test]
    fn supersession_of_an_unsettled_branch_is_not_a_reorg() {
        let mut metrics = EngineMetrics::default();
        // A branch recorded while Resolving was never confirmed to the app.
        metrics.note_applied_selection(&gid(1), RESOLVING, 1, 2, "branch-a", 100);
        // Even a later Settled branch that diverges below it is not a
        // post-settle reorg, because the superseded branch was never settled.
        metrics.note_applied_selection(&gid(1), SETTLED, 0, 2, "branch-b", 300);

        let snap = metrics.snapshot();
        assert_eq!(snap.settles, 1);
        assert_eq!(snap.post_settle_reorgs, 0);
    }

    #[test]
    fn first_settle_after_restart_is_not_a_reorg() {
        // A restart drops the in-memory last-applied record. The first settle
        // afterwards re-establishes it against an already-advanced tip and is
        // not classified as a reorg (the spec accepts the slight under-count).
        let mut restarted = EngineMetrics::default();
        restarted.note_applied_selection(&gid(1), SETTLED, 4, 5, "branch-post-restart", 100);

        let snap = restarted.snapshot();
        assert_eq!(snap.settles, 1);
        assert_eq!(snap.post_settle_reorgs, 0);
        assert_eq!(snap.reorg_rewind_depth.sample_count(), 0);
    }

    #[test]
    fn reorgs_are_tracked_per_group_and_aggregated() {
        let mut metrics = EngineMetrics::default();
        // Group 1 reorgs.
        metrics.note_applied_selection(&gid(1), SETTLED, 1, 2, "g1-a", 100);
        metrics.note_applied_selection(&gid(1), SETTLED, 1, 2, "g1-b", 200);
        // Group 2 only ever advances forward.
        metrics.note_applied_selection(&gid(2), SETTLED, 0, 1, "g2-a", 150);
        metrics.note_applied_selection(&gid(2), SETTLED, 1, 2, "g2-a-b", 250);

        let snap = metrics.snapshot();
        // Per-group records do not cross-contaminate: only group 1's flip is a
        // reorg, but settles aggregate across both groups.
        assert_eq!(snap.settles, 4);
        assert_eq!(snap.post_settle_reorgs, 1);
        assert_eq!(snap.observed_reorg_rate(), Some(0.25));
    }

    #[test]
    fn reorg_rate_is_none_without_settles() {
        let metrics = EngineMetrics::default();
        assert_eq!(metrics.snapshot().observed_reorg_rate(), None);
    }

    #[test]
    fn lateness_beyond_largest_bucket_counts_as_overflow() {
        let mut metrics = EngineMetrics::default();
        metrics.note_applied_selection(&gid(1), SETTLED, 1, 2, "branch-a", 0);
        // Reorg 40s after the superseded settle: beyond the 30s top bucket.
        metrics.note_applied_selection(&gid(1), SETTLED, 1, 2, "branch-b", 40_000);

        let snap = metrics.snapshot();
        assert_eq!(snap.post_settle_reorgs, 1);
        assert_eq!(snap.reorg_lateness_ms.overflow_count, 1);
        assert_eq!(snap.reorg_lateness_ms.approx_percentile(1.0), None);
    }
}
