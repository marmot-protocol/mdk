//! Detection policy for epoch-gap backfill (commit-loss recovery).
//!
//! A device that misses a single commit sits stuck below its group's live
//! epoch: it keeps receiving that group's later-epoch traffic but cannot decrypt
//! any of it — the kind-445 envelope is sealed under the per-epoch exporter
//! secret and carries no cleartext epoch, so every such message fails to peel.
//! This detector turns that otherwise-invisible signal into a per-group "the
//! group moved on without me" decision *without ever decrypting the traffic*: it
//! counts the distinct undecryptable messages a group accumulates while its
//! epoch does not advance, and signals a backfill once that count crosses a
//! threshold.
//!
//! The policy is deliberately I/O-free so it can be unit-tested in isolation;
//! the recovery action it triggers — a full-history transport replay — lives in
//! the caller, which owns the runtime.

use std::collections::{HashMap, HashSet};

use cgka_traits::{EpochId, GroupId};

/// Distinct undecryptable messages a group may accumulate at one stalled epoch
/// before the runtime reads it as stuck and triggers an epoch-gap backfill.
///
/// This is an empirical estimate with structural safety — the `CATCH_UP_GRACE_MS`
/// class, not a uniquely-derived bound like `EPOCH_DIVERGENCE_MIN_LAG`. It was
/// chosen by replaying this detector over the two real forensic exports on hand
/// (2026-07-15, a single cohort): the genuinely stuck device accumulated 45
/// distinct undecryptables at its stalled epoch, while the healthy tip devices
/// never exceeded 7 (a diverged peer's complete send burst). 8 is the smallest
/// count above that healthy plateau. Its safety is structural on both sides: too
/// low costs at most one debounced full-history replay per (group, epoch) — the
/// same operation a key-package publish already performs — while too high only
/// delays healing, since the count is monotone while a group stays stuck. Being
/// single-cohort, it should be firmed up against more cohorts before it is
/// treated as general.
pub(crate) const EPOCH_STALL_BACKFILL_THRESHOLD: usize = 8;

/// Per-group stall accounting.
struct GroupStall {
    /// The epoch the undecryptable messages accumulated at; a new epoch resets
    /// the count, because advancing proves the group's commits are reaching us.
    epoch: EpochId,
    /// Distinct undecryptable message ids seen at `epoch` (hex), capped at the
    /// threshold — the identity is attacker-mintable, so the set never needs to
    /// grow past the point where it decides.
    undecryptable: HashSet<String>,
    /// The epoch a backfill was last signalled for, so the detector signals at
    /// most once per stalled epoch.
    fired_at_epoch: Option<EpochId>,
}

/// Decides, per group, when a run of undecryptable traffic at a stalled epoch
/// means the group has advanced past this device and a backfill is warranted.
pub(crate) struct EpochStallDetector {
    threshold: usize,
    groups: HashMap<GroupId, GroupStall>,
}

impl EpochStallDetector {
    pub(crate) fn new(threshold: usize) -> Self {
        Self {
            threshold,
            groups: HashMap::new(),
        }
    }

    /// The distinct-undecryptable count at which this detector arms a backfill.
    /// Reported on the `epoch_stall_backfill_armed` audit row so the row is
    /// honest even when the detector was built with a non-default threshold
    /// (unit tests, or a future configurable value).
    pub(crate) fn threshold(&self) -> usize {
        self.threshold
    }

    /// Record that an account-wide full-history replay was just triggered. One
    /// replay re-fetches every group's history, so suppress a further backfill
    /// for every currently-tracked group at its current epoch: N groups stuck at
    /// once cost one replay, not N. A group re-arms only when its epoch advances
    /// and it stalls again at the new epoch.
    pub(crate) fn mark_replayed(&mut self) {
        for stall in self.groups.values_mut() {
            stall.fired_at_epoch = Some(stall.epoch);
        }
    }

    /// Record one undecryptable message for `group` observed while the group is
    /// at `epoch`. Returns `true` exactly once when the group crosses the
    /// threshold at a stalled epoch and a backfill should be triggered.
    pub(crate) fn observe_undecryptable(
        &mut self,
        group: GroupId,
        message: String,
        epoch: EpochId,
    ) -> bool {
        let stall = self.groups.entry(group).or_insert_with(|| GroupStall {
            epoch,
            undecryptable: HashSet::new(),
            fired_at_epoch: None,
        });
        if stall.epoch != epoch {
            stall.epoch = epoch;
            stall.undecryptable.clear();
            stall.fired_at_epoch = None;
        }
        // The message identity is attacker-mintable (a fresh envelope is a fresh
        // id), so the set never needs to grow past the point where it decides.
        if stall.undecryptable.len() < self.threshold {
            stall.undecryptable.insert(message);
        }
        let crossed = stall.undecryptable.len() >= self.threshold;
        if crossed && stall.fired_at_epoch != Some(epoch) {
            stall.fired_at_epoch = Some(epoch);
            true
        } else {
            false
        }
    }
}

impl Default for EpochStallDetector {
    fn default() -> Self {
        Self::new(EPOCH_STALL_BACKFILL_THRESHOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(byte: u8) -> GroupId {
        GroupId::new(vec![byte])
    }

    #[test]
    fn signals_backfill_after_threshold_distinct_undecryptables_at_a_stable_epoch() {
        let mut detector = EpochStallDetector::new(3);
        let g = group(0x01);
        let e = EpochId(19);

        assert!(!detector.observe_undecryptable(g.clone(), "m1".into(), e));
        assert!(!detector.observe_undecryptable(g.clone(), "m2".into(), e));
        assert!(
            detector.observe_undecryptable(g.clone(), "m3".into(), e),
            "the threshold-crossing message should signal a backfill"
        );
    }

    #[test]
    fn signals_at_most_once_per_stalled_epoch() {
        let mut detector = EpochStallDetector::new(3);
        let g = group(0x01);
        let e = EpochId(19);

        detector.observe_undecryptable(g.clone(), "m1".into(), e);
        detector.observe_undecryptable(g.clone(), "m2".into(), e);
        assert!(detector.observe_undecryptable(g.clone(), "m3".into(), e));
        // Further undecryptable traffic at the same stalled epoch must not
        // re-signal: one replay per stalled epoch is enough, and re-signalling
        // would let a burst (or a spray of attacker-minted ids) trigger a storm.
        assert!(!detector.observe_undecryptable(g.clone(), "m4".into(), e));
        assert!(!detector.observe_undecryptable(g.clone(), "m5".into(), e));
    }

    #[test]
    fn mark_replayed_collapses_a_storm_of_simultaneously_stuck_groups() {
        let mut detector = EpochStallDetector::new(3);
        let a = group(0x0A);
        let b = group(0x0B);
        let e = EpochId(19);

        // Group A crosses the threshold and the caller runs ONE account-wide
        // replay (which re-fetches every group's history, B included).
        detector.observe_undecryptable(a.clone(), "a1".into(), e);
        detector.observe_undecryptable(a.clone(), "a2".into(), e);
        assert!(detector.observe_undecryptable(a.clone(), "a3".into(), e));

        // Group B was accumulating undecryptables at the same epoch in the same
        // drain but had not yet crossed the threshold.
        detector.observe_undecryptable(b.clone(), "b1".into(), e);
        detector.observe_undecryptable(b.clone(), "b2".into(), e);

        detector.mark_replayed();

        // B crossing the threshold after the replay must NOT trigger a second
        // one: the single replay already covered it.
        assert!(
            !detector.observe_undecryptable(b.clone(), "b3".into(), e),
            "one account-wide replay should cover every stuck group at this epoch"
        );
    }

    #[test]
    fn an_epoch_advance_resets_the_count() {
        let mut detector = EpochStallDetector::new(3);
        let g = group(0x01);

        detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(19));
        detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(19));
        // The group advanced to epoch 20 — its commits are reaching us again, so
        // the earlier undecryptables must not count toward a stall at epoch 20.
        assert!(!detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(20)));
        assert!(!detector.observe_undecryptable(g.clone(), "m4".into(), EpochId(20)));
        assert!(
            detector.observe_undecryptable(g.clone(), "m5".into(), EpochId(20)),
            "the count should restart at the new epoch, not carry over"
        );
    }
}
