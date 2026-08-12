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
//! It also decides when that recovery is not working. A device can arm backfill
//! after backfill and still trail the group — the replay recovers some backlog,
//! the device advances an epoch, and the next epoch stalls just the same. The
//! detector counts the arms in such a run and escalates once it reaches
//! [`EPOCH_STALL_ESCALATION_ARM_THRESHOLD`], so the runtime can report a group
//! that full-history replay cannot repair instead of retrying it silently.
//!
//! All of this state is process-local, like the stall counts it extends: a
//! restart — or the client rebuild the runtime performs after a failed receive
//! pass — forgets an escalated run entirely. Re-escalating then costs a whole
//! fresh run of [`EPOCH_STALL_ESCALATION_ARM_THRESHOLD`] arms, and only the
//! first of those can land at the epoch the device already sits at, because an
//! arm at an epoch already fired at is skipped: every further arm needs a real
//! local epoch advance. A group whose epoch is still advancing therefore
//! escalates again two epochs later at the default threshold — delayed, not
//! lost — while a group frozen at one local epoch arms once and never escalates
//! again. That second case is a pre-existing blind spot of the arm counter, not
//! a restart artifact — a group frozen from its first arm never escalates in a
//! fresh process either — and is tracked for a follow-up. The
//! `epoch_stall_backfill_escalated` audit row the caller writes is the only
//! record that outlives the process, and only where audit logging is enabled
//! (opt-in, off by default).
//!
//! The policy is deliberately I/O-free so it can be unit-tested in isolation;
//! the recovery action it triggers — a full-history transport replay — lives in
//! the caller, which owns the runtime.

use std::collections::{HashMap, HashSet};

use cgka_traits::{EpochId, GroupId};
use marmot_forensics::EpochBackfillDeferredReason;
use rand::RngCore;

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

/// Backfills a group may arm in one unrecovered run — arms with no epoch the
/// device passed through cleanly in between — before the runtime reports the
/// full-history replay as insufficient and escalates to the app.
///
/// Empirical, like `EPOCH_STALL_BACKFILL_THRESHOLD`, and chosen from the
/// 2026-07-29 field cohort: one device armed at stalled epochs 10, 11, and 12
/// while staying nine epochs behind for hours, and a second armed a fourth time
/// with no new ingests in between — so both cases are worth escalating by their
/// third arm. Two would escalate a single unlucky follow-up (a commit landing
/// mid-replay legitimately leaves one arm's replay short of the tip); four costs
/// another stalled epoch, each of which needs a genuine commit plus a fresh
/// stall run, so it delays the report by the same hours the field devices lost.
///
/// Safety is structural on both sides: escalation only *reports*, it never
/// changes recovery behavior — the stronger heal (key-package rotation plus full
/// re-activation) stays an app decision — and an arm run cannot be inflated by
/// minted traffic, because each additional arm requires a real epoch advance,
/// which only an authenticated commit produces.
pub(crate) const EPOCH_STALL_ESCALATION_ARM_THRESHOLD: u32 = 3;

/// What one undecryptable-traffic observation decided.
///
/// `#[must_use]` because dropping a decision is unrecoverable, not merely
/// wasteful: the detector latches `escalated` when it raises
/// [`BackfillDecision::ArmAndEscalate`], so no later arm in the run raises it
/// again. Every decision belongs in `AppClient::apply_backfill_decision`.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackfillDecision {
    /// Nothing to do: the group has not (yet) crossed its stall threshold, or a
    /// backfill for this stalled epoch was already signalled.
    Skip,
    /// Arm one account-wide full-history backfill.
    Arm,
    /// Arm, and report that repeated arming is not recovering this group:
    /// `arms` backfills have been armed without the device passing cleanly
    /// through a single epoch.
    ArmAndEscalate { arms: u32 },
}

impl BackfillDecision {
    /// Whether this decision arms a full-history backfill.
    pub(crate) fn arms_backfill(self) -> bool {
        !matches!(self, Self::Skip)
    }
}

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
    /// The epoch this group last *armed* a backfill at. Distinct from
    /// `fired_at_epoch`, which also absorbs the storm-collapse suppression a
    /// replay applies to groups that never armed.
    armed_at_epoch: Option<EpochId>,
    /// Arms in the current unrecovered run: arms with no epoch the device left
    /// without arming at it (see [`GroupStall::observe_epoch`]).
    arms: u32,
    /// Whether the current run already escalated, so a run that keeps arming
    /// reports once rather than on every further arm.
    escalated: bool,
}

impl GroupStall {
    fn new(epoch: EpochId) -> Self {
        Self {
            epoch,
            undecryptable: HashSet::new(),
            fired_at_epoch: None,
            armed_at_epoch: None,
            arms: 0,
            escalated: false,
        }
    }

    /// Note the group's current local epoch, resetting the per-epoch stall
    /// accounting when it changed.
    ///
    /// Leaving an epoch the device *armed* at continues the unrecovered run: the
    /// replay moved the device forward but the group had already gone further.
    /// Leaving an epoch it passed through without arming ends the run — that is
    /// the closest this layer can observe to "the group reached the tip", since
    /// a device that cannot decrypt a group's traffic can never learn the
    /// group's live epoch. Ending the run also clears the escalation latch, so a
    /// group that stalls again much later is reported again.
    ///
    /// Deliberately *not* "the device decrypted something": a replay that
    /// recovers old backlog the device can read has not caught it up, and
    /// treating that as recovery is exactly what would hide the failure this
    /// counter exists to report. The cost of the stricter rule is that a device
    /// which keeps up fine but cannot read one peer's traffic — a forked peer, or
    /// minted envelopes — can also complete a run. The report stays true as
    /// stated (this device cannot read this group's traffic), and because
    /// escalation only reports, the app still owns whether a re-sync is the right
    /// answer.
    fn observe_epoch(&mut self, epoch: EpochId) {
        if self.epoch == epoch {
            return;
        }
        if self.armed_at_epoch != Some(self.epoch) {
            self.arms = 0;
            self.escalated = false;
        }
        self.epoch = epoch;
        self.undecryptable.clear();
        self.fired_at_epoch = None;
    }

    /// Record an arm at the current epoch and decide whether this run has now
    /// armed enough times to escalate.
    fn arm(&mut self, escalation_arm_threshold: u32) -> BackfillDecision {
        self.fired_at_epoch = Some(self.epoch);
        self.armed_at_epoch = Some(self.epoch);
        self.arms = self.arms.saturating_add(1);
        if self.arms >= escalation_arm_threshold && !self.escalated {
            self.escalated = true;
            BackfillDecision::ArmAndEscalate { arms: self.arms }
        } else {
            BackfillDecision::Arm
        }
    }
}

/// Decides, per group, when a run of undecryptable traffic at a stalled epoch
/// means the group has advanced past this device and a backfill is warranted.
pub(crate) struct EpochStallDetector {
    threshold: usize,
    escalation_arm_threshold: u32,
    groups: HashMap<GroupId, GroupStall>,
}

impl EpochStallDetector {
    pub(crate) fn new(threshold: usize, escalation_arm_threshold: u32) -> Self {
        Self {
            threshold,
            escalation_arm_threshold,
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

    /// The arms-per-unrecovered-run count at which this detector escalates.
    /// Reported on the `epoch_stall_backfill_escalated` audit row for the same
    /// reason [`Self::threshold`] is reported on the arm row.
    pub(crate) fn escalation_arm_threshold(&self) -> u32 {
        self.escalation_arm_threshold
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

    /// Note the current local epoch of an already-tracked `group` from a
    /// delivery that carried no stall evidence. Groups with no stall history are
    /// deliberately left untracked: this only exists so a tracked group's
    /// unrecovered arm run can end when the device leaves an epoch it never
    /// armed at (see [`GroupStall::observe_epoch`]).
    pub(crate) fn observe_group_epoch(&mut self, group: &GroupId, epoch: EpochId) {
        if let Some(stall) = self.groups.get_mut(group) {
            stall.observe_epoch(epoch);
        }
    }

    /// Record one undecryptable message for `group` observed while the group is
    /// at `epoch`. Arms exactly once when the group crosses the threshold at a
    /// stalled epoch, and escalates on the arm that completes an unrecovered run
    /// of [`EpochStallDetector::escalation_arm_threshold`] arms.
    pub(crate) fn observe_undecryptable(
        &mut self,
        group: GroupId,
        message: String,
        epoch: EpochId,
    ) -> BackfillDecision {
        let stall = self
            .groups
            .entry(group)
            .or_insert_with(|| GroupStall::new(epoch));
        stall.observe_epoch(epoch);
        // The message identity is attacker-mintable (a fresh envelope is a fresh
        // id), so the set never needs to grow past the point where it decides.
        if stall.undecryptable.len() < self.threshold {
            stall.undecryptable.insert(message);
        }
        let crossed = stall.undecryptable.len() >= self.threshold;
        if crossed && stall.fired_at_epoch != Some(epoch) {
            stall.arm(self.escalation_arm_threshold)
        } else {
            BackfillDecision::Skip
        }
    }

    /// A resource refusal proves that at least one object in the fetched
    /// history was not retained. Signal a replay immediately (once per epoch)
    /// instead of waiting for the undecryptable-message threshold: the
    /// threshold detects a likely gap, while this outcome is direct evidence
    /// of one. Refusal arms count toward escalation exactly like threshold arms:
    /// both mean "a full-history replay was armed for this group", and a run of
    /// refusals is the stronger evidence that replay cannot recover the group,
    /// since the objects it needs were not retained at all.
    pub(crate) fn observe_resource_refusal(
        &mut self,
        group: GroupId,
        epoch: EpochId,
    ) -> BackfillDecision {
        let stall = self
            .groups
            .entry(group)
            .or_insert_with(|| GroupStall::new(epoch));
        stall.observe_epoch(epoch);
        if stall.fired_at_epoch == Some(epoch) {
            BackfillDecision::Skip
        } else {
            stall.arm(self.escalation_arm_threshold)
        }
    }
}

impl Default for EpochStallDetector {
    fn default() -> Self {
        Self::new(
            EPOCH_STALL_BACKFILL_THRESHOLD,
            EPOCH_STALL_ESCALATION_ARM_THRESHOLD,
        )
    }
}

/// One armed group participating in a coalesced account-wide epoch-gap replay.
#[derive(Clone, Debug)]
pub(crate) struct PendingEpochBackfillGroup {
    pub(crate) stalled_epoch: u64,
}

/// In-memory deferral seam identity for epoch-gap replay audit debouncing.
///
/// Never emitted on the forensic wire; bounded by the pending group's armed set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EpochBackfillDeferredSnapshot {
    pub(crate) reason: EpochBackfillDeferredReason,
    pub(crate) retry_ordinal: u64,
    /// Armed group identity paired with the latest observed local epoch, if any.
    /// Sorted by opaque group-id bytes for stable comparison.
    pub(crate) group_epochs: Vec<(GroupId, Option<u64>)>,
}

/// Pending epoch-gap recovery intent: one opaque attempt id correlates every
/// lifecycle row for the current arm, and additional groups coalesce into the
/// same account-wide replay without minting a second attempt.
#[derive(Clone, Debug)]
pub(crate) struct PendingEpochBackfill {
    pub(crate) attempt_id: String,
    pub(crate) groups: HashMap<GroupId, PendingEpochBackfillGroup>,
    /// How many execution tries have started for this pending intent.
    pub(crate) execution_attempts: u32,
    /// Last deferred audit evidence keyed by the exact deferral seam snapshot.
    pub(crate) last_deferred_audit: Option<EpochBackfillDeferredSnapshot>,
}

impl PendingEpochBackfill {
    pub(crate) fn new() -> Self {
        Self {
            attempt_id: new_recovery_attempt_id(),
            groups: HashMap::new(),
            execution_attempts: 0,
            last_deferred_audit: None,
        }
    }
}

fn new_recovery_attempt_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let encoded = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &encoded[0..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(byte: u8) -> GroupId {
        GroupId::new(vec![byte])
    }

    /// A detector with a small stall threshold and the production escalation
    /// threshold, for the tests that are not about escalation.
    fn stall_detector(threshold: usize) -> EpochStallDetector {
        EpochStallDetector::new(threshold, EPOCH_STALL_ESCALATION_ARM_THRESHOLD)
    }

    #[test]
    fn escalates_when_arms_repeat_without_passing_cleanly_through_an_epoch() {
        // One undecryptable arms, so each stalled epoch below is one arm.
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // The field shape: the replay recovers some backlog, the device advances
        // an epoch, and it stalls again — three times over, never reaching tip.
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10)),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11)),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(12)),
            BackfillDecision::ArmAndEscalate { arms: 3 },
            "the threshold-th arm in an unrecovered run must escalate"
        );
    }

    #[test]
    fn an_escalated_run_reports_once_however_long_it_keeps_arming() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10));
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11));
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(12)),
            BackfillDecision::ArmAndEscalate { arms: 3 }
        );
        // The device keeps arming and keeps falling behind. It is already
        // reported; re-reporting every further arm would be the noise the app
        // cannot act on.
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m4".into(), EpochId(13)),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m5".into(), EpochId(14)),
            BackfillDecision::Arm
        );
    }

    #[test]
    fn an_epoch_the_device_passes_through_cleanly_ends_the_arm_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // Two arms into an unrecovered run.
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10));
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11));

        // The device then processes this group's traffic at 12 and moves on to 13
        // without ever stalling at 12 — it kept up with an epoch, which is as
        // close to "reached the tip" as this layer can observe.
        detector.observe_group_epoch(&g, EpochId(12));
        detector.observe_group_epoch(&g, EpochId(13));

        // So a fresh stall opens a new run instead of completing the old one.
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(13)),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m4".into(), EpochId(14)),
            BackfillDecision::Arm,
            "the arm count must have restarted, so this is the run's second arm"
        );
    }

    #[test]
    fn resource_refusal_arms_count_toward_the_same_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // A refused object and a stalled epoch are both "a full-history replay
        // was armed and did not get this device to the tip".
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10)),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_resource_refusal(g.clone(), EpochId(11)),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_resource_refusal(g.clone(), EpochId(12)),
            BackfillDecision::ArmAndEscalate { arms: 3 }
        );
    }

    #[test]
    fn storm_collapse_suppression_is_not_an_arm() {
        let mut detector = EpochStallDetector::new(2, 2);
        let a = group(0x0A);
        let b = group(0x0B);
        let e = EpochId(5);

        // A arms and the caller runs one account-wide replay, which suppresses
        // every tracked group at its current epoch — including B, which was
        // accumulating undecryptables but never armed.
        let _ = detector.observe_undecryptable(a.clone(), "a1".into(), e);
        assert_eq!(
            detector.observe_undecryptable(a, "a2".into(), e),
            BackfillDecision::Arm
        );
        let _ = detector.observe_undecryptable(b.clone(), "b1".into(), e);
        detector.mark_replayed();

        // B stalls at the next two epochs. Its run starts at the first of those
        // arms: the suppression it inherited was never a repair attempt of its
        // own, so it must not count toward escalating B.
        let _ = detector.observe_undecryptable(b.clone(), "b2".into(), EpochId(6));
        assert_eq!(
            detector.observe_undecryptable(b.clone(), "b3".into(), EpochId(6)),
            BackfillDecision::Arm
        );
        let _ = detector.observe_undecryptable(b.clone(), "b4".into(), EpochId(7));
        assert_eq!(
            detector.observe_undecryptable(b, "b5".into(), EpochId(7)),
            BackfillDecision::ArmAndEscalate { arms: 2 }
        );
    }

    #[test]
    fn deferred_snapshot_distinguishes_observed_epoch_at_same_cardinality() {
        let g = group(0x01);
        let phantom = group(0xde);
        let unchanged = EpochBackfillDeferredSnapshot {
            reason: EpochBackfillDeferredReason::GroupEpochUnavailable,
            retry_ordinal: 0,
            group_epochs: vec![(g.clone(), Some(5)), (phantom.clone(), None)],
        };
        let epoch_advanced = EpochBackfillDeferredSnapshot {
            reason: EpochBackfillDeferredReason::GroupEpochUnavailable,
            retry_ordinal: 0,
            group_epochs: vec![(g, Some(6)), (phantom, None)],
        };
        assert_ne!(
            unchanged, epoch_advanced,
            "observed local epoch transitions must change the deferral snapshot"
        );
    }

    #[test]
    fn signals_backfill_after_threshold_distinct_undecryptables_at_a_stable_epoch() {
        let mut detector = stall_detector(3);
        let g = group(0x01);
        let e = EpochId(19);

        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m1".into(), e)
                .arms_backfill()
        );
        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m2".into(), e)
                .arms_backfill()
        );
        assert!(
            detector
                .observe_undecryptable(g.clone(), "m3".into(), e)
                .arms_backfill(),
            "the threshold-crossing message should signal a backfill"
        );
    }

    #[test]
    fn signals_at_most_once_per_stalled_epoch() {
        let mut detector = stall_detector(3);
        let g = group(0x01);
        let e = EpochId(19);

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), e);
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), e);
        assert!(
            detector
                .observe_undecryptable(g.clone(), "m3".into(), e)
                .arms_backfill()
        );
        // Further undecryptable traffic at the same stalled epoch must not
        // re-signal: one replay per stalled epoch is enough, and re-signalling
        // would let a burst (or a spray of attacker-minted ids) trigger a storm.
        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m4".into(), e)
                .arms_backfill()
        );
        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m5".into(), e)
                .arms_backfill()
        );
    }

    #[test]
    fn resource_refusal_signals_immediately_once_per_epoch() {
        let mut detector = stall_detector(8);
        let g = group(0x01);

        assert!(
            detector
                .observe_resource_refusal(g.clone(), EpochId(19))
                .arms_backfill()
        );
        assert!(
            !detector
                .observe_resource_refusal(g.clone(), EpochId(19))
                .arms_backfill()
        );
        assert!(
            detector
                .observe_resource_refusal(g, EpochId(20))
                .arms_backfill()
        );
    }

    #[test]
    fn mark_replayed_collapses_a_storm_of_simultaneously_stuck_groups() {
        let mut detector = stall_detector(3);
        let a = group(0x0A);
        let b = group(0x0B);
        let e = EpochId(19);

        // Group A crosses the threshold and the caller runs ONE account-wide
        // replay (which re-fetches every group's history, B included).
        let _ = detector.observe_undecryptable(a.clone(), "a1".into(), e);
        let _ = detector.observe_undecryptable(a.clone(), "a2".into(), e);
        assert!(
            detector
                .observe_undecryptable(a.clone(), "a3".into(), e)
                .arms_backfill()
        );

        // Group B was accumulating undecryptables at the same epoch in the same
        // drain but had not yet crossed the threshold.
        let _ = detector.observe_undecryptable(b.clone(), "b1".into(), e);
        let _ = detector.observe_undecryptable(b.clone(), "b2".into(), e);

        detector.mark_replayed();

        // B crossing the threshold after the replay must NOT trigger a second
        // one: the single replay already covered it.
        assert!(
            !detector
                .observe_undecryptable(b.clone(), "b3".into(), e)
                .arms_backfill(),
            "one account-wide replay should cover every stuck group at this epoch"
        );
    }

    #[test]
    fn an_epoch_advance_resets_the_count() {
        let mut detector = stall_detector(3);
        let g = group(0x01);

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(19));
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(19));
        // The group advanced to epoch 20 — its commits are reaching us again, so
        // the earlier undecryptables must not count toward a stall at epoch 20.
        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m3".into(), EpochId(20))
                .arms_backfill()
        );
        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m4".into(), EpochId(20))
                .arms_backfill()
        );
        assert!(
            detector
                .observe_undecryptable(g.clone(), "m5".into(), EpochId(20))
                .arms_backfill(),
            "the count should restart at the new epoch, not carry over"
        );
    }
}
