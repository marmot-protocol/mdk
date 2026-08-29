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
//! What the detector counts is bounded by what it is told. Its only view of a
//! group's local epoch is the epoch handed to its own `observe_*` calls, so an
//! advance nobody reports leaves it believing the group never moved. Movement
//! reaches it as an epoch *passage*
//! ([`EpochStallDetector::observe_epoch_passage`]) — the engine's own
//! `EpochChanged` — so a device that recovers can end its own run even across
//! epochs no delivery was ever read at. Only a convergence reorg spans more than
//! one epoch in a single passage; a confirmed local publish and a folded peer
//! commit each advance exactly one, which is why the adjacency rule in
//! [`EpochStallDetector::observe_epoch_passage`] must stay a *delayed* reset and
//! not no reset at all.
//!
//! A group whose reported epoch never moves at all is the one shape that rule
//! cannot report, because every arm after the first needs that epoch to change
//! and the missing commit is the only thing that would change it. That group
//! gets a second rule, on a second kind of evidence. Its same-epoch re-arms are
//! paced on a wall clock
//! ([`EPOCH_STALL_WEDGE_REARM_INTERVAL_MS`]) — each one buys another
//! full-history replay, because a replay is the only thing that can learn
//! anything new — and it escalates once
//! [`EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD`] of those replays have come
//! back end-of-stored-events confirmed and empty
//! ([`EpochStallDetector::observe_fruitless_completion`]). Counting the relays'
//! verdicts rather than the arms is what keeps the minted-traffic property
//! below: garbage can pace attempts, it cannot forge a relay's confirmation
//! that it served everything it had.
//!
//! Runs are bounded in wall-clock too. Nothing else ends a quiet group's run,
//! so two arms more than [`EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS`] apart are
//! two runs, not one — an unrelated stall weeks after a single arm starts fresh
//! rather than landing as arm two of something long dead.
//!
//! The arm run is process-local, like the stall counts it extends. The
//! frozen-epoch evidence is not: a group with nothing to re-arm on but the
//! clock earns at most one confirmed fruitless replay per pacing interval, so a
//! device restarted more often than that would never reach the threshold at
//! all. (A group whose replay keeps *refusing* its history re-arms off those
//! refusals instead, unpaced, and reaches the threshold faster.) That evidence
//! and the
//! wall-clock mark of the last arm are persisted per group and restored at
//! account open ([`EpochStallDetector::restore_wedge_evidence`]). Wall-clock
//! deliberately: the counter survives a restart, but the restart never becomes
//! the re-arm clock.
//! `sync_with_partial_progress` moves a one-shot escalation into either its
//! success summary or its failure prefix before the managed runtime can rebuild
//! the client. The compatibility `sync()` API instead leaves it stashed after
//! an error so a caller retaining that client receives it on the next successful
//! seam. A caller that discards such a client also discards the detector run;
//! the opt-in `epoch_stall_backfill_escalated` audit row is then the only durable
//! trace.
//!
//! A discarded run is re-earned from zero rather than re-raised: escalating
//! again costs a whole fresh run of [`EPOCH_STALL_ESCALATION_ARM_THRESHOLD`]
//! arms, and only the first can land at the epoch the device already sits at,
//! because an arm at an epoch already fired at is skipped until the pacing
//! interval elapses. A group still reporting epoch advances therefore escalates
//! again once the run refills — delayed, not lost — and a frozen group reports
//! off its restored evidence instead.
//!
//! The policy is deliberately I/O-free so it can be unit-tested in isolation;
//! the recovery action it triggers — a full-history transport replay — lives in
//! the caller, which owns the runtime.

use std::collections::{HashMap, HashSet};

use cgka_traits::ingest::{DeferralLineage, IngestOutcome};
use cgka_traits::{EpochId, GroupId};
use marmot_forensics::{EpochBackfillDeferredReason, EpochStallBackfillTrigger};
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

/// Backfills a group may arm in one unrecovered run before the runtime reports
/// the full-history replay as insufficient and escalates to the app.
/// [`GroupStall::observe_epoch`] defines what starts and ends a run, and is the
/// place to read before reasoning about what this count means.
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
/// Safety on the output side is structural: escalation only *reports*, it never
/// changes recovery behavior — the stronger heal (key-package rotation plus full
/// re-activation) stays an app decision.
///
/// Safety on the input side is weaker than it looks, and the weakness is
/// recorded here rather than argued away. Each counted arm needs either a real
/// epoch advance, which only an authenticated commit produces, or a replay that
/// came back having refused this group's own history. Counting the refusal is
/// right: it is genuine local evidence that the deferred-peel cap is full and
/// that a replay could not retain what this group needs. But that cap is one
/// minted traffic can saturate by itself (mdk#339 — a fresh wrap yields a fresh
/// raw transport id, so a flood costs a sender nothing), and a saturated cap
/// answers `ResourceRefused` to the account-wide replay's own fetch for the
/// group too. That refusal lands in the drain's refused set, so
/// [`EpochStallDetector::rearm_refused_groups`] clears the very latch the arm
/// just set, and the next refusal takes the counted
/// [`GroupStall::arm`] branch instead of the paced one. A flood therefore walks
/// a group to this threshold in a run of retry backoffs rather than a run of
/// real stalls. What it buys is a false report and nothing else — the arm run
/// changes no recovery behavior — so the exposure is telemetry integrity, not
/// amplification. It is bounded, known, and tracked with the cap itself
/// (mdk#339); the loop is pinned by
/// `a_saturated_cap_can_drive_counted_arms_through_the_refusal_loop`, and the
/// remedy under discussion is a rate bound on refusal-driven re-arms, not
/// dropping the count.
///
/// The paced same-epoch re-arm a wedged group spends
/// ([`EPOCH_STALL_WEDGE_REARM_INTERVAL_MS`]) is a different path and does keep
/// its property: it deliberately does not count here, and what reports a wedged
/// group instead is [`EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD`].
pub(crate) const EPOCH_STALL_ESCALATION_ARM_THRESHOLD: u32 = 3;

/// How long a group wedged at one stalled epoch must wait between paced
/// same-epoch re-arms of its full-history replay.
///
/// A device whose missing commit is genuinely absent from the relays never sees
/// its epoch move, and every arm after the first needs that epoch to change —
/// so before this interval existed such a device armed once and then retried
/// nothing, forever. Re-arming is what runs another replay, and the replay is
/// the only thing that can produce new evidence, because decryption is
/// deterministic: a re-replay pays off only when its *inputs* changed, and
/// exactly two do change with time. Relay-side content changes when a commit is
/// published late — it carries an old `created_at`, so the floored live
/// subscription can never deliver it and the unfloored replay is the only
/// channel back to it. Local admission capacity changes when the deferred-peel
/// cap drains — a commit refused at a full cap is admitted by an identical
/// later replay. Both are time-shaped, which is why the pacing is a clock and
/// not a count.
///
/// One hour, cited to `CATCH_UP_GRACE_MS`
/// (`crates/incident-replay/src/classify.rs`), which already answers almost
/// exactly this question — how long being behind stops being ordinary catch-up
/// — and records a measured insensitivity plateau across [15 min, ~6 h]. Safety
/// is structural on both sides: too low costs extra whole-account replays,
/// which is the same operation a key-package publish already performs and is
/// separately bounded by the fruitless-replay retry cooldown; too high only
/// delays a report, because the evidence being gathered is monotone while the
/// group stays wedged.
///
/// A paced re-arm deliberately does *not* count toward
/// [`EPOCH_STALL_ESCALATION_ARM_THRESHOLD`]: what it is allowed to do is gather
/// evidence, and only the relay-confirmed evidence in
/// [`EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD`] escalates.
pub(crate) const EPOCH_STALL_WEDGE_REARM_INTERVAL_MS: u64 = 60 * 60 * 1_000;

/// How far apart two arms may be and still belong to the same unrecovered run.
///
/// [`GroupStall::observe_epoch`] ends a run on evidence and nothing ends it on
/// time, so without this bound a run is unbounded in wall-clock: a group that
/// armed once and then went quiet for weeks has an arm counter still sitting at
/// one, and an unrelated stall a month later lands as arm two of a long-dead
/// run. Bounding the *gap between consecutive arms* rather than the total run
/// length is what keeps the field shape — the 2026-07-29 cohort ran for hours —
/// while making a weeks-later arm start fresh.
///
/// Twenty-four hours, sized off the same incident-replay cohort
/// `EPOCH_STALL_WEDGE_REARM_INTERVAL_MS` cites: its real incidents stayed
/// behind 6 h and 18 h, so a genuine long stall stays one run.
///
/// Invariant: this window must exceed
/// [`EPOCH_STALL_WEDGE_REARM_INTERVAL_MS`], or a wedged group's own paced
/// re-arms would age out the very run they are continuing. Enforced by the
/// compile-time `const` assertion beside these constants.
pub(crate) const EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;

/// Replay completions that reached end-of-stored-events and recovered nothing,
/// at one stalled epoch, before the runtime reports the group as beyond what
/// full-history replay can repair.
///
/// This is the escalation rule for a group whose epoch never moves, and it
/// counts *evidence*, not attempts. A completion counts only when the relays
/// confirmed they had served the account's stored history
/// (`EpochBackfillCompletionKind::EndOfStoredEvents`) and the replay still
/// recovered nothing for the group (`AppClient::replay_recovered_something`).
/// That second check is account-wide, not per group: one kept delivery, or one
/// tracked group advancing anywhere in that replay, suppresses the count for
/// every group the replay was armed for. So the evidence this threshold
/// accumulates is conservative by construction — a busy account raises the bar
/// for reporting any of its groups, which delays a report rather than
/// inventing one.
/// A drain that gave up unconfirmed proves only that the drain gave up, and the
/// legacy `quiescence_fallback` completion is a deliberately weaker claim — so
/// neither counts. That restriction is what preserves the property
/// [`EPOCH_STALL_ESCALATION_ARM_THRESHOLD`] relies on: minted undecryptable
/// traffic can pace re-arms, but it cannot manufacture a relay's confirmation
/// that the history it asked for was served in full and held nothing.
///
/// Three, matching [`EPOCH_STALL_ESCALATION_ARM_THRESHOLD`] and for the same
/// reason: two escalates a single unlucky follow-up, four costs another whole
/// pacing interval. Safety is structural on both sides in the same way —
/// escalation only *reports*, and the count is monotone while the group stays
/// wedged, so being wrong high delays the report rather than losing it.
pub(crate) const EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD: u32 = 3;

/// The invariant the two wall-clock constants above are chosen under, checked
/// at compile time rather than by a test: a wedged group's own paced re-arms
/// must land inside the run window they are meant to continue, or the group
/// would age out its own run.
const _: () = assert!(EPOCH_STALL_WEDGE_REARM_INTERVAL_MS < EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS);

/// How far a recorded wall-clock mark may sit ahead of a later reading and
/// still be read as ordinary skew rather than as a clock that was wrong.
///
/// Five minutes, the same allowance ledger A8's `TRANSPORT_CURSOR_MAX_FUTURE_SKEW`
/// makes for a sender's timestamp, and for the same reason: two readings of
/// wall-clock time disagree a little, and a bound is what separates that from a
/// reading that cannot be true. Beyond it, a mark in the future of `now` is not
/// a duration at all — it is a dead RTC, a hand-set date, or a saturated
/// reading, taken before the clock was corrected — and treating it as zero
/// elapsed would wedge both gates permanently, durably, and silently.
pub(crate) const EPOCH_STALL_CLOCK_SKEW_ALLOWANCE_MS: u64 = 5 * 60 * 1_000;

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
    /// `arms` backfills have been armed in one unrecovered run (see
    /// [`GroupStall::observe_epoch`]).
    ArmAndEscalate { arms: u32 },
}

impl BackfillDecision {
    /// Whether this decision arms a full-history backfill.
    pub(crate) fn arms_backfill(self) -> bool {
        !matches!(self, Self::Skip)
    }
}

/// Which trigger a stall-arming ingest outcome records on its durable armed row.
///
/// **The chosen semantics for a fork-side deferral: it counts, it arms, and it
/// says so.** A deferral whose group's stored commit graph is contested is
/// evidence of being stuck exactly as any other undecryptable is, and it is fed
/// to the detector unchanged — suppressing it would cost more than the wasted
/// replay it saves. The detector's frozen-device escalation is gated on having
/// armed at the epoch the evidence was gathered at
/// ([`GroupStall::observe_fruitless_completion`]), so a group whose deferrals
/// did not arm can never report at all — and a forked group that never resolves
/// is precisely the wedge that most needs reporting. What changes is the label,
/// not the decision: the armed row names the fork, so an incident that keeps
/// arming under [`EpochStallBackfillTrigger::ContestedForkDeferral`] reads as a
/// fork to adjudicate rather than a device to re-sync. That costs the
/// escalation none of its #1590 properties — the evidence behind a report is
/// still the relays' own end-of-stored-events verdict, and the label is derived
/// from retained authenticated commits, so it cannot be minted by publishing
/// undecryptable envelopes.
///
/// Routing the group to convergence, which is what actually recovers it, needs
/// nothing here: the engine schedules a group for convergence on the same seam
/// that defers the object, and the app absorbs that through
/// `effects.pending_convergence` on the very same delivery.
pub(crate) fn backfill_trigger_for(outcome: &IngestOutcome) -> EpochStallBackfillTrigger {
    match outcome {
        IngestOutcome::TransportDeferred {
            lineage: DeferralLineage::ContestedFork,
            ..
        } => EpochStallBackfillTrigger::ContestedForkDeferral,
        IngestOutcome::ResourceRefused { .. } => EpochStallBackfillTrigger::ResourceRefusal,
        // Every other outcome reaching an arm decision is threshold evidence,
        // including a deferral with no fork evidence behind it — which is the
        // case a full-history replay is the right answer for.
        _ => EpochStallBackfillTrigger::UndecryptableThreshold,
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
    /// without arming at it (see [`GroupStall::observe_epoch`]). Paced
    /// same-epoch re-arms of a wedged group are deliberately not counted here;
    /// see [`GroupStall::rearm_wedged`].
    arms: u32,
    /// Whether the current run already escalated, so a run that keeps arming
    /// reports once rather than on every further arm. Process-local, like the
    /// `arms` it is paired with — a rebuilt client re-earns both.
    escalated: bool,
    /// Whether this run already reported off *frozen-epoch* evidence at
    /// `epoch`. The durable half of the report latch, and separate from
    /// `escalated` for exactly that reason: `arms` is not persisted, so
    /// rehydrating one shared latch would silence a fresh arm run the restart
    /// had nothing to say about. Its lifetime is the shorter of the run and the
    /// epoch, so both resets clear it.
    fruitless_reported: bool,
    /// Wall-clock ms at the last arm of the current run, whether it counted
    /// toward `arms` or not. Paces a wedged group's re-arms
    /// ([`EPOCH_STALL_WEDGE_REARM_INTERVAL_MS`]) and bounds a run in time
    /// ([`EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS`]).
    last_arm_at_ms: Option<u64>,
    /// End-of-stored-events replay completions that recovered nothing while
    /// this group sat at `epoch`. Per-epoch like `undecryptable`, because the
    /// question it answers is "how many times have the relays confirmed they
    /// have nothing that moves this device off *this* epoch".
    fruitless_completions: u32,
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
            fruitless_reported: false,
            last_arm_at_ms: None,
            fruitless_completions: 0,
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
    /// "Passed through" means *reported to this method*, which is narrower than
    /// "the device advanced": `self.epoch` only moves when a caller reports an
    /// epoch. A landing position — the epoch a delivery was read at — cannot be
    /// the *first* such report after an arm, because it arrives at the epoch the
    /// device already sits on, which leaves the armed epoch as the one being
    /// left. A *second* landing, at a further epoch, does end the run
    /// (`an_epoch_the_device_passes_through_cleanly_ends_the_arm_run` pins
    /// exactly that), but only if traffic happens to be read at both — which is
    /// accident, not design. The engine's `EpochChanged` passage makes the report
    /// unconditional: fed here as `from + 1` and then `to` by
    /// [`EpochStallDetector::observe_epoch_passage`], one passage supplies both
    /// reports on its own.
    ///
    /// The app routes that passage from every effects batch whose events it
    /// gates or projects (`AppClient::observe_recovery_evidence`) — the
    /// convergence folds a trailing device usually catches up by, and the
    /// maintenance tick's own confirmed evolution, included. Two send-path
    /// seams sit outside that routing, and both are empty exceptions rather
    /// than holes. `AppClient::redeliver_welcome` re-publishes a stored
    /// envelope without re-committing and never drains the engine, so its batch
    /// carries no events to observe. `AppClient::disband_group` is the same
    /// shape for a different reason: `Engine::do_send` short-circuits
    /// `SendIntent::Disband` straight to `do_request_disband`, which persists
    /// the durable request without staging a Commit, so that batch carries no
    /// publish work and no events of its own
    /// (`a_disband_request_carries_no_publish_work` pins that at the session
    /// layer). The `EpochChanged` the engine emits when a disband Commit
    /// confirms belongs to the later convergence pass `prepare_pending_disband`
    /// prepares that Commit on, and that batch does reach
    /// `observe_recovery_evidence`, through
    /// `AppClient::observe_scheduled_convergence_effects`. So the disband
    /// passage is reported like any other, and the same seam gates its publish.
    /// Arming from an observed batch is conditional on it carrying a
    /// `TransportObjectResourceRefused`; observing a passage is not.
    ///
    /// A batch that reports neither leaves the run exactly as it was: an advance
    /// nobody reports is invisible here, as
    /// `an_epoch_advance_the_detector_never_observed_does_not_end_the_arm_run`
    /// pins, and the runtime side of the passage report is pinned by
    /// `a_clean_recovery_reported_as_a_passage_ends_the_arm_run` in
    /// `tests/epoch_stall_backfill_audit.rs`.
    ///
    /// How far the epoch jumped does not enter into it: the rule compares only
    /// the armed epoch against the epoch being left, so a reported advance of
    /// five epochs decides exactly as one of a single epoch does. Span decides
    /// one level up, in [`EpochStallDetector::observe_epoch_passage`], where a
    /// passage becomes the two reports this rule then reads.
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
            self.end_run();
        }
        self.epoch = epoch;
        self.undecryptable.clear();
        self.fired_at_epoch = None;
        // Relay-confirmed evidence about the epoch being left says nothing
        // about the one being entered, and neither does having reported it.
        self.fruitless_completions = 0;
        self.fruitless_reported = false;
    }

    /// Start counting a fresh run.
    ///
    /// The frozen-epoch evidence goes with it. A run and a stalled epoch are
    /// two different lifetimes and only one of them is an epoch change, so a run
    /// can end while the group sits exactly where it was — the continuation
    /// window expiring is precisely that case. Clearing the report latch there
    /// without clearing the evidence behind it would let the very next
    /// completion report off a run that had already ended. A fresh run re-earns
    /// its evidence exactly as it re-earns its arms.
    fn end_run(&mut self) {
        self.arms = 0;
        self.escalated = false;
        self.fruitless_reported = false;
        self.fruitless_completions = 0;
        self.last_arm_at_ms = None;
    }

    /// End the arm run, leaving every epoch-scoped field standing.
    ///
    /// The one caller is [`Self::observe_convergence_reorg`], and the narrow
    /// blast radius is what makes it safe. [`Self::end_run`] is the *run and
    /// epoch* reset: it also drops the frozen-epoch evidence and the arm clock,
    /// which is right for its callers because each either re-notes an arm in
    /// the same breath ([`Self::arm`], [`Self::rearm_wedged`]) or is itself an
    /// epoch change ([`Self::observe_epoch`]). A same-epoch reorg is neither.
    /// It does not move the epoch, so nothing keyed on the epoch has expired:
    /// `fruitless_completions` and `fruitless_reported` still describe the
    /// relays' verdict about the epoch this device is still sitting on,
    /// `last_arm_at_ms` still paces re-arms at it, and `fired_at_epoch` /
    /// `armed_at_epoch` still debounce it.
    ///
    /// Both omissions are load-bearing, in opposite directions. Dropping
    /// `last_arm_at_ms` would leave `fired_at_epoch` naming an epoch with no
    /// mark to pace against, wedging [`Self::may_rearm_wedged`] shut for good on
    /// a group whose epoch never moves again — the exact failure the paced
    /// re-arm exists to prevent. Dropping the frozen-epoch evidence would hand a
    /// recurring reorg the power to silence the wedge report, and reorgs do
    /// recur: a losing commit is parked rather than consumed, so stored
    /// convergence re-derives and re-announces the same withdrawal on every pass
    /// it runs, and one unresolved fork plus ordinary member traffic produces a
    /// reorg per pass indefinitely.
    fn end_arm_run_keeping_epoch_evidence(&mut self) {
        self.arms = 0;
        self.escalated = false;
    }

    /// Convergence adjudicated a fork for this group: a commit on the branch
    /// this device was following lost a same-epoch branch selection and its
    /// state notifications were withdrawn.
    ///
    /// Ends the unrecovered *arm run*, for the same reason a passage spanning
    /// two or more epochs does. It is not proof the device reached the tip —
    /// nothing at this layer ever is — but it is proof that authenticated
    /// commits are arriving and being adjudicated against each other, which is
    /// the signature of a group that is alive rather than one this device has
    /// fallen out of. Escalating such a device recommends the wrong recovery:
    /// an account-wide relay replay cannot supply the branch adoption that
    /// fork-side traffic is waiting on.
    ///
    /// It has to be its own signal because nothing else carries it. A
    /// same-epoch reorg leaves `previous_tip == selected_tip`, so the engine
    /// emits no `EpochChanged`, and the epoch every other `observe_*` call
    /// reports is unchanged — [`Self::observe_epoch`] returns early and decides
    /// nothing.
    ///
    /// ### What this hands an adversary, and what bounds it
    ///
    /// State it plainly: this is a new capability, and unlike an ordinary
    /// commit it really can suppress the arm-run rule. An ordinary commit does
    /// not — [`Self::observe_epoch`] continues a run across an epoch the device
    /// *armed* at, which is the core rule of the escalation design — so a
    /// member who can fork the group gains something here that a member who
    /// merely commits does not have.
    ///
    /// Two things bound it. First, authentication holds: the withdrawal is
    /// raised only by stored convergence adjudicating commits that already
    /// passed authenticated admission, so a forgery is rejected against the
    /// candidate state long before it can supersede anything, and a non-member
    /// cannot provoke one at all. The capability is member-only, and a member
    /// already outranks the threat model the arm-run threshold was written
    /// against — that threshold exists to keep *minted undecryptable traffic*,
    /// which anyone can publish, from inflating a run.
    ///
    /// Second, and this is the half that has to hold by construction rather
    /// than by argument: the report a wedged group actually depends on is the
    /// frozen-epoch one, escalated from the relays' own end-of-stored-events
    /// verdict ([`Self::observe_fruitless_completion`]), and this method does
    /// not touch its evidence. So no reorg cadence, however dense, can silence
    /// a wedge report — it can only stop the arm *count* from being the thing
    /// that raises it.
    ///
    /// Deliberately does not touch `epoch`, `undecryptable`, `fired_at_epoch`,
    /// or `armed_at_epoch` either. Those are keyed on the stalled epoch, and a
    /// same-epoch reorg is exactly the movement that does not change it: the
    /// device is still where it was, still unable to read what it could not
    /// read, and still debounced against re-arming here.
    fn observe_convergence_reorg(&mut self) {
        self.end_arm_run_keeping_epoch_evidence();
    }

    /// Record an arm at the current epoch and decide whether this run has now
    /// armed enough times to escalate.
    ///
    /// An arm landing more than [`EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS`]
    /// after the previous one starts a fresh run instead of continuing the old
    /// one. Nothing else bounds a run in wall-clock — [`Self::observe_epoch`]
    /// ends runs on evidence, and a quiet group produces none — so without this
    /// an unrelated stall weeks later would land as arm two of a long-dead run.
    /// The bound is on the *gap between consecutive arms*, not on total run
    /// length: the field shape this counter exists for ran for hours, and
    /// bounding total length would lose it.
    fn arm(&mut self, now_ms: u64, escalation_arm_threshold: u32) -> BackfillDecision {
        self.expire_run_if_stale(now_ms);
        self.armed_at_epoch = Some(self.epoch);
        self.arms = self.arms.saturating_add(1);
        self.note_arm(now_ms);
        if self.arms >= escalation_arm_threshold && !self.escalated {
            self.escalated = true;
            BackfillDecision::ArmAndEscalate { arms: self.arms }
        } else {
            BackfillDecision::Arm
        }
    }

    /// Re-arm at an epoch this group already armed at, to gather evidence.
    ///
    /// Deliberately *not* an arm of the run. The undecryptable traffic that
    /// reaches this path is attacker-mintable, so letting a paced re-arm count
    /// toward [`EPOCH_STALL_ESCALATION_ARM_THRESHOLD`] would hand minted
    /// traffic an escalation for the price of waiting — exactly the property
    /// that threshold's doc claims it does not have. What the re-arm is allowed
    /// to do instead is run one more full-history replay, and the relays'
    /// verdict on that replay is the evidence that escalates
    /// ([`EpochStallDetector::observe_fruitless_completion`]).
    ///
    /// It expires a stale run exactly as [`Self::arm`] does. Pacing keeps
    /// consecutive re-arms an interval apart, which is well inside
    /// [`EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS`], but nothing keeps them
    /// *close*: a wedged group hears from its relays only when traffic arrives,
    /// so one message after a quiet week is a re-arm the window has already
    /// outlived. Without the check here that message would extend a run whose
    /// last arm was days ago and count its evidence toward the next report.
    fn rearm_wedged(&mut self, now_ms: u64) -> BackfillDecision {
        self.expire_run_if_stale(now_ms);
        self.note_arm(now_ms);
        BackfillDecision::Arm
    }

    /// End the run when this arm lands more than
    /// [`EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS`] after the previous one.
    ///
    /// Reads the mark through [`elapsed_since_mark_ms`], like the pacing gate
    /// beside it: a mark in the future of `now` is a clock that was wrong when
    /// it was taken, and calling that zero elapsed would let a corrected clock
    /// carry a dead run's arms and evidence into the next report. `end_run`
    /// leaves `armed_at_epoch` alone, so a fresh run does not cost this group
    /// the paced re-arm it just qualified for.
    fn expire_run_if_stale(&mut self, now_ms: u64) {
        if self.last_arm_at_ms.is_some_and(|last| {
            elapsed_since_mark_ms(now_ms, last) > EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS
        }) {
            self.end_run();
        }
    }

    /// Whether this group may spend a paced re-arm now.
    ///
    /// `armed_at_epoch == Some(self.epoch)` is load-bearing:
    /// [`EpochStallDetector::mark_replayed`] latches `fired_at_epoch` for every
    /// tracked group without setting `armed_at_epoch`, so without this conjunct
    /// a group that never armed would re-arm out of another group's replay
    /// suppression.
    ///
    /// There is no separate "fresh traffic arrived" conjunct because this is
    /// only ever asked from the two calls a message arriving *is*:
    /// [`EpochStallDetector::observe_undecryptable`] and
    /// [`EpochStallDetector::observe_resource_refusal`], which are the two
    /// answers the engine gives a message it cannot read. Liveness without
    /// leverage — the traffic decides when the question is asked, the clock
    /// decides the answer, and the relays decide what it is worth.
    fn may_rearm_wedged(&self, now_ms: u64, interval_ms: u64) -> bool {
        self.armed_at_epoch == Some(self.epoch)
            && self
                .last_arm_at_ms
                .is_some_and(|last| elapsed_since_mark_ms(now_ms, last) >= interval_ms)
    }

    fn note_arm(&mut self, now_ms: u64) {
        self.fired_at_epoch = Some(self.epoch);
        self.last_arm_at_ms = Some(now_ms);
    }

    /// Count one end-of-stored-events replay completion that recovered nothing
    /// while this group sat at the epoch it armed at. Reports whether that
    /// evidence has now earned an escalation this run has not already made.
    fn observe_fruitless_completion(&mut self, threshold: u32) -> Option<u32> {
        if self.armed_at_epoch != Some(self.epoch) {
            return None;
        }
        self.fruitless_completions = self.fruitless_completions.saturating_add(1);
        if self.fruitless_completions >= threshold && !self.escalated && !self.fruitless_reported {
            self.escalated = true;
            self.fruitless_reported = true;
            return Some(self.fruitless_completions);
        }
        None
    }
}

/// Wall-clock elapsed since a recorded mark, tolerant of a clock that ran ahead.
///
/// A mark ahead of `now` is not a negative duration — it is a reading that was
/// wrong when it was taken, from a dead RTC, a hand-set date, or a saturated
/// clock, and the device has since been corrected. Saturating the subtraction
/// would call that zero elapsed at every later reading, so both gates that
/// consult a mark would stay shut forever; and because the mark is durable, a
/// restart would not clear it either. Beyond
/// [`EPOCH_STALL_CLOCK_SKEW_ALLOWANCE_MS`] such a mark therefore reads as fully
/// elapsed, which self-heals in the safe direction: the pacing gate allows one
/// re-arm, and the run window starts a fresh run that re-earns its arms and its
/// evidence from zero.
///
/// Inside the allowance the answer is zero, because two honest readings of
/// wall-clock time disagree a little and a few minutes of that must not buy a
/// re-arm the interval had not earned.
fn elapsed_since_mark_ms(now_ms: u64, mark_ms: u64) -> u64 {
    match now_ms.checked_sub(mark_ms) {
        Some(elapsed) => elapsed,
        None if mark_ms - now_ms <= EPOCH_STALL_CLOCK_SKEW_ALLOWANCE_MS => 0,
        None => u64::MAX,
    }
}

/// Decides, per group, when a run of undecryptable traffic at a stalled epoch
/// means the group has advanced past this device and a backfill is warranted.
pub(crate) struct EpochStallDetector {
    threshold: usize,
    escalation_arm_threshold: u32,
    wedge_rearm_interval_ms: u64,
    fruitless_completion_threshold: u32,
    groups: HashMap<GroupId, GroupStall>,
}

impl EpochStallDetector {
    pub(crate) fn new(threshold: usize, escalation_arm_threshold: u32) -> Self {
        Self {
            threshold,
            escalation_arm_threshold,
            wedge_rearm_interval_ms: EPOCH_STALL_WEDGE_REARM_INTERVAL_MS,
            fruitless_completion_threshold: EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD,
            groups: HashMap::new(),
        }
    }

    /// Pace a wedged group's same-epoch re-arms `interval_ms` apart instead of
    /// the production [`EPOCH_STALL_WEDGE_REARM_INTERVAL_MS`].
    ///
    /// The only injection seam for the wedge clock: an hour is not a wall-clock
    /// budget any test can spend, and the alternative — reading a clock inside
    /// the detector — would cost the I/O-freedom the whole module is built on.
    pub(crate) fn with_wedge_rearm_interval_ms(mut self, interval_ms: u64) -> Self {
        self.wedge_rearm_interval_ms = interval_ms;
        self
    }

    /// Escalate a wedged group after `threshold` fruitless end-of-stored-events
    /// completions instead of the production
    /// [`EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD`].
    #[cfg(test)]
    pub(crate) fn with_fruitless_completion_threshold(mut self, threshold: u32) -> Self {
        self.fruitless_completion_threshold = threshold;
        self
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

    /// The confirmed-fruitless-completion count at which this detector reports a
    /// group wedged at one epoch. Logged as the deciding threshold when that
    /// rule is what escalated.
    pub(crate) fn fruitless_completion_threshold(&self) -> u32 {
        self.fruitless_completion_threshold
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

    /// Clear the replay-suppression latch for the groups a completed replay
    /// fetched history for and could not retain.
    ///
    /// Withholding [`Self::mark_replayed`] on a fruitless replay re-arms
    /// *bystanders* only. It cannot re-arm the group that caused the replay:
    /// that group latched `fired_at_epoch` itself in [`GroupStall::arm`], which
    /// writes the same value `mark_replayed` would have. Nothing else clears it
    /// — [`GroupStall::observe_epoch`] clears only on a *different* epoch, and
    /// the epoch cannot move without the very commit the replay failed to
    /// retain. So without this, one fruitless replay permanently ends automatic
    /// repair for that group: the refused object is neither marked seen nor
    /// allowed past the relay `since` floor, and the armed backfill is the only
    /// automatic path that re-serves it.
    ///
    /// Scoped to the refusals *this* drain counted rather than swept
    /// account-wide: a group the replay refused nothing for learned nothing from
    /// it, and clearing its latch would re-arm on evidence that does not exist.
    ///
    /// The run itself is untouched — `armed_at_epoch`, `arms` and `escalated`
    /// all survive — so a group that keeps re-arming still escalates exactly
    /// once per unrecovered run rather than restarting its count.
    pub(crate) fn rearm_refused_groups(&mut self, groups: &HashSet<GroupId>) {
        for group_id in groups {
            if let Some(stall) = self.groups.get_mut(group_id) {
                stall.fired_at_epoch = None;
            }
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

    /// Note that an already-tracked `group` moved *through* the epochs between
    /// `from` and `to`: the engine's own `EpochChanged` passage, as reported by a
    /// convergence reorg, a folded peer commit, or a confirmed local publish.
    ///
    /// A passage carries strictly more than a landing position: it names an epoch
    /// the device is no longer at. Every other `observe_*` call reports the epoch
    /// a delivery was *read* at, which is where the device already sits, while
    /// [`GroupStall::observe_epoch`] decides on the epoch being *left*. A device
    /// armed at 10 and recovered to 13 that reports only 13 is therefore still
    /// judged on leaving 10 — the epoch it armed at — and its run never ends.
    /// Feeding `from + 1` first moves the detector off the armed epoch, and
    /// feeding `to` then leaves an epoch nothing armed at, which is what ends the
    /// run.
    ///
    /// An adjacent passage (`to == from + 1`) deliberately does not end a run by
    /// itself: the second feed is the epoch the first already recorded, so it
    /// returns early, and the run ends only on the device's next movement off
    /// that epoch. One epoch of progress per arm is a device limping, not a
    /// device recovered — exactly the field shape escalation exists to report —
    /// while sustained movement resets. Adjacency is the common case, not the
    /// exception: a confirmed local publish (`from` synthesized as
    /// `new_epoch - 1`) and a folded peer commit (`before` -> `after`) always
    /// advance exactly one epoch, and only a convergence reorg can span several.
    /// So the rule has to be a *delayed* reset rather than none — a single-commit
    /// catch-up resets on the movement after it, which is the next passage the
    /// device reports. Pinned by
    /// `a_device_limping_one_epoch_per_arm_still_escalates` and
    /// `the_movement_after_an_adjacent_passage_ends_the_arm_run`.
    ///
    /// The observed epoch is monotone, and two guards keep it that way: a
    /// passage the engine reports as backward (`to <= from`) is dropped, and so
    /// is one ending at or behind the epoch already observed. Together they make
    /// a rollback and the re-climb after it silent — the device must pass its own
    /// previous high-water mark before anything is reported again, and then only
    /// the part of the passage beyond that mark is. Without the second guard the
    /// re-climb would walk `self.epoch` backwards, which resets the run and
    /// clears `fired_at_epoch`, so a device that merely retraced ground would end
    /// an unrecovered run *and* re-arm at an epoch it had already armed at. The
    /// same guard is what makes observing one `EpochChanged` twice decide as
    /// observing it once does. Pinned by
    /// `re_climbing_the_epochs_a_rollback_dropped_does_not_end_the_arm_run`,
    /// `a_passage_ending_at_or_behind_the_observed_epoch_changes_nothing`, and
    /// `a_stale_passage_does_not_reopen_storm_collapse_suppression`.
    ///
    /// What a span of two or more proves is worth stating plainly, because the
    /// reset turns on it. It is not proof the device reached the tip — this layer
    /// can never learn a group's live epoch, for the reason
    /// [`GroupStall::observe_epoch`] gives. It is proof that more than one commit
    /// applied in one go, which is the signature of an ingest pipe that started
    /// flowing again rather than one delivering a commit at a time. So the reset
    /// means "stop counting this run", not "this device recovered", and it is
    /// deliberately cheap to earn. A device still behind stalls again at its new
    /// epoch, re-arms, and escalates off the fresh run: being wrong here delays
    /// the report, it does not lose it, whereas the opposite default keeps
    /// escalating devices that did heal.
    ///
    /// `get_mut` like [`Self::observe_group_epoch`]: a passage is evidence about
    /// a stall run, never the start of one, so a group with no stall history
    /// stays untracked.
    pub(crate) fn observe_epoch_passage(&mut self, group: &GroupId, from: EpochId, to: EpochId) {
        // Only forward movement is evidence of progress. A reorg that rolls the
        // tip back reports a passage too, and synthesizing its intermediate
        // epoch would end an unrecovered run on a rollback.
        if to <= from {
            return;
        }
        let Some(stall) = self.groups.get_mut(group) else {
            return;
        };
        // The observed epoch only ever moves forward. A passage ending at or
        // behind it is ground already covered — a re-observed event, or the
        // re-climb after a dropped rollback — and feeding it would walk
        // `self.epoch` backwards, taking the fired-at suppression with it.
        if to <= stall.epoch {
            return;
        }
        // Synthesize the intermediate epoch only when it is itself forward.
        // Below the observed epoch it is not a step the device is taking now,
        // and reporting it would make the next feed misread which epoch is
        // being left.
        if from.next() > stall.epoch {
            stall.observe_epoch(from.next());
        }
        stall.observe_epoch(to);
    }

    /// Note that stored convergence adjudicated a fork for an already-tracked
    /// `group`: see [`GroupStall::observe_convergence_reorg`] for what that
    /// ends and what it deliberately leaves alone.
    ///
    /// The caller passes the group off the engine's own
    /// [`GroupEvent::GroupStateInvalidated`] withdrawal, once per superseded
    /// commit. Ending an already-ended arm run is a no-op, so a pass that
    /// withdraws several commits decides as one that withdrew one — and so does
    /// the *next* pass re-announcing the same withdrawal, which is the ordinary
    /// case for a fork that has not resolved.
    ///
    /// `get_mut` like [`Self::observe_epoch_passage`]: a reorg is evidence
    /// about a stall run, never the start of one, so a group with no stall
    /// history stays untracked.
    ///
    /// [`GroupEvent::GroupStateInvalidated`]: cgka_traits::engine::GroupEvent::GroupStateInvalidated
    pub(crate) fn observe_convergence_reorg(&mut self, group: &GroupId) {
        if let Some(stall) = self.groups.get_mut(group) {
            stall.observe_convergence_reorg();
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
        now_ms: u64,
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
        if stall.undecryptable.len() < self.threshold {
            return BackfillDecision::Skip;
        }
        if stall.fired_at_epoch != Some(epoch) {
            return stall.arm(now_ms, self.escalation_arm_threshold);
        }
        // Already signalled at this epoch. A group whose epoch still moves gets
        // its next arm from that movement; a group wedged at one epoch gets no
        // movement ever, so its only way back to a replay is this paced re-arm.
        if stall.may_rearm_wedged(now_ms, self.wedge_rearm_interval_ms) {
            return stall.rearm_wedged(now_ms);
        }
        BackfillDecision::Skip
    }

    /// A resource refusal proves that at least one object in the fetched
    /// history was not retained. Signal a replay immediately (once per epoch)
    /// instead of waiting for the undecryptable-message threshold: the
    /// threshold detects a likely gap, while this outcome is direct evidence
    /// of one. Refusal arms count toward escalation exactly like threshold arms:
    /// both mean "a full-history replay was armed for this group", and a run of
    /// refusals is the stronger evidence that replay cannot recover the group,
    /// since the objects it needs were not retained at all. The paced
    /// same-epoch re-arm below is the one exception, and it is the same
    /// exception [`EpochStallDetector::observe_undecryptable`] makes: it is not
    /// an arm of the run, only of the replay, because the flood cap a refusal
    /// reports is one minted traffic can saturate by itself (mdk#339). What
    /// reports a group re-arming off refusals alone is
    /// [`EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD`].
    ///
    /// That re-arm is not a nicety for symmetry's sake. A group whose
    /// deferred-peel cap is full is answered `ResourceRefused` for *every*
    /// further message, undecryptable ones included, so this is the only
    /// `observe_*` call it makes — and its cap is durable, so a restart
    /// restores the latch without restoring any other way past it.
    pub(crate) fn observe_resource_refusal(
        &mut self,
        group: GroupId,
        epoch: EpochId,
        now_ms: u64,
    ) -> BackfillDecision {
        let stall = self
            .groups
            .entry(group)
            .or_insert_with(|| GroupStall::new(epoch));
        stall.observe_epoch(epoch);
        if stall.fired_at_epoch != Some(epoch) {
            return stall.arm(now_ms, self.escalation_arm_threshold);
        }
        if stall.may_rearm_wedged(now_ms, self.wedge_rearm_interval_ms) {
            return stall.rearm_wedged(now_ms);
        }
        BackfillDecision::Skip
    }

    /// Count one replay completion that reached end-of-stored-events and
    /// recovered nothing, against each of the `groups` it was armed for.
    ///
    /// This is the escalation rule for a group whose epoch never moves, and the
    /// admission test is deliberately narrow (see
    /// [`EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD`]): the caller passes only
    /// completions the relays confirmed served the account's stored history in
    /// full, and only ones that recovered nothing. A group that has since left
    /// the epoch it armed at is skipped — it is no longer wedged where the
    /// evidence was gathered.
    ///
    /// Returns one entry per group whose evidence has now earned a report that
    /// its run has not already made. Like every escalation, this only reports;
    /// the replay it followed is unaffected.
    pub(crate) fn observe_fruitless_completion<'groups>(
        &mut self,
        groups: impl IntoIterator<Item = &'groups GroupId>,
    ) -> Vec<FruitlessEscalation> {
        let threshold = self.fruitless_completion_threshold;
        groups
            .into_iter()
            .filter_map(|group_id| {
                let stall = self.groups.get_mut(group_id)?;
                let completions = stall.observe_fruitless_completion(threshold)?;
                Some(FruitlessEscalation {
                    group_id: group_id.clone(),
                    stalled_epoch: stall.epoch.0,
                    completions,
                })
            })
            .collect()
    }

    /// The durable frozen-epoch evidence for `group`, for the storage row that
    /// carries it across a restart. `None` for a group with no stall history.
    pub(crate) fn wedge_evidence(&self, group: &GroupId) -> Option<EpochStallEvidence> {
        let stall = self.groups.get(group)?;
        Some(EpochStallEvidence {
            stalled_epoch: stall.epoch.0,
            fruitless_completions: stall.fruitless_completions,
            fruitless_reported: stall.fruitless_reported,
            last_arm_at_ms: stall.last_arm_at_ms?,
        })
    }

    /// Rebuild the frozen-epoch evidence a previous process gathered.
    ///
    /// Only the per-epoch evidence and the wall-clock arm mark survive: the arm
    /// run itself stays process-local, as the module header describes. That
    /// split is the whole point. Persisting the counter is what stops a restart
    /// from erasing hours of confirmed relay verdicts, while persisting
    /// `last_arm_at_ms` as wall-clock is what stops the restart from *becoming*
    /// the re-arm clock — a force-killed daemon must not buy a re-arm it had
    /// not waited for. `fruitless_reported` rides along so a restart cannot
    /// re-report frozen-epoch evidence that already earned its report.
    ///
    /// A restored group starts with an empty undecryptable set, so it must
    /// re-earn the stall threshold before it can spend a paced re-arm. An entry
    /// whose `stalled_epoch` no longer matches is harmless: the first
    /// observation at the real epoch resets the per-epoch evidence exactly as a
    /// live epoch move does.
    pub(crate) fn restore_wedge_evidence(
        &mut self,
        entries: impl IntoIterator<Item = (GroupId, EpochStallEvidence)>,
    ) {
        for (group_id, evidence) in entries {
            let epoch = EpochId(evidence.stalled_epoch);
            let stall = self
                .groups
                .entry(group_id)
                .or_insert_with(|| GroupStall::new(epoch));
            stall.epoch = epoch;
            stall.armed_at_epoch = Some(epoch);
            stall.fired_at_epoch = Some(epoch);
            stall.last_arm_at_ms = Some(evidence.last_arm_at_ms);
            stall.fruitless_completions = evidence.fruitless_completions;
            stall.fruitless_reported = evidence.fruitless_reported;
        }
    }
}

/// A wedged group whose fruitless end-of-stored-events completions have reached
/// [`EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FruitlessEscalation {
    pub(crate) group_id: GroupId,
    pub(crate) stalled_epoch: u64,
    /// Confirmed fruitless replay completions at `stalled_epoch`. Reported as
    /// the escalation's `arms`: each completion is one armed full-history
    /// replay the relays confirmed served the stored history and that recovered
    /// nothing, which is the same claim the arm count makes and a stricter one.
    pub(crate) completions: u32,
}

/// The part of a group's stall state that survives a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EpochStallEvidence {
    pub(crate) stalled_epoch: u64,
    pub(crate) fruitless_completions: u32,
    pub(crate) fruitless_reported: bool,
    pub(crate) last_arm_at_ms: u64,
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
    /// How many drains ended because the EOSE gate timed out or could not be
    /// observed. Worker-quantum yields do not unlock the weaker fallback.
    pub(crate) eose_unconfirmed_attempts: u32,
    /// Consecutive worker-quantum yields with no durable novel progress, used
    /// only to pace retries without changing the drain-completion contract.
    pub(crate) no_progress_attempts: u32,
    /// Last deferred audit evidence keyed by the exact deferral seam snapshot.
    pub(crate) last_deferred_audit: Option<EpochBackfillDeferredSnapshot>,
}

impl PendingEpochBackfill {
    pub(crate) fn new() -> Self {
        Self {
            attempt_id: new_recovery_attempt_id(),
            groups: HashMap::new(),
            execution_attempts: 0,
            eose_unconfirmed_attempts: 0,
            no_progress_attempts: 0,
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

    /// One fixed wall-clock instant, in ms.
    ///
    /// Every test below that does not care about the frozen-epoch clock arms at
    /// exactly this instant, so no pacing interval ever elapses and no run
    /// continuation window ever expires: the two time gates stay inert and the
    /// test decides on the evidence rules alone.
    const T0: u64 = 1_700_000_000_000;

    const HOUR_MS: u64 = 60 * 60 * 1_000;

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
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11), T0),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(12), T0),
            BackfillDecision::ArmAndEscalate { arms: 3 },
            "the threshold-th arm in an unrecovered run must escalate"
        );
    }

    #[test]
    fn an_escalated_run_reports_once_however_long_it_keeps_arming() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11), T0);
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(12), T0),
            BackfillDecision::ArmAndEscalate { arms: 3 }
        );
        // The device keeps arming and keeps falling behind. It is already
        // reported; re-reporting every further arm would be the noise the app
        // cannot act on.
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m4".into(), EpochId(13), T0),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m5".into(), EpochId(14), T0),
            BackfillDecision::Arm
        );
    }

    #[test]
    fn an_epoch_the_device_passes_through_cleanly_ends_the_arm_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // Two arms into an unrecovered run.
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11), T0);

        // The device then processes this group's traffic at 12 and moves on to 13
        // without ever stalling at 12 — it kept up with an epoch, which is as
        // close to "reached the tip" as this layer can observe.
        detector.observe_group_epoch(&g, EpochId(12));
        detector.observe_group_epoch(&g, EpochId(13));

        // So a fresh stall opens a new run instead of completing the old one.
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(13), T0),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m4".into(), EpochId(14), T0),
            BackfillDecision::Arm,
            "the arm count must have restarted, so this is the run's second arm"
        );
    }

    /// Pins the reporting rule in [`GroupStall::observe_epoch`]: a run ends on an
    /// *observation* at an epoch the device did not arm at, and an epoch the
    /// detector is never told about cannot be that observation.
    ///
    /// The runtime now reports the epochs a fold carries a device through, as a
    /// passage — so the field shape this rule used to punish is handled by
    /// [`EpochStallDetector::observe_epoch_passage`] and pinned by
    /// `a_spanning_passage_off_the_armed_epoch_ends_the_arm_run`. The rule below
    /// is still the one the detector runs on, and it still decides any batch that
    /// reports nothing: the observation is omitted here by hand, so this test
    /// states what silence costs rather than what the runtime does.
    #[test]
    fn an_epoch_advance_the_detector_never_observed_does_not_end_the_arm_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // One arm at 10, then the device is carried to 13 by advances the
        // detector is never told about — the convergence fold reaches no
        // `observe_*` call, so nothing between the arm and the next stall records
        // 11, 12 or 13.
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);

        // The next stall is therefore the first observation since the arm, and it
        // finds the detector still sitting at the epoch it armed at. The run
        // continues even though the device passed through three epochs in between,
        // and reaches its escalation threshold.
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(13), T0),
            BackfillDecision::Arm,
            "an unobserved advance leaves the run open, so this is arm two"
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(14), T0),
            BackfillDecision::ArmAndEscalate { arms: 3 },
        );
    }

    /// A passage that leaves the armed epoch behind ends the run, and clears the
    /// escalation latch with it, so a group that stalls again much later is
    /// reported again.
    #[test]
    fn a_spanning_passage_off_the_armed_epoch_ends_the_arm_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // A full unrecovered run, reported.
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11), T0);
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(12), T0),
            BackfillDecision::ArmAndEscalate { arms: 3 }
        );

        // One convergence fold then carries the device from 12 to 15. It passed
        // through 13 and 14 without arming at either, which is as close to
        // "reached the tip" as this layer can observe.
        detector.observe_epoch_passage(&g, EpochId(12), EpochId(15));

        // So the stalls that follow are a new run, counted from one, and able to
        // report again on their own third arm rather than staying latched shut.
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m4".into(), EpochId(15), T0),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m5".into(), EpochId(16), T0),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m6".into(), EpochId(17), T0),
            BackfillDecision::ArmAndEscalate { arms: 3 },
            "the passage must have cleared the escalation latch too"
        );
    }

    /// One epoch of progress per arm is not recovery, so an adjacent passage
    /// does not end the run by itself — the run keeps counting to escalation.
    #[test]
    fn a_device_limping_one_epoch_per_arm_still_escalates() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // Arm, limp forward exactly one epoch, stall again at it: the field
        // shape, now with the advance actually reported.
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        detector.observe_epoch_passage(&g, EpochId(10), EpochId(11));
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11), T0),
            BackfillDecision::Arm
        );
        detector.observe_epoch_passage(&g, EpochId(11), EpochId(12));
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(12), T0),
            BackfillDecision::ArmAndEscalate { arms: 3 },
            "a device that arms at every epoch it reaches is still failing to catch up"
        );
    }

    /// The movement *after* an adjacent passage is what ends the run: it leaves
    /// an epoch nothing armed at.
    #[test]
    fn the_movement_after_an_adjacent_passage_ends_the_arm_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // Two arms into a run, one epoch apart.
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        detector.observe_epoch_passage(&g, EpochId(10), EpochId(11));
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11), T0);

        // The device then keeps moving: it reaches 12, arms nothing there, and
        // moves on to 13. Leaving 12 is the clean pass that ends the run.
        detector.observe_epoch_passage(&g, EpochId(11), EpochId(12));
        detector.observe_epoch_passage(&g, EpochId(12), EpochId(13));

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(13), T0),
            BackfillDecision::Arm,
            "sustained movement must restart the run, so this is its first arm"
        );
    }

    #[test]
    fn a_passage_for_a_group_with_no_stall_history_leaves_it_untracked() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // A passage is evidence *about* a stall run, never the start of one.
        detector.observe_epoch_passage(&g, EpochId(10), EpochId(14));

        // Storm-collapse suppression covers tracked groups only, so a first arm
        // surviving it proves the passage created no entry to suppress.
        detector.mark_replayed();
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(14), T0),
            BackfillDecision::Arm,
            "a passage must not enroll a group with no stall history"
        );
    }

    #[test]
    fn a_backward_passage_is_not_progress_and_leaves_the_run_open() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);

        // A reorg that rolls the tip back moves the device away from the group's
        // history, not toward it. Synthesizing an intermediate epoch here would
        // end an unrecovered run on a rollback.
        detector.observe_epoch_passage(&g, EpochId(10), EpochId(9));

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11), T0),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(12), T0),
            BackfillDecision::ArmAndEscalate { arms: 3 },
            "the rollback must not have ended the run"
        );
    }

    /// A dropped backward passage leaves the detector above the engine's tip.
    /// The forward passages that re-climb that same ground are not new progress,
    /// so they must not end the run, reopen the fired-at suppression, or let the
    /// device re-arm at an epoch it already armed at.
    #[test]
    fn re_climbing_the_epochs_a_rollback_dropped_does_not_end_the_arm_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // Two arms into a run, one epoch apart, so the detector sits at 15.
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(14), T0);
        detector.observe_epoch_passage(&g, EpochId(14), EpochId(15));
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(15), T0);

        // A reorg rolls the tip back to 12. The passage is dropped, so the
        // detector keeps believing 15 while the engine restarts from 12.
        detector.observe_epoch_passage(&g, EpochId(15), EpochId(12));
        detector.observe_epoch_passage(&g, EpochId(12), EpochId(13));
        detector.observe_epoch_passage(&g, EpochId(13), EpochId(14));
        detector.observe_epoch_passage(&g, EpochId(14), EpochId(15));

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(15), T0),
            BackfillDecision::Skip,
            "re-climbing to 15 must not reopen the backfill already fired there"
        );

        // And the run is intact: the next genuine advance is still arm three.
        detector.observe_epoch_passage(&g, EpochId(15), EpochId(16));
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m4".into(), EpochId(16), T0),
            BackfillDecision::ArmAndEscalate { arms: 3 },
            "the re-climb must not have reset the run"
        );
    }

    /// The detector's epoch only ever moves forward, so a passage that ends
    /// at-or-behind where it already sits is not evidence of anything. Pins
    /// idempotency: observing one `EpochChanged` twice decides as observing it
    /// once does.
    #[test]
    fn a_passage_ending_at_or_behind_the_observed_epoch_changes_nothing() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // A spanning passage ends the first run, then two arms open a new one.
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(12), T0);
        detector.observe_epoch_passage(&g, EpochId(12), EpochId(15));
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(15), T0);
        detector.observe_epoch_passage(&g, EpochId(15), EpochId(16));
        let _ = detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(16), T0);

        // The very same passage observed a second time, now far behind the tip.
        detector.observe_epoch_passage(&g, EpochId(12), EpochId(15));

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m4".into(), EpochId(16), T0),
            BackfillDecision::Skip,
            "a re-observed passage must not reopen the backfill fired at 16"
        );

        detector.observe_epoch_passage(&g, EpochId(16), EpochId(17));
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m5".into(), EpochId(17), T0),
            BackfillDecision::ArmAndEscalate { arms: 3 },
            "a re-observed passage must not reset the run either"
        );
    }

    /// The same rule guarding the run also guards storm-collapse suppression: a
    /// stale passage that lands back on the epoch a replay already covered must
    /// not hand the group a second account-wide replay for free.
    #[test]
    fn a_stale_passage_does_not_reopen_storm_collapse_suppression() {
        let mut detector = EpochStallDetector::new(2, 3);
        let g = group(0x01);

        // Tracked but never armed, then suppressed by someone else's replay.
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0),
            BackfillDecision::Skip
        );
        detector.mark_replayed();

        // A passage the device already made, re-reported: no movement at all.
        detector.observe_epoch_passage(&g, EpochId(8), EpochId(10));

        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(10), T0);
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(10), T0),
            BackfillDecision::Skip,
            "the replay suppression at 10 must survive a stale passage"
        );
    }

    #[test]
    fn resource_refusal_arms_count_toward_the_same_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        // A refused object and a stalled epoch are both "a full-history replay
        // was armed and did not get this device to the tip".
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_resource_refusal(g.clone(), EpochId(11), T0),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_resource_refusal(g.clone(), EpochId(12), T0),
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
        let _ = detector.observe_undecryptable(a.clone(), "a1".into(), e, T0);
        assert_eq!(
            detector.observe_undecryptable(a, "a2".into(), e, T0),
            BackfillDecision::Arm
        );
        let _ = detector.observe_undecryptable(b.clone(), "b1".into(), e, T0);
        detector.mark_replayed();

        // B stalls at the next two epochs. Its run starts at the first of those
        // arms: the suppression it inherited was never a repair attempt of its
        // own, so it must not count toward escalating B.
        let _ = detector.observe_undecryptable(b.clone(), "b2".into(), EpochId(6), T0);
        assert_eq!(
            detector.observe_undecryptable(b.clone(), "b3".into(), EpochId(6), T0),
            BackfillDecision::Arm
        );
        let _ = detector.observe_undecryptable(b.clone(), "b4".into(), EpochId(7), T0);
        assert_eq!(
            detector.observe_undecryptable(b, "b5".into(), EpochId(7), T0),
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
                .observe_undecryptable(g.clone(), "m1".into(), e, T0)
                .arms_backfill()
        );
        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m2".into(), e, T0)
                .arms_backfill()
        );
        assert!(
            detector
                .observe_undecryptable(g.clone(), "m3".into(), e, T0)
                .arms_backfill(),
            "the threshold-crossing message should signal a backfill"
        );
    }

    #[test]
    fn signals_at_most_once_per_stalled_epoch() {
        let mut detector = stall_detector(3);
        let g = group(0x01);
        let e = EpochId(19);

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), e, T0);
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), e, T0);
        assert!(
            detector
                .observe_undecryptable(g.clone(), "m3".into(), e, T0)
                .arms_backfill()
        );
        // Further undecryptable traffic at the same stalled epoch must not
        // re-signal: one replay per stalled epoch is enough, and re-signalling
        // would let a burst (or a spray of attacker-minted ids) trigger a storm.
        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m4".into(), e, T0)
                .arms_backfill()
        );
        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m5".into(), e, T0)
                .arms_backfill()
        );
    }

    #[test]
    fn resource_refusal_signals_immediately_once_per_epoch() {
        let mut detector = stall_detector(8);
        let g = group(0x01);

        assert!(
            detector
                .observe_resource_refusal(g.clone(), EpochId(19), T0)
                .arms_backfill()
        );
        assert!(
            !detector
                .observe_resource_refusal(g.clone(), EpochId(19), T0)
                .arms_backfill()
        );
        assert!(
            detector
                .observe_resource_refusal(g, EpochId(20), T0)
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
        let _ = detector.observe_undecryptable(a.clone(), "a1".into(), e, T0);
        let _ = detector.observe_undecryptable(a.clone(), "a2".into(), e, T0);
        assert!(
            detector
                .observe_undecryptable(a.clone(), "a3".into(), e, T0)
                .arms_backfill()
        );

        // Group B was accumulating undecryptables at the same epoch in the same
        // drain but had not yet crossed the threshold.
        let _ = detector.observe_undecryptable(b.clone(), "b1".into(), e, T0);
        let _ = detector.observe_undecryptable(b.clone(), "b2".into(), e, T0);

        detector.mark_replayed();

        // B crossing the threshold after the replay must NOT trigger a second
        // one: the single replay already covered it.
        assert!(
            !detector
                .observe_undecryptable(b.clone(), "b3".into(), e, T0)
                .arms_backfill(),
            "one account-wide replay should cover every stuck group at this epoch"
        );
    }

    #[test]
    fn an_epoch_advance_resets_the_count() {
        let mut detector = stall_detector(3);
        let g = group(0x01);

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(19), T0);
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(19), T0);
        // The group advanced to epoch 20 — its commits are reaching us again, so
        // the earlier undecryptables must not count toward a stall at epoch 20.
        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m3".into(), EpochId(20), T0)
                .arms_backfill()
        );
        assert!(
            !detector
                .observe_undecryptable(g.clone(), "m4".into(), EpochId(20), T0)
                .arms_backfill()
        );
        assert!(
            detector
                .observe_undecryptable(g.clone(), "m5".into(), EpochId(20), T0)
                .arms_backfill(),
            "the count should restart at the new epoch, not carry over"
        );
    }

    /// A reorg ends the run without opening a window on the replay.
    ///
    /// This is one of the omissions `end_arm_run_keeping_epoch_evidence`
    /// exists for, from both sides. Clear the mark and the paced re-arm gate
    /// reads `None` and stays shut forever on a wedged group — the very group
    /// the pacing was added for. Clear `fired_at_epoch` instead and every reorg
    /// buys an immediate unpaced account-wide replay, which is leverage a
    /// member who forks the group at will would happily pay for.
    #[test]
    fn a_reorg_ends_the_run_without_unlocking_an_unpaced_rearm() {
        let mut detector = EpochStallDetector::new(1, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0),
            BackfillDecision::Arm
        );
        detector.observe_convergence_reorg(&g);

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(10), T0 + HOUR_MS - 1),
            BackfillDecision::Skip,
            "the reorg left the arm clock standing, so pacing still gates the replay",
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(10), T0 + HOUR_MS),
            BackfillDecision::Arm,
            "and the wedged group still earns its paced re-arm once the interval elapses",
        );
    }

    /// The shape that decides the whole rescope: a group whose fork never
    /// resolves still escalates, off the relays' own verdict.
    ///
    /// Reorgs are not rare punctuation on a forked group — they recur. A losing
    /// commit is parked rather than consumed, so every convergence pass
    /// re-derives and re-announces the same withdrawal, and ordinary member
    /// traffic is enough to run a pass per round indefinitely. If a reorg reset
    /// the frozen-epoch evidence along with the arm run, the count below would
    /// return to zero every round and this group — wedged at one epoch, relays
    /// confirming round after round that they hold nothing that moves it —
    /// could never report at all. Keeping the epoch-scoped evidence out of the
    /// reset makes the report survive by construction rather than by cadence.
    #[test]
    fn a_chronically_forked_group_still_escalates_off_relay_confirmed_evidence() {
        let mut detector = EpochStallDetector::new(1, 3)
            .with_wedge_rearm_interval_ms(HOUR_MS)
            .with_fruitless_completion_threshold(3);
        let g = group(0x01);

        let mut reports = Vec::new();
        for round in 0..12u64 {
            // Fresh undecryptable traffic arrives and the paced replay runs.
            assert_eq!(
                detector.observe_undecryptable(
                    g.clone(),
                    format!("fork-side-{round}"),
                    EpochId(10),
                    T0 + round * HOUR_MS,
                ),
                BackfillDecision::Arm,
                "round {round}: a wedged group's paced re-arm is its only replay",
            );
            // The relays serve the account's stored history in full and it
            // recovers nothing.
            reports.extend(detector.observe_fruitless_completion([&g]));
            // And the unresolved fork is re-adjudicated, announcing the same
            // withdrawal again.
            detector.observe_convergence_reorg(&g);
        }

        assert_eq!(
            reports.len(),
            1,
            "exactly one report: earned on the third relay-confirmed completion, then latched for this epoch",
        );
        assert_eq!(reports[0].completions, 3);
        assert_eq!(reports[0].stalled_epoch, 10);
    }

    /// Re-announcement is the ordinary case, not an edge one, so it must cost
    /// the evidence nothing. The engine has no idempotence guard on the
    /// withdrawal it derives from a parked losing commit; every pass emits the
    /// same pair again.
    #[test]
    fn re_announcing_the_same_withdrawal_does_not_reset_the_frozen_epoch_evidence() {
        let mut detector = EpochStallDetector::new(1, 3).with_fruitless_completion_threshold(3);
        let g = group(0x01);

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0),
            BackfillDecision::Arm
        );
        assert!(detector.observe_fruitless_completion([&g]).is_empty());
        assert!(detector.observe_fruitless_completion([&g]).is_empty());

        for _ in 0..10 {
            detector.observe_convergence_reorg(&g);
        }

        let reports = detector.observe_fruitless_completion([&g]);
        assert_eq!(
            reports.len(),
            1,
            "ten re-announcements of one withdrawal must not spend the two completions already banked",
        );
        assert_eq!(reports[0].completions, 3);
    }

    /// A reorg is evidence about a run, never the start of one.
    #[test]
    fn a_reorg_for_a_group_with_no_stall_history_leaves_it_untracked() {
        let mut detector = stall_detector(1);
        let g = group(0x01);

        detector.observe_convergence_reorg(&g);

        assert_eq!(
            detector.observe_undecryptable(g, "m1".into(), EpochId(10), T0),
            BackfillDecision::Arm,
            "the first arm of a fresh run, not a second one off invented history",
        );
    }

    /// Fork-side traffic still arms, and the row it arms says which kind of
    /// recovery it is: the deferral counts as stall evidence exactly as any
    /// other undecryptable does, because a fork that never resolves is a wedge
    /// and the wedge report is gated on having armed.
    #[test]
    fn a_contested_fork_deferral_arms_under_its_own_trigger() {
        let deferred = |lineage| IngestOutcome::TransportDeferred {
            group_id: group(0x01),
            lineage,
        };

        assert_eq!(
            backfill_trigger_for(&deferred(DeferralLineage::ContestedFork)),
            EpochStallBackfillTrigger::ContestedForkDeferral,
        );
        assert_eq!(
            backfill_trigger_for(&deferred(DeferralLineage::Uncontested)),
            EpochStallBackfillTrigger::UndecryptableThreshold,
        );
        assert_eq!(
            backfill_trigger_for(&IngestOutcome::ResourceRefused {
                group_id: group(0x01),
                resource: cgka_traits::ingest::InboundResourceLimit::TransportDeferredCapacity,
            }),
            EpochStallBackfillTrigger::ResourceRefusal,
        );

        // And the label changes nothing about the decision: a fork-side
        // deferral crosses the same threshold and arms the same replay.
        let mut detector = stall_detector(1);
        assert_eq!(
            detector.observe_undecryptable(group(0x01), "fork-side".into(), EpochId(10), T0),
            BackfillDecision::Arm,
        );
    }

    /// The blind spot this pacing exists for: a group whose epoch never moves
    /// arms once and nothing else can ever re-arm it, because `fired_at_epoch`
    /// is cleared only by an epoch change and the epoch cannot change without
    /// the very commit the replay could not find.
    #[test]
    fn a_wedged_group_cannot_rearm_before_the_pacing_interval_elapses() {
        let mut detector = EpochStallDetector::new(1, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(10), T0 + HOUR_MS - 1),
            BackfillDecision::Skip,
            "traffic alone must not re-arm: the clock is what paces the attempt",
        );
    }

    #[test]
    fn a_wedged_group_rearms_once_the_pacing_interval_elapses() {
        let mut detector = EpochStallDetector::new(1, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(10), T0 + HOUR_MS),
            BackfillDecision::Arm,
            "a wedged group's only way back to a replay is the paced re-arm",
        );
        // And the re-arm resets its own clock rather than opening a window.
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(10), T0 + HOUR_MS + 1),
            BackfillDecision::Skip,
        );
    }

    /// The security property `EPOCH_STALL_ESCALATION_ARM_THRESHOLD` claims:
    /// minted traffic cannot inflate an arm run. Pacing must not weaken it, so
    /// a paced re-arm buys a replay and nothing else — however many of them a
    /// patient attacker pays for.
    #[test]
    fn paced_rearms_never_escalate_by_themselves() {
        let mut detector = EpochStallDetector::new(1, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);

        for hour in 0..10 {
            assert_eq!(
                detector.observe_undecryptable(
                    g.clone(),
                    format!("minted-{hour}"),
                    EpochId(10),
                    T0 + hour * HOUR_MS,
                ),
                BackfillDecision::Arm,
                "hour {hour}: a paced re-arm is an arm of the replay, never of the run",
            );
        }
    }

    /// What does escalate a wedged group: replays whose relays confirmed they
    /// had served the account's stored history and that recovered nothing.
    #[test]
    fn fruitless_end_of_stored_events_completions_escalate_a_wedged_group_once() {
        let mut detector = EpochStallDetector::new(1, 3)
            .with_wedge_rearm_interval_ms(HOUR_MS)
            .with_fruitless_completion_threshold(3);
        let g = group(0x01);
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);

        assert!(
            detector.observe_fruitless_completion([&g]).is_empty(),
            "one confirmed fruitless replay is not yet a report",
        );
        assert!(detector.observe_fruitless_completion([&g]).is_empty());
        assert_eq!(
            detector.observe_fruitless_completion([&g]),
            vec![FruitlessEscalation {
                group_id: g.clone(),
                stalled_epoch: 10,
                completions: 3,
            }],
        );
        assert!(
            detector.observe_fruitless_completion([&g]).is_empty(),
            "a run reports once, however long it keeps gathering evidence",
        );
    }

    /// Evidence is about one epoch. A group that has moved on since it armed is
    /// no longer wedged where the evidence was gathered, so the completion says
    /// nothing about it.
    #[test]
    fn a_completion_for_a_group_that_left_its_armed_epoch_is_not_evidence() {
        let mut detector = EpochStallDetector::new(1, 3).with_fruitless_completion_threshold(1);
        let g = group(0x01);
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        detector.observe_epoch_passage(&g, EpochId(10), EpochId(12));

        assert!(
            detector.observe_fruitless_completion([&g]).is_empty(),
            "a group that moved off its armed epoch cannot be reported wedged at it",
        );
    }

    /// And the count is per-epoch: evidence gathered at one stalled epoch says
    /// nothing about the next one.
    #[test]
    fn leaving_a_stalled_epoch_discards_its_fruitless_evidence() {
        let mut detector = EpochStallDetector::new(1, 3).with_fruitless_completion_threshold(2);
        let g = group(0x01);
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        assert!(detector.observe_fruitless_completion([&g]).is_empty());

        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11), T0);
        assert!(
            detector.observe_fruitless_completion([&g]).is_empty(),
            "the first epoch's evidence must not carry into the second",
        );
    }

    /// The storm-collapse suppression a replay applies to groups that never
    /// armed sets `fired_at_epoch` without `armed_at_epoch`. It must not be
    /// mistaken for an arm this group can pace a re-arm off.
    #[test]
    fn storm_collapse_suppression_does_not_unlock_a_paced_rearm() {
        let mut detector = EpochStallDetector::new(2, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        detector.mark_replayed();

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(10), T0 + HOUR_MS * 5),
            BackfillDecision::Skip,
            "a group that never armed has no arm to pace a re-arm from",
        );
    }

    /// The same guard on the refusal path. `mark_replayed` latches
    /// `fired_at_epoch` for every tracked group without setting
    /// `armed_at_epoch`, and a refusal reaching that latch must read it as
    /// another group's suppression rather than as an arm of its own.
    #[test]
    fn storm_collapse_suppression_does_not_unlock_a_refused_rearm() {
        let mut detector = EpochStallDetector::new(2, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        detector.mark_replayed();

        assert_eq!(
            detector.observe_resource_refusal(g.clone(), EpochId(10), T0 + HOUR_MS * 5),
            BackfillDecision::Skip,
            "a group that never armed has no arm to pace a re-arm from",
        );
    }

    /// The shape a restart leaves a cap-saturated group in. Its deferred-peel
    /// cap is full, so the engine answers every further message with
    /// `ResourceRefused` rather than deferring it — the undecryptable path is
    /// never called at all, and the restored `fired_at_epoch` skips the refusal
    /// path. Without a paced re-arm here that group never replays again, which
    /// is the one shape the restored evidence exists to report on.
    #[test]
    fn a_restored_refusal_only_group_still_earns_its_paced_rearm() {
        let mut detector = EpochStallDetector::new(1, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);
        detector.restore_wedge_evidence([(
            g.clone(),
            EpochStallEvidence {
                stalled_epoch: 10,
                fruitless_completions: 1,
                fruitless_reported: false,
                last_arm_at_ms: T0,
            },
        )]);

        assert_eq!(
            detector.observe_resource_refusal(g.clone(), EpochId(10), T0 + HOUR_MS - 1),
            BackfillDecision::Skip,
            "the clock paces the refusal path exactly as it paces the other one",
        );
        assert_eq!(
            detector.observe_resource_refusal(g.clone(), EpochId(10), T0 + HOUR_MS),
            BackfillDecision::Arm,
            "a restored latch must not end this group's recovery for good",
        );
        assert_eq!(
            detector.observe_resource_refusal(g.clone(), EpochId(10), T0 + HOUR_MS + 1),
            BackfillDecision::Skip,
            "and the re-arm resets its own clock rather than opening a window",
        );
    }

    /// A refused re-arm is paced, so it must not be counted either: the flood
    /// cap a refusal reports is one minted traffic can saturate on its own
    /// (mdk#339), which would otherwise buy an arm run for the price of
    /// waiting.
    #[test]
    fn paced_refused_rearms_never_escalate_by_themselves() {
        let mut detector = EpochStallDetector::new(1, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);
        detector.restore_wedge_evidence([(
            g.clone(),
            EpochStallEvidence {
                stalled_epoch: 10,
                fruitless_completions: 0,
                fruitless_reported: false,
                last_arm_at_ms: T0,
            },
        )]);

        for hour in 1..=10 {
            assert_eq!(
                detector.observe_resource_refusal(g.clone(), EpochId(10), T0 + hour * HOUR_MS),
                BackfillDecision::Arm,
                "hour {hour}: a paced re-arm is an arm of the replay, never of the run",
            );
        }
    }

    /// The exposure the test above does *not* cover, pinned as documentation.
    ///
    /// Deliberately green: this records today's behavior while the design
    /// question is open, and is not a missed red. The fix, if there is one, is a
    /// rate bound decided against the frozen-device escalation's liveness — not
    /// something to land beside the pin.
    ///
    /// `paced_refused_rearms_never_escalate_by_themselves` holds only while a
    /// group's latch stays set, which is the case when the account-wide replay
    /// never runs or never refuses anything for this group. A saturated
    /// deferred-peel cap breaks exactly that: the cap is one minted traffic can
    /// fill by itself (mdk#339), it answers `ResourceRefused` to the replay's
    /// own fetch for the group as well as to live traffic, and
    /// [`EpochStallDetector::rearm_refused_groups`] then clears the latch the
    /// arm just set. The next refusal takes the counted branch rather than the
    /// paced one, so the loop refusal -> arm -> fruitless replay -> unlatch
    /// walks straight to [`EPOCH_STALL_ESCALATION_ARM_THRESHOLD`] with no epoch
    /// advance and no hour elapsed. Bounded by what escalation does: it reports.
    #[test]
    fn a_saturated_cap_can_drive_counted_arms_through_the_refusal_loop() {
        let mut detector = EpochStallDetector::new(1, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);
        let refused: HashSet<GroupId> = std::iter::once(g.clone()).collect();

        // One turn per whole-account replay: a flood-driven refusal, then the
        // fruitless drain re-arming the group whose history it could not
        // retain. Turns sit one retry backoff apart, far inside both the pacing
        // interval and the run-continuation window.
        let mut decisions = Vec::new();
        for turn in 0..3u64 {
            decisions.push(detector.observe_resource_refusal(
                g.clone(),
                EpochId(10),
                T0 + turn * 15_000,
            ));
            detector.rearm_refused_groups(&refused);
        }

        assert_eq!(
            decisions,
            vec![
                BackfillDecision::Arm,
                BackfillDecision::Arm,
                BackfillDecision::ArmAndEscalate { arms: 3 },
            ],
            "every refusal behind a fruitless replay takes the counted arm branch, so a \
             saturated cap reaches the escalation threshold without an authenticated commit \
             and without waiting out a single pacing interval",
        );
    }

    /// A run is unbounded in wall-clock without this: an unrelated stall weeks
    /// after a single arm would land as arm two of a long-dead run.
    #[test]
    fn an_arm_past_the_run_continuation_window_starts_a_fresh_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        let _ = detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(11), T0);
        // Weeks of quiet, then an unrelated stall.
        let later = T0 + EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS + 1;
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m3".into(), EpochId(12), later),
            BackfillDecision::Arm,
            "an arm this far from the last one starts its own run",
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m4".into(), EpochId(13), later),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m5".into(), EpochId(14), later),
            BackfillDecision::ArmAndEscalate { arms: 3 },
            "the fresh run still escalates on its own third arm",
        );
    }

    #[test]
    fn an_arm_inside_the_run_continuation_window_continues_the_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        let _ = detector.observe_undecryptable(
            g.clone(),
            "m2".into(),
            EpochId(11),
            T0 + EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS,
        );
        assert_eq!(
            detector.observe_undecryptable(
                g.clone(),
                "m3".into(),
                EpochId(12),
                T0 + 2 * EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS,
            ),
            BackfillDecision::ArmAndEscalate { arms: 3 },
            "hours-long field stalls have to stay one run",
        );
    }

    /// The restart rule, in both directions. Restored evidence is not lost, and
    /// the restart itself buys nothing: the arm mark is wall-clock, so a device
    /// force-killed a minute after arming still owes the rest of the interval.
    #[test]
    fn a_restart_carries_the_evidence_without_becoming_the_clock() {
        let mut detector = EpochStallDetector::new(1, 3)
            .with_wedge_rearm_interval_ms(HOUR_MS)
            .with_fruitless_completion_threshold(3);
        let g = group(0x01);
        detector.restore_wedge_evidence([(
            g.clone(),
            EpochStallEvidence {
                stalled_epoch: 10,
                fruitless_completions: 2,
                fruitless_reported: false,
                last_arm_at_ms: T0,
            },
        )]);

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0 + 60_000),
            BackfillDecision::Skip,
            "a restart must not shorten the interval the previous process owed",
        );
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(10), T0 + HOUR_MS),
            BackfillDecision::Arm
        );
        assert_eq!(
            detector.observe_fruitless_completion([&g]),
            vec![FruitlessEscalation {
                group_id: g.clone(),
                stalled_epoch: 10,
                completions: 3,
            }],
            "the two completions the previous process confirmed still count",
        );
    }

    /// And a run already reported stays reported, so a restart cannot re-raise
    /// a group whose evidence is already past the threshold.
    #[test]
    fn a_restart_does_not_re_report_an_already_escalated_run() {
        let mut detector = EpochStallDetector::new(1, 3).with_fruitless_completion_threshold(3);
        let g = group(0x01);
        detector.restore_wedge_evidence([(
            g.clone(),
            EpochStallEvidence {
                stalled_epoch: 10,
                fruitless_completions: 3,
                fruitless_reported: true,
                last_arm_at_ms: T0,
            },
        )]);

        assert!(
            detector.observe_fruitless_completion([&g]).is_empty(),
            "the run reported before the restart; restarting is not new evidence",
        );
    }

    /// A dead run's evidence must not report a live one.
    ///
    /// `end_run` and `observe_epoch` are two different resets: the first fires
    /// when an arm lands past the run continuation window, at whatever epoch the
    /// group happens to sit on, and the second only when the epoch changes. The
    /// fruitless counter is per-epoch, so only the second used to clear it —
    /// which left a window where a stale-run arm cleared the report latch while
    /// the evidence behind it survived, and the very next completion re-reported
    /// off a run that had already ended. The cap-saturated shape reaches it for
    /// real: `rearm_refused_groups` clears `fired_at_epoch` at the same epoch, so
    /// the next undecryptable takes the unpaced arm branch.
    #[test]
    fn a_run_that_ended_on_the_clock_does_not_report_off_its_predecessor() {
        let mut detector = EpochStallDetector::new(1, 3).with_fruitless_completion_threshold(3);
        let g = group(0x01);
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        let _ = detector.observe_fruitless_completion([&g]);
        let _ = detector.observe_fruitless_completion([&g]);
        assert_eq!(
            detector.observe_fruitless_completion([&g]).len(),
            1,
            "the first run reports on its third confirmed fruitless replay",
        );
        // A fruitless replay re-arms the groups whose refusals it counted, and
        // the device then goes quiet long enough for the run to age out.
        detector.rearm_refused_groups(&std::iter::once(g.clone()).collect());
        let later = T0 + EPOCH_STALL_RUN_CONTINUATION_WINDOW_MS + 1;
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(10), later),
            BackfillDecision::Arm,
            "an arm this far from the last one starts a fresh run",
        );
        assert!(
            detector.observe_fruitless_completion([&g]).is_empty(),
            "a fresh run re-earns its evidence exactly as it re-earns its arms",
        );
        assert!(detector.observe_fruitless_completion([&g]).is_empty());
        assert_eq!(
            detector.observe_fruitless_completion([&g]).len(),
            1,
            "and reports again only once it has earned three of its own",
        );
    }

    /// A restart must not suppress the arm-run rule.
    ///
    /// The report latch gates both escalation rules, but only the frozen-epoch
    /// half of the state is durable: `arms` deliberately restarts at zero.
    /// Rehydrating one shared latch therefore silenced a whole fresh arm run —
    /// and a device limping one epoch per arm, which is the field shape the arm
    /// run exists for, never clears it, because leaving an epoch it armed at
    /// continues the run. The durable half is scoped to the frozen-epoch rule
    /// instead.
    #[test]
    fn a_restart_does_not_suppress_a_fresh_arm_run() {
        let mut detector = EpochStallDetector::new(1, 3);
        let g = group(0x01);
        detector.restore_wedge_evidence([(
            g.clone(),
            EpochStallEvidence {
                stalled_epoch: 10,
                fruitless_completions: 3,
                fruitless_reported: true,
                last_arm_at_ms: T0,
            },
        )]);

        // The device limps: one epoch of progress per arm, three times over.
        detector.observe_epoch_passage(&g, EpochId(10), EpochId(11));
        let first =
            detector.observe_undecryptable(g.clone(), "a".into(), EpochId(11), T0 + HOUR_MS);
        detector.observe_epoch_passage(&g, EpochId(11), EpochId(12));
        let second =
            detector.observe_undecryptable(g.clone(), "b".into(), EpochId(12), T0 + 2 * HOUR_MS);
        detector.observe_epoch_passage(&g, EpochId(12), EpochId(13));
        let third =
            detector.observe_undecryptable(g.clone(), "c".into(), EpochId(13), T0 + 3 * HOUR_MS);

        assert_eq!(
            (first, second, third),
            (
                BackfillDecision::Arm,
                BackfillDecision::Arm,
                BackfillDecision::ArmAndEscalate { arms: 3 },
            ),
            "a run earned entirely after the restart is a report the restart never made",
        );
    }

    /// The durable latch is scoped to the epoch it was gathered at, which is
    /// what makes a stale row harmless. Nothing persists the voiding
    /// transitions — they happen on the delivery hot path — so a recovered
    /// group leaves its last row behind; the first observation at any other
    /// epoch has to discard it, latch included.
    #[test]
    fn a_restored_report_latch_does_not_survive_leaving_its_epoch() {
        let mut detector = EpochStallDetector::new(1, 3).with_fruitless_completion_threshold(1);
        let g = group(0x01);
        detector.restore_wedge_evidence([(
            g.clone(),
            EpochStallEvidence {
                stalled_epoch: 10,
                fruitless_completions: 3,
                fruitless_reported: true,
                last_arm_at_ms: T0,
            },
        )]);

        // The group moved on and later wedged somewhere else entirely.
        detector.observe_epoch_passage(&g, EpochId(10), EpochId(11));
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(11), T0 + HOUR_MS);
        assert_eq!(
            detector.observe_fruitless_completion([&g]),
            vec![FruitlessEscalation {
                group_id: g.clone(),
                stalled_epoch: 11,
                completions: 1,
            }],
            "a report about the epoch it left cannot silence the epoch it is stuck at now",
        );
    }

    /// A clock that ran ahead must not wedge the gate for good.
    ///
    /// A mark taken under a dead RTC, a hand-set date, or a saturating
    /// `unix_now_ms` sits in the future of every later correct reading, and a
    /// plain saturating subtraction calls that zero elapsed forever. The mark is
    /// durable, so restarting does not clear it either: the device would never
    /// re-arm again.
    #[test]
    fn a_mark_from_a_clock_that_ran_ahead_does_not_wedge_the_pacing_gate() {
        let mut detector = EpochStallDetector::new(1, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);
        detector.restore_wedge_evidence([(
            g.clone(),
            EpochStallEvidence {
                stalled_epoch: 10,
                fruitless_completions: 0,
                fruitless_reported: false,
                last_arm_at_ms: T0 + 365 * 24 * HOUR_MS,
            },
        )]);

        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0),
            BackfillDecision::Arm,
            "a mark the clock cannot have produced reads as elapsed, not as zero",
        );
    }

    /// The run window has to read that same corrected clock. A mark in the
    /// future is not zero elapsed there either: a run whose last arm cannot
    /// have happened is over, and its evidence has to be re-earned rather than
    /// counted toward the next report.
    #[test]
    fn a_mark_from_a_clock_that_ran_ahead_expires_the_run_it_marked() {
        let mut detector = EpochStallDetector::new(1, 3)
            .with_wedge_rearm_interval_ms(HOUR_MS)
            .with_fruitless_completion_threshold(3);
        let g = group(0x01);
        detector.restore_wedge_evidence([(
            g.clone(),
            EpochStallEvidence {
                stalled_epoch: 10,
                fruitless_completions: 2,
                fruitless_reported: false,
                last_arm_at_ms: T0 + 365 * 24 * HOUR_MS,
            },
        )]);
        // A fruitless replay that refused this group's history clears the
        // latch, which is what lets the next refusal reach `arm` rather than
        // the paced re-arm.
        detector.rearm_refused_groups(&HashSet::from([g.clone()]));
        assert_eq!(
            detector.observe_resource_refusal(g.clone(), EpochId(10), T0),
            BackfillDecision::Arm,
        );

        assert!(
            detector.observe_fruitless_completion([&g]).is_empty(),
            "evidence from a run that ended cannot complete the next run's report",
        );
    }

    /// Nothing paces a wedged group but the clock, so its re-arms have to read
    /// the run window too. A group that went quiet for a week and then received
    /// one message is starting a new run, not continuing one whose last arm was
    /// days ago.
    #[test]
    fn a_paced_rearm_past_the_run_continuation_window_starts_a_fresh_run() {
        let mut detector = EpochStallDetector::new(1, 3)
            .with_wedge_rearm_interval_ms(HOUR_MS)
            .with_fruitless_completion_threshold(3);
        let g = group(0x01);
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        let _ = detector.observe_fruitless_completion([&g]);
        let _ = detector.observe_fruitless_completion([&g]);

        let a_week_later = T0 + 7 * 24 * HOUR_MS;
        assert_eq!(
            detector.observe_undecryptable(g.clone(), "m2".into(), EpochId(10), a_week_later),
            BackfillDecision::Arm,
            "the interval has long elapsed, so the re-arm itself is due",
        );
        assert!(
            detector.observe_fruitless_completion([&g]).is_empty(),
            "week-old evidence belongs to a run the window already ended",
        );
    }

    /// Ordinary skew between two readings is not a corrected clock, though, and
    /// must not hand out a re-arm the interval had not earned.
    #[test]
    fn ordinary_clock_skew_does_not_buy_a_rearm() {
        let mut detector = EpochStallDetector::new(1, 3).with_wedge_rearm_interval_ms(HOUR_MS);
        let g = group(0x01);
        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);

        assert_eq!(
            detector.observe_undecryptable(
                g.clone(),
                "m2".into(),
                EpochId(10),
                T0 - EPOCH_STALL_CLOCK_SKEW_ALLOWANCE_MS,
            ),
            BackfillDecision::Skip,
            "a reading a few minutes behind the mark is skew, not a year of waiting",
        );
    }

    #[test]
    fn wedge_evidence_round_trips_what_a_restart_has_to_carry() {
        let mut detector = EpochStallDetector::new(1, 3).with_fruitless_completion_threshold(3);
        let g = group(0x01);
        assert_eq!(
            detector.wedge_evidence(&g),
            None,
            "a group with no stall history has nothing durable to say",
        );

        let _ = detector.observe_undecryptable(g.clone(), "m1".into(), EpochId(10), T0);
        let _ = detector.observe_fruitless_completion([&g]);
        assert_eq!(
            detector.wedge_evidence(&g),
            Some(EpochStallEvidence {
                stalled_epoch: 10,
                fruitless_completions: 1,
                fruitless_reported: false,
                last_arm_at_ms: T0,
            }),
        );
    }
}
