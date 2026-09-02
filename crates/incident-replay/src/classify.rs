//! The classification gate.
//!
//! Everything downstream (extraction, fault synthesis, replay) is gated behind
//! this verdict, so a healthy export yields zero vectors and a clean exit rather
//! than a crash. Built incrementally, one rule per behaviour.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::export::{AgentStateExport, EventKind};
use serde::Serialize;

/// How many epochs an engine may trail the group's epoch high-water mark
/// before it counts as left behind. The value is derived, not tuned. Lag 1 is
/// the noise floor: every commit leaves every other engine one epoch behind
/// until it propagates, so a snapshot routinely catches healthy engines there —
/// indistinguishable from a commit in flight, and so carrying no information.
/// Lag 2 is the smallest lag that *cannot* be one in-flight commit: the engine
/// missed a commit and the group then produced another it also missed (e.g. two
/// members invited back-to-back), so the gap provably outlived an inter-commit
/// interval. Being event-anchored rather than clock-anchored, it means the same
/// in a chatty group and a weekly one — the property that disqualified
/// wall-clock staleness. Any higher threshold is the arbitrary one: "one
/// survived commit is fine but two are not" has no structural answer, whereas 2
/// is just the noise floor plus one. A commit burst can still park healthy
/// engines at lag 2 for its propagation window — the claim bounds transients,
/// it does not erase them — so an entry here is fail-closed evidence to
/// re-pull, not a verdict; persistence across pulls is the signal. A backtest
/// over hourly slices of the 2026-07-09 incident export could have refuted 2 by
/// firing through healthy windows; instead the neighbors failed exactly as the
/// structure predicts — lag 1 on engines merely one behind during a routine
/// multi-commit rollout, lag 3 losing half the incident (stuck devices exactly
/// two behind the tip, including its only active-while-behind signal) — and 2
/// held.
const EPOCH_DIVERGENCE_MIN_LAG: u64 = 2;

/// How long an engine may keep recording events after the group provably moved
/// past its final epoch before its lag counts as *active while behind* rather
/// than *went dark*. Unlike the lag threshold, this constant is empirical, not
/// derived: an operational estimate — ordinary catch-up after a reconnect
/// drains in seconds to minutes, plus a margin that absorbs cross-device clock
/// skew. Its safety is nonetheless structural. The grace only chooses between
/// the two hedged mode labels; it never decides whether the quarantine fires
/// (arming needs only the lag and the timestamps that order it), so a wrong
/// grace can yield neither a false healthy nor a false quarantine, only a
/// mislabeled mode. And the estimate sat
/// on a plateau, not a knife-edge: the same backtest measured the verdict
/// insensitive across any grace in [15 min, ~6 h], and no engine that later
/// caught up was ever labeled active-while-behind. The real incidents it was
/// validated on stayed behind for six hours (a live device no longer receiving
/// commits) and eighteen hours (the second real export on hand).
const CATCH_UP_GRACE_MS: u64 = 60 * 60 * 1000;

/// How the pipeline should route an export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// No contested branch — the common case. Zero vectors, clean exit.
    Healthy,
    /// A same-epoch commit race resolved by the fork-recovery seam (Phase 3).
    ForkRecovery,
    /// A quiescence-window branch selection (Phase 4; needs the convergence
    /// assert surface).
    ConvergenceSelected,
    /// Unusable for faithful replay; never fabricate a vector from it.
    Quarantine { reason: QuarantineReason },
}

/// Why an export was quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    /// A `derived_projections` section was capped server-side (`has_more`), so
    /// the export is incomplete.
    TruncatedProjections,
    /// A fork resolution's winning snapshot was missing — unreproducible.
    MissingSnapshot,
    /// Engines recorded halting unrecoverably and are *still* halted at the end
    /// of the export: no verified repair cleared the marker afterwards. Unlike
    /// [`QuarantineReason::EpochDivergence`], this is not an inference from lag —
    /// the engine itself recorded that it stopped — so it needs no cross-pull
    /// confirmation and it is a diagnosis rather than a re-pull target. There is
    /// still nothing to replay: a halt is a client failure, not a branch contest.
    ///
    /// "Still halted" is decided per `(engine, group)` by comparing the newest
    /// halt row against the newest verified-repair row
    /// (`epoch_state_changed { new_state: "stable", reason: "join_welcome_repair"
    /// }`); surviving halts then fold back per engine. See [`HaltLifecycle`] for
    /// why newest-wins needs no global ordering and why missing evidence keeps the
    /// halt.
    UnrecoverableHalt {
        /// Every engine that recorded a halt, in engine-id order.
        engines: Vec<HaltedEngine>,
    },
    /// Engines trail the group's epoch high-water mark by at least
    /// [`EPOCH_DIVERGENCE_MIN_LAG`] epochs with no recorded contest explaining
    /// it. Persistent across pulls this is a silent split; on any single pull an
    /// entry can equally be catch-up in flight or an engine whose audit uploads
    /// merely lagged (the incident exports carry a proven instance of each), so
    /// the named engines are a re-pull target first and a triage starting point
    /// second.
    /// Either way it is not a branch contest, so there is nothing to replay as a
    /// vector.
    EpochDivergence {
        /// The group's epoch high-water mark across all engines.
        group_epoch: u64,
        /// Every engine left behind it, in engine-id order.
        engines: Vec<BehindEngine>,
    },
}

impl fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuarantineReason::TruncatedProjections => {
                f.write_str("a derived_projections section was truncated server-side (has_more)")
            }
            QuarantineReason::MissingSnapshot => {
                f.write_str("a fork resolution's winning snapshot was missing")
            }
            QuarantineReason::UnrecoverableHalt { engines } => {
                f.write_str("engines halted unrecoverably:")?;
                for (index, engine) in engines.iter().enumerate() {
                    let separator = if index == 0 { " " } else { ", " };
                    write!(f, "{separator}{engine}")?;
                }
                Ok(())
            }
            QuarantineReason::EpochDivergence {
                group_epoch,
                engines,
            } => {
                write!(f, "engines behind the group tip (epoch {group_epoch}):")?;
                for (index, engine) in engines.iter().enumerate() {
                    let separator = if index == 0 { " " } else { ", " };
                    write!(f, "{separator}{engine}")?;
                }
                Ok(())
            }
        }
    }
}

/// One engine that recorded halting unrecoverably.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HaltedEngine {
    /// The engine that halted.
    pub engine_id: String,
    /// Why it halted, deduplicated and in sort order: the causes it recorded, or
    /// its re-assertions when it recorded no cause. See [`reported_halt_reasons`].
    pub reasons: Vec<String>,
}

impl fmt::Display for HaltedEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.engine_id, self.reasons.join(", "))
    }
}

/// One engine left behind the group's epoch high-water mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BehindEngine {
    /// The engine that fell behind.
    pub engine_id: String,
    /// The epoch the engine's own events currently place it at — its newest
    /// timed position, not its high-water mark, so a rolled-back device is
    /// reported where it actually sits.
    pub epoch: u64,
    /// How the engine was behaving once the group moved past it.
    pub mode: BehindMode,
}

impl fmt::Display for BehindEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at epoch {} ({})",
            self.engine_id, self.epoch, self.mode
        )
    }
}

/// How an engine that fell behind was behaving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BehindMode {
    /// The engine stopped recording events before — or within the catch-up
    /// grace of — the group provably advancing past it: a dead device, an
    /// uninstalled app, or stopped uploads. (An engine belonging to a member
    /// who *left* the group looks identical; telling the two apart needs a
    /// member-to-engine linkage the export does not carry yet.) A healthy engine
    /// sitting at the tip whose audit uploads merely lag reads the same way —
    /// the 2026-07-09 incident export carried a proven instance, uploads three
    /// days behind a live tip — so within one export this mode is not a
    /// diagnosis; only persistence across pulls tells a dark device from a live
    /// one whose stream just ended early.
    WentDark,
    /// The engine kept recording events for longer than the catch-up grace
    /// after the group provably advanced past its final epoch, without
    /// catching up: commits are not reaching it even though its other traffic
    /// flows.
    ActiveWhileBehind,
    /// The engine's newest timed epoch is *below* one it already reported: its
    /// local state moved backwards. Nothing in the protocol walks an epoch
    /// back, so this is a local-storage event — a device restored from an
    /// older backup, a rolled-back database. It outranks the other two modes:
    /// an engine that rolled back is also, necessarily, active or dark, and
    /// the rollback is the sharper of the two readings.
    ///
    /// The mode says where the device is, not that it is beyond repair. A
    /// restored device still holds valid state at the epoch it fell back to,
    /// so a full-history replay that reaches every commit from there forward
    /// can carry it up again — mdk#1548 healed a device from epoch 13 to 16
    /// exactly that way. What the rollback changes is the size of the ask: the
    /// gap spans every epoch since the restore rather than a commit or two, so
    /// it needs that replay rather than ordinary redelivery, and re-invite
    /// only once relay retention no longer covers the span. Whether it still
    /// does is not a question this export can answer.
    RolledBack,
}

impl fmt::Display for BehindMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BehindMode::WentDark => "went dark",
            BehindMode::ActiveWhileBehind => "active while behind",
            BehindMode::RolledBack => "rolled back",
        })
    }
}

/// Classify an export into its routing verdict.
pub fn classify(export: &AgentStateExport) -> Verdict {
    // A truncated projection means the export is incomplete: reproduction could
    // miss witnesses or hidden state, so it is unusable regardless of what the
    // (uncapped) event log shows. Gate this first.
    if export
        .derived_projections
        .pagination
        .values()
        .any(|section| section.has_more)
    {
        return Verdict::Quarantine {
            reason: QuarantineReason::TruncatedProjections,
        };
    }
    let kinds = || export.events.iter().map(|event| &event.kind);
    // A contested convergence selection dominates: a real incident can carry
    // both a fork resolution and a convergence decision, and the convergence
    // route (Phase 4) is the one that reproduces it.
    if kinds().any(EventKind::is_contested_convergence) {
        return Verdict::ConvergenceSelected;
    }
    // Below here the export routes to fork recovery, where an unrecoverable
    // winner (missing snapshot) can't be replayed — quarantine instead of
    // fabricating a vector.
    if kinds().any(EventKind::is_missing_snapshot_fork) {
        return Verdict::Quarantine {
            reason: QuarantineReason::MissingSnapshot,
        };
    }
    if kinds().any(EventKind::is_fork_resolution) {
        return Verdict::ForkRecovery;
    }
    // No contested branch anywhere. Two liveness gates now guard the healthy
    // verdict, the better-evidenced one first: an engine that *recorded* halting
    // unrecoverably outranks one merely *inferred* to be behind, because the halt
    // is the engine's own statement and it usually explains the lag (on the real
    // 26a9f546 export the halted engine is exactly the one the divergence gate
    // labelled `went dark`). Reporting the inference over the diagnosis would
    // send the operator to re-pull for confirmation they already have.
    if let Some(reason) = unrecoverable_halt(export) {
        return Verdict::Quarantine { reason };
    }
    // The liveness gate ranks below the incident routes deliberately: a reproducible
    // contest is worth replaying even when another engine's data is stale
    // (recovery fail-closes downstream if the data it needs is missing). It
    // exists because a stuck or dead device is only visible *across* engines:
    // both real exports this gate was validated on previously classified
    // healthy while genuinely split (2026-07-09 incident: three engines dark
    // and one active engine cut off from commits; the second real export: one
    // engine eighteen hours behind the other).
    if let Some(reason) = epoch_divergence(export) {
        return Verdict::Quarantine { reason };
    }
    Verdict::Healthy
}

/// The liveness (epoch-divergence) incident an export carries, independent of
/// its routing [`Verdict`].
///
/// [`classify`] returns a single verdict, and a reproducible incident (fork or
/// convergence) outranks the liveness gate on purpose — so an export that
/// carries *both* a replayable incident and an engine left behind routes to the
/// incident, and the liveness signal never reaches the operator. This exposes the
/// same rule-6 computation so a caller (the CLI) can surface it as a secondary
/// advisory alongside the primary outcome. Returns `None` when no engine is left
/// behind — the gate stays unarmed on untimed or synthetic exports, exactly as
/// [`classify`]'s healthy path does.
pub fn liveness_advisory(export: &AgentStateExport) -> Option<QuarantineReason> {
    epoch_divergence(export)
}

/// The unrecoverable-halt incident an export carries, independent of its routing
/// [`Verdict`].
///
/// The sibling of [`liveness_advisory`], for the same reason: [`classify`]
/// returns one verdict, so an export carrying both a replayable incident and a
/// halted engine routes to the incident and the halt would never reach the
/// operator. The CLI prints this as a secondary advisory alongside the primary
/// outcome.
pub fn halt_advisory(export: &AgentStateExport) -> Option<QuarantineReason> {
    unrecoverable_halt(export)
}

/// One group's halt lifecycle on one engine, folded from the event log.
///
/// `Unrecoverable` is per-group state with exactly one legal exit, so the halt
/// and its repair are a two-event lifecycle rather than two independent facts —
/// hence the newest of each, not a count.
#[derive(Default)]
struct HaltLifecycle<'a> {
    /// Every distinct reason the engine gave for halting this group.
    reasons: BTreeSet<&'a str>,
    /// The newest *timed* halt row's timestamp. Only the halt's position when
    /// every halt row carried a clock — see [`HaltLifecycle::halt_position_ms`].
    last_halt_ms: Option<u64>,
    /// Whether any halt row carried no clock at all.
    untimed_halt: bool,
    /// The newest verified-repair row's timestamp, when it carries one.
    last_repair_ms: Option<u64>,
}

impl HaltLifecycle<'_> {
    /// Whether the halt still stands at the end of the export.
    ///
    /// Newest-repair-strictly-after-newest-halt is the whole rule, and it needs
    /// no global event ordering because a live halt is *continuously
    /// re-asserted*: opening a session over a durably halted group re-emits
    /// `hydrate_unrecoverable_group` (`cgka-engine/src/engine.rs`) and every
    /// convergence attempt against one emits `already_unrecoverable`
    /// (`cgka-engine/src/distributed_convergence.rs`). A halt that outlived a
    /// repair therefore leaves rows *after* it, and one that did not, does not.
    /// Both rows also come from a single engine — one clock, one recorder file —
    /// so none of rule 6's cross-device [`CATCH_UP_GRACE_MS`] skew allowance
    /// applies and a strict comparison is sound. (`seq` must never be substituted
    /// for the clock. It restarts at 0 on every recorder open, so it does not
    /// order rows across a restart — the exact boundary a durable halt
    /// survives — and since mdk#1181 it does not identify a file either: a
    /// segment roll carries `seq` across into an `audit-*-seg<NNNNNN>.jsonl`
    /// sibling, so one session's rows span several source files and a file can
    /// start at a nonzero `seq`. Neither direction is orderable by `seq`. See
    /// `docs/marmot-architecture/audit-logging.md`.)
    ///
    /// Absence fails closed in both directions: an unrepaired halt keeps its
    /// quarantine, and so does a halt whose evidence cannot be ordered — arming
    /// rule 5 needs no timestamps, but *clearing* it does. See
    /// [`Self::halt_position_ms`] for when the halt's position is unknowable and
    /// why guessing it is the one fail-open direction. This is also why untimed
    /// fixtures and pre-instrumentation exports classify exactly as before.
    fn still_halted(&self) -> bool {
        if self.reasons.is_empty() {
            return false;
        }
        match (self.halt_position_ms(), self.last_repair_ms) {
            (Some(halt), Some(repair)) => repair <= halt,
            _ => true,
        }
    }

    /// Where the halt sits on the engine's clock, or `None` when its evidence
    /// cannot be placed there at all.
    ///
    /// One untimed halt row makes the *whole* halt side unorderable, not just
    /// that row: the untimed row may be the newest evidence of the halt, so the
    /// newest timed row is a lower bound on the halt's position rather than the
    /// position itself, and a repair after that bound proves nothing. Reading the
    /// newest timed row as the answer is the one direction [`Self::still_halted`]
    /// must not take — on partially instrumented input it clears a live halt
    /// whose position is unknown.
    fn halt_position_ms(&self) -> Option<u64> {
        if self.untimed_halt {
            return None;
        }
        self.last_halt_ms
    }
}

/// The gate for engines that recorded halting unrecoverably.
///
/// Like the liveness gate it fires only on positive evidence, but it needs far
/// less of it to arm: a halt is self-reported, so no threshold is needed to
/// distinguish it from noise. It does require an `engine_id` — the report is
/// per-engine, and an unattributable halt could not be named.
///
/// The gate is *cleared* per `(engine_id, group_ref)` rather than per engine,
/// because that is the granularity the halt actually has: the engine's state
/// machine holds `Unrecoverable` for one group, and a repair in another group
/// proves nothing about it. Surviving halts then fold back per engine, so an
/// engine halted in two groups is still one halted engine with the union of its
/// reasons — the report shape rule 5 has always had.
fn unrecoverable_halt(export: &AgentStateExport) -> Option<QuarantineReason> {
    let mut lifecycles: BTreeMap<(&str, Option<&str>), HaltLifecycle> = BTreeMap::new();
    for event in &export.events {
        let Some(engine_id) = event.engine_id.as_deref() else {
            continue;
        };
        let group_scope = (engine_id, event.group_ref.as_deref());
        if let Some(reason) = event.kind.unrecoverable_halt_reason() {
            let lifecycle = lifecycles.entry(group_scope).or_default();
            lifecycle.reasons.insert(reason);
            match event.wall_time_ms {
                Some(ms) => lifecycle.last_halt_ms = lifecycle.last_halt_ms.max(Some(ms)),
                None => lifecycle.untimed_halt = true,
            }
        } else if event.kind.is_verified_repair() {
            // Recorded even when no halt has been seen yet: the fold is over
            // timestamps, not file order, so a repair may legitimately arrive
            // before the halt it postdates.
            let lifecycle = lifecycles.entry(group_scope).or_default();
            lifecycle.last_repair_ms = lifecycle.last_repair_ms.max(event.wall_time_ms);
        }
    }

    let mut halted: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for ((engine_id, _group_ref), lifecycle) in &lifecycles {
        if lifecycle.still_halted() {
            halted
                .entry(engine_id)
                .or_default()
                .extend(lifecycle.reasons.iter().copied());
        }
    }

    let engines: Vec<HaltedEngine> = halted
        .into_iter()
        .map(|(engine_id, reasons)| HaltedEngine {
            engine_id: engine_id.to_owned(),
            reasons: reported_halt_reasons(&reasons),
        })
        .collect();
    (!engines.is_empty()).then_some(QuarantineReason::UnrecoverableHalt { engines })
}

/// One engine's halt reasons as the operator should read them: its causes, or
/// everything it recorded when it recorded no cause.
///
/// A non-cause never names why the engine stopped (see
/// [`export::is_halt_cause`]), so beside a real cause it is noise in the line an
/// operator reads first. Non-causes are not dropped unconditionally, because a
/// halt that predates the export window leaves nothing *but* non-causes and that
/// engine still has to be named — which is also the honest report for it: this
/// export shows the halt standing, not what caused it.
///
/// [`export::is_halt_cause`]: crate::export::is_halt_cause
fn reported_halt_reasons(reasons: &BTreeSet<&str>) -> Vec<String> {
    let causes: Vec<String> = reasons
        .iter()
        .filter(|reason| crate::export::is_halt_cause(reason))
        .map(|reason| (*reason).to_owned())
        .collect();
    if causes.is_empty() {
        return reasons.iter().map(|reason| (*reason).to_owned()).collect();
    }
    causes
}

/// Per-engine activity, folded from the event log.
#[derive(Default)]
struct EngineActivity {
    /// The engine's newest event timestamp, when its events carry one.
    last_seen_ms: Option<u64>,
    /// The highest epoch the engine reported itself at.
    high_water_epoch: Option<u64>,
    /// The engine's newest *timed* epoch observation, as `(wall_time_ms,
    /// epoch)`. Held beside the high-water mark because the two disagree
    /// exactly when local state moved backwards, which is the whole signal
    /// behind [`BehindMode::RolledBack`] — a max alone reports a restored
    /// device at the epoch it used to hold and understates its lag.
    current: Option<(u64, u64)>,
    /// Whether any epoch observation arrived without a timestamp. One such row
    /// makes the engine's whole epoch sequence unorderable, exactly as one
    /// untimed halt row does in [`unrecoverable_halt`]: an untimed epoch may
    /// be the newest one, so a "newest timed" reading could sit behind the
    /// engine's real position and invent a rollback. The fail-closed answer is
    /// to keep the high-water reading, which claims no ordering at all.
    has_untimed_epoch: bool,
}

/// The weaker of the two gates between "no contested branch" and "healthy":
/// engines left ≥ [`EPOCH_DIVERGENCE_MIN_LAG`] epochs behind the group's
/// high-water mark. Weaker because it *infers* the split from lag, where
/// [`unrecoverable_halt`] reads the engine's own report of it — hence the lower
/// precedence and the hedged, re-pull-first framing below.
///
/// It fires only on positive evidence — events without an `engine_id` or
/// `wall_time_ms` leave it unarmed — so synthetic fixtures and older exports
/// classify as before. Lag is measured in epochs, not wall-clock silence: a
/// device that is merely offline while nothing is committed misses nothing and
/// stays healthy, and an idle group never reads as stale. A device offline
/// *while* commits land is the transient case: it reads as went-dark on that
/// pull and self-resolves on the next — quarantined fail-closed by choice
/// (measured on the incident-export backtest).
fn epoch_divergence(export: &AgentStateExport) -> Option<QuarantineReason> {
    let mut engines: BTreeMap<&str, EngineActivity> = BTreeMap::new();
    // Per epoch, the earliest timed evidence of it from any engine: the moment
    // after which staying behind that epoch stops being propagation delay.
    let mut epoch_first_seen: BTreeMap<u64, u64> = BTreeMap::new();
    for event in &export.events {
        let Some(engine_id) = event.engine_id.as_deref() else {
            continue;
        };
        let activity = engines.entry(engine_id).or_default();
        activity.last_seen_ms = activity.last_seen_ms.max(event.wall_time_ms);
        let observed = event.kind.observed_epoch();
        activity.high_water_epoch = activity.high_water_epoch.max(observed);
        if let (Some(epoch), Some(ms)) = (observed, event.wall_time_ms) {
            // Newest timed observation wins. A tie orders nothing, so it keeps
            // the higher epoch rather than assert a regression the timestamps
            // do not actually establish.
            let candidate = (ms, epoch);
            activity.current = Some(match activity.current {
                Some(current) if current > candidate => current,
                _ => candidate,
            });
            epoch_first_seen
                .entry(epoch)
                .and_modify(|first| *first = (*first).min(ms))
                .or_insert(ms);
        } else if observed.is_some() {
            activity.has_untimed_epoch = true;
        }
    }

    let group_epoch = engines
        .values()
        .filter_map(|activity| activity.high_water_epoch)
        .max()?;
    let behind: Vec<BehindEngine> = engines
        .iter()
        .filter_map(|(engine_id, activity)| {
            let high_water = activity.high_water_epoch?;
            // Lag is measured from where the engine is now, not from the best
            // it ever managed. The two differ only on a rollback, and only
            // ever widen the lag, so this can add a finding but never mask
            // one. Any untimed epoch row forfeits that reading for the whole
            // engine: the untimed row may be its newest, and preferring the
            // newest *timed* one would then invent a rollback out of ordinary
            // forward movement nobody stamped.
            let epoch = match activity.current {
                Some((_, epoch)) if !activity.has_untimed_epoch => epoch,
                _ => high_water,
            };
            let rolled_back = epoch < high_water;
            if group_epoch - epoch < EPOCH_DIVERGENCE_MIN_LAG {
                return None;
            }
            // Both the engine's own liveness and the group's advance past it
            // must be timestamped to order them; untimed evidence stays
            // unarmed rather than guessing.
            let last_seen = activity.last_seen_ms?;
            let moved_past = epoch_first_seen
                .range(epoch + 1..)
                .map(|(_, first_seen)| *first_seen)
                .min()?;
            let catch_up_deadline = moved_past.saturating_add(CATCH_UP_GRACE_MS);
            let mode = if rolled_back {
                BehindMode::RolledBack
            } else if last_seen > catch_up_deadline {
                BehindMode::ActiveWhileBehind
            } else {
                BehindMode::WentDark
            };
            Some(BehindEngine {
                engine_id: (*engine_id).to_owned(),
                epoch,
                mode,
            })
        })
        .collect();

    (!behind.is_empty()).then_some(QuarantineReason::EpochDivergence {
        group_epoch,
        engines: behind,
    })
}
