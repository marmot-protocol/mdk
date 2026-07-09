//! The classification gate.
//!
//! Everything downstream (extraction, fault synthesis, replay) is gated behind
//! this verdict, so a healthy export yields zero vectors and a clean exit rather
//! than a crash. Built incrementally, one rule per behaviour.

use std::collections::BTreeMap;
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

/// One engine left behind the group's epoch high-water mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BehindEngine {
    /// The engine that fell behind.
    pub engine_id: String,
    /// The highest epoch the engine's own events place it at.
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
}

impl fmt::Display for BehindMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BehindMode::WentDark => "went dark",
            BehindMode::ActiveWhileBehind => "active while behind",
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
    // No contested branch anywhere — the liveness gate now guards the healthy
    // verdict. It ranks below the incident routes deliberately: a reproducible
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

/// Per-engine activity, folded from the event log.
#[derive(Default)]
struct EngineActivity {
    /// The engine's newest event timestamp, when its events carry one.
    last_seen_ms: Option<u64>,
    /// The highest epoch the engine reported itself at.
    high_water_epoch: Option<u64>,
}

/// The gate that separates "no contested branch" from "healthy": engines left
/// ≥ [`EPOCH_DIVERGENCE_MIN_LAG`] epochs behind the group's high-water mark.
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
            epoch_first_seen
                .entry(epoch)
                .and_modify(|first| *first = (*first).min(ms))
                .or_insert(ms);
        }
    }

    let group_epoch = engines
        .values()
        .filter_map(|activity| activity.high_water_epoch)
        .max()?;
    let behind: Vec<BehindEngine> = engines
        .iter()
        .filter_map(|(engine_id, activity)| {
            let epoch = activity.high_water_epoch?;
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
            let mode = if last_seen > moved_past + CATCH_UP_GRACE_MS {
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
