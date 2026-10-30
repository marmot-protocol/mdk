//! The recovery runner's durable retry state (mdk#2660 phase 4): one row per
//! (route, relay) unit, each relay's health, the account's rolling-hour
//! budget, and the parked and retired spans, which are never coverage.
//!
//! Each quantum's outcome, each re-arm rule and each dismissal is one
//! transaction. The policy values come from the caller. Whether an active
//! unit is caught up, owed or backing off is not stored: it follows from the
//! unit's debt in the coverage ledger and from its next attempt time.
//! "Sweeping" is the runner's in-memory lease, so a restart reads it as owed.
//!
//! An attempt is charged to the account when it begins, so a process that
//! dies mid-quantum still counts it; the outcomes the account is not charged
//! for refund it at settlement.
//!
//! Nothing schedules on this state yet. Route ids and relay URLs are
//! account-private and must never be logged.
#[cfg(test)]
mod tests;

use crate::app::recovery_coverage::{
    RecoveryCoverageRange, integer, invalid, route_from, subtract, union,
};
use crate::base::codec::i64_to_u64;
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, TransportReconciliationRoute};
use cgka_traits::storage::StorageResult;
use rusqlite::{Connection, OptionalExtension, params};

const ACTIVE: i64 = 0;
const BROKEN: i64 = 1;
const RETIRED: i64 = 2;
const PARKED_SPAN: i64 = 0;
const RETIRED_SPAN: i64 = 1;
const BUDGET_WINDOW_SECS: u64 = 3_600;

/// What a relay says about its own limits, from its NIP-11 document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryRelayCaps {
    /// The most events one filter returns.
    pub max_limit: Option<u32>,
    /// The relay supports NIP-77.
    pub negentropy: bool,
}

/// Why a unit stopped being retried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryUnitBreak {
    /// It answered without progress until its budget ran out.
    NoProgress,
    /// The relay refused the request.
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryUnitState {
    /// Retried as its debt and backoff allow.
    Active,
    /// Not retried until new evidence re-arms it; its remaining debt is parked.
    Broken(RecoveryUnitBreak),
    /// Its parked debt was dismissed. Any debt it owes besides its retired
    /// spans is served as for an active unit, with a fresh budget, until
    /// progress makes it active or its budget breaks it again; its retired
    /// spans stay retired either way.
    Retired,
}

/// Why a span was retired. A retired span is never coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverySpanRetirement {
    Dismissed,
    RouteGone,
    BeforeThisCopy,
}

/// The result of one quantum on a unit, as the runner classifies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryUnitOutcome {
    /// Newly covered seconds on the unit's own (route, relay), including a cut
    /// or cancellation after progress.
    Advanced,
    /// The requested range was already covered.
    NothingOwed,
    /// The relay answered and nothing was newly covered.
    NoProgress,
    /// The relay could not be reached or timed out.
    Unreachable,
    /// The relay kept rate-limiting.
    RateLimited,
    /// The relay refused: auth required, restricted, blocked or unsupported.
    Refused,
    /// The runner preempted the call.
    Unanswered,
    /// Staging or the ledger write failed; the runner backs off in memory.
    LocalFailure,
}

/// The retry policy's values, owned by the runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryUnitPolicy {
    /// The first no-progress backoff; each further one doubles it.
    pub backoff_base_seconds: u64,
    pub backoff_cap_seconds: u64,
    /// No-progress answers before a unit breaks.
    pub break_after_no_progress: u32,
    /// How long an unreachable unit waits before its next attempt.
    pub unreachable_retry_seconds: u64,
    /// Unreachable results in a row before the relay cools down.
    pub cooldown_after_unreachable: u32,
    /// The first relay cooldown; each further one doubles it.
    pub cooldown_base_seconds: u64,
    pub cooldown_cap_seconds: u64,
    /// Attempts per rolling hour before the account breaker pauses.
    pub max_attempts_per_hour: u64,
    /// Fetched event bytes per rolling hour before the account breaker pauses.
    pub max_event_bytes_per_hour: u64,
    /// A relay cooldown spell longer than this makes every re-check on the
    /// relay due when the spell ends.
    pub recheck_after_cooldown_seconds: u64,
}

/// A broken unit's park. Its revision identifies the occurrence: a failed
/// probe keeps it, and a later park after the unit recovers is a new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryUnitPark {
    pub revision: u64,
    pub parked_at_seconds: u64,
}

/// A resumable re-check pass over the unit's covered and retired ranges.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryRecheckPass {
    /// Where the running pass resumes; `None` starts from the window floor.
    pub position_seconds: Option<u64>,
    /// When the last full pass completed; `None` means one is due.
    pub completed_at_seconds: Option<u64>,
    /// Bumped by every request that makes the pass due. Progress is recorded
    /// only under the revision its quantum began on
    /// ([`SqliteAppStorage::record_recovery_recheck`]).
    pub revision: u64,
}

/// One (route, relay) unit's durable state. Not `Debug`: it carries the route
/// and the relay.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryUnit {
    pub route: TransportReconciliationRoute,
    pub relay: String,
    pub state: RecoveryUnitState,
    /// A broken unit holds one probe attempt, earned by new loss over its park.
    pub probe: bool,
    pub no_progress: u32,
    pub backoff_step: u32,
    pub next_attempt_at_seconds: u64,
    pub slice_width_seconds: Option<u64>,
    pub observed_cap: Option<u32>,
    /// The caps its last attempt was planned with; `None` when unknown.
    pub planned_caps: Option<RecoveryRelayCaps>,
    /// Set while the unit is broken.
    pub park: Option<RecoveryUnitPark>,
    pub recheck: RecoveryRecheckPass,
    pub last_served_at_seconds: Option<u64>,
}

/// One relay's health. Not `Debug`: it carries the relay.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryRelayHealth {
    pub relay: String,
    pub unreachable_streak: u32,
    /// Cooldowns since the relay last answered; the next one lasts longer.
    pub cooldown_step: u32,
    /// The current cooldown spell: when it began and when it ends.
    pub cooldown: Option<(u64, u64)>,
    /// The last known caps; an unknown read never replaces them.
    pub caps: Option<RecoveryRelayCaps>,
    pub caps_fetched_at_seconds: Option<u64>,
}

/// What the account spent in the rolling hour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryAccountUsage {
    pub attempts: u64,
    pub event_bytes: u64,
}

/// One range of capture debt a unit fences: the part of a live REQ's range
/// its relay's non-empty count left unproven. Not `Debug`: it carries the
/// route and the relay.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryUnitFence {
    pub route: TransportReconciliationRoute,
    pub relay: String,
    pub range: RecoveryCoverageRange,
}

/// A parked or retired range on one unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryUnitSpan {
    pub range: RecoveryCoverageRange,
    /// `None` for a parked span.
    pub retired: Option<RecoverySpanRetirement>,
}

/// A route with at least one broken unit: one notice, whose revision is the
/// newest park among them and the route's remainder. Not `Debug`: it carries
/// the route and relays.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryParkedRoute {
    pub route: TransportReconciliationRoute,
    pub revision: u64,
    /// The oldest park among its broken units.
    pub parked_at_seconds: u64,
    pub relays: Vec<String>,
}

/// Debt the retention floor overtook on a route while some relay still owed
/// it: the earliest and latest such second. It is never fetched and never
/// coverage; only a dismissal clears it. Not `Debug`: it carries the route.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryRouteRemainder {
    pub route: TransportReconciliationRoute,
    pub range: RecoveryCoverageRange,
    pub revision: u64,
    /// When the route's remainder was first parked.
    pub parked_at_seconds: u64,
}

fn retirement_code(reason: RecoverySpanRetirement) -> i64 {
    match reason {
        RecoverySpanRetirement::Dismissed => 0,
        RecoverySpanRetirement::RouteGone => 1,
        RecoverySpanRetirement::BeforeThisCopy => 2,
    }
}

fn retirement(code: i64) -> StorageResult<RecoverySpanRetirement> {
    Ok(match code {
        0 => RecoverySpanRetirement::Dismissed,
        1 => RecoverySpanRetirement::RouteGone,
        2 => RecoverySpanRetirement::BeforeThisCopy,
        _ => return Err(invalid()),
    })
}

fn break_code(reason: RecoveryUnitBreak) -> i64 {
    match reason {
        RecoveryUnitBreak::NoProgress => 0,
        RecoveryUnitBreak::Refused => 1,
    }
}

fn count(value: i64) -> StorageResult<u32> {
    u32::try_from(value).map_err(|_| invalid())
}

fn optional(value: Option<i64>) -> StorageResult<Option<u64>> {
    value.map(i64_to_u64).transpose()
}

/// `base` doubled `step` times, capped.
fn doubling(base: u64, step: u32, cap: u64) -> u64 {
    base.saturating_mul(1u64.checked_shl(step).unwrap_or(u64::MAX))
        .min(cap)
}

fn caps(
    known: i64,
    max_limit: Option<i64>,
    negentropy: i64,
) -> StorageResult<Option<RecoveryRelayCaps>> {
    if known == 0 {
        return Ok(None);
    }
    Ok(Some(RecoveryRelayCaps {
        max_limit: max_limit
            .map(|limit| u32::try_from(limit).map_err(|_| invalid()))
            .transpose()?,
        negentropy: negentropy == 1,
    }))
}

fn caps_columns(caps: Option<RecoveryRelayCaps>) -> (i64, Option<i64>, i64) {
    match caps {
        None => (0, None, 0),
        Some(caps) => (1, caps.max_limit.map(i64::from), i64::from(caps.negentropy)),
    }
}

const UNIT_COLUMNS: &str = "route_kind, route_id, relay, state, broken_reason, probe, no_progress,
    backoff_step, next_attempt_at_seconds, slice_width_seconds, observed_cap, planned_caps_known,
    planned_max_limit, planned_negentropy, park_revision, parked_at_seconds,
    recheck_position_seconds, recheck_completed_at_seconds, last_served_at_seconds, recheck_revision";

fn unit_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UnitRow> {
    Ok(UnitRow {
        route_kind: row.get(0)?,
        route_id: row.get(1)?,
        relay: row.get(2)?,
        state: row.get(3)?,
        broken_reason: row.get(4)?,
        probe: row.get(5)?,
        no_progress: row.get(6)?,
        backoff_step: row.get(7)?,
        next_attempt_at: row.get(8)?,
        slice_width: row.get(9)?,
        observed_cap: row.get(10)?,
        planned_known: row.get(11)?,
        planned_max_limit: row.get(12)?,
        planned_negentropy: row.get(13)?,
        park_revision: row.get(14)?,
        parked_at: row.get(15)?,
        recheck_position: row.get(16)?,
        recheck_completed_at: row.get(17)?,
        last_served_at: row.get(18)?,
        recheck_revision: row.get(19)?,
    })
}

struct UnitRow {
    route_kind: i64,
    route_id: Vec<u8>,
    relay: String,
    state: i64,
    broken_reason: Option<i64>,
    probe: i64,
    no_progress: i64,
    backoff_step: i64,
    next_attempt_at: i64,
    slice_width: Option<i64>,
    observed_cap: Option<i64>,
    planned_known: i64,
    planned_max_limit: Option<i64>,
    planned_negentropy: i64,
    park_revision: i64,
    parked_at: Option<i64>,
    recheck_position: Option<i64>,
    recheck_completed_at: Option<i64>,
    last_served_at: Option<i64>,
    recheck_revision: i64,
}

impl UnitRow {
    fn decode(self) -> StorageResult<RecoveryUnit> {
        let state = match (self.state, self.broken_reason) {
            (ACTIVE, None) => RecoveryUnitState::Active,
            (BROKEN, Some(0)) => RecoveryUnitState::Broken(RecoveryUnitBreak::NoProgress),
            (BROKEN, Some(1)) => RecoveryUnitState::Broken(RecoveryUnitBreak::Refused),
            (RETIRED, None) => RecoveryUnitState::Retired,
            _ => return Err(invalid()),
        };
        let park = match (state, self.parked_at) {
            (RecoveryUnitState::Broken(_), Some(parked_at)) => Some(RecoveryUnitPark {
                revision: i64_to_u64(self.park_revision)?,
                parked_at_seconds: i64_to_u64(parked_at)?,
            }),
            (RecoveryUnitState::Broken(_), None) => return Err(invalid()),
            _ => None,
        };
        Ok(RecoveryUnit {
            route: route_from(self.route_kind, &self.route_id)?,
            relay: self.relay,
            state,
            probe: self.probe == 1,
            no_progress: count(self.no_progress)?,
            backoff_step: count(self.backoff_step)?,
            next_attempt_at_seconds: i64_to_u64(self.next_attempt_at)?,
            slice_width_seconds: optional(self.slice_width)?,
            observed_cap: self
                .observed_cap
                .map(|cap| u32::try_from(cap).map_err(|_| invalid()))
                .transpose()?,
            planned_caps: caps(
                self.planned_known,
                self.planned_max_limit,
                self.planned_negentropy,
            )?,
            park,
            recheck: RecoveryRecheckPass {
                position_seconds: optional(self.recheck_position)?,
                completed_at_seconds: optional(self.recheck_completed_at)?,
                revision: i64_to_u64(self.recheck_revision)?,
            },
            last_served_at_seconds: optional(self.last_served_at)?,
        })
    }
}

fn ensure_unit_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    relay: &str,
) -> StorageResult<()> {
    if relay.is_empty() {
        return Err(invalid());
    }
    let (kind, id) = route.storage_key();
    conn.execute_cached(
        "INSERT OR IGNORE INTO account_recovery_units (route_kind, route_id, relay)
         VALUES (?1, ?2, ?3)",
        params![kind, id, relay],
    )
    .storage()?;
    Ok(())
}

fn ensure_relay_tx(conn: &Connection, relay: &str) -> StorageResult<()> {
    if relay.is_empty() {
        return Err(invalid());
    }
    conn.execute_cached(
        "INSERT OR IGNORE INTO account_recovery_relays (relay) VALUES (?1)",
        [relay],
    )
    .storage()?;
    Ok(())
}

fn unit_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    relay: &str,
) -> StorageResult<Option<RecoveryUnit>> {
    let (kind, id) = route.storage_key();
    conn.query_row_cached(
        &format!(
            "SELECT {UNIT_COLUMNS} FROM account_recovery_units
             WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3"
        ),
        params![kind, id, relay],
        unit_from_row,
    )
    .optional()
    .storage()?
    .map(UnitRow::decode)
    .transpose()
}

fn units_tx(
    conn: &Connection,
    filter: &str,
    args: impl rusqlite::Params,
) -> StorageResult<Vec<RecoveryUnit>> {
    conn.prepare_cached(&format!(
        "SELECT {UNIT_COLUMNS} FROM account_recovery_units {filter}
         ORDER BY route_kind, route_id, relay"
    ))
    .storage()?
    .query_map(args, unit_from_row)
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()?
    .into_iter()
    .map(UnitRow::decode)
    .collect()
}

fn spans_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    relay: &str,
    kind: i64,
) -> StorageResult<Vec<RecoveryUnitSpan>> {
    let (route_kind, id) = route.storage_key();
    conn.prepare_cached(
        "SELECT since_seconds, until_seconds, reason FROM account_recovery_unit_spans
         WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3 AND kind = ?4
         ORDER BY since_seconds",
    )
    .storage()?
    .query_map(params![route_kind, id, relay, kind], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<i64>>(2)?,
        ))
    })
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()?
    .into_iter()
    .map(|(since, until, reason)| {
        Ok(RecoveryUnitSpan {
            range: RecoveryCoverageRange {
                since_seconds: i64_to_u64(since)?,
                until_seconds: i64_to_u64(until)?,
            },
            retired: reason.map(retirement).transpose()?,
        })
    })
    .collect()
}

/// Replace a unit's spans of one kind. Retired spans keep each range's
/// reason; `ranges` must not overlap.
fn replace_spans_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    relay: &str,
    kind: i64,
    spans: &[RecoveryUnitSpan],
) -> StorageResult<()> {
    let (route_kind, id) = route.storage_key();
    conn.execute_cached(
        "DELETE FROM account_recovery_unit_spans
         WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3 AND kind = ?4",
        params![route_kind, id, relay, kind],
    )
    .storage()?;
    for span in spans {
        conn.execute_cached(
            "INSERT INTO account_recovery_unit_spans
             (route_kind, route_id, relay, kind, since_seconds, until_seconds, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                route_kind,
                id,
                relay,
                kind,
                integer(span.range.since_seconds)?,
                integer(span.range.until_seconds)?,
                span.retired.map(retirement_code)
            ],
        )
        .storage()?;
    }
    Ok(())
}

/// What one relay covers on a route, merged.
fn relay_covered_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    relay: &str,
) -> StorageResult<Vec<RecoveryCoverageRange>> {
    let (kind, id) = route.storage_key();
    let rows = conn
        .prepare_cached(
            "SELECT since_seconds, until_seconds FROM account_recovery_coverage
             WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
        )
        .storage()?
        .query_map(params![kind, id, relay], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    Ok(union(
        rows.into_iter()
            .map(|(since, until)| {
                Ok(RecoveryCoverageRange {
                    since_seconds: i64_to_u64(since)?,
                    until_seconds: i64_to_u64(until)?,
                })
            })
            .collect::<StorageResult<_>>()?,
    ))
}

/// Every range in `ranges` minus a merged, sorted `taken` list.
fn subtract_all(
    ranges: &[RecoveryCoverageRange],
    taken: &[RecoveryCoverageRange],
) -> Vec<RecoveryCoverageRange> {
    ranges
        .iter()
        .flat_map(|range| subtract(*range, taken))
        .collect()
}

/// The unit's debt up to `until_seconds`: its route's goal minus what this
/// relay covers and its retired spans, and minus its parked spans unless it
/// holds a probe.
fn unit_debt_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    relay: &str,
    until_seconds: u64,
) -> StorageResult<Vec<RecoveryCoverageRange>> {
    let (kind, id) = route.storage_key();
    let Some(goal) = conn
        .query_row_cached(
            "SELECT since_seconds FROM account_recovery_coverage_goals
             WHERE route_kind = ?1 AND route_id = ?2",
            params![kind, id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .storage()?
    else {
        return Ok(Vec::new());
    };
    let goal = i64_to_u64(goal)?;
    if goal > until_seconds {
        return Ok(Vec::new());
    }
    let probing = unit_tx(conn, route, relay)?.is_some_and(|unit| unit.probe);
    let mut taken = relay_covered_tx(conn, route, relay)?;
    taken.extend(
        spans_tx(conn, route, relay, RETIRED_SPAN)?
            .iter()
            .map(|span| span.range),
    );
    if !probing {
        taken.extend(
            spans_tx(conn, route, relay, PARKED_SPAN)?
                .iter()
                .map(|span| span.range),
        );
    }
    Ok(subtract(
        RecoveryCoverageRange {
            since_seconds: goal,
            until_seconds,
        },
        &union(taken),
    ))
}

fn next_park_revision_tx(conn: &Connection) -> StorageResult<i64> {
    conn.query_row_cached(
        "UPDATE account_recovery_park_revision SET revision = revision + 1
         WHERE singleton = 1 RETURNING revision",
        [],
        |row| row.get(0),
    )
    .storage()
}

/// Break the unit and park its remaining debt. `revision` keeps an existing
/// park's identity (a failed probe); `None` starts a new park.
fn park_tx(
    conn: &Connection,
    unit: &RecoveryUnit,
    reason: RecoveryUnitBreak,
    keep: Option<RecoveryUnitPark>,
    now_seconds: u64,
) -> StorageResult<()> {
    let (revision, parked_at) = match keep {
        Some(park) => (integer(park.revision)?, integer(park.parked_at_seconds)?),
        None => (next_park_revision_tx(conn)?, integer(now_seconds)?),
    };
    let (kind, id) = unit.route.storage_key();
    conn.execute_cached(
        "UPDATE account_recovery_units SET state = ?4, broken_reason = ?5, probe = 0,
         park_revision = ?6, parked_at_seconds = ?7
         WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
        params![
            kind,
            id,
            unit.relay,
            BROKEN,
            break_code(reason),
            revision,
            parked_at
        ],
    )
    .storage()?;
    // A re-park keeps every parked second this relay still does not cover.
    // With the old park cleared and the probe flag clear, the debt adds
    // whatever else is owed now.
    let covered = relay_covered_tx(conn, &unit.route, &unit.relay)?;
    let mut parked = subtract_all(
        &spans_tx(conn, &unit.route, &unit.relay, PARKED_SPAN)?
            .iter()
            .map(|span| span.range)
            .collect::<Vec<_>>(),
        &covered,
    );
    replace_spans_tx(conn, &unit.route, &unit.relay, PARKED_SPAN, &[])?;
    parked.extend(unit_debt_tx(conn, &unit.route, &unit.relay, now_seconds)?);
    let parked = union(parked)
        .into_iter()
        .map(|range| RecoveryUnitSpan {
            range,
            retired: None,
        })
        .collect::<Vec<_>>();
    replace_spans_tx(conn, &unit.route, &unit.relay, PARKED_SPAN, &parked)
}

/// Make the unit active with a fresh budget, dropping any park.
fn rearm_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    relay: &str,
) -> StorageResult<()> {
    let (kind, id) = route.storage_key();
    conn.execute_cached(
        "UPDATE account_recovery_units SET state = ?4, broken_reason = NULL, probe = 0,
         no_progress = 0, backoff_step = 0, next_attempt_at_seconds = 0, parked_at_seconds = NULL
         WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
        params![kind, id, relay, ACTIVE],
    )
    .storage()?;
    replace_spans_tx(conn, route, relay, PARKED_SPAN, &[])
}

fn budget_add_tx(conn: &Connection, minute: u64, attempts: i64, bytes: u64) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM account_recovery_budget WHERE minute < ?1",
        [integer(minute.saturating_sub(BUDGET_WINDOW_SECS / 60))?],
    )
    .storage()?;
    conn.execute_cached(
        "INSERT INTO account_recovery_budget (minute, attempts, event_bytes) VALUES (?1, MAX(?2, 0), ?3)
         ON CONFLICT (minute) DO UPDATE SET attempts = MAX(attempts + ?2, 0),
         event_bytes = event_bytes + ?3",
        params![integer(minute)?, attempts, integer(bytes)?],
    )
    .storage()?;
    Ok(())
}

/// Charge fetched event bytes to the account's rolling hour.
pub(crate) fn charge_event_bytes_tx(
    conn: &Connection,
    bytes: u64,
    now_seconds: u64,
) -> StorageResult<()> {
    if bytes == 0 {
        return Ok(());
    }
    budget_add_tx(conn, now_seconds / 60, 0, bytes)
}

fn budget_rows_tx(conn: &Connection, now_seconds: u64) -> StorageResult<Vec<(u64, u64, u64)>> {
    let first = integer(now_seconds.saturating_sub(BUDGET_WINDOW_SECS) / 60)?;
    conn.execute_cached(
        "DELETE FROM account_recovery_budget WHERE minute < ?1",
        [first],
    )
    .storage()?;
    conn.prepare_cached(
        "SELECT minute, attempts, event_bytes FROM account_recovery_budget ORDER BY minute",
    )
    .storage()?
    .query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()?
    .into_iter()
    .map(|(minute, attempts, bytes)| {
        Ok((
            i64_to_u64(minute)?,
            i64_to_u64(attempts)?,
            i64_to_u64(bytes)?,
        ))
    })
    .collect()
}

fn relay_answered_tx(
    conn: &Connection,
    relay: &str,
    policy: &RecoveryUnitPolicy,
    now_seconds: u64,
) -> StorageResult<()> {
    let since = cooldown_since_tx(conn, relay)?;
    conn.execute_cached(
        "UPDATE account_recovery_relays SET unreachable_streak = 0, cooldown_step = 0,
         cooldown_since_seconds = NULL, cooldown_until_seconds = NULL WHERE relay = ?1",
        [relay],
    )
    .storage()?;
    cooldown_ended_tx(conn, relay, since, policy, now_seconds)
}

/// When the relay's cooldown spell began, if one has not ended yet.
fn cooldown_since_tx(conn: &Connection, relay: &str) -> StorageResult<Option<u64>> {
    let since: Option<Option<i64>> = conn
        .query_row_cached(
            "SELECT cooldown_since_seconds FROM account_recovery_relays WHERE relay = ?1",
            [relay],
            |row| row.get(0),
        )
        .optional()
        .storage()?;
    optional(since.flatten())
}

/// The relay's cooldown spell that began at `since` just ended, in the same
/// transaction. One longer than the policy's bound makes every re-check on
/// the relay due from the window floor: the relay may have accepted history
/// while the device could not reach it.
fn cooldown_ended_tx(
    conn: &Connection,
    relay: &str,
    since: Option<u64>,
    policy: &RecoveryUnitPolicy,
    now_seconds: u64,
) -> StorageResult<()> {
    if since.is_some_and(|since| {
        now_seconds.saturating_sub(since) > policy.recheck_after_cooldown_seconds
    }) {
        recheck_due_tx(conn, None, Some(relay), None)?;
    }
    Ok(())
}

/// Make re-checks due now, on `route` (every route when `None`) and `relay`
/// (every relay when `None`), from `from_seconds` when given and from the
/// window floor otherwise. A pass already due or running keeps whatever it
/// would check below `from_seconds`.
fn recheck_due_tx(
    conn: &Connection,
    route: Option<&TransportReconciliationRoute>,
    relay: Option<&str>,
    from_seconds: Option<u64>,
) -> StorageResult<()> {
    let (kind, id) = match route.map(TransportReconciliationRoute::storage_key) {
        Some((kind, id)) => (Some(kind), Some(id)),
        None => (None, None),
    };
    conn.execute_cached(
        "UPDATE account_recovery_units SET recheck_position_seconds = CASE
          WHEN ?4 IS NULL THEN NULL
          WHEN recheck_position_seconds IS NOT NULL THEN MIN(recheck_position_seconds, ?4)
          WHEN recheck_completed_at_seconds IS NOT NULL THEN ?4
          ELSE NULL END,
         recheck_completed_at_seconds = NULL, recheck_revision = recheck_revision + 1
         WHERE (?1 IS NULL OR (route_kind = ?1 AND route_id = ?2)) AND (?3 IS NULL OR relay = ?3)",
        params![kind, id, relay, from_seconds.map(integer).transpose()?],
    )
    .storage()?;
    Ok(())
}

fn relay_cool_down_tx(
    conn: &Connection,
    relay: &str,
    policy: &RecoveryUnitPolicy,
    now_seconds: u64,
) -> StorageResult<()> {
    let step: i64 = conn
        .query_row_cached(
            "SELECT cooldown_step FROM account_recovery_relays WHERE relay = ?1",
            [relay],
            |row| row.get(0),
        )
        .storage()?;
    let until = now_seconds.saturating_add(doubling(
        policy.cooldown_base_seconds,
        count(step)?,
        policy.cooldown_cap_seconds,
    ));
    conn.execute_cached(
        "UPDATE account_recovery_relays SET cooldown_step = cooldown_step + 1,
         cooldown_since_seconds = COALESCE(cooldown_since_seconds, ?2),
         cooldown_until_seconds = ?3 WHERE relay = ?1",
        params![relay, integer(now_seconds)?, integer(until)?],
    )
    .storage()?;
    Ok(())
}

/// New loss or a released receipt un-covered `ranges` on `route` (every route
/// when `None`). Retired seconds it overlaps are owed again, whatever the
/// unit's state: an active unit serves them as ordinary debt, a broken unit
/// adds them to its park, and a retired unit parks them under a new revision.
/// A broken unit whose park it overlaps earns one probe attempt under its
/// current park, as does a retired unit that reopened anything. Runs inside
/// the un-cover's transaction.
pub(crate) fn probe_on_uncover_tx(
    conn: &Connection,
    route: Option<&TransportReconciliationRoute>,
    ranges: &[(u64, Option<u64>)],
    now_seconds: u64,
) -> StorageResult<()> {
    let uncovered = union(
        ranges
            .iter()
            .map(|(since, until)| RecoveryCoverageRange {
                since_seconds: *since,
                until_seconds: until.unwrap_or(u64::MAX),
            })
            .collect(),
    );
    // Only a unit with a span can be affected.
    const WITH_SPANS: &str = "EXISTS (SELECT 1 FROM account_recovery_unit_spans s
        WHERE s.route_kind = account_recovery_units.route_kind
          AND s.route_id = account_recovery_units.route_id
          AND s.relay = account_recovery_units.relay)";
    let units = match route {
        Some(route) => {
            let (kind, id) = route.storage_key();
            units_tx(
                conn,
                &format!("WHERE route_kind = ?1 AND route_id = ?2 AND {WITH_SPANS}"),
                params![kind, id],
            )?
        }
        None => units_tx(conn, &format!("WHERE {WITH_SPANS}"), [])?,
    };
    for unit in units {
        let (kind, id) = unit.route.storage_key();
        let retired = spans_tx(conn, &unit.route, &unit.relay, RETIRED_SPAN)?;
        let mut kept = Vec::new();
        let mut reopened = Vec::new();
        for span in &retired {
            let rest = subtract(span.range, &uncovered);
            reopened.extend(subtract(span.range, &rest));
            kept.extend(rest.into_iter().map(|range| RecoveryUnitSpan {
                range,
                retired: span.retired,
            }));
        }
        let reopened = union(reopened);
        if !reopened.is_empty() {
            replace_spans_tx(conn, &unit.route, &unit.relay, RETIRED_SPAN, &kept)?;
        }
        let parked = spans_tx(conn, &unit.route, &unit.relay, PARKED_SPAN)?;
        let park_overlaps = parked
            .iter()
            .any(|span| !subtract(span.range, &uncovered).eq(&[span.range]));
        let parked_now = |extra: &[RecoveryCoverageRange]| {
            union(
                parked
                    .iter()
                    .map(|span| span.range)
                    .chain(extra.iter().copied())
                    .collect(),
            )
            .into_iter()
            .map(|range| RecoveryUnitSpan {
                range,
                retired: None,
            })
            .collect::<Vec<_>>()
        };
        match unit.state {
            RecoveryUnitState::Active => {}
            RecoveryUnitState::Broken(_) => {
                if !reopened.is_empty() {
                    replace_spans_tx(
                        conn,
                        &unit.route,
                        &unit.relay,
                        PARKED_SPAN,
                        &parked_now(&reopened),
                    )?;
                }
                if (park_overlaps || !reopened.is_empty()) && !unit.probe {
                    // The probe does not wait out a backoff from before.
                    conn.execute_cached(
                        "UPDATE account_recovery_units SET probe = 1, next_attempt_at_seconds = 0
                         WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                        params![kind, id, unit.relay],
                    )
                    .storage()?;
                }
            }
            RecoveryUnitState::Retired => {
                if reopened.is_empty() {
                    continue;
                }
                let revision = next_park_revision_tx(conn)?;
                conn.execute_cached(
                    "UPDATE account_recovery_units SET state = ?4, broken_reason = 0, probe = 1,
                     next_attempt_at_seconds = 0, park_revision = ?5, parked_at_seconds = ?6
                     WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                    params![
                        kind,
                        id,
                        unit.relay,
                        BROKEN,
                        revision,
                        integer(now_seconds)?
                    ],
                )
                .storage()?;
                replace_spans_tx(
                    conn,
                    &unit.route,
                    &unit.relay,
                    PARKED_SPAN,
                    &parked_now(&reopened),
                )?;
            }
        }
    }
    Ok(())
}

/// Coverage now proves part of a unit's parked or retired spans; those parts
/// are no longer debt of either kind. A broken unit whose last parked part is
/// proved has nothing parked left, so it is re-armed and its notice ends. Runs
/// inside every coverage write.
pub(crate) fn trim_spans_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    relay: &str,
) -> StorageResult<()> {
    let parked = spans_tx(conn, route, relay, PARKED_SPAN)?;
    let retired = spans_tx(conn, route, relay, RETIRED_SPAN)?;
    if parked.is_empty() && retired.is_empty() {
        return Ok(());
    }
    let covered = relay_covered_tx(conn, route, relay)?;
    let trim = |spans: &[RecoveryUnitSpan]| {
        spans
            .iter()
            .flat_map(|span| {
                subtract(span.range, &covered)
                    .into_iter()
                    .map(|range| RecoveryUnitSpan {
                        range,
                        retired: span.retired,
                    })
            })
            .collect::<Vec<_>>()
    };
    let kept_retired = trim(&retired);
    if kept_retired != retired {
        replace_spans_tx(conn, route, relay, RETIRED_SPAN, &kept_retired)?;
    }
    let kept_parked = trim(&parked);
    if kept_parked == parked {
        return Ok(());
    }
    if kept_parked.is_empty()
        && unit_tx(conn, route, relay)?
            .is_some_and(|unit| matches!(unit.state, RecoveryUnitState::Broken(_)))
    {
        return rearm_tx(conn, route, relay);
    }
    replace_spans_tx(conn, route, relay, PARKED_SPAN, &kept_parked)
}

/// The retention floor is about to overtake each route's goal below `floor`.
/// Whatever any of the route's `relays` still owes there (not covered on that
/// relay and not retired; parked seconds are owed) joins the route's parked
/// remainder, so the prune never makes debt vanish. With no relays, nothing
/// covers the route and all of it is owed. Only seconds from the route's
/// settled floor up count: an earlier prune parked or dropped everything
/// below it and kept no coverage there, so a goal widened back below it
/// parks nothing twice, and a dismissed remainder stays dismissed until loss
/// lowers the settled floor. A route's first remainder takes a new park
/// revision; a later one widens it under the same revision. Runs inside that
/// prune, before it drops anything.
pub(crate) fn park_overtaken_tx(
    conn: &Connection,
    floor: u64,
    routes: &[(TransportReconciliationRoute, Vec<String>)],
    now_seconds: u64,
) -> StorageResult<()> {
    let Some(top) = floor.checked_sub(1) else {
        return Ok(());
    };
    for (route, relays) in routes {
        let (kind, id) = route.storage_key();
        let Some(since) = conn
            .query_row_cached(
                "SELECT MAX(since_seconds, settled_below_seconds)
                 FROM account_recovery_coverage_goals
                 WHERE route_kind = ?1 AND route_id = ?2
                   AND MAX(since_seconds, settled_below_seconds) < ?3",
                params![kind, id, integer(floor)?],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .storage()?
        else {
            continue;
        };
        let below = RecoveryCoverageRange {
            since_seconds: i64_to_u64(since)?,
            until_seconds: top,
        };
        let owed = if relays.is_empty() {
            vec![below]
        } else {
            let mut owed = Vec::new();
            for relay in relays {
                let mut taken = relay_covered_tx(conn, route, relay)?;
                taken.extend(
                    spans_tx(conn, route, relay, RETIRED_SPAN)?
                        .iter()
                        .map(|span| span.range),
                );
                owed.extend(subtract(below, &union(taken)));
            }
            union(owed)
        };
        let (Some(first), Some(last)) = (owed.first(), owed.last()) else {
            continue;
        };
        let (since, until) = (integer(first.since_seconds)?, integer(last.until_seconds)?);
        let widened = conn
            .execute_cached(
                "UPDATE account_recovery_coverage_remainders
                 SET since_seconds = MIN(since_seconds, ?3), until_seconds = MAX(until_seconds, ?4)
                 WHERE route_kind = ?1 AND route_id = ?2",
                params![kind, id, since, until],
            )
            .storage()?;
        if widened == 0 {
            let revision = next_park_revision_tx(conn)?;
            conn.execute_cached(
                "INSERT INTO account_recovery_coverage_remainders
                 (route_kind, route_id, since_seconds, until_seconds, park_revision,
                  parked_at_seconds)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![kind, id, since, until, revision, integer(now_seconds)?],
            )
            .storage()?;
        }
    }
    Ok(())
}

/// The route's remainder revision, if it has one.
fn remainder_revision_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
) -> StorageResult<Option<u64>> {
    let (kind, id) = route.storage_key();
    conn.query_row_cached(
        "SELECT park_revision FROM account_recovery_coverage_remainders
         WHERE route_kind = ?1 AND route_id = ?2",
        params![kind, id],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .storage()?
    .map(i64_to_u64)
    .transpose()
}

/// Drop parked and retired span parts below the retention floor, as the
/// coverage prune does for ranges and goals, so every span stays inside the
/// route's goal and any re-arm turns a parked span back into ordinary debt.
/// Parked parts were added to the route's remainder first. Fenced ranges
/// wholly below the floor go too: nothing there is owed any more. Runs inside
/// that prune.
pub(crate) fn prune_spans_tx(conn: &Connection, floor: i64) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM account_recovery_unit_fences WHERE until_seconds < ?1",
        [floor],
    )
    .storage()?;
    conn.execute_cached(
        "DELETE FROM account_recovery_unit_spans WHERE until_seconds < ?1",
        [floor],
    )
    .storage()?;
    // Spans of one unit and kind never overlap, so at most one straddles the
    // floor and raising it cannot collide.
    conn.execute_cached(
        "UPDATE account_recovery_unit_spans SET since_seconds = ?1 WHERE since_seconds < ?1",
        [floor],
    )
    .storage()?;
    Ok(())
}

impl SqliteAppStorage {
    /// The runner picked this unit: remember when and with which caps, and
    /// charge one attempt to the account's rolling hour.
    pub fn begin_recovery_unit_attempt(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
        planned_caps: Option<RecoveryRelayCaps>,
        now_seconds: u64,
    ) -> StorageResult<()> {
        let (known, max_limit, negentropy) = caps_columns(planned_caps);
        let minute = now_seconds / 60;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            ensure_unit_tx(&conn, route, relay)?;
            let (kind, id) = route.storage_key();
            conn.execute_cached(
                "UPDATE account_recovery_units SET last_served_at_seconds = ?4,
                 attempt_minute = ?5, planned_caps_known = ?6, planned_max_limit = ?7,
                 planned_negentropy = ?8
                 WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                params![
                    kind,
                    id,
                    relay,
                    integer(now_seconds)?,
                    integer(minute)?,
                    known,
                    max_limit,
                    negentropy
                ],
            )
            .storage()?;
            budget_add_tx(&conn, minute, 1, 0)
        })
    }

    /// Apply one quantum's outcome to the unit, its relay and the account, in
    /// one transaction, and return the unit as it now stands.
    pub fn settle_recovery_unit(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
        outcome: RecoveryUnitOutcome,
        policy: &RecoveryUnitPolicy,
        now_seconds: u64,
    ) -> StorageResult<RecoveryUnit> {
        use RecoveryUnitOutcome as Outcome;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            ensure_unit_tx(&conn, route, relay)?;
            ensure_relay_tx(&conn, relay)?;
            let (kind, id) = route.storage_key();
            let attempt_minute: Option<i64> = conn
                .query_row_cached(
                    "SELECT attempt_minute FROM account_recovery_units
                     WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                    params![kind, id, relay],
                    |row| row.get(0),
                )
                .storage()?;
            conn.execute_cached(
                "UPDATE account_recovery_units SET attempt_minute = NULL
                 WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                params![kind, id, relay],
            )
            .storage()?;
            if let (Some(minute), Outcome::NothingOwed | Outcome::Unanswered | Outcome::LocalFailure) =
                (attempt_minute, outcome)
            {
                budget_add_tx(&conn, i64_to_u64(minute)?, -1, 0)?;
            }
            let unit = unit_tx(&conn, route, relay)?.ok_or_else(invalid)?;
            match outcome {
                Outcome::Advanced => {
                    rearm_tx(&conn, route, relay)?;
                    relay_answered_tx(&conn, relay, policy, now_seconds)?;
                }
                Outcome::NothingOwed => match unit.state {
                    // A broken unit's debt leaves its park out, so only a
                    // probing one learns anything here.
                    RecoveryUnitState::Broken(_) if !unit.probe => {}
                    // A retired unit stays retired until progress or a break.
                    RecoveryUnitState::Retired => {
                        conn.execute_cached(
                            "UPDATE account_recovery_units SET no_progress = 0, backoff_step = 0,
                             next_attempt_at_seconds = 0
                             WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                            params![kind, id, relay],
                        )
                        .storage()?;
                    }
                    _ => rearm_tx(&conn, route, relay)?,
                },
                Outcome::NoProgress => {
                    relay_answered_tx(&conn, relay, policy, now_seconds)?;
                    match unit.state {
                        RecoveryUnitState::Broken(reason) if unit.probe => {
                            park_tx(&conn, &unit, reason, unit.park, now_seconds)?;
                        }
                        RecoveryUnitState::Active | RecoveryUnitState::Retired => {
                            let no_progress = unit.no_progress.saturating_add(1);
                            if no_progress >= policy.break_after_no_progress {
                                conn.execute_cached(
                                    "UPDATE account_recovery_units SET no_progress = ?4
                                     WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                                    params![kind, id, relay, i64::from(no_progress)],
                                )
                                .storage()?;
                                park_tx(&conn, &unit, RecoveryUnitBreak::NoProgress, None, now_seconds)?;
                            } else {
                                let next = now_seconds.saturating_add(doubling(
                                    policy.backoff_base_seconds,
                                    unit.backoff_step,
                                    policy.backoff_cap_seconds,
                                ));
                                conn.execute_cached(
                                    "UPDATE account_recovery_units SET no_progress = ?4,
                                     backoff_step = backoff_step + 1, next_attempt_at_seconds = ?5
                                     WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                                    params![kind, id, relay, i64::from(no_progress), integer(next)?],
                                )
                                .storage()?;
                            }
                        }
                        _ => {}
                    }
                }
                Outcome::Unreachable => {
                    let next = now_seconds.saturating_add(policy.unreachable_retry_seconds);
                    conn.execute_cached(
                        "UPDATE account_recovery_units SET next_attempt_at_seconds = ?4
                         WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                        params![kind, id, relay, integer(next)?],
                    )
                    .storage()?;
                    let streak: i64 = conn
                        .query_row_cached(
                            "UPDATE account_recovery_relays SET unreachable_streak = unreachable_streak + 1
                             WHERE relay = ?1 RETURNING unreachable_streak",
                            [relay],
                            |row| row.get(0),
                        )
                        .storage()?;
                    if count(streak)? >= policy.cooldown_after_unreachable {
                        relay_cool_down_tx(&conn, relay, policy, now_seconds)?;
                    }
                }
                Outcome::RateLimited => relay_cool_down_tx(&conn, relay, policy, now_seconds)?,
                Outcome::Refused => match unit.state {
                    RecoveryUnitState::Broken(_) if unit.probe => {
                        park_tx(&conn, &unit, RecoveryUnitBreak::Refused, unit.park, now_seconds)?;
                    }
                    RecoveryUnitState::Active | RecoveryUnitState::Retired => {
                        park_tx(&conn, &unit, RecoveryUnitBreak::Refused, None, now_seconds)?;
                    }
                    _ => {}
                },
                Outcome::Unanswered | Outcome::LocalFailure => {}
            }
            unit_tx(&conn, route, relay)?.ok_or_else(invalid)
        })
    }

    /// Apply one re-check quantum's outcome to the relay and the account, in
    /// one transaction. A re-check reads covered and retired ranges, which
    /// the unit does not owe, so it never touches the unit's retry state: its
    /// backoff, budget, break and park stay as its debt left them. The pass's
    /// own progress is [`Self::record_recovery_recheck`]'s.
    pub fn settle_recovery_recheck(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
        outcome: RecoveryUnitOutcome,
        policy: &RecoveryUnitPolicy,
        now_seconds: u64,
    ) -> StorageResult<()> {
        use RecoveryUnitOutcome as Outcome;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            ensure_unit_tx(&conn, route, relay)?;
            ensure_relay_tx(&conn, relay)?;
            let (kind, id) = route.storage_key();
            let attempt_minute: Option<i64> = conn
                .query_row_cached(
                    "SELECT attempt_minute FROM account_recovery_units
                     WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                    params![kind, id, relay],
                    |row| row.get(0),
                )
                .storage()?;
            conn.execute_cached(
                "UPDATE account_recovery_units SET attempt_minute = NULL
                 WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                params![kind, id, relay],
            )
            .storage()?;
            if let (Some(minute), Outcome::NothingOwed | Outcome::Unanswered | Outcome::LocalFailure) =
                (attempt_minute, outcome)
            {
                budget_add_tx(&conn, i64_to_u64(minute)?, -1, 0)?;
            }
            match outcome {
                Outcome::Advanced | Outcome::NoProgress => relay_answered_tx(&conn, relay, policy, now_seconds)?,
                Outcome::Unreachable => {
                    let streak: i64 = conn
                        .query_row_cached(
                            "UPDATE account_recovery_relays SET unreachable_streak = unreachable_streak + 1
                             WHERE relay = ?1 RETURNING unreachable_streak",
                            [relay],
                            |row| row.get(0),
                        )
                        .storage()?;
                    if count(streak)? >= policy.cooldown_after_unreachable {
                        relay_cool_down_tx(&conn, relay, policy, now_seconds)?;
                    }
                }
                Outcome::RateLimited => relay_cool_down_tx(&conn, relay, policy, now_seconds)?,
                Outcome::NothingOwed
                | Outcome::Refused
                | Outcome::Unanswered
                | Outcome::LocalFailure => {}
            }
            Ok(())
        })
    }

    /// Re-arm one unit fully: a relay was added to its route. A unit that is
    /// not broken is left as it is. Returns whether it was broken.
    pub fn rearm_recovery_unit(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let broken = unit_tx(&conn, route, relay)?
                .is_some_and(|unit| matches!(unit.state, RecoveryUnitState::Broken(_)));
            if broken {
                rearm_tx(&conn, route, relay)?;
            }
            Ok(broken)
        })
    }

    /// Explicit repair: every broken and retired unit is active again with a
    /// fresh budget, every parked and retired span is owed again, and every
    /// unit's re-check falls due now. Returns the units re-armed.
    pub fn rearm_all_recovery_units(&self) -> StorageResult<usize> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let rearmed = conn
                .execute_cached(
                    "UPDATE account_recovery_units SET state = 0, broken_reason = NULL, probe = 0,
                     no_progress = 0, backoff_step = 0, next_attempt_at_seconds = 0,
                     parked_at_seconds = NULL WHERE state != 0",
                    [],
                )
                .storage()?;
            conn.execute_cached("DELETE FROM account_recovery_unit_spans", [])
                .storage()?;
            conn.execute_cached(
                "UPDATE account_recovery_units SET recheck_position_seconds = NULL,
                 recheck_completed_at_seconds = NULL, recheck_revision = recheck_revision + 1",
                [],
            )
            .storage()?;
            Ok(rearmed)
        })
    }

    /// Record a relay's NIP-11 caps. An unknown read is never evidence and
    /// changes nothing. A known read re-arms every broken unit on the relay
    /// that was planned with unknown or different caps. Returns the units
    /// re-armed.
    pub fn record_recovery_relay_caps(
        &self,
        relay: &str,
        caps: Option<RecoveryRelayCaps>,
        now_seconds: u64,
    ) -> StorageResult<usize> {
        let Some(known) = caps else {
            return Ok(0);
        };
        let (_, max_limit, negentropy) = caps_columns(caps);
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            ensure_relay_tx(&conn, relay)?;
            conn.execute_cached(
                "UPDATE account_recovery_relays SET caps_known = 1, caps_max_limit = ?2,
                 caps_negentropy = ?3, caps_fetched_at_seconds = ?4 WHERE relay = ?1",
                params![relay, max_limit, negentropy, integer(now_seconds)?],
            )
            .storage()?;
            let mut rearmed = 0;
            for unit in units_tx(&conn, "WHERE state = 1 AND relay = ?1", [relay])? {
                if unit.planned_caps != Some(known) {
                    rearm_tx(&conn, &unit.route, &unit.relay)?;
                    rearmed += 1;
                }
            }
            Ok(rearmed)
        })
    }

    /// The relay reconnected: its cooldown and unreachable streak end, and a
    /// spell longer than the policy's bound makes its re-checks due in the
    /// same transaction. Returns when the cooldown spell it ended began, if
    /// one was running.
    pub fn record_recovery_relay_reconnected(
        &self,
        relay: &str,
        policy: &RecoveryUnitPolicy,
        now_seconds: u64,
    ) -> StorageResult<Option<u64>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let since = cooldown_since_tx(&conn, relay)?;
            conn.execute_cached(
                "UPDATE account_recovery_relays SET unreachable_streak = 0,
                 cooldown_since_seconds = NULL, cooldown_until_seconds = NULL WHERE relay = ?1",
                [relay],
            )
            .storage()?;
            cooldown_ended_tx(&conn, relay, since, policy, now_seconds)?;
            Ok(since)
        })
    }

    /// Dismiss a parked route's notice: its broken units become retired with
    /// a fresh budget for anything else they owe, their parked spans are
    /// retired as dismissed, never covered, and its remainder is gone. Returns
    /// `false` when `revision` is not the route's current park: the newest
    /// among its broken units and its remainder.
    pub fn dismiss_recovery_route_park(
        &self,
        route: &TransportReconciliationRoute,
        revision: u64,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let (kind, id) = route.storage_key();
            let broken = units_tx(
                &conn,
                "WHERE state = 1 AND route_kind = ?1 AND route_id = ?2",
                params![kind, id],
            )?;
            let current = broken
                .iter()
                .filter_map(|unit| unit.park)
                .map(|park| park.revision)
                .chain(remainder_revision_tx(&conn, route)?)
                .max();
            if current != Some(revision) {
                return Ok(false);
            }
            conn.execute_cached(
                "DELETE FROM account_recovery_coverage_remainders
                 WHERE route_kind = ?1 AND route_id = ?2",
                params![kind, id],
            )
            .storage()?;
            for unit in &broken {
                let mut retired = spans_tx(&conn, route, &unit.relay, RETIRED_SPAN)?;
                retired.extend(
                    spans_tx(&conn, route, &unit.relay, PARKED_SPAN)?
                        .into_iter()
                        .map(|span| RecoveryUnitSpan {
                            range: span.range,
                            retired: Some(RecoverySpanRetirement::Dismissed),
                        }),
                );
                retired.sort_by_key(|span| span.range);
                replace_spans_tx(&conn, route, &unit.relay, PARKED_SPAN, &[])?;
                replace_spans_tx(&conn, route, &unit.relay, RETIRED_SPAN, &retired)?;
                conn.execute_cached(
                    "UPDATE account_recovery_units SET state = ?4, broken_reason = NULL,
                     probe = 0, no_progress = 0, backoff_step = 0, next_attempt_at_seconds = 0,
                     parked_at_seconds = NULL
                     WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                    params![kind, id, unit.relay, RETIRED],
                )
                .storage()?;
            }
            Ok(true)
        })
    }

    /// Replace the capture debt the unit fences with `fences`: sorted,
    /// disjoint ranges, none to drop its fence.
    pub fn set_recovery_unit_fences(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
        fences: &[RecoveryCoverageRange],
    ) -> StorageResult<()> {
        if relay.is_empty()
            || fences
                .iter()
                .any(|range| range.since_seconds > range.until_seconds)
            || fences
                .windows(2)
                .any(|pair| pair[1].since_seconds <= pair[0].until_seconds)
        {
            return Err(invalid());
        }
        let (kind, id) = route.storage_key();
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "DELETE FROM account_recovery_unit_fences
                 WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                params![kind, id, relay],
            )
            .storage()?;
            for range in fences {
                conn.execute_cached(
                    "INSERT INTO account_recovery_unit_fences
                     (route_kind, route_id, relay, since_seconds, until_seconds)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        kind,
                        id,
                        relay,
                        integer(range.since_seconds)?,
                        integer(range.until_seconds)?
                    ],
                )
                .storage()?;
            }
            Ok(())
        })
    }

    /// Remember the sweep's slice width and the cap it observed on this unit.
    pub fn record_recovery_unit_slicing(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
        slice_width_seconds: u64,
        observed_cap: Option<u32>,
    ) -> StorageResult<()> {
        if slice_width_seconds == 0 || observed_cap == Some(0) {
            return Err(invalid());
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            ensure_unit_tx(&conn, route, relay)?;
            let (kind, id) = route.storage_key();
            conn.execute_cached(
                "UPDATE account_recovery_units SET slice_width_seconds = ?4, observed_cap = ?5
                 WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3",
                params![
                    kind,
                    id,
                    relay,
                    integer(slice_width_seconds)?,
                    observed_cap.map(i64::from)
                ],
            )
            .storage()?;
            Ok(())
        })
    }

    /// Record a re-check pass's progress, if its revision is still
    /// `revision`: a request that made the pass due since the quantum began
    /// wins, and the pass runs again. A complete pass records its time and
    /// clears the position; a failed or truncated one keeps where it got to.
    /// Returns whether it recorded anything.
    pub fn record_recovery_recheck(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
        revision: u64,
        position_seconds: u64,
        complete: bool,
        now_seconds: u64,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            ensure_unit_tx(&conn, route, relay)?;
            let (kind, id) = route.storage_key();
            let (position, completed) = if complete {
                (None, Some(integer(now_seconds)?))
            } else {
                (Some(integer(position_seconds)?), None)
            };
            let recorded = conn
                .execute_cached(
                    "UPDATE account_recovery_units SET recheck_position_seconds = ?4,
                     recheck_completed_at_seconds = COALESCE(?5, recheck_completed_at_seconds)
                     WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3
                     AND recheck_revision = ?6",
                    params![kind, id, relay, position, completed, integer(revision)?],
                )
                .storage()?;
            Ok(recorded > 0)
        })
    }

    /// Make the route's re-checks due now, from `from_seconds` when given (an
    /// epoch gap's bound) and from the window floor otherwise. `relay` limits
    /// it to one relay's unit. A pass already due or running keeps whatever
    /// it would check below `from_seconds`. Each pass's revision is bumped, so
    /// a quantum already running records nothing over the request.
    pub fn make_recovery_recheck_due(
        &self,
        route: &TransportReconciliationRoute,
        relay: Option<&str>,
        from_seconds: Option<u64>,
    ) -> StorageResult<()> {
        recheck_due_tx(&*self.lock()?, Some(route), relay, from_seconds)
    }

    /// One unit's state, if the runner has touched it.
    pub fn recovery_unit(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
    ) -> StorageResult<Option<RecoveryUnit>> {
        unit_tx(&*self.lock()?, route, relay)
    }

    /// Every unit the runner has touched.
    pub fn recovery_units(&self) -> StorageResult<Vec<RecoveryUnit>> {
        units_tx(&*self.lock()?, "", [])
    }

    /// Every fenced range, by unit and oldest first.
    pub fn recovery_unit_fences(&self) -> StorageResult<Vec<RecoveryUnitFence>> {
        self.lock()?
            .prepare_cached(
                "SELECT route_kind, route_id, relay, since_seconds, until_seconds
                 FROM account_recovery_unit_fences
                 ORDER BY route_kind, route_id, relay, since_seconds",
            )
            .storage()?
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .storage()?
            .map(|row| {
                let (kind, id, relay, since, until) = row.storage()?;
                Ok(RecoveryUnitFence {
                    route: route_from(kind, &id)?,
                    relay,
                    range: RecoveryCoverageRange {
                        since_seconds: i64_to_u64(since)?,
                        until_seconds: i64_to_u64(until)?,
                    },
                })
            })
            .collect()
    }

    /// A unit's parked and retired spans, oldest first.
    pub fn recovery_unit_spans(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
    ) -> StorageResult<Vec<RecoveryUnitSpan>> {
        let conn = self.lock()?;
        let mut spans = spans_tx(&conn, route, relay, PARKED_SPAN)?;
        spans.extend(spans_tx(&conn, route, relay, RETIRED_SPAN)?);
        spans.sort_by_key(|span| span.range);
        Ok(spans)
    }

    /// One relay's health, if the runner has touched it.
    pub fn recovery_relay_health(&self, relay: &str) -> StorageResult<Option<RecoveryRelayHealth>> {
        type Row = (
            i64,
            i64,
            Option<i64>,
            Option<i64>,
            i64,
            Option<i64>,
            i64,
            Option<i64>,
        );
        let row: Option<Row> = self
            .lock()?
            .query_row_cached(
                "SELECT unreachable_streak, cooldown_step, cooldown_since_seconds,
                 cooldown_until_seconds, caps_known, caps_max_limit, caps_negentropy,
                 caps_fetched_at_seconds FROM account_recovery_relays WHERE relay = ?1",
                [relay],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()
            .storage()?;
        let Some((streak, step, since, until, known, max_limit, negentropy, fetched)) = row else {
            return Ok(None);
        };
        Ok(Some(RecoveryRelayHealth {
            relay: relay.to_owned(),
            unreachable_streak: count(streak)?,
            cooldown_step: count(step)?,
            cooldown: match (since, until) {
                (Some(since), Some(until)) => Some((i64_to_u64(since)?, i64_to_u64(until)?)),
                _ => None,
            },
            caps: caps(known, max_limit, negentropy)?,
            caps_fetched_at_seconds: optional(fetched)?,
        }))
    }

    /// Attempts and fetched event bytes in the rolling hour ending now.
    pub fn recovery_account_usage(&self, now_seconds: u64) -> StorageResult<RecoveryAccountUsage> {
        let rows = budget_rows_tx(&*self.lock()?, now_seconds)?;
        Ok(rows.into_iter().fold(
            RecoveryAccountUsage::default(),
            |usage, (_, attempts, bytes)| RecoveryAccountUsage {
                attempts: usage.attempts.saturating_add(attempts),
                event_bytes: usage.event_bytes.saturating_add(bytes),
            },
        ))
    }

    /// When the account breaker lets the runner go again: `None` while the
    /// rolling hour is under both caps, otherwise the time enough of it has
    /// rolled off, or `u64::MAX` when a cap is zero.
    pub fn recovery_account_paused_until(
        &self,
        policy: &RecoveryUnitPolicy,
        now_seconds: u64,
    ) -> StorageResult<Option<u64>> {
        let rows = budget_rows_tx(&*self.lock()?, now_seconds)?;
        let over = |attempts: u64, bytes: u64| {
            attempts >= policy.max_attempts_per_hour || bytes >= policy.max_event_bytes_per_hour
        };
        let (mut attempts, mut bytes) = rows.iter().fold((0u64, 0u64), |(a, b), row| {
            (a.saturating_add(row.1), b.saturating_add(row.2))
        });
        if !over(attempts, bytes) {
            return Ok(None);
        }
        for (minute, row_attempts, row_bytes) in rows {
            attempts -= row_attempts;
            bytes -= row_bytes;
            if !over(attempts, bytes) {
                return Ok(Some(
                    (minute + 1)
                        .saturating_mul(60)
                        .saturating_add(BUDGET_WINDOW_SECS),
                ));
            }
        }
        // A zero cap is over with nothing spent: the pause never ends.
        Ok(Some(u64::MAX))
    }

    /// Every route with a broken unit, one notice each. Its revision also
    /// covers the route's remainder, so dismissing the notice clears both.
    pub fn parked_recovery_routes(&self) -> StorageResult<Vec<RecoveryParkedRoute>> {
        let conn = self.lock()?;
        let units = units_tx(&conn, "WHERE state = 1", [])?;
        let mut routes: Vec<RecoveryParkedRoute> = Vec::new();
        for unit in units {
            let park = unit.park.ok_or_else(invalid)?;
            match routes.last_mut() {
                Some(last) if last.route == unit.route => {
                    last.revision = last.revision.max(park.revision);
                    last.parked_at_seconds = last.parked_at_seconds.min(park.parked_at_seconds);
                    last.relays.push(unit.relay);
                }
                _ => routes.push(RecoveryParkedRoute {
                    route: unit.route,
                    revision: park.revision,
                    parked_at_seconds: park.parked_at_seconds,
                    relays: vec![unit.relay],
                }),
            }
        }
        for parked in &mut routes {
            if let Some(revision) = remainder_revision_tx(&conn, &parked.route)? {
                parked.revision = parked.revision.max(revision);
            }
        }
        Ok(routes)
    }

    /// Every route's parked remainder, by route.
    pub fn recovery_coverage_remainders(&self) -> StorageResult<Vec<RecoveryRouteRemainder>> {
        let conn = self.lock()?;
        let rows = conn
            .prepare_cached(
                "SELECT route_kind, route_id, since_seconds, until_seconds, park_revision,
                 parked_at_seconds FROM account_recovery_coverage_remainders
                 ORDER BY route_kind, route_id",
            )
            .storage()?
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(kind, id, since, until, revision, parked_at)| {
                Ok(RecoveryRouteRemainder {
                    route: route_from(kind, &id)?,
                    range: RecoveryCoverageRange {
                        since_seconds: i64_to_u64(since)?,
                        until_seconds: i64_to_u64(until)?,
                    },
                    revision: i64_to_u64(revision)?,
                    parked_at_seconds: i64_to_u64(parked_at)?,
                })
            })
            .collect()
    }

    /// The unit's debt up to `until_seconds`: its route's goal minus what this
    /// relay covers, minus its retired spans, and minus its parked spans
    /// unless it holds a probe.
    pub fn recovery_unit_debt(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
        until_seconds: u64,
    ) -> StorageResult<Vec<RecoveryCoverageRange>> {
        unit_debt_tx(&*self.lock()?, route, relay, until_seconds)
    }

    /// Where a sweep of `[since, until]` on this relay resumes: the first
    /// second in it the ledger does not cover there, or `None` when it is all
    /// covered.
    pub fn recovery_unit_cursor(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
        since_seconds: u64,
        until_seconds: u64,
    ) -> StorageResult<Option<u64>> {
        if since_seconds > until_seconds {
            return Ok(None);
        }
        let covered = relay_covered_tx(&*self.lock()?, route, relay)?;
        Ok(subtract_all(
            &[RecoveryCoverageRange {
                since_seconds,
                until_seconds,
            }],
            &covered,
        )
        .first()
        .map(|range| range.since_seconds))
    }
}
