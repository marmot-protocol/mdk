//! The one-time conversion of the old recovery owner's rows into the coverage
//! ledger and the runner's retry state (mdk#2660 phase 4, PR 5d).
//!
//! The account worker runs it once, before the recovery runner first starts
//! with routing hydrated. Each step is one transaction that also advances the
//! marker from migration 0136, so a crash leaves every row either intact or
//! converted and gone, and the next run resumes at the step it stopped in;
//! the runner starts only once every step is done. A step deletes the
//! obligations it converted with their scopes and counts them by cause and
//! disposition. Obligations of the causes the runner owns are converted:
//! queue and notification loss, explicit and incremental history, and native
//! replay. Epoch-gap, known-event and maintenance obligations stay with the old
//! owner, untouched.
//!
//! Nothing here records coverage: goals widen, coverage only goes, and parked
//! and retired spans are never coverage. The conversion is one-way; nothing
//! puts a converted row back.
//!
//! Converted loss evidence is neither orphaned nor deleted here. Its rows stay,
//! counted as imported and with no obligation, as the watermark that keeps a
//! delayed duplicate observation from counting as new loss, and
//! [`SqliteAppStorage::converted_recovery_loss`] keeps their set until the
//! worker has finished the relay plane's overflow recovery for them and
//! reclaims them with [`SqliteAppStorage::reclaim_converted_recovery_loss`].
//! Until then they are a state the worker resolves, not a leak.
use super::*;
use crate::TransportReconciliationRoute;
use crate::app::recovery_coverage::{
    RecoveryCoverageProof, RecoveryCoverageRange, reopen_goal, settle_goals_tx, uncover_loss_tx,
    uncover_route_loss_tx, widen_goal,
};
use crate::app::recovery_units::{
    break_converted_route_tx, park_overtaken_tx, rearm_all_units_tx, retire_converted_ranges_tx,
};
use std::collections::BTreeMap;

/// One current route as the conversion needs it. Not `Debug`: it carries the
/// route and its relays.
#[derive(Clone)]
pub struct RecoveryConversionRoute {
    pub route: TransportReconciliationRoute,
    /// The relays that certify the route, spelled as the ledger keys them.
    pub required_relays: Vec<String>,
    /// Where the route's standing goal starts: the retention floor, or a later
    /// floor from a group copy's Welcome time.
    pub standing_floor_seconds: u64,
}

/// What the conversion needs from routing and the clock, which storage does
/// not have.
pub struct RecoveryConversionInput<'a> {
    /// Every current route, each once, the inbox included.
    pub routes: &'a [RecoveryConversionRoute],
    /// The ledger's spelling of a relay a stored scope names.
    pub canonical_relay: &'a dyn Fn(&str) -> String,
    /// The retained window's floor.
    pub retention_floor_seconds: u64,
    pub now_seconds: u64,
}

/// What became of one cause's obligations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryConvertedObligations {
    /// Pending: the routes' goals hold their debt. A pending explicit repair
    /// re-armed every unit.
    pub pending: u64,
    /// Parked: the required relays of their routes that still owe history
    /// broke, keeping the time they parked.
    pub parked: u64,
    /// Dismissed by the user: retired spans on the routes and relays they
    /// recorded.
    pub dismissed: u64,
    /// Satisfied: nothing owed.
    pub settled: u64,
}

/// One account's loss of one cause that the conversion turned into ledger
/// debt. The relay plane still guards its overflow until the worker finishes
/// that recovery. Never log account labels or marker identities.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryConvertedLoss {
    pub account_label: String,
    pub cause: RecoveryLossCause,
    /// Every generation of this account and cause as the conversion found
    /// it, in marker-token order: the live ones it un-covered and any the
    /// user retired, which acknowledgment reclaims with them.
    pub watermarks: Vec<RecoveryLossWatermark>,
}

/// What the conversion converted, kept until the worker has written its audit
/// summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryConversionReport {
    /// By cause, in cause order. A cause with no obligations is left out.
    pub obligations: Vec<(RecoveryCause, RecoveryConvertedObligations)>,
    /// Live-boundary ranges the shadow quarantine dropped.
    pub shadow_ranges: u64,
    /// Shadow-era parked remainders the quarantine dropped.
    pub shadow_remainders: u64,
    /// Units broken for parked obligations.
    pub units_broken: u64,
}

/// The steps, in order. Each depends on the ones before it: dismissals leave
/// out the range live loss un-covers, loss is owed before parked units park
/// it, and a pending explicit repair re-arms everything last, as if it were
/// requested after the conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Drop phase 2's shadow coverage and remainders, settle goals at the
    /// window floor and start every current route's standing goal.
    Quarantine,
    /// Dismissed obligations become retired spans.
    Dismissed,
    /// Live loss un-covers what it reached once.
    Loss,
    /// Parked obligations break their routes' required relays.
    Parked,
    /// Pending obligations go; a pending explicit repair re-arms every unit.
    Pending,
    /// Satisfied obligations go.
    Settled,
}

const STEPS: [Step; 6] = [
    Step::Quarantine,
    Step::Dismissed,
    Step::Loss,
    Step::Parked,
    Step::Pending,
    Step::Settled,
];

/// The marker value once every step has run.
const DONE: i64 = STEPS.len() as i64;

/// The causes the runner owns. Their obligations are converted.
const CONVERTED: &str = "cause IN (0, 3, 5, 6, 7)";

#[derive(Clone, Copy)]
#[repr(i64)]
enum Disposition {
    Pending = 0,
    Parked = 1,
    Dismissed = 2,
    Settled = 3,
}

/// Live loss: generations neither the user nor a legacy clear retired.
const LIVE_LOSS: &str = "(legacy_retired_count IS NULL OR legacy_retired_count < dropped_count)
    AND (retired_count IS NULL OR retired_count < dropped_count)";

#[cfg(test)]
thread_local! {
    /// Test hook: fail this step's transaction after its writes.
    pub(super) static FAIL_STEP: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// One frozen scope's proof, from its payload.
enum ScopeProof {
    Certified,
    /// Not certified; its required relays as the plan spelled them.
    Open(Vec<String>),
    /// The payload does not decode, so neither is known.
    Unreadable,
}

/// One frozen scope on a route the ledger keys.
struct FrozenScope {
    route: TransportReconciliationRoute,
    since_seconds: Option<u64>,
    until_seconds: u64,
    proof: ScopeProof,
}

/// One obligation to convert.
struct Converted {
    id: Vec<u8>,
    cause: RecoveryCause,
    predicate: i64,
    parked_at_seconds: u64,
}

impl RecoveryConversionInput<'_> {
    /// The current routes by route. Rejects a duplicate route, an empty relay,
    /// a floor after now, and a route list without the inbox, which only
    /// unhydrated routing would give.
    fn current(
        &self,
    ) -> StorageResult<BTreeMap<&TransportReconciliationRoute, &RecoveryConversionRoute>> {
        let mut current = BTreeMap::new();
        for route in self.routes {
            if route.required_relays.iter().any(String::is_empty)
                || current.insert(&route.route, route).is_some()
            {
                return Err(invalid_conversion());
            }
        }
        if self.retention_floor_seconds > self.now_seconds
            || !current.contains_key(&TransportReconciliationRoute::Inbox)
        {
            return Err(invalid_conversion());
        }
        Ok(current)
    }
}

fn invalid_conversion() -> StorageError {
    StorageError::Serialization("invalid recovery conversion".into())
}

fn step_tx(conn: &Connection) -> StorageResult<i64> {
    conn.query_row_cached(
        "SELECT step FROM account_recovery_conversion WHERE singleton = 1",
        [],
        |row| row.get(0),
    )
    .storage()
}

/// Run `step` and advance the marker past it. The report is complete once
/// the last step has run.
fn run_step_tx(
    conn: &Connection,
    step: Step,
    input: &RecoveryConversionInput<'_>,
    current: &BTreeMap<&TransportReconciliationRoute, &RecoveryConversionRoute>,
) -> StorageResult<()> {
    match step {
        Step::Quarantine => quarantine_tx(conn, input),
        Step::Dismissed => dismissed_tx(conn, input, current),
        Step::Loss => loss_tx(conn, input),
        Step::Parked => parked_tx(conn, input, current),
        Step::Pending => pending_tx(conn, input),
        Step::Settled => delete_converted_tx(conn, "state = 1", Disposition::Settled).map(|_| ()),
    }?;
    conn.execute_cached(
        "UPDATE account_recovery_conversion SET step = step + 1,
         report_pending = CASE WHEN step + 1 = ?1 THEN 1 ELSE report_pending END
         WHERE singleton = 1",
        [DONE],
    )
    .storage()?;
    Ok(())
}

fn add_count_tx(conn: &Connection, column: &str, count: u64) -> StorageResult<()> {
    conn.execute_cached(
        &format!(
            "UPDATE account_recovery_conversion SET {column} = {column} + ?1 WHERE singleton = 1"
        ),
        [sqlite_integer(count)?],
    )
    .storage()?;
    Ok(())
}

fn notices_changed_tx(conn: &Connection) -> StorageResult<()> {
    conn.execute_cached(
        "UPDATE account_recovery_conversion SET notices_changed = 1 WHERE singleton = 1",
        [],
    )
    .storage()?;
    Ok(())
}

/// Phase 2's shadow ledger proved nothing a runner relies on. Live boundaries
/// recorded under its unproven boundary are dropped and become debt over
/// history the device mostly holds, which comparison serves cheaply;
/// comparison, sweep and re-check ranges stay. Shadow remainders recorded gaps
/// nothing swept, not lost history, and so does whatever lies below the
/// window that no prune has settled yet: goals settle at the window floor
/// without parking it. Then every current route's goal widens to its standing
/// floor, the goal the runner serves. A database from before the ledger has no
/// goals at all.
fn quarantine_tx(conn: &Connection, input: &RecoveryConversionInput<'_>) -> StorageResult<()> {
    let ranges = conn
        .execute_cached(
            "DELETE FROM account_recovery_coverage WHERE proof = ?1",
            [RecoveryCoverageProof::LiveBoundary as i64],
        )
        .storage()?;
    let remainders = conn
        .execute_cached("DELETE FROM account_recovery_coverage_remainders", [])
        .storage()?;
    let floor = input.retention_floor_seconds;
    settle_goals_tx(conn, floor)?;
    for current in input.routes {
        widen_goal(
            conn,
            &current.route,
            current.standing_floor_seconds.max(floor),
        )?;
    }
    add_count_tx(conn, "shadow_ranges", ranges as u64)?;
    add_count_tx(conn, "shadow_remainders", remainders as u64)
}

/// Where live loss may have lost events, as imports charge it: a generation
/// that named its routes (with a known bound) reaches each of them from its
/// own bound, and any other reaches every route from its floor, or from zero
/// when its bound is unknown. `None` without live loss.
fn live_loss_reach_tx(conn: &Connection) -> StorageResult<Option<RecoveryLossReach>> {
    let live = conn
        .prepare_cached(&format!(
            "SELECT DISTINCT account_label, cause FROM account_delivery_loss_evidence
             WHERE {LIVE_LOSS} ORDER BY account_label, cause"
        ))
        .storage()?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    if live.is_empty() {
        return Ok(None);
    }
    let mut merged = RecoveryLossReach::default();
    for (label, cause) in live {
        let reach = loss::reach(conn, &label, loss::ReachOf::Cause(loss_cause(cause)?))?;
        merged.every_route_from = match (merged.every_route_from, reach.every_route_from) {
            (Some(merged), Some(floor)) => Some(merged.min(floor)),
            (merged, floor) => merged.or(floor),
        };
        for (route, bound) in reach.routes {
            let lowest = merged.routes.entry(route).or_insert(bound);
            *lowest = (*lowest).min(bound);
        }
    }
    Ok(Some(merged))
}

fn loss_cause(cause: i64) -> StorageResult<RecoveryLossCause> {
    match cause {
        0 => Ok(RecoveryLossCause::Queue),
        1 => Ok(RecoveryLossCause::NotificationConsumer),
        _ => Err(invalid_conversion()),
    }
}

fn obligations_tx(conn: &Connection, filter: &str) -> StorageResult<Vec<Converted>> {
    conn.prepare_cached(&format!(
        "SELECT id, cause, predicate, COALESCE(parked_at_ms, updated_at_ms)
         FROM account_recovery_obligations WHERE {CONVERTED} AND {filter} ORDER BY id"
    ))
    .storage()?
    .query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()?
    .into_iter()
    .map(|(id, cause, predicate, parked_at_ms)| {
        Ok(Converted {
            id,
            cause: demand::recovery_cause(cause)?,
            predicate,
            parked_at_seconds: i64_to_u64(parked_at_ms)? / 1_000,
        })
    })
    .collect()
}

/// The obligation's frozen scopes on routes the ledger keys. The SQL columns
/// name the route and window; the payload says whether the scope is
/// certified. A scope that was never frozen has neither.
fn frozen_scopes_tx(conn: &Connection, obligation: &Converted) -> StorageResult<Vec<FrozenScope>> {
    let rows = conn
        .prepare_cached(
            "SELECT route_kind, transport_group_id, since_seconds, until_seconds, scope_format,
                    scope_payload, known_event_id IS NOT NULL
             FROM account_recovery_scopes
             WHERE obligation_id = ?1 AND snapshot_state = 1 ORDER BY scope_id",
        )
        .storage()?
        .query_map([obligation.id.as_slice()], |row| {
            Ok((
                row.get::<_, Option<i64>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, bool>(6)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let mut scopes = Vec::with_capacity(rows.len());
    for (kind, transport_id, since, until, format, payload, known_event) in rows {
        let route = match (kind, transport_id) {
            (Some(0), _) => TransportReconciliationRoute::Inbox,
            (Some(1), Some(id)) => match <[u8; 32]>::try_from(id.as_slice()) {
                Ok(id) => TransportReconciliationRoute::Group(id),
                Err(_) => continue,
            },
            _ => continue,
        };
        // A payload that does not decode must not stop the conversion for
        // good: its scope's route is still known.
        let proof = match plan::decode_scope(format, &payload) {
            Ok(payload)
                if plan::payload_is_qualified(&payload, obligation.predicate, known_event) =>
            {
                ScopeProof::Certified
            }
            Ok(payload) => ScopeProof::Open(payload.required_endpoints),
            Err(_) => ScopeProof::Unreadable,
        };
        scopes.push(FrozenScope {
            route,
            since_seconds: since.map(i64_to_u64).transpose()?,
            until_seconds: i64_to_u64(until)?,
            proof,
        });
    }
    Ok(scopes)
}

/// Delete the converted obligations `filter` selects, with their scopes, and
/// count them under `disposition`. Settles the comparison slot when one was
/// incremental history, as retiring it does: that slot served only its debt.
fn delete_converted_tx(
    conn: &Connection,
    filter: &str,
    disposition: Disposition,
) -> StorageResult<usize> {
    let rows = obligations_tx(conn, filter)?;
    let mut counts = BTreeMap::<i64, i64>::new();
    for row in &rows {
        *counts.entry(row.cause as i64).or_default() += 1;
    }
    conn.execute_cached(
        &format!(
            "DELETE FROM account_recovery_scopes WHERE obligation_id IN
                (SELECT id FROM account_recovery_obligations WHERE {CONVERTED} AND {filter})"
        ),
        [],
    )
    .storage()?;
    conn.execute_cached(
        &format!("DELETE FROM account_recovery_obligations WHERE {CONVERTED} AND {filter}"),
        [],
    )
    .storage()?;
    for (cause, count) in &counts {
        conn.execute_cached(
            "INSERT INTO account_recovery_conversion_counts (cause, disposition, obligations)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (cause, disposition)
             DO UPDATE SET obligations = obligations + excluded.obligations",
            params![cause, disposition as i64, count],
        )
        .storage()?;
    }
    if counts.contains_key(&(RecoveryCause::IncrementalHistory as i64)) {
        conn.execute_cached(
            "UPDATE account_recovery_comparison SET settled_revision = revision WHERE singleton = 1",
            [],
        )
        .storage()?;
    }
    Ok(rows.len())
}

/// A dismissed obligation becomes retired spans, never coverage, so the
/// runner does not raise its notice again: each frozen scope it could not
/// certify retires its window inside the retained window on each relay it
/// recorded, on routes that are still current. Live loss is newer debt than
/// any dismissal of the same range can answer, so the range it un-covers on
/// the scope's route stays owed.
fn dismissed_tx(
    conn: &Connection,
    input: &RecoveryConversionInput<'_>,
    current: &BTreeMap<&TransportReconciliationRoute, &RecoveryConversionRoute>,
) -> StorageResult<()> {
    let floor = input.retention_floor_seconds;
    let reach = live_loss_reach_tx(conn)?.unwrap_or_default();
    for obligation in obligations_tx(conn, "state = 2")? {
        for scope in frozen_scopes_tx(conn, &obligation)? {
            let ScopeProof::Open(relays) = scope.proof else {
                continue;
            };
            if !current.contains_key(&scope.route) {
                continue;
            }
            let since = scope.since_seconds.unwrap_or(0).max(floor);
            let until = match reach.floor(&scope.route).map(|lowest| lowest.max(floor)) {
                Some(0) => continue,
                Some(from) => scope.until_seconds.min(from - 1),
                None => scope.until_seconds,
            };
            if since > until {
                continue;
            }
            let window = RecoveryCoverageRange {
                since_seconds: since,
                until_seconds: until,
            };
            for relay in relays {
                let relay = (input.canonical_relay)(&relay);
                if !relay.is_empty() {
                    retire_converted_ranges_tx(conn, &scope.route, &relay, &[window])?;
                }
            }
        }
    }
    delete_converted_tx(conn, "state = 2", Disposition::Dismissed).map(|_| ())
}

/// Live loss un-covers what it reached once, as an import charges it: every
/// route from the floor of the generations that named no routes, and each
/// named route from its own bound. The part inside the window is owed again,
/// and what lies below it, where a bound is unknown or older, parks in each
/// current route's remainder, whatever coverage proved it before the loss.
/// Generations no import charged yet are charged now, under a new loss
/// revision they are stamped with, and every live generation then counts as
/// imported, so a later import does not un-cover it again; their rows stay as
/// the watermark that keeps a delayed duplicate observation from counting as
/// new loss. Each account and cause with live loss is recorded with every
/// generation of it, so the worker can finish the plane's overflow recovery
/// and reclaim them.
fn loss_tx(conn: &Connection, input: &RecoveryConversionInput<'_>) -> StorageResult<()> {
    let Some(reach) = live_loss_reach_tx(conn)? else {
        return Ok(());
    };
    let (floor, now) = (input.retention_floor_seconds, input.now_seconds);
    if let Some(every) = reach.every_route_from {
        uncover_loss_tx(conn, every, now)?;
    }
    for (route, &bound) in &reach.routes {
        match reach.every_route_from {
            // Its coverage went with the account-wide floor.
            Some(every) if bound >= every => reopen_goal(conn, route, every)?,
            _ => uncover_route_loss_tx(conn, route, bound, now)?,
        }
    }
    // The un-covers widened the goals the ledger holds; a current route
    // without one owes from the same floor.
    for current in input.routes {
        if let Some(lowest) = reach.floor(&current.route) {
            reopen_goal(conn, &current.route, lowest)?;
        }
    }
    if reach
        .every_route_from
        .into_iter()
        .chain(reach.routes.values().copied())
        .any(|lowest| lowest < floor)
    {
        let certifying = input
            .routes
            .iter()
            .map(|current| (current.route.clone(), current.required_relays.clone()))
            .collect::<Vec<_>>();
        park_overtaken_tx(conn, floor, &certifying, now)?;
        settle_goals_tx(conn, floor)?;
        let parked: i64 = conn
            .query_row_cached(
                "SELECT COUNT(*) FROM account_recovery_coverage_remainders",
                [],
                |row| row.get(0),
            )
            .storage()?;
        if parked > 0 {
            notices_changed_tx(conn)?;
        }
    }
    let uncharged =
        format!("{LIVE_LOSS} AND (imported_count IS NULL OR imported_count < dropped_count)");
    let newly: i64 = conn
        .query_row_cached(
            &format!("SELECT COUNT(*) FROM account_delivery_loss_evidence WHERE {uncharged}"),
            [],
            |row| row.get(0),
        )
        .storage()?;
    if newly > 0 {
        conn.execute_cached(
            "UPDATE account_recovery_state SET loss_revision = loss_revision + 1
             WHERE singleton = 1",
            [],
        )
        .storage()?;
        conn.execute_cached(
            &format!(
                "UPDATE account_delivery_loss_evidence SET import_revision =
                     (SELECT loss_revision FROM account_recovery_state WHERE singleton = 1)
                 WHERE {uncharged}"
            ),
            [],
        )
        .storage()?;
    }
    conn.execute_cached(
        &format!(
            "INSERT INTO account_recovery_conversion_loss
                 (account_label, cause, marker_token, observed_count)
             SELECT account_label, cause, marker_token, dropped_count
             FROM account_delivery_loss_evidence
             WHERE (account_label, cause) IN
                 (SELECT account_label, cause FROM account_delivery_loss_evidence
                  WHERE {LIVE_LOSS})"
        ),
        [],
    )
    .storage()?;
    conn.execute_cached(
        &format!(
            "UPDATE account_delivery_loss_evidence SET imported_count = dropped_count
             WHERE {LIVE_LOSS}"
        ),
        [],
    )
    .storage()?;
    Ok(())
}

/// A parked obligation's notice becomes a park on each required relay of its
/// routes that still owes history there, broken for no progress under one
/// revision per route that keeps the time the obligation parked; a route
/// several obligations parked keeps the earliest. Its routes are those of the frozen
/// scopes it could not certify, or every current route when it froze none.
/// Notice ids change, so the worker announces the new set once.
fn parked_tx(
    conn: &Connection,
    input: &RecoveryConversionInput<'_>,
    current: &BTreeMap<&TransportReconciliationRoute, &RecoveryConversionRoute>,
) -> StorageResult<()> {
    let obligations = obligations_tx(conn, "state = 0 AND eligibility = 4")?;
    if obligations.is_empty() {
        return Ok(());
    }
    let floor = input.retention_floor_seconds;
    let mut parks = BTreeMap::<&TransportReconciliationRoute, u64>::new();
    for obligation in &obligations {
        if obligation.cause == RecoveryCause::ExplicitHistory {
            // An explicit repair owes the whole window.
            for current in input.routes {
                widen_goal(conn, &current.route, floor)?;
            }
        }
        let scopes = frozen_scopes_tx(conn, obligation)?;
        let routes = if scopes.is_empty() {
            current.keys().copied().collect::<Vec<_>>()
        } else {
            scopes
                .iter()
                .filter(|scope| !matches!(scope.proof, ScopeProof::Certified))
                .filter_map(|scope| current.get_key_value(&scope.route).map(|(route, _)| *route))
                .collect()
        };
        for route in routes {
            let parked_at = parks.entry(route).or_insert(obligation.parked_at_seconds);
            *parked_at = (*parked_at).min(obligation.parked_at_seconds);
        }
    }
    let mut broken = 0_u64;
    for (route, parked_at) in parks {
        broken += break_converted_route_tx(
            conn,
            route,
            &current[route].required_relays,
            parked_at,
            input.now_seconds,
        )?;
    }
    delete_converted_tx(conn, "state = 0 AND eligibility = 4", Disposition::Parked)?;
    notices_changed_tx(conn)?;
    add_count_tx(conn, "units_broken", broken)
}

/// Pending obligations need nothing more: the standing goals and loss's own
/// un-cover hold their debt. A pending explicit repair becomes what the
/// runner does for one: every current route owes the whole window, and every
/// unit is re-armed, parked and retired spans included.
fn pending_tx(conn: &Connection, input: &RecoveryConversionInput<'_>) -> StorageResult<()> {
    let filter = "state = 0 AND eligibility != 4";
    if obligations_tx(conn, filter)?
        .iter()
        .any(|obligation| obligation.cause == RecoveryCause::ExplicitHistory)
    {
        for current in input.routes {
            widen_goal(conn, &current.route, input.retention_floor_seconds)?;
        }
        rearm_all_units_tx(conn)?;
    }
    delete_converted_tx(conn, filter, Disposition::Pending).map(|_| ())
}

/// The converted loss not reclaimed yet, by account label and cause.
fn converted_loss_tx(conn: &Connection) -> StorageResult<Vec<RecoveryConvertedLoss>> {
    let rows = conn
        .prepare_cached(
            "SELECT account_label, cause, marker_token, observed_count
             FROM account_recovery_conversion_loss ORDER BY account_label, cause, marker_token",
        )
        .storage()?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let mut loss: Vec<RecoveryConvertedLoss> = Vec::new();
    for (account_label, cause, marker_token, observed_count) in rows {
        let cause = loss_cause(cause)?;
        if loss
            .last()
            .is_none_or(|last| last.account_label != account_label || last.cause != cause)
        {
            loss.push(RecoveryConvertedLoss {
                account_label,
                cause,
                watermarks: Vec::new(),
            });
        }
        loss.last_mut()
            .ok_or_else(invalid_conversion)?
            .watermarks
            .push(RecoveryLossWatermark {
                marker_token: i64_to_u64(marker_token)?,
                observed_count: i64_to_u64(observed_count)?,
            });
    }
    Ok(loss)
}

fn report_tx(conn: &Connection) -> StorageResult<RecoveryConversionReport> {
    let (shadow_ranges, shadow_remainders, units_broken) = conn
        .query_row_cached(
            "SELECT shadow_ranges, shadow_remainders, units_broken
             FROM account_recovery_conversion WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .storage()?;
    let rows = conn
        .prepare_cached(
            "SELECT cause, disposition, obligations FROM account_recovery_conversion_counts
             ORDER BY cause, disposition",
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
        .storage()?;
    let mut obligations: Vec<(RecoveryCause, RecoveryConvertedObligations)> = Vec::new();
    for (cause, disposition, count) in rows {
        let cause = demand::recovery_cause(cause)?;
        if obligations.last().is_none_or(|(last, _)| *last != cause) {
            obligations.push((cause, RecoveryConvertedObligations::default()));
        }
        let counts = &mut obligations.last_mut().ok_or_else(invalid_conversion)?.1;
        let count = i64_to_u64(count)?;
        match disposition {
            0 => counts.pending = count,
            1 => counts.parked = count,
            2 => counts.dismissed = count,
            3 => counts.settled = count,
            _ => return Err(invalid_conversion()),
        }
    }
    Ok(RecoveryConversionReport {
        obligations,
        shadow_ranges: i64_to_u64(shadow_ranges)?,
        shadow_remainders: i64_to_u64(shadow_remainders)?,
        units_broken: i64_to_u64(units_broken)?,
    })
}

impl SqliteAppStorage {
    /// Whether the conversion still has steps to run. The runner must not
    /// start while it does.
    pub fn recovery_conversion_pending(&self) -> StorageResult<bool> {
        Ok(step_tx(&*self.lock()?)? < DONE)
    }

    /// Run the conversion's remaining steps, each in its own transaction,
    /// against current routing. Does nothing once every step is done. An
    /// error leaves the step it stopped in to the next call, every earlier
    /// step converted and every later row intact. Obligations of a converted
    /// cause written after their step ran are left as they are, so the caller
    /// must write none once the conversion has begun.
    pub fn convert_recovery_obligations(
        &self,
        input: &RecoveryConversionInput<'_>,
    ) -> StorageResult<()> {
        self.convert_recovery_steps(input, STEPS.len())
    }

    /// Run at most `limit` of the remaining steps.
    pub(super) fn convert_recovery_steps(
        &self,
        input: &RecoveryConversionInput<'_>,
        limit: usize,
    ) -> StorageResult<()> {
        let current = input.current()?;
        for _ in 0..limit {
            let done = self.connection.with_transaction(|| {
                let conn = self.lock()?;
                let Some(&step) = usize::try_from(step_tx(&conn)?)
                    .ok()
                    .and_then(|index| STEPS.get(index))
                else {
                    return Ok(true);
                };
                run_step_tx(&conn, step, input, &current)?;
                #[cfg(test)]
                if FAIL_STEP.get() == STEPS.iter().position(|candidate| *candidate == step) {
                    return Err(StorageError::Backend("injected conversion failure".into()));
                }
                Ok::<_, StorageError>(false)
            })?;
            if done {
                break;
            }
        }
        Ok(())
    }

    /// What the finished conversion converted, until
    /// [`Self::acknowledge_recovery_conversion_report`]. `None` while steps
    /// remain or once acknowledged.
    pub fn recovery_conversion_report(&self) -> StorageResult<Option<RecoveryConversionReport>> {
        let conn = self.lock()?;
        let pending: bool = conn
            .query_row_cached(
                "SELECT report_pending FROM account_recovery_conversion WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .storage()?;
        pending.then(|| report_tx(&conn)).transpose()
    }

    /// The worker wrote the conversion's audit summary. The converted loss
    /// stays until it is reclaimed.
    pub fn acknowledge_recovery_conversion_report(&self) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "UPDATE account_recovery_conversion SET report_pending = 0 WHERE singleton = 1",
                [],
            )
            .storage()?;
            conn.execute_cached("DELETE FROM account_recovery_conversion_counts", [])
                .storage()?;
            Ok(())
        })
    }

    /// The loss the conversion turned into ledger debt and the worker has not
    /// reclaimed yet, by account label and cause: the plane still guards each
    /// until the worker finishes its overflow recovery. Durable, and empty
    /// before the conversion's loss step has run.
    pub fn converted_recovery_loss(&self) -> StorageResult<Vec<RecoveryConvertedLoss>> {
        converted_loss_tx(&*self.lock()?)
    }

    /// Reclaim one entry of [`Self::converted_recovery_loss`] once the plane's
    /// matching generations are acknowledged and every writer for their
    /// tokens has finished; SQL cannot prove that prerequisite. Deletes each
    /// of its generations still at the count the conversion found, keeping
    /// how recent the deleted loss was, and ends the entry. A generation whose
    /// count grew since is new loss and stays for the import, and so does any
    /// newer generation. Returns `false`, changing nothing, unless `loss` is a
    /// current entry of a finished conversion.
    pub fn reclaim_converted_recovery_loss(
        &self,
        loss: &RecoveryConvertedLoss,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if step_tx(&conn)? < DONE || !converted_loss_tx(&conn)?.contains(loss) {
                return Ok(false);
            }
            let (label, cause) = (loss.account_label.as_str(), loss.cause as i64);
            for watermark in &loss.watermarks {
                let generation = params![
                    label,
                    cause,
                    sqlite_integer(watermark.marker_token)?,
                    sqlite_integer(watermark.observed_count)?
                ];
                conn.execute_cached(
                    "UPDATE account_recovery_state SET acknowledged_import_revision =
                        MAX(acknowledged_import_revision, COALESCE(
                            (SELECT import_revision FROM account_delivery_loss_evidence
                             WHERE account_label = ?1 AND cause = ?2 AND marker_token = ?3
                                 AND dropped_count = ?4 AND imported_count = dropped_count),
                            0))
                     WHERE singleton = 1",
                    generation,
                )
                .storage()?;
                conn.execute_cached(
                    "DELETE FROM account_delivery_loss_evidence
                     WHERE account_label = ?1 AND cause = ?2 AND marker_token = ?3
                         AND dropped_count = ?4 AND imported_count = dropped_count",
                    generation,
                )
                .storage()?;
            }
            conn.execute_cached(
                "DELETE FROM account_recovery_conversion_loss
                 WHERE account_label = ?1 AND cause = ?2",
                params![label, cause],
            )
            .storage()?;
            Ok(true)
        })
    }

    /// The conversion changed which "history may be incomplete" notices
    /// exist and the worker has not announced it yet. Read it only once the
    /// conversion is done.
    pub fn recovery_conversion_notices_changed(&self) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT notices_changed FROM account_recovery_conversion WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .storage()
    }

    /// The worker announced the conversion's notice change.
    pub fn acknowledge_recovery_conversion_notices(&self) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE account_recovery_conversion SET notices_changed = 0 WHERE singleton = 1",
                [],
            )
            .storage()?;
        Ok(())
    }
}
