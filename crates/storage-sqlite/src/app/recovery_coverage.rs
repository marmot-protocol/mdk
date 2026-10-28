//! The recovery coverage ledger (mdk#2660): per route and relay, the
//! `created_at` ranges proved complete, and each route's goal floor.
//!
//! Debt is the goal minus what is covered. A loss un-covers only the routes it
//! could have affected, from its floor upward; nothing is invalidated
//! account-wide. Ranges are inclusive whole seconds.
//!
//! Every write that takes coverage away also appends what it took to the
//! un-cover log under a new generation. A fetch keeps the generation it
//! started at ([`RecoveryCoverageMark`]), and its coverage write subtracts
//! every range un-covered after that, so loss or a released receipt that lands
//! mid-fetch keeps its debt. Retention pruning is not an un-cover.
//!
//! A released receipt's second also stays owed against live boundaries: the
//! REQ that delivered the event will not deliver it again, so only a fetch
//! (a comparison, sweep slice or re-check) can prove that second again.
//!
//! The ledger is in shadow mode: the app owner fills it from facts it already
//! has and compares it with the obligations, but nothing schedules, retries or
//! fences on it yet. Route ids and relay URLs are account-private and must never
//! be logged.
#[cfg(test)]
use crate::SqliteAccountStorage;
use crate::base::codec::i64_to_u64;
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, TransportReconciliationRoute};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::BTreeMap;

/// How long the un-cover log keeps a range. A coverage write whose fetch
/// started before the oldest pruned range records nothing, so this outlasts
/// any fetch.
const UNCOVER_LOG_RETENTION_SECS: u64 = 3_600;

/// At most this many un-cover rows are kept; the oldest go first, with the
/// same effect on older fetches as age.
const UNCOVER_LOG_MAX_ROWS: i64 = 4_096;

/// How a range was proved complete for one relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i64)]
pub enum RecoveryCoverageProof {
    /// A live REQ's stored history ended and was admitted and placed for its
    /// whole original window.
    LiveBoundary = 1,
    /// A NIP-77 comparison certified the window and every difference was
    /// admitted.
    Comparison = 2,
    /// A time-sliced sweep read a slice below the relay's cap.
    SweepSlice = 3,
    /// A NIP-77 re-check of an already covered range found nothing missing.
    Recheck = 4,
}

impl RecoveryCoverageProof {
    fn from_i64(value: i64) -> StorageResult<Self> {
        Ok(match value {
            1 => Self::LiveBoundary,
            2 => Self::Comparison,
            3 => Self::SweepSlice,
            4 => Self::Recheck,
            _ => return Err(invalid()),
        })
    }
}

/// An inclusive `created_at` range in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecoveryCoverageRange {
    pub since_seconds: u64,
    pub until_seconds: u64,
}

/// One proved range as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryCoverageProved {
    pub range: RecoveryCoverageRange,
    pub proof: RecoveryCoverageProof,
    /// The oldest proof time among the ranges merged into this one.
    pub recorded_at_seconds: u64,
}

/// A covered slice to record: `(route, relay, since, until, proof)`. Not
/// `Debug`: it carries the route and the relay.
#[derive(Clone, Copy)]
pub struct RecoveryCoverageSlice<'a> {
    pub route: &'a TransportReconciliationRoute,
    pub relay: &'a str,
    pub since_seconds: u64,
    pub until_seconds: u64,
    pub proof: RecoveryCoverageProof,
}

/// The un-cover generation a fetch started at. A coverage write made with it
/// subtracts every range un-covered since.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecoveryCoverageMark(u64);

fn invalid() -> StorageError {
    StorageError::Serialization("invalid recovery coverage".into())
}

fn integer(value: u64) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| invalid())
}

fn route_from(kind: i64, id: &[u8]) -> StorageResult<TransportReconciliationRoute> {
    match (kind, id.len()) {
        (0, 0) => Ok(TransportReconciliationRoute::Inbox),
        (1, 32) => Ok(TransportReconciliationRoute::Group(
            id.try_into().map_err(|_| invalid())?,
        )),
        _ => Err(invalid()),
    }
}

/// Sort and merge overlapping or touching ranges.
fn union(mut ranges: Vec<RecoveryCoverageRange>) -> Vec<RecoveryCoverageRange> {
    ranges.sort();
    let mut merged: Vec<RecoveryCoverageRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.since_seconds <= last.until_seconds.saturating_add(1) => {
                last.until_seconds = last.until_seconds.max(range.until_seconds);
            }
            _ => merged.push(range),
        }
    }
    merged
}

/// The parts of two merged, sorted range lists that both cover.
fn intersect(
    left: &[RecoveryCoverageRange],
    right: &[RecoveryCoverageRange],
) -> Vec<RecoveryCoverageRange> {
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < left.len() && j < right.len() {
        let since = left[i].since_seconds.max(right[j].since_seconds);
        let until = left[i].until_seconds.min(right[j].until_seconds);
        if since <= until {
            out.push(RecoveryCoverageRange {
                since_seconds: since,
                until_seconds: until,
            });
        }
        if left[i].until_seconds < right[j].until_seconds {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

/// `goal` minus a merged, sorted `covered` list.
fn subtract(
    goal: RecoveryCoverageRange,
    covered: &[RecoveryCoverageRange],
) -> Vec<RecoveryCoverageRange> {
    let mut debt = Vec::new();
    let mut cursor = goal.since_seconds;
    for range in covered {
        if range.until_seconds < cursor {
            continue;
        }
        if range.since_seconds > goal.until_seconds {
            break;
        }
        if range.since_seconds > cursor {
            debt.push(RecoveryCoverageRange {
                since_seconds: cursor,
                until_seconds: range.since_seconds - 1,
            });
        }
        if range.until_seconds >= goal.until_seconds {
            return debt;
        }
        cursor = range.until_seconds + 1;
    }
    if cursor <= goal.until_seconds {
        debt.push(RecoveryCoverageRange {
            since_seconds: cursor,
            until_seconds: goal.until_seconds,
        });
    }
    debt
}

/// Seconds on `route` inside `[since, until]` released for replay that no
/// fetch has proved since, as one-second ranges, oldest first.
fn released_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    since_seconds: u64,
    until_seconds: u64,
) -> StorageResult<Vec<RecoveryCoverageRange>> {
    let (kind, id) = route.storage_key();
    conn.prepare_cached(
        "SELECT second FROM account_recovery_coverage_released
         WHERE route_kind = ?1 AND route_id = ?2 AND second BETWEEN ?3 AND ?4 ORDER BY second",
    )
    .storage()?
    .query_map(
        params![kind, id, integer(since_seconds)?, integer(until_seconds)?],
        |row| row.get::<_, i64>(0),
    )
    .storage()?
    .map(|second| {
        let second = i64_to_u64(second.storage()?)?;
        Ok(RecoveryCoverageRange {
            since_seconds: second,
            until_seconds: second,
        })
    })
    .collect()
}

/// Record a slice. A live boundary leaves out every second released for
/// replay that no fetch has proved since: its REQ delivered that event before
/// the release and will not deliver it again. Any other proof fetched what it
/// covers, so the released seconds it covers are proved again.
fn record_slice(
    conn: &Connection,
    slice: &RecoveryCoverageSlice<'_>,
    now_seconds: u64,
) -> StorageResult<()> {
    if slice.since_seconds > slice.until_seconds || slice.relay.is_empty() {
        return Err(invalid());
    }
    let range = RecoveryCoverageRange {
        since_seconds: slice.since_seconds,
        until_seconds: slice.until_seconds,
    };
    if slice.proof == RecoveryCoverageProof::LiveBoundary {
        let released = released_tx(conn, slice.route, range.since_seconds, range.until_seconds)?;
        for kept in subtract(range, &released) {
            record_range(
                conn,
                &RecoveryCoverageSlice {
                    since_seconds: kept.since_seconds,
                    until_seconds: kept.until_seconds,
                    ..*slice
                },
                now_seconds,
            )?;
        }
        return Ok(());
    }
    record_range(conn, slice, now_seconds)?;
    let (kind, id) = slice.route.storage_key();
    conn.execute_cached(
        "DELETE FROM account_recovery_coverage_released
         WHERE route_kind = ?1 AND route_id = ?2 AND second BETWEEN ?3 AND ?4",
        params![
            kind,
            id,
            integer(range.since_seconds)?,
            integer(range.until_seconds)?
        ],
    )
    .storage()?;
    Ok(())
}

/// Record a validated slice, merging it with the same proof's ranges it
/// touches.
fn record_range(
    conn: &Connection,
    slice: &RecoveryCoverageSlice<'_>,
    now_seconds: u64,
) -> StorageResult<()> {
    let (kind, id) = slice.route.storage_key();
    let proof = slice.proof as i64;
    let since = integer(slice.since_seconds)?;
    let until = integer(slice.until_seconds)?;
    let mut merged = RecoveryCoverageRange {
        since_seconds: slice.since_seconds,
        until_seconds: slice.until_seconds,
    };
    let mut recorded = integer(now_seconds)?;
    let touching = conn
        .prepare_cached(
            "SELECT since_seconds, until_seconds, recorded_at_seconds
             FROM account_recovery_coverage
             WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3 AND proof = ?4
               AND since_seconds <= ?5 + 1 AND until_seconds >= ?6 - 1",
        )
        .storage()?
        .query_map(params![kind, id, slice.relay, proof, until, since], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    for (old_since, old_until, old_recorded) in touching {
        merged.since_seconds = merged.since_seconds.min(i64_to_u64(old_since)?);
        merged.until_seconds = merged.until_seconds.max(i64_to_u64(old_until)?);
        recorded = recorded.min(old_recorded);
        conn.execute_cached(
            "DELETE FROM account_recovery_coverage
             WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3 AND proof = ?4
               AND since_seconds = ?5",
            params![kind, id, slice.relay, proof, old_since],
        )
        .storage()?;
    }
    conn.execute_cached(
        "INSERT INTO account_recovery_coverage
         (route_kind, route_id, relay, proof, since_seconds, until_seconds, recorded_at_seconds)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            kind,
            id,
            slice.relay,
            proof,
            integer(merged.since_seconds)?,
            integer(merged.until_seconds)?,
            recorded
        ],
    )
    .storage()?;
    Ok(())
}

fn widen_goal(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    since_seconds: u64,
) -> StorageResult<()> {
    let (kind, id) = route.storage_key();
    conn.execute_cached(
        "INSERT INTO account_recovery_coverage_goals (route_kind, route_id, since_seconds)
         VALUES (?1, ?2, ?3)
         ON CONFLICT (route_kind, route_id)
         DO UPDATE SET since_seconds = MIN(since_seconds, excluded.since_seconds)",
        params![kind, id, integer(since_seconds)?],
    )
    .storage()?;
    Ok(())
}

/// Remove `[since, until]` (`until` open to the top when `None`) from the
/// coverage of `route`, or of every route. A range straddling either edge
/// keeps its outer part with its proof time.
fn remove_coverage_tx(
    conn: &Connection,
    route: Option<&TransportReconciliationRoute>,
    since_seconds: u64,
    until_seconds: Option<u64>,
) -> StorageResult<()> {
    let since = integer(since_seconds)?;
    let until = until_seconds.map(integer).transpose()?;
    let (kind, id) = route.map_or((None, None), |route| {
        let (kind, id) = route.storage_key();
        (Some(kind), Some(id))
    });
    let overlapping = conn
        .prepare_cached(
            "SELECT route_kind, route_id, relay, proof, since_seconds, until_seconds,
                    recorded_at_seconds
             FROM account_recovery_coverage
             WHERE (?1 IS NULL OR (route_kind = ?1 AND route_id = ?2))
               AND until_seconds >= ?3 AND (?4 IS NULL OR since_seconds <= ?4)",
        )
        .storage()?
        .query_map(params![kind, id, since, until], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    for (kind, id, relay, proof, old_since, old_until, recorded) in overlapping {
        conn.execute_cached(
            "DELETE FROM account_recovery_coverage
             WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3 AND proof = ?4
               AND since_seconds = ?5",
            params![kind, id, relay, proof, old_since],
        )
        .storage()?;
        // Ranges of one route, relay and proof never touch, so neither
        // remainder can collide with another range.
        let mut keep = Vec::with_capacity(2);
        if old_since < since {
            keep.push((old_since, since - 1));
        }
        if let Some(until) = until
            && old_until > until
        {
            keep.push((until + 1, old_until));
        }
        for (keep_since, keep_until) in keep {
            conn.execute_cached(
                "INSERT INTO account_recovery_coverage
                 (route_kind, route_id, relay, proof, since_seconds, until_seconds,
                  recorded_at_seconds)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![kind, id, relay, proof, keep_since, keep_until, recorded],
            )
            .storage()?;
        }
    }
    Ok(())
}

/// Append un-covered ranges on `route` (every route when `None`) under the
/// account's next generation, then prune the log to its row bound.
fn log_uncover_tx(
    conn: &Connection,
    route: Option<&TransportReconciliationRoute>,
    ranges: &[(u64, Option<u64>)],
    now_seconds: u64,
) -> StorageResult<()> {
    if ranges.is_empty() {
        return Ok(());
    }
    let generation: i64 = conn
        .query_row_cached(
            "UPDATE account_recovery_coverage_uncover_state SET generation = generation + 1
             WHERE singleton = 1 RETURNING generation",
            [],
            |row| row.get(0),
        )
        .storage()?;
    let (kind, id) = route.map_or((None, None), |route| {
        let (kind, id) = route.storage_key();
        (Some(kind), Some(id))
    });
    for (since, until) in ranges {
        conn.execute_cached(
            "INSERT INTO account_recovery_coverage_uncovers
             (generation, route_kind, route_id, since_seconds, until_seconds, recorded_at_seconds)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                generation,
                kind,
                id,
                integer(*since)?,
                until.map(integer).transpose()?,
                integer(now_seconds)?
            ],
        )
        .storage()?;
    }
    prune_uncover_log_tx(conn, None)
}

/// Drop un-cover rows past the row bound, and those older than the log's
/// retention when `now_seconds` is given, remembering the highest generation
/// dropped so a write from before it records nothing.
fn prune_uncover_log_tx(conn: &Connection, now_seconds: Option<u64>) -> StorageResult<()> {
    let mut dropped: Option<i64> = conn
        .query_row_cached(
            "SELECT MAX(generation) FROM (SELECT generation FROM account_recovery_coverage_uncovers
             ORDER BY generation DESC, rowid DESC LIMIT -1 OFFSET ?1)",
            [UNCOVER_LOG_MAX_ROWS],
            |row| row.get(0),
        )
        .storage()?;
    if let Some(now) = now_seconds {
        let oldest_kept = integer(now.saturating_sub(UNCOVER_LOG_RETENTION_SECS))?;
        let aged: Option<i64> = conn
            .query_row_cached(
                "SELECT MAX(generation) FROM account_recovery_coverage_uncovers
                 WHERE recorded_at_seconds < ?1",
                [oldest_kept],
                |row| row.get(0),
            )
            .storage()?;
        dropped = dropped.max(aged);
    }
    let Some(dropped) = dropped else {
        return Ok(());
    };
    // Whole generations go, so a kept generation is never half there.
    conn.execute_cached(
        "DELETE FROM account_recovery_coverage_uncovers WHERE generation <= ?1",
        [dropped],
    )
    .storage()?;
    conn.execute_cached(
        "UPDATE account_recovery_coverage_uncover_state
         SET pruned_through = MAX(pruned_through, ?1) WHERE singleton = 1",
        [dropped],
    )
    .storage()?;
    Ok(())
}

/// Account-wide loss from `floor_seconds` upward, inside the transaction that
/// imports it: every route the ledger holds loses its coverage from the floor
/// up, and its goal widens to the floor. Routes the ledger does not hold yet
/// have no coverage to lose; the owner widens their goals afterwards. The log
/// records the loss for every route, so a fetch already running on any route
/// keeps the debt too.
pub(crate) fn uncover_loss_tx(conn: &Connection, floor_seconds: u64) -> StorageResult<()> {
    let floor = integer(floor_seconds)?;
    conn.execute_cached(
        "INSERT INTO account_recovery_coverage_goals (route_kind, route_id, since_seconds)
         SELECT DISTINCT route_kind, route_id, ?1 FROM account_recovery_coverage WHERE true
         ON CONFLICT (route_kind, route_id)
         DO UPDATE SET since_seconds = MIN(since_seconds, excluded.since_seconds)",
        [floor],
    )
    .storage()?;
    conn.execute_cached(
        "UPDATE account_recovery_coverage_goals SET since_seconds = ?1 WHERE since_seconds > ?1",
        [floor],
    )
    .storage()?;
    remove_coverage_tx(conn, None, floor_seconds, None)?;
    log_uncover_tx(
        conn,
        None,
        &[(floor_seconds, None)],
        i64_to_u64(crate::base::codec::unix_now_seconds_i64())?,
    )
}

/// A released receipt lets its event be delivered and admitted again, so the
/// second it was sent in is no longer covered on the routes the inventory
/// placed it on, and those routes owe it until a fetch proves it again; a live
/// boundary cannot. Runs in the release's transaction, before the inventory
/// rows go. A release without inventory rows has no
/// trustworthy route or time; the epoch gap it arms keeps that debt.
pub(crate) fn uncover_released_event_tx(conn: &Connection, event_id: &[u8]) -> StorageResult<()> {
    let placed = conn
        .prepare_cached(
            "SELECT route_kind, route_id, created_at FROM transport_reconciliation_items
             WHERE event_id = ?1",
        )
        .storage()?
        .query_map([event_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let now = i64_to_u64(crate::base::codec::unix_now_seconds_i64())?;
    for (kind, id, created_at) in placed {
        let route = route_from(kind, &id)?;
        let second = i64_to_u64(created_at)?;
        remove_coverage_tx(conn, Some(&route), second, Some(second))?;
        widen_goal(conn, &route, second)?;
        conn.execute_cached(
            "INSERT OR IGNORE INTO account_recovery_coverage_released (route_kind, route_id, second)
             VALUES (?1, ?2, ?3)",
            params![kind, id, created_at],
        )
        .storage()?;
        log_uncover_tx(conn, Some(&route), &[(second, Some(second))], now)?;
    }
    Ok(())
}

impl SqliteAppStorage {
    /// Record covered slices in one transaction. This is the entry point for
    /// every proof, sweep slices included: each slice merges with the same
    /// route, relay and proof's overlapping or touching ranges. A live
    /// boundary leaves out the seconds released for replay that no fetch has
    /// proved since.
    pub fn record_recovery_coverage(
        &self,
        slices: &[RecoveryCoverageSlice<'_>],
        now_seconds: u64,
    ) -> StorageResult<()> {
        if slices.is_empty() {
            return Ok(());
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for slice in slices {
                record_slice(&conn, slice, now_seconds)?;
            }
            Ok(())
        })
    }

    /// The un-cover generation now: what a fetch starting now remembers.
    pub fn recovery_coverage_mark(&self) -> StorageResult<RecoveryCoverageMark> {
        let generation: i64 = self
            .lock()?
            .query_row_cached(
                "SELECT generation FROM account_recovery_coverage_uncover_state
                 WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .storage()?;
        Ok(RecoveryCoverageMark(i64_to_u64(generation)?))
    }

    /// Record slices proved by a fetch that started at `mark`, less every
    /// range un-covered on their routes since: a loss or release that landed
    /// during the fetch may lie inside a slice, so its debt stays. Returns
    /// `false`, recording nothing, when the log no longer reaches back to
    /// `mark`.
    pub fn record_recovery_coverage_since(
        &self,
        slices: &[RecoveryCoverageSlice<'_>],
        now_seconds: u64,
        mark: RecoveryCoverageMark,
    ) -> StorageResult<bool> {
        if slices
            .iter()
            .any(|slice| slice.since_seconds > slice.until_seconds || slice.relay.is_empty())
        {
            return Err(invalid());
        }
        if slices.is_empty() {
            return Ok(true);
        }
        let mark = integer(mark.0)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let pruned: i64 = conn
                .query_row_cached(
                    "SELECT pruned_through FROM account_recovery_coverage_uncover_state
                     WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .storage()?;
            if pruned > mark {
                return Ok(false);
            }
            let uncovered = conn
                .prepare_cached(
                    "SELECT route_kind, route_id, since_seconds, until_seconds
                     FROM account_recovery_coverage_uncovers WHERE generation > ?1",
                )
                .storage()?
                .query_map([mark], |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                })
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?;
            let uncovered = uncovered
                .into_iter()
                .map(|(kind, id, since, until)| {
                    let route = match (kind, id) {
                        (Some(kind), Some(id)) => Some(route_from(kind, &id)?),
                        _ => None,
                    };
                    let range = RecoveryCoverageRange {
                        since_seconds: i64_to_u64(since)?,
                        until_seconds: until.map_or(Ok(u64::MAX), i64_to_u64)?,
                    };
                    Ok((route, range))
                })
                .collect::<StorageResult<Vec<_>>>()?;
            for slice in slices {
                let taken = union(
                    uncovered
                        .iter()
                        .filter(|(route, _)| {
                            route.as_ref().is_none_or(|route| route == slice.route)
                        })
                        .map(|(_, range)| *range)
                        .collect(),
                );
                let kept = subtract(
                    RecoveryCoverageRange {
                        since_seconds: slice.since_seconds,
                        until_seconds: slice.until_seconds,
                    },
                    &taken,
                );
                for range in kept {
                    record_slice(
                        &conn,
                        &RecoveryCoverageSlice {
                            since_seconds: range.since_seconds,
                            until_seconds: range.until_seconds,
                            ..*slice
                        },
                        now_seconds,
                    )?;
                }
            }
            Ok(true)
        })
    }

    /// The routes need everything from `since_seconds` up to now. A goal only
    /// widens; an existing lower floor stays.
    pub fn widen_recovery_coverage_goals(
        &self,
        routes: &[TransportReconciliationRoute],
        since_seconds: u64,
    ) -> StorageResult<()> {
        if routes.is_empty() {
            return Ok(());
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for route in routes {
                widen_goal(&conn, route, since_seconds)?;
            }
            Ok(())
        })
    }

    /// A loss on `routes` from `floor_seconds` upward: their coverage at and
    /// above the floor is dropped, and their goals widen to the floor. Other
    /// routes keep everything.
    pub fn uncover_recovery_coverage(
        &self,
        routes: &[TransportReconciliationRoute],
        floor_seconds: u64,
    ) -> StorageResult<()> {
        if routes.is_empty() {
            return Ok(());
        }
        let now = i64_to_u64(crate::base::codec::unix_now_seconds_i64())?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for route in routes {
                remove_coverage_tx(&conn, Some(route), floor_seconds, None)?;
                widen_goal(&conn, route, floor_seconds)?;
                log_uncover_tx(&conn, Some(route), &[(floor_seconds, None)], now)?;
            }
            Ok(())
        })
    }

    /// Drop coverage older than the retention floor and raise goals to it, and
    /// age the un-cover log. Returns how many ranges were deleted. Pruning
    /// un-covers nothing: what falls below the floor is no longer owed.
    pub fn prune_recovery_coverage(&self, floor_seconds: u64) -> StorageResult<usize> {
        let floor = integer(floor_seconds)?;
        let now = i64_to_u64(crate::base::codec::unix_now_seconds_i64())?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            prune_uncover_log_tx(&conn, Some(now))?;
            conn.execute_cached(
                "DELETE FROM account_recovery_coverage_released WHERE second < ?1",
                [floor],
            )
            .storage()?;
            let deleted = conn
                .execute_cached(
                    "DELETE FROM account_recovery_coverage WHERE until_seconds < ?1",
                    [floor],
                )
                .storage()?;
            // Ranges of one route, relay and proof never touch, so at most one
            // straddles the floor and raising it cannot collide.
            conn.execute_cached(
                "UPDATE account_recovery_coverage SET since_seconds = ?1 WHERE since_seconds < ?1",
                [floor],
            )
            .storage()?;
            conn.execute_cached(
                "UPDATE account_recovery_coverage_goals SET since_seconds = ?1
                 WHERE since_seconds < ?1",
                [floor],
            )
            .storage()?;
            Ok(deleted)
        })
    }

    /// One relay's proved ranges on a route, oldest first.
    pub fn recovery_coverage_ranges(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
    ) -> StorageResult<Vec<RecoveryCoverageProved>> {
        let (kind, id) = route.storage_key();
        let conn = self.lock()?;
        let rows = conn
            .prepare_cached(
                "SELECT since_seconds, until_seconds, proof, recorded_at_seconds
                 FROM account_recovery_coverage
                 WHERE route_kind = ?1 AND route_id = ?2 AND relay = ?3
                 ORDER BY since_seconds, proof",
            )
            .storage()?
            .query_map(params![kind, id, relay], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(since, until, proof, recorded)| {
                Ok(RecoveryCoverageProved {
                    range: RecoveryCoverageRange {
                        since_seconds: i64_to_u64(since)?,
                        until_seconds: i64_to_u64(until)?,
                    },
                    proof: RecoveryCoverageProof::from_i64(proof)?,
                    recorded_at_seconds: i64_to_u64(recorded)?,
                })
            })
            .collect()
    }

    /// The route's goal floor, if it has a goal.
    pub fn recovery_coverage_goal(
        &self,
        route: &TransportReconciliationRoute,
    ) -> StorageResult<Option<u64>> {
        let (kind, id) = route.storage_key();
        self.lock()?
            .query_row_cached(
                "SELECT since_seconds FROM account_recovery_coverage_goals
                 WHERE route_kind = ?1 AND route_id = ?2",
                params![kind, id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .storage()?
            .map(i64_to_u64)
            .transpose()
    }

    /// Every route with a goal.
    pub fn recovery_coverage_goal_routes(
        &self,
    ) -> StorageResult<Vec<TransportReconciliationRoute>> {
        let conn = self.lock()?;
        let rows = conn
            .prepare_cached(
                "SELECT route_kind, route_id FROM account_recovery_coverage_goals
                 ORDER BY route_kind, route_id",
            )
            .storage()?
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(kind, id)| route_from(kind, &id))
            .collect()
    }

    /// What every one of `relays` covers on the route, merged across proofs.
    /// No relays cover nothing.
    pub fn recovery_coverage_covered(
        &self,
        route: &TransportReconciliationRoute,
        relays: &[String],
    ) -> StorageResult<Vec<RecoveryCoverageRange>> {
        if relays.is_empty() {
            return Ok(Vec::new());
        }
        let (kind, id) = route.storage_key();
        let conn = self.lock()?;
        let rows = conn
            .prepare_cached(
                "SELECT relay, since_seconds, until_seconds FROM account_recovery_coverage
                 WHERE route_kind = ?1 AND route_id = ?2",
            )
            .storage()?
            .query_map(params![kind, id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        drop(conn);
        let mut by_relay: BTreeMap<&str, Vec<RecoveryCoverageRange>> = relays
            .iter()
            .map(|relay| (relay.as_str(), Vec::new()))
            .collect();
        for (relay, since, until) in &rows {
            if let Some(ranges) = by_relay.get_mut(relay.as_str()) {
                ranges.push(RecoveryCoverageRange {
                    since_seconds: i64_to_u64(*since)?,
                    until_seconds: i64_to_u64(*until)?,
                });
            }
        }
        let mut covered: Option<Vec<RecoveryCoverageRange>> = None;
        for ranges in by_relay.into_values() {
            let ranges = union(ranges);
            covered = Some(match covered {
                None => ranges,
                Some(previous) => intersect(&previous, &ranges),
            });
        }
        Ok(covered.unwrap_or_default())
    }

    /// Whether every one of `relays` covers `[since, until]` on the route.
    pub fn recovery_coverage_covers(
        &self,
        route: &TransportReconciliationRoute,
        relays: &[String],
        since_seconds: u64,
        until_seconds: u64,
    ) -> StorageResult<bool> {
        if since_seconds > until_seconds {
            return Ok(true);
        }
        let covered = self.recovery_coverage_covered(route, relays)?;
        Ok(subtract(
            RecoveryCoverageRange {
                since_seconds,
                until_seconds,
            },
            &covered,
        )
        .is_empty()
            && !relays.is_empty())
    }

    /// The route's debt up to `until_seconds` on `relays`: its goal minus what
    /// every relay covers. A route without a goal owes nothing.
    pub fn recovery_coverage_debt(
        &self,
        route: &TransportReconciliationRoute,
        relays: &[String],
        until_seconds: u64,
    ) -> StorageResult<Vec<RecoveryCoverageRange>> {
        let Some(since) = self.recovery_coverage_goal(route)? else {
            return Ok(Vec::new());
        };
        if since > until_seconds {
            return Ok(Vec::new());
        }
        let covered = self.recovery_coverage_covered(route, relays)?;
        Ok(subtract(
            RecoveryCoverageRange {
                since_seconds: since,
                until_seconds,
            },
            &covered,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY_A: &str = "wss://a.example";
    const RELAY_B: &str = "wss://b.example";

    fn range(since: u64, until: u64) -> RecoveryCoverageRange {
        RecoveryCoverageRange {
            since_seconds: since,
            until_seconds: until,
        }
    }

    fn group(byte: u8) -> TransportReconciliationRoute {
        TransportReconciliationRoute::Group([byte; 32])
    }

    fn record(
        app: &SqliteAppStorage,
        route: &TransportReconciliationRoute,
        relay: &str,
        since: u64,
        until: u64,
        proof: RecoveryCoverageProof,
        now: u64,
    ) {
        app.record_recovery_coverage(
            &[RecoveryCoverageSlice {
                route,
                relay,
                since_seconds: since,
                until_seconds: until,
                proof,
            }],
            now,
        )
        .unwrap();
    }

    fn ranges(
        app: &SqliteAppStorage,
        route: &TransportReconciliationRoute,
        relay: &str,
    ) -> Vec<(u64, u64, RecoveryCoverageProof)> {
        app.recovery_coverage_ranges(route, relay)
            .unwrap()
            .into_iter()
            .map(|proved| {
                (
                    proved.range.since_seconds,
                    proved.range.until_seconds,
                    proved.proof,
                )
            })
            .collect()
    }

    #[test]
    fn range_algebra_merges_intersects_and_subtracts() {
        assert_eq!(
            union(vec![
                range(10, 20),
                range(21, 30),
                range(40, 50),
                range(5, 12)
            ]),
            vec![range(5, 30), range(40, 50)]
        );
        assert_eq!(
            intersect(&[range(0, 10), range(20, 30)], &[range(5, 25)]),
            vec![range(5, 10), range(20, 25)]
        );
        assert_eq!(
            subtract(range(0, 100), &[range(10, 20), range(50, 200)]),
            vec![range(0, 9), range(21, 49)]
        );
        assert_eq!(subtract(range(10, 20), &[range(0, 30)]), vec![]);
        assert_eq!(subtract(range(10, 20), &[]), vec![range(10, 20)]);
    }

    #[test]
    fn slices_merge_with_touching_ranges_of_the_same_proof_only() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let route = group(1);
        let proof = RecoveryCoverageProof::SweepSlice;
        record(&app, &route, RELAY_A, 100, 199, proof, 1_000);
        record(&app, &route, RELAY_A, 300, 399, proof, 1_001);
        // Touches the first and overlaps the second: all three merge.
        record(&app, &route, RELAY_A, 200, 310, proof, 1_002);
        assert_eq!(ranges(&app, &route, RELAY_A), vec![(100, 399, proof)]);
        let merged = app.recovery_coverage_ranges(&route, RELAY_A).unwrap();
        assert_eq!(merged[0].recorded_at_seconds, 1_000, "oldest proof time");
        // Another proof is kept apart but counts toward coverage.
        record(
            &app,
            &route,
            RELAY_A,
            400,
            500,
            RecoveryCoverageProof::Comparison,
            1_003,
        );
        assert_eq!(ranges(&app, &route, RELAY_A).len(), 2);
        let relays = vec![RELAY_A.to_owned()];
        assert!(
            app.recovery_coverage_covers(&route, &relays, 100, 500)
                .unwrap()
        );
        assert!(
            !app.recovery_coverage_covers(&route, &relays, 99, 500)
                .unwrap()
        );
        // A slice strictly inside an existing range changes nothing.
        record(&app, &route, RELAY_A, 150, 160, proof, 2_000);
        assert_eq!(
            app.recovery_coverage_ranges(&route, RELAY_A).unwrap()[0],
            RecoveryCoverageProved {
                range: range(100, 399),
                proof,
                recorded_at_seconds: 1_000,
            }
        );
    }

    #[test]
    fn coverage_needs_every_relay_and_debt_is_goal_minus_covered() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let route = TransportReconciliationRoute::Inbox;
        let both = vec![RELAY_A.to_owned(), RELAY_B.to_owned()];
        assert!(
            app.recovery_coverage_debt(&route, &both, 1_000)
                .unwrap()
                .is_empty()
        );
        app.widen_recovery_coverage_goals(std::slice::from_ref(&route), 100)
            .unwrap();
        app.widen_recovery_coverage_goals(std::slice::from_ref(&route), 500)
            .unwrap();
        assert_eq!(app.recovery_coverage_goal(&route).unwrap(), Some(100));
        record(
            &app,
            &route,
            RELAY_A,
            100,
            1_000,
            RecoveryCoverageProof::LiveBoundary,
            1,
        );
        record(
            &app,
            &route,
            RELAY_B,
            300,
            600,
            RecoveryCoverageProof::Comparison,
            1,
        );
        assert_eq!(
            app.recovery_coverage_debt(&route, &both, 1_000).unwrap(),
            vec![range(100, 299), range(601, 1_000)]
        );
        assert!(
            app.recovery_coverage_debt(&route, &[RELAY_A.to_owned()], 1_000)
                .unwrap()
                .is_empty()
        );
        assert!(!app.recovery_coverage_covers(&route, &[], 0, 0).unwrap());
    }

    #[test]
    fn loss_uncovers_only_the_affected_routes_from_its_floor() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let (lost, kept) = (group(1), group(2));
        for route in [&lost, &kept] {
            for relay in [RELAY_A, RELAY_B] {
                record(
                    &app,
                    route,
                    relay,
                    100,
                    199,
                    RecoveryCoverageProof::Comparison,
                    1,
                );
                record(
                    &app,
                    route,
                    relay,
                    300,
                    999,
                    RecoveryCoverageProof::Comparison,
                    1,
                );
            }
        }
        app.widen_recovery_coverage_goals(&[lost.clone(), kept.clone()], 100)
            .unwrap();
        app.uncover_recovery_coverage(std::slice::from_ref(&lost), 500)
            .unwrap();
        for relay in [RELAY_A, RELAY_B] {
            assert_eq!(
                ranges(&app, &lost, relay),
                vec![
                    (100, 199, RecoveryCoverageProof::Comparison),
                    (300, 499, RecoveryCoverageProof::Comparison)
                ]
            );
            assert_eq!(ranges(&app, &kept, relay).len(), 2, "unaffected route");
        }
        let both = vec![RELAY_A.to_owned(), RELAY_B.to_owned()];
        assert_eq!(
            app.recovery_coverage_debt(&lost, &both, 999).unwrap(),
            vec![range(200, 299), range(500, 999)]
        );
        // A loss below every range drops all of the route's coverage and
        // widens its goal to the floor.
        app.uncover_recovery_coverage(std::slice::from_ref(&lost), 50)
            .unwrap();
        assert!(ranges(&app, &lost, RELAY_A).is_empty());
        assert_eq!(app.recovery_coverage_goal(&lost).unwrap(), Some(50));
        assert_eq!(app.recovery_coverage_goal(&kept).unwrap(), Some(100));
        // A loss on a route with no goal gives it one.
        let fresh = group(3);
        app.uncover_recovery_coverage(std::slice::from_ref(&fresh), 700)
            .unwrap();
        assert_eq!(app.recovery_coverage_goal(&fresh).unwrap(), Some(700));
    }

    #[test]
    fn pruning_drops_ranges_below_the_retention_floor_and_raises_goals() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let route = group(1);
        let proof = RecoveryCoverageProof::LiveBoundary;
        record(&app, &route, RELAY_A, 0, 99, proof, 1);
        record(&app, &route, RELAY_A, 150, 400, proof, 1);
        record(&app, &route, RELAY_A, 500, 600, proof, 1);
        app.widen_recovery_coverage_goals(std::slice::from_ref(&route), 0)
            .unwrap();
        assert_eq!(app.prune_recovery_coverage(200).unwrap(), 1);
        assert_eq!(
            ranges(&app, &route, RELAY_A),
            vec![(200, 400, proof), (500, 600, proof)]
        );
        assert_eq!(app.recovery_coverage_goal(&route).unwrap(), Some(200));
        assert_eq!(app.recovery_coverage_goal_routes().unwrap(), vec![route]);
    }

    #[test]
    fn importing_loss_uncovers_every_ledger_route_in_its_own_transaction() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        app.ensure_account_projection("alice").unwrap();
        let (inbox, group) = (TransportReconciliationRoute::Inbox, group(1));
        for route in [&inbox, &group] {
            record(
                &app,
                route,
                RELAY_A,
                100,
                900,
                RecoveryCoverageProof::Comparison,
                1,
            );
        }
        app.widen_recovery_coverage_goals(std::slice::from_ref(&inbox), 100)
            .unwrap();
        app.record_account_delivery_loss_bounded("alice", 41, 3, 1_000, Some(500))
            .unwrap();
        let imports = app.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(imports.len(), 1);
        for route in [&inbox, &group] {
            assert_eq!(
                ranges(&app, route, RELAY_A),
                vec![(100, 499, RecoveryCoverageProof::Comparison)]
            );
        }
        assert_eq!(app.recovery_coverage_goal(&inbox).unwrap(), Some(100));
        assert_eq!(app.recovery_coverage_goal(&group).unwrap(), Some(500));
        // The worker's own observation of a generation imports the same way;
        // an unknown floor un-covers everything.
        assert!(
            app.mark_account_delivery_recovery_observed("alice", 42, 1, None)
                .unwrap()
                .is_some()
        );
        for route in [&inbox, &group] {
            assert!(ranges(&app, route, RELAY_A).is_empty());
            assert_eq!(app.recovery_coverage_goal(route).unwrap(), Some(0));
        }
    }

    #[test]
    fn legacy_clear_that_restores_loss_uncovers_the_ledger() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        app.ensure_account_projection("alice").unwrap();
        // Generation 12 joins 11's obligation; the worker then re-adopts 11.
        for token in [11, 12, 11] {
            app.mark_account_delivery_recovery_bounded("alice", token, 3, Some(500))
                .unwrap();
        }
        let inbox = TransportReconciliationRoute::Inbox;
        record(
            &app,
            &inbox,
            RELAY_A,
            100,
            900,
            RecoveryCoverageProof::Comparison,
            1,
        );
        // Retiring one generation re-arms the other, which still owes from
        // its floor.
        assert!(!app.clear_account_delivery_recovery("alice", 11).unwrap());
        assert_eq!(
            ranges(&app, &inbox, RELAY_A),
            vec![(100, 499, RecoveryCoverageProof::Comparison)]
        );
        assert_eq!(app.recovery_coverage_goal(&inbox).unwrap(), Some(500));
    }

    fn slice<'a>(
        route: &'a TransportReconciliationRoute,
        since: u64,
        until: u64,
    ) -> RecoveryCoverageSlice<'a> {
        RecoveryCoverageSlice {
            route,
            relay: RELAY_A,
            since_seconds: since,
            until_seconds: until,
            proof: RecoveryCoverageProof::Comparison,
        }
    }

    /// Losses with rising and falling floors on different routes land while
    /// one fetch runs: its write keeps only what lies below the lowest floor
    /// on each route, and a route no loss touched keeps the whole slice.
    #[test]
    fn a_write_subtracts_every_loss_imported_during_its_fetch() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        app.ensure_account_projection("alice").unwrap();
        let (a, b, c) = (group(1), group(2), group(3));
        // Loss before the fetch started is not subtracted again.
        app.uncover_recovery_coverage(std::slice::from_ref(&c), 200)
            .unwrap();
        let mark = app.recovery_coverage_mark().unwrap();
        app.uncover_recovery_coverage(std::slice::from_ref(&a), 600)
            .unwrap();
        app.uncover_recovery_coverage(std::slice::from_ref(&b), 300)
            .unwrap();
        app.uncover_recovery_coverage(std::slice::from_ref(&a), 800)
            .unwrap();
        app.uncover_recovery_coverage(std::slice::from_ref(&a), 450)
            .unwrap();
        assert!(
            app.record_recovery_coverage_since(
                &[
                    slice(&a, 100, 900),
                    slice(&b, 100, 900),
                    slice(&c, 100, 900)
                ],
                1_000,
                mark,
            )
            .unwrap()
        );
        let comparison = RecoveryCoverageProof::Comparison;
        assert_eq!(ranges(&app, &a, RELAY_A), vec![(100, 449, comparison)]);
        assert_eq!(ranges(&app, &b, RELAY_A), vec![(100, 299, comparison)]);
        assert_eq!(ranges(&app, &c, RELAY_A), vec![(100, 900, comparison)]);

        // An imported loss un-covers every route, including one the ledger
        // did not hold when the fetch started.
        let mark = app.recovery_coverage_mark().unwrap();
        app.record_account_delivery_loss_bounded("alice", 41, 3, 1_000, Some(700))
            .unwrap();
        app.synchronize_account_delivery_loss("alice").unwrap();
        let fresh = group(4);
        assert!(
            app.record_recovery_coverage_since(&[slice(&fresh, 100, 900)], 1_000, mark)
                .unwrap()
        );
        assert_eq!(ranges(&app, &fresh, RELAY_A), vec![(100, 699, comparison)]);
        // A fetch that started after every loss records its whole slice.
        let mark = app.recovery_coverage_mark().unwrap();
        assert!(
            app.record_recovery_coverage_since(&[slice(&a, 450, 900)], 1_000, mark)
                .unwrap()
        );
        assert_eq!(ranges(&app, &a, RELAY_A), vec![(100, 900, comparison)]);
    }

    /// Imports un-cover from each newly charged generation's own bound, not
    /// from the lowest of every unresolved one: a fetch that started after an
    /// older loss keeps what it proved below a newer loss's floor, and a
    /// falling floor still takes back everything from itself up.
    #[test]
    fn imports_with_rising_and_falling_floors_during_one_fetch() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        app.ensure_account_projection("alice").unwrap();
        let route = group(1);
        let comparison = RecoveryCoverageProof::Comparison;
        app.record_account_delivery_loss_bounded("alice", 41, 3, 1_000, Some(200))
            .unwrap();
        app.synchronize_account_delivery_loss("alice").unwrap();
        let mark = app.recovery_coverage_mark().unwrap();
        // A newer generation with a higher floor, then a notification lag
        // with a still higher one, while the fetch runs.
        app.record_account_delivery_loss_bounded("alice", 42, 2, 1_000, Some(600))
            .unwrap();
        app.record_account_recovery_loss_bounded(
            "alice",
            super::super::account_recovery::RecoveryLossCause::NotificationConsumer,
            7,
            0,
            1_000,
            Some(800),
        )
        .unwrap();
        app.synchronize_account_delivery_loss("alice").unwrap();
        assert!(
            app.record_recovery_coverage_since(&[slice(&route, 100, 900)], 1_000, mark)
                .unwrap()
        );
        assert_eq!(ranges(&app, &route, RELAY_A), vec![(100, 599, comparison)]);
        // A falling floor: an older delivery joins the newest generation.
        let mark = app.recovery_coverage_mark().unwrap();
        app.record_account_delivery_loss_bounded("alice", 42, 3, 1_000, Some(300))
            .unwrap();
        app.synchronize_account_delivery_loss("alice").unwrap();
        assert_eq!(ranges(&app, &route, RELAY_A), vec![(100, 299, comparison)]);
        assert!(
            app.record_recovery_coverage_since(&[slice(&route, 100, 900)], 1_000, mark)
                .unwrap()
        );
        assert_eq!(ranges(&app, &route, RELAY_A), vec![(100, 299, comparison)]);
    }

    /// A receipt released while a comparison runs: the release un-covers the
    /// event's second on its route, and the comparison's write leaves that
    /// second owed.
    #[test]
    fn a_receipt_released_during_a_fetch_keeps_its_second_owed() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let (route, other) = (group(1), group(2));
        let now = i64_to_u64(crate::base::codec::unix_now_seconds_i64()).unwrap();
        let (since, until, sent) = (now - 1_000, now - 100, now - 500);
        for route in [&route, &other] {
            record(
                &app,
                route,
                RELAY_A,
                since,
                until,
                RecoveryCoverageProof::LiveBoundary,
                1,
            );
        }
        app.widen_recovery_coverage_goals(&[route.clone(), other.clone()], since)
            .unwrap();
        let released = crate::TransportReconciliationItem {
            event_id: [9; 32],
            created_at: sent,
        };
        app.record_reconciliation_items(std::iter::once((&route, &released)))
            .unwrap();
        let mark = app.recovery_coverage_mark().unwrap();
        storage
            .connection
            .with_transaction(|| {
                let conn = storage.lock()?;
                crate::cross::release::retire_transport_receipts(
                    &conn,
                    &cgka_traits::types::MessageId::new(released.event_id.to_vec()),
                )
            })
            .unwrap();
        // The release split the live boundary around the event's second.
        let live = RecoveryCoverageProof::LiveBoundary;
        assert_eq!(
            ranges(&app, &route, RELAY_A),
            vec![(since, sent - 1, live), (sent + 1, until, live)]
        );
        assert_eq!(
            ranges(&app, &other, RELAY_A),
            vec![(since, until, live)],
            "another route keeps its coverage"
        );
        assert!(
            app.record_recovery_coverage_since(
                &[slice(&route, since, until), slice(&other, since, until)],
                now,
                mark,
            )
            .unwrap()
        );
        let relays = vec![RELAY_A.to_owned()];
        assert_eq!(
            app.recovery_coverage_debt(&route, &relays, until).unwrap(),
            vec![range(sent, sent)]
        );
        assert!(
            app.recovery_coverage_debt(&other, &relays, until)
                .unwrap()
                .is_empty()
        );
        // A release with no inventory row has no trustworthy second: the
        // epoch gap it arms keeps that debt, and the ledger keeps its ranges.
        let before = app.recovery_coverage_mark().unwrap();
        storage
            .connection
            .with_transaction(|| {
                let conn = storage.lock()?;
                crate::cross::release::retire_transport_receipts(
                    &conn,
                    &cgka_traits::types::MessageId::new(vec![7; 32]),
                )
            })
            .unwrap();
        assert_eq!(app.recovery_coverage_mark().unwrap(), before);
    }

    /// The live REQ that delivered a released event will not deliver it again,
    /// so rewriting its unchanged boundary leaves that second owed. A fetch
    /// that started before the release does not prove it either; one that
    /// started after does, and then the live boundary covers it again.
    /// Pruning below the retention floor forgets it.
    #[test]
    fn a_live_boundary_leaves_a_released_second_owed_until_a_fetch_proves_it() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let route = group(1);
        let live = RecoveryCoverageProof::LiveBoundary;
        let now = i64_to_u64(crate::base::codec::unix_now_seconds_i64()).unwrap();
        let (since, sent) = (now - 1_000, now - 500);
        record(&app, &route, RELAY_A, since, now - 100, live, 1);
        let released = crate::TransportReconciliationItem {
            event_id: [9; 32],
            created_at: sent,
        };
        app.record_reconciliation_items(std::iter::once((&route, &released)))
            .unwrap();
        let before_release = app.recovery_coverage_mark().unwrap();
        storage
            .connection
            .with_transaction(|| {
                crate::cross::release::retire_transport_receipts(
                    &*storage.lock()?,
                    &cgka_traits::types::MessageId::new(released.event_id.to_vec()),
                )
            })
            .unwrap();
        record(&app, &route, RELAY_A, since, now, live, 2);
        assert_eq!(
            ranges(&app, &route, RELAY_A),
            vec![(since, sent - 1, live), (sent + 1, now, live)],
            "the unchanged boundary leaves the released second out"
        );
        assert!(
            app.record_recovery_coverage_since(
                &[slice(&route, sent - 10, sent + 10)],
                now,
                before_release
            )
            .unwrap()
        );
        record(&app, &route, RELAY_A, since, now, live, 3);
        let relays = vec![RELAY_A.to_owned()];
        assert_eq!(
            app.recovery_coverage_debt(&route, &relays, now).unwrap(),
            vec![range(sent, sent)],
            "a fetch from before the release does not prove it"
        );
        let after_release = app.recovery_coverage_mark().unwrap();
        assert!(
            app.record_recovery_coverage_since(
                &[slice(&route, sent - 10, sent + 10)],
                now,
                after_release
            )
            .unwrap()
        );
        assert!(
            app.recovery_coverage_debt(&route, &relays, now)
                .unwrap()
                .is_empty()
        );
        record(&app, &route, RELAY_A, since, now, live, 4);
        assert_eq!(
            ranges(&app, &route, RELAY_A)
                .into_iter()
                .filter(|(_, _, proof)| *proof == live)
                .collect::<Vec<_>>(),
            vec![(since, now, live)],
            "once a fetch proved it, the live boundary covers it too"
        );

        // A second release, then retention passes it: nothing is left owed.
        let again = crate::TransportReconciliationItem {
            event_id: [8; 32],
            created_at: sent,
        };
        app.record_reconciliation_items(std::iter::once((&route, &again)))
            .unwrap();
        storage
            .connection
            .with_transaction(|| {
                crate::cross::release::retire_transport_receipts(
                    &*storage.lock()?,
                    &cgka_traits::types::MessageId::new(again.event_id.to_vec()),
                )
            })
            .unwrap();
        app.prune_recovery_coverage(sent + 1).unwrap();
        record(&app, &route, RELAY_A, sent - 10, now, live, 5);
        assert_eq!(
            ranges(&app, &route, RELAY_A)
                .into_iter()
                .filter(|(_, _, proof)| *proof == live)
                .collect::<Vec<_>>(),
            vec![(sent - 10, now, live)],
            "a pruned release no longer holds the boundary back"
        );
    }

    /// Once the log has pruned past a fetch's start, its write cannot know
    /// what was un-covered since, so it records nothing.
    #[test]
    fn a_write_older_than_the_pruned_log_records_nothing() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let route = group(1);
        let stale = app.recovery_coverage_mark().unwrap();
        app.uncover_recovery_coverage(std::slice::from_ref(&route), 600)
            .unwrap();
        let current = app.recovery_coverage_mark().unwrap();
        let later = i64_to_u64(crate::base::codec::unix_now_seconds_i64()).unwrap()
            + UNCOVER_LOG_RETENTION_SECS
            + 1;
        storage
            .connection
            .with_transaction(|| prune_uncover_log_tx(&*storage.lock()?, Some(later)))
            .unwrap();
        assert!(
            !app.record_recovery_coverage_since(&[slice(&route, 100, 900)], 1_000, stale)
                .unwrap()
        );
        assert!(ranges(&app, &route, RELAY_A).is_empty());
        assert!(
            app.record_recovery_coverage_since(&[slice(&route, 100, 900)], 1_000, current)
                .unwrap()
        );
        assert_eq!(ranges(&app, &route, RELAY_A).len(), 1);
    }

    /// The log keeps at most its row bound, dropping whole generations, and
    /// a fetch from before a dropped generation records nothing.
    #[test]
    fn the_log_drops_its_oldest_generations_past_the_row_bound() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let route = group(1);
        let stale = app.recovery_coverage_mark().unwrap();
        let routes = (0..=UNCOVER_LOG_MAX_ROWS)
            .map(|byte| group(u8::try_from(byte % 251).unwrap()))
            .collect::<Vec<_>>();
        for chunk in routes.chunks(64) {
            app.uncover_recovery_coverage(chunk, 10).unwrap();
        }
        let rows: i64 = storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM account_recovery_coverage_uncovers",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(rows <= UNCOVER_LOG_MAX_ROWS, "{rows}");
        assert!(
            !app.record_recovery_coverage_since(&[slice(&route, 0, 5)], 1_000, stale)
                .unwrap()
        );
        let current = app.recovery_coverage_mark().unwrap();
        assert!(
            app.record_recovery_coverage_since(&[slice(&route, 0, 5)], 1_000, current)
                .unwrap()
        );
    }

    /// Removing a bounded range splits a straddling range on every relay and
    /// proof and keeps each part's proof time.
    #[test]
    fn removing_a_bounded_range_splits_straddling_ranges() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let route = group(1);
        let live = RecoveryCoverageProof::LiveBoundary;
        let comparison = RecoveryCoverageProof::Comparison;
        record(&app, &route, RELAY_A, 100, 900, live, 5);
        record(&app, &route, RELAY_B, 400, 600, comparison, 6);
        record(&app, &route, RELAY_B, 700, 800, comparison, 7);
        storage
            .connection
            .with_transaction(|| {
                remove_coverage_tx(&*storage.lock()?, Some(&route), 500, Some(700))
            })
            .unwrap();
        assert_eq!(
            ranges(&app, &route, RELAY_A),
            vec![(100, 499, live), (701, 900, live)]
        );
        assert_eq!(
            ranges(&app, &route, RELAY_B),
            vec![(400, 499, comparison), (701, 800, comparison)]
        );
        let times = app
            .recovery_coverage_ranges(&route, RELAY_A)
            .unwrap()
            .iter()
            .map(|proved| proved.recorded_at_seconds)
            .collect::<Vec<_>>();
        assert_eq!(times, vec![5, 5]);
    }

    #[test]
    fn invalid_slices_are_refused_without_partial_writes() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let route = group(1);
        let slices = [
            RecoveryCoverageSlice {
                route: &route,
                relay: RELAY_A,
                since_seconds: 1,
                until_seconds: 2,
                proof: RecoveryCoverageProof::SweepSlice,
            },
            RecoveryCoverageSlice {
                route: &route,
                relay: RELAY_A,
                since_seconds: 9,
                until_seconds: 3,
                proof: RecoveryCoverageProof::SweepSlice,
            },
        ];
        assert!(app.record_recovery_coverage(&slices, 1).is_err());
        assert!(ranges(&app, &route, RELAY_A).is_empty());
    }
}
