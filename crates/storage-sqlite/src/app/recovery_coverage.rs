//! The recovery coverage ledger (mdk#2660): per route and relay, the
//! `created_at` ranges proved complete, and each route's goal floor.
//!
//! Debt is the goal minus what is covered. A loss un-covers only the routes it
//! could have affected, from its floor upward; nothing is invalidated
//! account-wide. Ranges are inclusive whole seconds.
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
use rusqlite::{Connection, params};
use std::collections::BTreeMap;

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

fn record_slice(
    conn: &Connection,
    slice: &RecoveryCoverageSlice<'_>,
    now_seconds: u64,
) -> StorageResult<()> {
    if slice.since_seconds > slice.until_seconds || slice.relay.is_empty() {
        return Err(invalid());
    }
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

/// Account-wide loss from `floor_seconds` upward, inside the transaction that
/// imports it: every route the ledger holds loses its coverage from the floor
/// up, and its goal widens to the floor. Routes the ledger does not hold yet
/// have no coverage to lose; the owner widens their goals afterwards.
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
    conn.execute_cached(
        "DELETE FROM account_recovery_coverage WHERE since_seconds >= ?1",
        [floor],
    )
    .storage()?;
    conn.execute_cached(
        "UPDATE account_recovery_coverage SET until_seconds = ?1 - 1 WHERE until_seconds >= ?1",
        [floor],
    )
    .storage()?;
    Ok(())
}

impl SqliteAppStorage {
    /// Record covered slices in one transaction. This is the entry point for
    /// every proof, sweep slices included: each slice merges with the same
    /// route, relay and proof's overlapping or touching ranges.
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

    /// Record slices proved by work frozen at `loss_revision`, only while that
    /// is still the account's loss revision. A loss imported since then may
    /// fall inside the slices, so they are dropped and the debt the import
    /// left stays. Returns whether the slices were recorded.
    pub fn record_recovery_coverage_at_loss_revision(
        &self,
        slices: &[RecoveryCoverageSlice<'_>],
        now_seconds: u64,
        loss_revision: u64,
    ) -> StorageResult<bool> {
        if slices.is_empty() {
            return Ok(true);
        }
        let expected = integer(loss_revision)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let current: i64 = conn
                .query_row_cached(
                    "SELECT loss_revision FROM account_recovery_state WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .storage()?;
            if current != expected {
                return Ok(false);
            }
            for slice in slices {
                record_slice(&conn, slice, now_seconds)?;
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
        let floor = integer(floor_seconds)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for route in routes {
                let (kind, id) = route.storage_key();
                conn.execute_cached(
                    "DELETE FROM account_recovery_coverage
                     WHERE route_kind = ?1 AND route_id = ?2 AND since_seconds >= ?3",
                    params![kind, id, floor],
                )
                .storage()?;
                // Only a range straddling the floor is left above it; its
                // primary key does not change.
                conn.execute_cached(
                    "UPDATE account_recovery_coverage SET until_seconds = ?3 - 1
                     WHERE route_kind = ?1 AND route_id = ?2 AND until_seconds >= ?3",
                    params![kind, id, floor],
                )
                .storage()?;
                widen_goal(&conn, route, floor_seconds)?;
            }
            Ok(())
        })
    }

    /// Drop coverage older than the retention floor and raise goals to it.
    /// Returns how many ranges were deleted.
    pub fn prune_recovery_coverage(&self, floor_seconds: u64) -> StorageResult<usize> {
        let floor = integer(floor_seconds)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
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
        use rusqlite::OptionalExtension;
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

    #[test]
    fn fenced_slices_are_dropped_after_a_newer_loss() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        app.ensure_account_projection("alice").unwrap();
        let route = group(1);
        let frozen = app.recovery_revision_fence().unwrap().loss_revision;
        app.record_account_delivery_loss_bounded("alice", 41, 3, 1_000, Some(500))
            .unwrap();
        app.synchronize_account_delivery_loss("alice").unwrap();
        assert!(app.recovery_revision_fence().unwrap().loss_revision > frozen);
        let slice = RecoveryCoverageSlice {
            route: &route,
            relay: RELAY_A,
            since_seconds: 100,
            until_seconds: 900,
            proof: RecoveryCoverageProof::Comparison,
        };
        assert!(
            !app.record_recovery_coverage_at_loss_revision(&[slice], 1_000, frozen)
                .unwrap()
        );
        assert!(ranges(&app, &route, RELAY_A).is_empty());
        let current = app.recovery_revision_fence().unwrap().loss_revision;
        assert!(
            app.record_recovery_coverage_at_loss_revision(&[slice], 1_000, current)
                .unwrap()
        );
        assert_eq!(ranges(&app, &route, RELAY_A).len(), 1);
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
