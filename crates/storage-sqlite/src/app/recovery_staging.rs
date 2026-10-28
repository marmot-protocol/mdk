//! Fetched history held for oldest-first admission (mdk#2660 phase 4).
//!
//! A proven slice's events and its coverage are written in one transaction:
//! the events to `account_recovery_staged`, keyed by event id, and the slice
//! to the coverage ledger through the subtracting write. A crash after that
//! loses nothing and refetches nothing: the ledger-derived cursor is past the
//! slice and its events are durable. Staging is not admission. A staged row
//! leaves only once its event is in the seen index, or, when it no longer
//! decodes, by un-covering its second so the history is fetched again. Rows
//! are encoded like spill rows, in the account's encrypted database.
//!
//! Nothing stages yet. Route ids, relay URLs and event ids are account-private
//! and must never be logged.
#[cfg(test)]
mod tests;

use crate::app::recovery_coverage::{
    RecoveryCoverageMark, RecoveryCoverageProof, RecoveryCoverageRange, RecoveryCoverageSlice,
    integer, invalid, record_coverage_since_tx, route_from, uncover_second_tx,
};
use crate::app::recovery_units::charge_event_bytes_tx;
use crate::app::transport::delivery_spill::{EncodedDelivery, already_seen};
use crate::base::codec::i64_to_u64;
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, TransportReconciliationRoute};
use cgka_traits::TransportDelivery;
use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension, params};

/// Artifact-local version of the `metadata` encoding, as for spill rows.
const STAGED_FORMAT: i64 = 1;

/// One proven slice of a fetch on a (route, relay): the events it returned and
/// the ranges it proved. Not `Debug`: it carries the route and the relay.
#[derive(Clone, Copy)]
pub struct RecoveryStagedSlice<'a> {
    pub route: &'a TransportReconciliationRoute,
    pub relay: &'a str,
    pub events: &'a [TransportDelivery],
    /// Every event byte the relay returned, duplicates included, for the
    /// account's rolling-hour budget.
    pub fetched_bytes: u64,
    pub covered: &'a [RecoveryCoverageRange],
    /// A sweep slice, comparison or re-check; never a live boundary.
    pub proof: RecoveryCoverageProof,
    /// The un-cover generation the fetch started at.
    pub mark: RecoveryCoverageMark,
}

/// What staging a slice did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryStaged {
    /// Events newly staged; seen or already staged events are not.
    pub staged: usize,
    /// Whether the coverage was recorded. `false` when the un-cover log no
    /// longer reaches the fetch's start: the events stay staged, and the
    /// range is fetched again.
    pub covered: bool,
}

/// One staged event. Not `Debug`: it carries the route, relay and event.
#[derive(Clone, PartialEq, Eq)]
pub struct StagedRecoveryEvent {
    pub route: TransportReconciliationRoute,
    pub relay: String,
    pub delivery: TransportDelivery,
}

/// One read of staged events, oldest first. Not `Debug`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct StagedRecoveryEvents {
    pub events: Vec<StagedRecoveryEvent>,
    /// Event ids of rows that no longer decode, for
    /// [`SqliteAppStorage::discard_undecodable_staged_recovery_event`].
    pub undecodable: Vec<Vec<u8>>,
}

/// How much is staged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryStagedUsage {
    pub events: u64,
    pub bytes: u64,
}

type StagedRow = (i64, Vec<u8>, Vec<u8>, String, Vec<u8>, Vec<u8>, i64);

impl SqliteAppStorage {
    /// Stage a proven slice: its unseen events and its coverage, written
    /// through the subtracting write, in one transaction.
    pub fn stage_recovery_slice(
        &self,
        slice: &RecoveryStagedSlice<'_>,
        now_seconds: u64,
    ) -> StorageResult<RecoveryStaged> {
        if slice.proof == RecoveryCoverageProof::LiveBoundary || slice.relay.is_empty() {
            return Err(invalid());
        }
        let encoded = slice
            .events
            .iter()
            .map(|delivery| {
                Ok((
                    EncodedDelivery::encode(delivery)?,
                    delivery.message.timestamp.0,
                ))
            })
            .collect::<StorageResult<Vec<_>>>()?;
        let slices = slice
            .covered
            .iter()
            .map(|range| RecoveryCoverageSlice {
                route: slice.route,
                relay: slice.relay,
                since_seconds: range.since_seconds,
                until_seconds: range.until_seconds,
                proof: slice.proof,
            })
            .collect::<Vec<_>>();
        let (kind, id) = slice.route.storage_key();
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let mut staged = 0;
            for (event, created_at) in &encoded {
                if already_seen(&conn, &event.event_id)? {
                    continue;
                }
                staged += conn
                    .execute_cached(
                        "INSERT OR IGNORE INTO account_recovery_staged
                         (event_id, route_kind, route_id, relay, created_at_seconds, payload,
                          metadata, format, bytes, staged_at_seconds)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            event.event_id,
                            kind,
                            id,
                            slice.relay,
                            integer(*created_at)?,
                            event.payload,
                            event.metadata,
                            STAGED_FORMAT,
                            integer(event.bytes)?,
                            integer(now_seconds)?
                        ],
                    )
                    .storage()?;
            }
            charge_event_bytes_tx(&conn, slice.fetched_bytes, now_seconds)?;
            let covered = record_coverage_since_tx(&conn, &slices, now_seconds, slice.mark)?;
            Ok(RecoveryStaged { staged, covered })
        })
    }

    /// Up to `limit` staged events on `routes` sent before `before_seconds`,
    /// oldest first by `(created_at, event id)` across all of them.
    pub fn staged_recovery_events(
        &self,
        routes: &[TransportReconciliationRoute],
        before_seconds: u64,
        limit: usize,
    ) -> StorageResult<StagedRecoveryEvents> {
        let conn = self.lock()?;
        let mut rows: Vec<StagedRow> = Vec::new();
        for route in routes {
            let (kind, id) = route.storage_key();
            rows.extend(
                conn.prepare_cached(
                    "SELECT created_at_seconds, event_id, route_id, relay, payload, metadata,
                     route_kind FROM account_recovery_staged
                     WHERE route_kind = ?1 AND route_id = ?2 AND created_at_seconds < ?3
                     ORDER BY created_at_seconds, event_id LIMIT ?4",
                )
                .storage()?
                .query_map(
                    params![kind, id, integer(before_seconds)?, integer(limit as u64)?],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .storage()?
                .collect::<Result<Vec<StagedRow>, _>>()
                .storage()?,
            );
        }
        rows.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
        rows.truncate(limit);
        let mut read = StagedRecoveryEvents::default();
        for (_, event_id, route_id, relay, payload, metadata, route_kind) in rows {
            match crate::base::codec::deserialize::<TransportDelivery>(&metadata) {
                Ok(mut delivery) => {
                    delivery.message.payload = payload;
                    read.events.push(StagedRecoveryEvent {
                        route: route_from(route_kind, &route_id)?,
                        relay,
                        delivery,
                    });
                }
                Err(_) => read.undecodable.push(event_id),
            }
        }
        Ok(read)
    }

    /// Remove staged rows whose events are now in the seen index. Rows whose
    /// events are not stay. Returns the rows removed.
    pub fn remove_seen_staged_recovery_events(&self, event_ids: &[&[u8]]) -> StorageResult<usize> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let mut removed = 0;
            for event_id in event_ids {
                if already_seen(&conn, event_id)? {
                    removed += conn
                        .execute_cached(
                            "DELETE FROM account_recovery_staged WHERE event_id = ?1",
                            [event_id],
                        )
                        .storage()?;
                }
            }
            Ok(removed)
        })
    }

    /// Drop a staged row that no longer decodes. Its event was never admitted,
    /// so its second is un-covered on its route, as for a released receipt,
    /// and fetched again. Returns whether the row was there.
    pub fn discard_undecodable_staged_recovery_event(
        &self,
        event_id: &[u8],
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let Some((kind, id, created_at)) = conn
                .query_row_cached(
                    "DELETE FROM account_recovery_staged WHERE event_id = ?1
                     RETURNING route_kind, route_id, created_at_seconds",
                    [event_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()
                .storage()?
            else {
                return Ok(false);
            };
            uncover_second_tx(&conn, &route_from(kind, &id)?, i64_to_u64(created_at)?)?;
            Ok(true)
        })
    }

    /// What is staged on `routes` (a group's routes), from `relay` when given.
    pub fn staged_recovery_usage(
        &self,
        routes: &[TransportReconciliationRoute],
        relay: Option<&str>,
    ) -> StorageResult<RecoveryStagedUsage> {
        let conn = self.lock()?;
        let mut usage = RecoveryStagedUsage::default();
        for route in routes {
            let (kind, id) = route.storage_key();
            let (events, bytes): (i64, i64) = conn
                .query_row_cached(
                    "SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM account_recovery_staged
                     WHERE route_kind = ?1 AND route_id = ?2 AND (?3 IS NULL OR relay = ?3)",
                    params![kind, id, relay],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .storage()?;
            usage.events = usage.events.saturating_add(i64_to_u64(events)?);
            usage.bytes = usage.bytes.saturating_add(i64_to_u64(bytes)?);
        }
        Ok(usage)
    }

    /// Everything staged on the account.
    pub fn staged_recovery_total(&self) -> StorageResult<RecoveryStagedUsage> {
        let (events, bytes): (i64, i64) = self
            .lock()?
            .query_row_cached(
                "SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM account_recovery_staged",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .storage()?;
        Ok(RecoveryStagedUsage {
            events: i64_to_u64(events)?,
            bytes: i64_to_u64(bytes)?,
        })
    }
}
