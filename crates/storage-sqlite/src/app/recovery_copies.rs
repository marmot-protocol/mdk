//! The local copy of each group the recovery ledger last settled, and the
//! one notice a rejoin raises (mdk#2660 row 11, migration 0153).
//!
//! A replacement Welcome installs a new copy of a group. The new copy cannot
//! open most of what its routes owed before its floor, so the rejoin retires
//! that debt as before this copy, never as coverage, and raises one notice
//! that messages from before the rejoin are unavailable. The app decides
//! which copy is a rejoin; this module records each settled copy, so a
//! rejoin settles once, and its notice is raised once and stays dismissed.
//! It also records a rejoined copy's floor, each of the group's routes it
//! holds on (with relays or without), and each relay of those routes that
//! retired what lay below it, so a relay that joins a route after the rejoin,
//! or returns to one it had left before, retires it too and owes only from
//! the floor.
//!
//! A retired span still counts for the re-check, loss inside it reopens it,
//! and explicit repair re-arms it (`recovery_units.rs`). Nothing else makes a
//! rejoined route owe below its floor again: every ledger write that widens a
//! goal or un-covers coverage names a [`CopyFloorReason`] and is clamped to
//! the floor ([`copy_floor_tx`]) unless the reason is an exemption; one second
//! the device held is owed alone, the seconds its goal widening opens below
//! the floor retiring; a relay leaving keeps what was retired below it; and
//! the retention prune parks nothing below it. A second still owed below the
//! floor when retention passes it (a held event given back, or loss) drops
//! without a remainder: the runner swept it for the whole retention window,
//! and the rejoin's notice already covers that history.
//! Group ids are account-private and must never be logged.
#[cfg(test)]
mod floor_tests;
#[cfg(test)]
mod tests;

use crate::app::recovery_coverage::{RecoveryCoverageRange, integer, invalid, subtract, union};
use crate::app::recovery_units::{next_park_revision_tx, retire_before_copy_unit_tx};
use crate::base::codec::i64_to_u64;
use crate::base::connection::CachedSql;
use crate::{
    RecoverySpanRetirement, SqliteAppStorage, SqliteResultExt, TransportReconciliationRoute,
};
use cgka_traits::storage::StorageResult;
use rusqlite::{Connection, OptionalExtension, params};

/// The copy of a group the ledger last settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryCopy {
    /// The group existed before copies were recorded and migration 0153 could
    /// not decode its record: its current copy is settled when it is first
    /// read, with no rejoin.
    Unknown,
    /// The install epoch of the copy last settled.
    Settled(u64),
}

/// A group's rejoin, settled once.
#[derive(Clone, Copy)]
pub struct RecoveryRejoin<'a> {
    pub group_id: &'a [u8],
    /// The new copy's install epoch.
    pub install_epoch: u64,
    /// Each of the group's routes with the relays it carries.
    pub routes: &'a [(TransportReconciliationRoute, Vec<String>)],
    /// The new copy's floor: what the routes owed or parked below it retires.
    pub floor_seconds: u64,
    pub now_seconds: u64,
}

/// The notice a rejoin raised: messages from before the rejoin are
/// unavailable. Its revision comes from the park revision counter, so a
/// later rejoin's notice is a new one.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryRejoinNotice {
    pub group_id: Vec<u8>,
    pub revision: u64,
    pub noticed_at_seconds: u64,
}

fn copy_tx(conn: &Connection, group_id: &[u8]) -> StorageResult<Option<RecoveryCopy>> {
    let epoch = conn
        .query_row_cached(
            "SELECT install_epoch FROM account_recovery_copies WHERE group_id = ?1",
            [group_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()
        .storage()?;
    epoch
        .map(|epoch| {
            Ok(match epoch {
                Some(epoch) => RecoveryCopy::Settled(i64_to_u64(epoch)?),
                None => RecoveryCopy::Unknown,
            })
        })
        .transpose()
}

/// Why a ledger write may make a route owe history below a rejoined copy's
/// floor (mdk#2660 row 11). Every write that widens a goal or un-covers a
/// range names one, and only an exemption reaches below the floor. The third
/// exemption, evidence, is not a reason a caller can give: it is one second
/// for an event this device held or a relay showed it, and only the ledger's
/// one-second un-cover takes it (`uncover_second_tx`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyFloorReason {
    /// The write reaches no lower than the floor, so what lay before the copy
    /// stays retired: goals, post-join, epoch-gap visits, replay windows.
    Clamp,
    /// Deliveries were lost: loss import and the upgrade conversion of the
    /// old owner's loss. Loss reopens what a rejoin retired (Jeff, 2026-11-08).
    Loss,
    /// Explicit repair owes the whole window again, below the floor too.
    Repair,
}

/// The lowest second a write for `reason` may reach on `route`: for
/// [`CopyFloorReason::Clamp`], the floor of the rejoin that recorded `route`,
/// with or without relays; otherwise, and on a route no rejoin floors, zero,
/// so the write is unchanged. One lookup on `account_recovery_copy_routes`'
/// route index (no rows unless a rejoin settled) and one on the copies'
/// primary key, in the writer's transaction; an exemption reads nothing.
pub(crate) fn copy_floor_tx(
    conn: &Connection,
    route: &TransportReconciliationRoute,
    reason: CopyFloorReason,
) -> StorageResult<u64> {
    if reason != CopyFloorReason::Clamp {
        return Ok(0);
    }
    let (kind, id) = route.storage_key();
    conn.query_row_cached(
        "SELECT MAX(copies.floor_seconds) FROM account_recovery_copy_routes AS routes
         JOIN account_recovery_copies AS copies ON copies.group_id = routes.group_id
         WHERE routes.route_kind = ?1 AND routes.route_id = ?2",
        params![kind, id],
        |row| row.get::<_, Option<i64>>(0),
    )
    .storage()?
    .map_or(Ok(0), i64_to_u64)
}

/// The floor `group_id`'s current copy recorded at its rejoin; `None` for a
/// copy that replaced none.
fn floor_tx(conn: &Connection, group_id: &[u8]) -> StorageResult<Option<u64>> {
    conn.query_row_cached(
        "SELECT floor_seconds FROM account_recovery_copies WHERE group_id = ?1",
        [group_id],
        |row| row.get::<_, Option<i64>>(0),
    )
    .optional()
    .storage()?
    .flatten()
    .map(i64_to_u64)
    .transpose()
}

/// Record `routes` as holding `group_id`'s floor, a route with no relay too,
/// and on each relay they carry that has not yet retired what lay before the
/// group's current copy, retire it below `floor_seconds`
/// ([`retire_before_copy_unit_tx`]) and record the relay. Returns how many
/// relays retired.
fn retire_before_copy_units_tx(
    conn: &Connection,
    group_id: &[u8],
    routes: &[(TransportReconciliationRoute, Vec<String>)],
    floor_seconds: u64,
) -> StorageResult<usize> {
    let mut retired = 0;
    for (route, relays) in routes {
        let (kind, id) = route.storage_key();
        conn.execute_cached(
            "INSERT OR IGNORE INTO account_recovery_copy_routes (group_id, route_kind, route_id)
             VALUES (?1, ?2, ?3)",
            params![group_id, kind, id],
        )
        .storage()?;
        for relay in relays {
            let recorded = conn
                .execute_cached(
                    "INSERT OR IGNORE INTO account_recovery_copy_units
                     (group_id, route_kind, route_id, relay) VALUES (?1, ?2, ?3, ?4)",
                    params![group_id, kind, id, relay],
                )
                .storage()?;
            if recorded > 0 {
                retire_before_copy_unit_tx(conn, route, relay, floor_seconds)?;
                retired += 1;
            }
        }
    }
    Ok(retired)
}

/// Forget the routes and relays an earlier rejoin of `group_id` recorded.
fn delete_copy_routes_tx(conn: &Connection, group_id: &[u8]) -> StorageResult<()> {
    for table in [
        "account_recovery_copy_routes",
        "account_recovery_copy_units",
    ] {
        conn.execute_cached(
            &format!("DELETE FROM {table} WHERE group_id = ?1"),
            [group_id],
        )
        .storage()?;
    }
    Ok(())
}

fn validate_routes(
    group_id: &[u8],
    routes: &[(TransportReconciliationRoute, Vec<String>)],
) -> StorageResult<()> {
    if group_id.is_empty()
        || routes
            .iter()
            .any(|(route, _)| *route == TransportReconciliationRoute::Inbox)
    {
        return Err(invalid());
    }
    Ok(())
}

impl SqliteAppStorage {
    /// The copy of `group_id` the ledger last settled; `None` for a group it
    /// has not recorded.
    pub fn recovery_copy(&self, group_id: &[u8]) -> StorageResult<Option<RecoveryCopy>> {
        copy_tx(&*self.lock()?, group_id)
    }

    /// Settle `install_epoch` as the group's copy with no rejoin: a group's
    /// first copy, the copy an upgrade found, or a new copy that replaced
    /// none. An earlier rejoin's floor and notice go with the copy they were
    /// about.
    pub fn record_recovery_copy(&self, group_id: &[u8], install_epoch: u64) -> StorageResult<()> {
        if group_id.is_empty() {
            return Err(invalid());
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "INSERT INTO account_recovery_copies (group_id, install_epoch) VALUES (?1, ?2)
                 ON CONFLICT(group_id) DO UPDATE SET install_epoch = excluded.install_epoch,
                    floor_seconds = NULL, notice_revision = NULL, noticed_at_seconds = NULL",
                params![group_id, integer(install_epoch)?],
            )
            .storage()?;
            delete_copy_routes_tx(&conn, group_id)
        })
    }

    /// Settle a rejoin in one transaction: on every relay each of the group's
    /// routes carries, what is owed or parked below the floor retires as
    /// before this copy and the unit starts over with a fresh budget
    /// ([`retire_before_copy_unit_tx`]); each route's parked remainder below
    /// the floor goes; the copy's floor and each of those relays are
    /// recorded, replacing an earlier copy's; and the group's notice is
    /// raised for the new copy, replacing an earlier one. Returns false,
    /// changing nothing, when this copy is already settled.
    pub fn settle_recovery_rejoin(&self, rejoin: &RecoveryRejoin<'_>) -> StorageResult<bool> {
        validate_routes(rejoin.group_id, rejoin.routes)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if copy_tx(&conn, rejoin.group_id)? == Some(RecoveryCopy::Settled(rejoin.install_epoch))
            {
                return Ok(false);
            }
            let floor = integer(rejoin.floor_seconds)?;
            delete_copy_routes_tx(&conn, rejoin.group_id)?;
            retire_before_copy_units_tx(
                &conn,
                rejoin.group_id,
                rejoin.routes,
                rejoin.floor_seconds,
            )?;
            for (route, _) in rejoin.routes {
                // A remainder is debt the retention floor overtook, so it
                // lies below the copy's floor.
                let (kind, id) = route.storage_key();
                conn.execute_cached(
                    "DELETE FROM account_recovery_coverage_remainders
                     WHERE route_kind = ?1 AND route_id = ?2 AND until_seconds < ?3",
                    params![kind, id, floor],
                )
                .storage()?;
                conn.execute_cached(
                    "UPDATE account_recovery_coverage_remainders SET since_seconds = ?3
                     WHERE route_kind = ?1 AND route_id = ?2 AND since_seconds < ?3",
                    params![kind, id, floor],
                )
                .storage()?;
            }
            let revision = next_park_revision_tx(&conn)?;
            conn.execute_cached(
                "INSERT INTO account_recovery_copies
                 (group_id, install_epoch, floor_seconds, notice_revision, noticed_at_seconds)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(group_id) DO UPDATE SET install_epoch = excluded.install_epoch,
                    floor_seconds = excluded.floor_seconds,
                    notice_revision = excluded.notice_revision,
                    noticed_at_seconds = excluded.noticed_at_seconds",
                params![
                    rejoin.group_id,
                    integer(rejoin.install_epoch)?,
                    floor,
                    revision,
                    integer(rejoin.now_seconds)?
                ],
            )
            .storage()?;
            Ok(true)
        })
    }

    /// The floor `group_id`'s current copy recorded at its rejoin: what lay
    /// below it retired as before this copy. `None` for a copy that replaced
    /// none.
    pub fn recovery_copy_floor(&self, group_id: &[u8]) -> StorageResult<Option<u64>> {
        floor_tx(&*self.lock()?, group_id)
    }

    /// Retire what lay before the group's current copy on each relay its
    /// `routes` carry that has not retired it yet: a relay that joined a route
    /// after the rejoin, or one that had left before the rejoin and returned.
    /// Each retires below the floor the rejoin recorded, as
    /// [`Self::settle_recovery_rejoin`] does, and is recorded, so loss or
    /// repair that later reopens its retirement is never undone. A copy that
    /// replaced none has no floor and retires nothing. Returns how many relays
    /// retired.
    pub fn retire_before_recovery_copy(
        &self,
        group_id: &[u8],
        routes: &[(TransportReconciliationRoute, Vec<String>)],
    ) -> StorageResult<usize> {
        validate_routes(group_id, routes)?;
        // Most copies replaced none: read before taking the write lock.
        if floor_tx(&*self.lock()?, group_id)?.is_none() {
            return Ok(0);
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            match floor_tx(&conn, group_id)? {
                Some(floor) => retire_before_copy_units_tx(&conn, group_id, routes, floor),
                None => Ok(0),
            }
        })
    }

    /// What `route` owes on `relay` up to `until_seconds` that its group's
    /// current copy can owe: [`Self::recovery_coverage_debt`] less what a
    /// rejoin retired there as before this copy. Parked, dismissed and
    /// route-gone seconds stay owed.
    pub fn recovery_copy_debt(
        &self,
        route: &TransportReconciliationRoute,
        relay: &str,
        until_seconds: u64,
    ) -> StorageResult<Vec<RecoveryCoverageRange>> {
        let before_copy = union(
            self.recovery_unit_spans(route, relay)?
                .into_iter()
                .filter(|span| span.retired == Some(RecoverySpanRetirement::BeforeThisCopy))
                .map(|span| span.range)
                .collect(),
        );
        Ok(self
            .recovery_coverage_debt(route, &[relay.to_owned()], until_seconds)?
            .into_iter()
            .flat_map(|owed| subtract(owed, &before_copy))
            .collect())
    }

    /// Every rejoin notice not yet dismissed, oldest first.
    pub fn recovery_rejoin_notices(&self) -> StorageResult<Vec<RecoveryRejoinNotice>> {
        self.lock()?
            .prepare_cached(
                "SELECT group_id, notice_revision, noticed_at_seconds FROM account_recovery_copies
                 WHERE notice_revision IS NOT NULL ORDER BY noticed_at_seconds, group_id",
            )
            .storage()?
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
            .into_iter()
            .map(|(group_id, revision, noticed_at)| {
                Ok(RecoveryRejoinNotice {
                    group_id,
                    revision: i64_to_u64(revision)?,
                    noticed_at_seconds: i64_to_u64(noticed_at)?,
                })
            })
            .collect()
    }

    /// Dismiss the group's rejoin notice at `revision`. It retires nothing
    /// further: the rejoin already retired what lay before the copy. Returns
    /// false, changing nothing, when the notice is stale: dismissed already,
    /// or replaced by a later rejoin's.
    pub fn dismiss_recovery_rejoin_notice(
        &self,
        group_id: &[u8],
        revision: u64,
    ) -> StorageResult<bool> {
        let dismissed = self
            .lock()?
            .execute_cached(
                "UPDATE account_recovery_copies SET notice_revision = NULL,
                 noticed_at_seconds = NULL WHERE group_id = ?1 AND notice_revision = ?2",
                params![group_id, integer(revision)?],
            )
            .storage()?;
        Ok(dismissed > 0)
    }
}
