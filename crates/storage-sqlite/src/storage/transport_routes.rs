//! Durable transport-route index rows (mdk#1161): opaque transport routing-id
//! bytes -> MLS group id plus the group epoch of the last write that observed
//! the route as current. Seeded into the engine's in-memory routing index at
//! session open so inbound routing does not require loading each group's MLS
//! state; the epoch lets the seed detect a stale route set after a crash and
//! lets the engine retire prior routes once the retained-history window moves
//! past them. The `GroupStorage` impl in `groups.rs` delegates here.

use crate::{SqliteAccountStorage, SqliteResultExt, epoch_to_i64, i64_to_u64};
use cgka_traits::storage::{StorageResult, TransportGroupRoute};
use cgka_traits::types::{EpochId, GroupId};
use rusqlite::params;

pub(super) fn put(
    store: &SqliteAccountStorage,
    transport_group_id: &[u8],
    group_id: &GroupId,
    source_epoch: EpochId,
) -> StorageResult<()> {
    store
        .lock()?
        .execute(
            "INSERT INTO cgka_transport_group_routes (transport_group_id, group_id, source_epoch)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(transport_group_id) DO UPDATE SET
                group_id = excluded.group_id,
                source_epoch = excluded.source_epoch",
            params![
                transport_group_id,
                group_id.as_slice(),
                epoch_to_i64(source_epoch)?
            ],
        )
        .storage()?;
    Ok(())
}

pub(super) fn list(store: &SqliteAccountStorage) -> StorageResult<Vec<TransportGroupRoute>> {
    let conn = store.lock()?;
    let mut statement = conn
        .prepare(
            "SELECT transport_group_id, group_id, source_epoch
             FROM cgka_transport_group_routes",
        )
        .storage()?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                GroupId::new(row.get::<_, Vec<u8>>(1)?),
                row.get::<_, i64>(2)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    rows.into_iter()
        .map(|(transport_group_id, group_id, epoch)| {
            Ok(TransportGroupRoute {
                transport_group_id,
                group_id,
                source_epoch: EpochId(i64_to_u64(epoch)?),
            })
        })
        .collect()
}

pub(super) fn delete_route(
    store: &SqliteAccountStorage,
    transport_group_id: &[u8],
) -> StorageResult<()> {
    store.connection.with_transaction(|| {
        let conn = store.lock()?;
        conn.execute(
            "DELETE FROM transport_reconciliation_items
         WHERE route_kind = 1 AND route_id = ?1",
            params![transport_group_id],
        )
        .storage()?;
        conn.execute(
            "DELETE FROM transport_reconciliation_route_state
         WHERE route_kind = 1 AND route_id = ?1",
            params![transport_group_id],
        )
        .storage()?;
        conn.execute(
            "DELETE FROM transport_reconciliation_scheduler
         WHERE singleton = 1 AND route_kind = 1 AND route_id = ?1",
            params![transport_group_id],
        )
        .storage()?;
        conn.execute(
            "DELETE FROM cgka_transport_group_routes WHERE transport_group_id = ?1",
            params![transport_group_id],
        )
        .storage()?;
        Ok(())
    })
}

pub(super) fn delete_below_epoch(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    cutoff: EpochId,
) -> StorageResult<()> {
    store.connection.with_transaction(|| {
        let conn = store.lock()?;
        conn.execute(
            "DELETE FROM transport_reconciliation_items
         WHERE route_kind = 1 AND route_id IN (
             SELECT transport_group_id
             FROM cgka_transport_group_routes
             WHERE group_id = ?1 AND source_epoch < ?2
         )",
            params![group_id.as_slice(), epoch_to_i64(cutoff)?],
        )
        .storage()?;
        conn.execute(
            "DELETE FROM transport_reconciliation_route_state
         WHERE route_kind = 1 AND route_id IN (
             SELECT transport_group_id
             FROM cgka_transport_group_routes
             WHERE group_id = ?1 AND source_epoch < ?2
         )",
            params![group_id.as_slice(), epoch_to_i64(cutoff)?],
        )
        .storage()?;
        conn.execute(
            "DELETE FROM transport_reconciliation_scheduler
         WHERE singleton = 1 AND route_kind = 1 AND route_id IN (
             SELECT transport_group_id
             FROM cgka_transport_group_routes
             WHERE group_id = ?1 AND source_epoch < ?2
         )",
            params![group_id.as_slice(), epoch_to_i64(cutoff)?],
        )
        .storage()?;
        conn.execute(
            "DELETE FROM cgka_transport_group_routes
             WHERE group_id = ?1 AND source_epoch < ?2",
            params![group_id.as_slice(), epoch_to_i64(cutoff)?],
        )
        .storage()?;
        Ok(())
    })
}

pub(super) fn delete_for_group(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
) -> StorageResult<()> {
    store.connection.with_transaction(|| {
        let conn = store.lock()?;
        conn.execute(
            "DELETE FROM transport_reconciliation_items
         WHERE route_kind = 1 AND route_id IN (
             SELECT transport_group_id
             FROM cgka_transport_group_routes
             WHERE group_id = ?1
         )",
            params![group_id.as_slice()],
        )
        .storage()?;
        conn.execute(
            "DELETE FROM transport_reconciliation_route_state
         WHERE route_kind = 1 AND route_id IN (
             SELECT transport_group_id
             FROM cgka_transport_group_routes
             WHERE group_id = ?1
         )",
            params![group_id.as_slice()],
        )
        .storage()?;
        conn.execute(
            "DELETE FROM transport_reconciliation_scheduler
         WHERE singleton = 1 AND route_kind = 1 AND route_id IN (
             SELECT transport_group_id
             FROM cgka_transport_group_routes
             WHERE group_id = ?1
         )",
            params![group_id.as_slice()],
        )
        .storage()?;
        conn.execute(
            "DELETE FROM cgka_transport_group_routes WHERE group_id = ?1",
            params![group_id.as_slice()],
        )
        .storage()?;
        Ok(())
    })
}
