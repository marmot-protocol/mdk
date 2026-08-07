//! Durable transport-route index rows (mdk#1161): opaque transport routing-id
//! bytes -> MLS group id, seeded into the engine's in-memory routing index at
//! session open so inbound routing does not require loading each group's MLS
//! state. The `GroupStorage` impl in `groups.rs` delegates here.

use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::StorageResult;
use cgka_traits::types::GroupId;
use rusqlite::params;

pub(super) fn put(
    store: &SqliteAccountStorage,
    transport_group_id: &[u8],
    group_id: &GroupId,
) -> StorageResult<()> {
    store
        .lock()?
        .execute(
            "INSERT INTO cgka_transport_group_routes (transport_group_id, group_id)
             VALUES (?1, ?2)
             ON CONFLICT(transport_group_id) DO UPDATE SET group_id = excluded.group_id",
            params![transport_group_id, group_id.as_slice()],
        )
        .storage()?;
    Ok(())
}

pub(super) fn list(store: &SqliteAccountStorage) -> StorageResult<Vec<(Vec<u8>, GroupId)>> {
    let conn = store.lock()?;
    let mut statement = conn
        .prepare("SELECT transport_group_id, group_id FROM cgka_transport_group_routes")
        .storage()?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                GroupId::new(row.get::<_, Vec<u8>>(1)?),
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    Ok(rows)
}

pub(super) fn delete_for_group(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
) -> StorageResult<()> {
    store
        .lock()?
        .execute(
            "DELETE FROM cgka_transport_group_routes WHERE group_id = ?1",
            params![group_id.as_slice()],
        )
        .storage()?;
    Ok(())
}
