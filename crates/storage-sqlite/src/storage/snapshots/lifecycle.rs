use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::params;

pub(super) fn list(store: &SqliteAccountStorage, group_id: &GroupId) -> StorageResult<Vec<String>> {
    let conn = store.lock()?;
    let mut stmt = conn
        .prepare(
            "SELECT name FROM cgka_group_snapshots
                 WHERE group_id = ?1
                 ORDER BY name",
        )
        .storage()?;
    stmt.query_map(params![group_id.as_slice()], |row| row.get(0))
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
}

pub(super) fn release(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
) -> StorageResult<()> {
    let changed = store
        .lock()?
        .execute(
            "DELETE FROM cgka_group_snapshots
                 WHERE group_id = ?1 AND name = ?2",
            params![group_id.as_slice(), name],
        )
        .storage()?;
    if changed == 0 {
        return Err(StorageError::SnapshotMissing(name.to_string()));
    }
    Ok(())
}
