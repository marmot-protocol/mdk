use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::params;

pub(super) fn list(store: &SqliteAccountStorage, group_id: &GroupId) -> StorageResult<Vec<String>> {
    let conn = store.lock()?;
    let mut stmt = conn
        .prepare_cached(
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

/// Selects only the key columns, which the primary-key index covers, so the
/// scan reads index pages and never a snapshot body.
pub(super) const SNAPSHOT_KEYS: &str = "SELECT group_id, name FROM cgka_group_snapshots";

/// Every group's snapshot names that start with one of `prefixes`, in one scan
/// of [`SNAPSHOT_KEYS`].
pub(super) fn list_with_prefixes(
    store: &SqliteAccountStorage,
    prefixes: &[&str],
) -> StorageResult<Vec<(GroupId, String)>> {
    let conn = store.lock()?;
    let mut stmt = conn.prepare_cached(SNAPSHOT_KEYS).storage()?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })
        .storage()?;
    let mut found = Vec::new();
    for row in rows {
        let (group_id, name) = row.storage()?;
        if prefixes.iter().any(|prefix| name.starts_with(prefix)) {
            found.push((GroupId::new(group_id), name));
        }
    }
    Ok(found)
}

pub(super) fn release(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
) -> StorageResult<()> {
    let changed = store
        .lock()?
        .execute_cached(
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
