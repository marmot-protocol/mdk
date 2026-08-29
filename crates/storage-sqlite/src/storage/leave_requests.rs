use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::storage::{LeaveRequest, LeaveRequestStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;

/// Every durable leave request keyed by lowercase hex group id, mapped to its
/// `requested_at_ms`.
///
/// The engine owns this table and clears rows from several paths that never
/// notify the app projection (an accepted commit that removed us, hydration
/// finding the local member already gone, a convergence reorg). Projections that
/// want to show a pending leave therefore read through to it at read time rather
/// than denormalizing a column that could silently go stale.
///
/// The table is bounded by leaves that are still in flight — normally zero or
/// one row — so sweeping it whole is cheaper than a per-row lookup, and it lets
/// callers join in Rust instead of expression-joining `hex(group_id)` against
/// `group_id_hex` (which could not use the primary-key index anyway).
pub(crate) fn pending_leave_requests_by_group_hex_tx(
    tx: &Connection,
) -> StorageResult<HashMap<String, u64>> {
    let mut statement = tx
        .prepare("SELECT group_id, record FROM cgka_leave_requests")
        .storage()?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .storage()?
        .collect::<rusqlite::Result<Vec<_>>>()
        .storage()?;
    rows.into_iter()
        .map(|(group_id, record)| {
            let request: LeaveRequest = deserialize(&record)?;
            Ok((hex::encode(group_id), request.requested_at_ms))
        })
        .collect()
}

impl SqliteAccountStorage {
    /// Every outstanding durable leave request, keyed by lowercase hex group id.
    ///
    /// The app layer uses this to project a pending leave onto group records
    /// without denormalizing a column; see
    /// [`pending_leave_requests_by_group_hex_tx`].
    pub fn pending_leave_requests(&self) -> StorageResult<HashMap<String, u64>> {
        let conn = self.lock()?;
        pending_leave_requests_by_group_hex_tx(&conn)
    }
}

impl LeaveRequestStorage for SqliteAccountStorage {
    fn put_leave_request(&self, request: &LeaveRequest) -> StorageResult<()> {
        let serialized = serialize(request)?;
        self.lock()?
            .execute(
                "INSERT OR REPLACE INTO cgka_leave_requests (group_id, record)
                 VALUES (?1, ?2)",
                params![request.group_id.as_slice(), serialized],
            )
            .storage()?;
        Ok(())
    }

    fn leave_request(&self, group_id: &GroupId) -> StorageResult<Option<LeaveRequest>> {
        self.lock()?
            .query_row(
                "SELECT record FROM cgka_leave_requests WHERE group_id = ?1",
                params![group_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .storage()?
            .map(|bytes| deserialize(&bytes))
            .transpose()
    }

    fn clear_leave_request(&self, group_id: &GroupId) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM cgka_leave_requests WHERE group_id = ?1",
                params![group_id.as_slice()],
            )
            .storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::storage::test_support::{gid, sample_group};
    use cgka_traits::storage::{GroupStorage, LeaveRequest, LeaveRequestStorage};
    use cgka_traits::types::EpochId;

    #[test]
    fn leave_request_roundtrips_and_cascades_with_group() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 3, 0);
        store.put_group(&group).unwrap();

        let request = LeaveRequest {
            group_id: group.id.clone(),
            requested_at_ms: 42,
            last_proposed_epoch: Some(EpochId(3)),
            last_proposed_message_id: None,
        };
        store.put_leave_request(&request).unwrap();
        assert_eq!(store.leave_request(&group.id).unwrap(), Some(request));

        store.delete_group(&group.id).unwrap();
        assert_eq!(store.leave_request(&group.id).unwrap(), None);
    }
}
