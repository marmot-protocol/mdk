use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::storage::{LeaveRequest, LeaveRequestStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

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
        };
        store.put_leave_request(&request).unwrap();
        assert_eq!(store.leave_request(&group.id).unwrap(), Some(request));

        store.delete_group(&group.id).unwrap();
        assert_eq!(store.leave_request(&group.id).unwrap(), None);
    }
}
