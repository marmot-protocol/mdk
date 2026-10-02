//! Per-group holds on epoch advancement while comparison still knows of
//! history the account has not downloaded (mdk#2086). The engine only reads
//! whether a hold exists; the app owns installing and releasing it.
use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{HistoryAcquisitionHoldStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

impl HistoryAcquisitionHoldStorage for SqliteAccountStorage {
    fn history_acquisition_held(&self, group_id: &GroupId) -> StorageResult<bool> {
        Ok(self
            .lock()?
            .query_row_cached(
                "SELECT 1 FROM cgka_history_acquisition_holds WHERE group_id = ?1 LIMIT 1",
                params![group_id.as_slice()],
                |_| Ok(()),
            )
            .optional()
            .storage()?
            .is_some())
    }
}

impl SqliteAccountStorage {
    /// Hold `group_id`'s epoch while its route `transport_group_id` still has
    /// known history to download. A group stays held while any route holds it.
    pub fn hold_history_acquisition(
        &self,
        group_id: &GroupId,
        transport_group_id: &[u8; 32],
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT OR IGNORE INTO cgka_history_acquisition_holds
                 (group_id, transport_group_id) VALUES (?1, ?2)",
                params![group_id.as_slice(), transport_group_id.as_slice()],
            )
            .storage()?;
        Ok(())
    }

    /// Whether `transport_group_id` holds `group_id`.
    pub fn history_acquisition_route_held(
        &self,
        group_id: &GroupId,
        transport_group_id: &[u8; 32],
    ) -> StorageResult<bool> {
        Ok(self
            .lock()?
            .query_row_cached(
                "SELECT 1 FROM cgka_history_acquisition_holds
                 WHERE group_id = ?1 AND transport_group_id = ?2",
                params![group_id.as_slice(), transport_group_id.as_slice()],
                |_| Ok(()),
            )
            .optional()
            .storage()?
            .is_some())
    }

    /// Release the hold `transport_group_id` placed on `group_id`. Returns
    /// whether this released the group's last hold.
    pub fn release_history_acquisition_hold(
        &self,
        group_id: &GroupId,
        transport_group_id: &[u8; 32],
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let released = conn
                .execute_cached(
                    "DELETE FROM cgka_history_acquisition_holds
                     WHERE group_id = ?1 AND transport_group_id = ?2",
                    params![group_id.as_slice(), transport_group_id.as_slice()],
                )
                .storage()?
                > 0;
            Ok(released && !group_held(&conn, group_id.as_slice())?)
        })
    }

    /// Release every hold whose route no automatic recovery still owes: no
    /// open obligation that can still run a pass has a scope on it. A parked
    /// obligation is already a "history may be incomplete" notice; a satisfied
    /// or retired one has nothing left to fetch. Returns the groups this left
    /// with no hold.
    pub fn release_unowed_history_acquisition_holds(&self) -> StorageResult<Vec<GroupId>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let unowed = conn
                .prepare_cached(
                    "SELECT hold.group_id, hold.transport_group_id
                     FROM cgka_history_acquisition_holds hold
                     WHERE NOT EXISTS (
                         SELECT 1 FROM account_recovery_scopes scope
                         JOIN account_recovery_obligations obligation
                             ON obligation.id = scope.obligation_id
                         WHERE scope.transport_group_id = hold.transport_group_id
                             AND obligation.state = 0
                             AND obligation.eligibility IN (0, 1, 2)
                     )
                     ORDER BY hold.group_id, hold.transport_group_id",
                )
                .storage()?
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?;
            let mut released = Vec::new();
            for (group_id, transport_group_id) in unowed {
                conn.execute_cached(
                    "DELETE FROM cgka_history_acquisition_holds
                     WHERE group_id = ?1 AND transport_group_id = ?2",
                    params![group_id, transport_group_id],
                )
                .storage()?;
                if released.last() != Some(&group_id) && !group_held(&conn, &group_id)? {
                    released.push(group_id);
                }
            }
            Ok(released.into_iter().map(GroupId::new).collect())
        })
    }
}

fn group_held(conn: &rusqlite::Connection, group_id: &[u8]) -> StorageResult<bool> {
    Ok(conn
        .query_row_cached(
            "SELECT 1 FROM cgka_history_acquisition_holds WHERE group_id = ?1 LIMIT 1",
            params![group_id],
            |_| Ok(()),
        )
        .optional()
        .storage()?
        .is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;

    #[test]
    fn history_acquisition_hold_round_trips_and_cascades() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 4, 0);
        store.put_group(&group).unwrap();
        assert!(!store.history_acquisition_held(&group.id).unwrap());

        // A group stays held while any of its routes still holds it.
        store.hold_history_acquisition(&group.id, &[7; 32]).unwrap();
        store.hold_history_acquisition(&group.id, &[7; 32]).unwrap();
        store.hold_history_acquisition(&group.id, &[8; 32]).unwrap();
        assert!(store.history_acquisition_held(&group.id).unwrap());
        assert!(
            store
                .history_acquisition_route_held(&group.id, &[7; 32])
                .unwrap()
        );
        assert!(
            !store
                .history_acquisition_route_held(&group.id, &[6; 32])
                .unwrap()
        );
        assert!(
            !store
                .release_history_acquisition_hold(&group.id, &[7; 32])
                .unwrap()
        );
        assert!(store.history_acquisition_held(&group.id).unwrap());
        assert!(
            store
                .release_history_acquisition_hold(&group.id, &[8; 32])
                .unwrap()
        );
        assert!(
            !store
                .release_history_acquisition_hold(&group.id, &[8; 32])
                .unwrap()
        );
        assert!(!store.history_acquisition_held(&group.id).unwrap());

        store.hold_history_acquisition(&group.id, &[8; 32]).unwrap();
        store.delete_group(&group.id).unwrap();
        assert!(!store.history_acquisition_held(&group.id).unwrap());
    }

    #[test]
    fn holds_on_routes_no_open_obligation_owes_are_released() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let owed = sample_group(gid(1), 4, 0);
        let parked = sample_group(gid(2), 4, 0);
        let unowed = sample_group(gid(3), 4, 0);
        for group in [&owed, &parked, &unowed] {
            store.put_group(group).unwrap();
        }
        let conn = store.lock().unwrap();
        for (id, eligibility, route) in [(1_u8, 1_i64, [1_u8; 32]), (2, 4, [2; 32])] {
            conn.execute(
                "INSERT INTO account_recovery_obligations
                 (id, demand_key, cause, predicate, created_at_ms, updated_at_ms, eligibility)
                 VALUES (?1, ?2, 5, 0, 0, 0, ?3)",
                params![vec![id; 16], format!("test:{id}"), eligibility],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO account_recovery_scopes
                 (obligation_id, scope_id, route_kind, transport_group_id)
                 VALUES (?1, 0, 1, ?2)",
                params![vec![id; 16], route.as_slice()],
            )
            .unwrap();
        }
        drop(conn);
        store.hold_history_acquisition(&owed.id, &[1; 32]).unwrap();
        store
            .hold_history_acquisition(&parked.id, &[2; 32])
            .unwrap();
        store
            .hold_history_acquisition(&unowed.id, &[3; 32])
            .unwrap();
        // A second route that is still owed keeps this group held.
        store
            .hold_history_acquisition(&unowed.id, &[1; 32])
            .unwrap();

        let released = store.release_unowed_history_acquisition_holds().unwrap();
        assert_eq!(released, vec![parked.id.clone()]);
        assert!(store.history_acquisition_held(&owed.id).unwrap());
        assert!(!store.history_acquisition_held(&parked.id).unwrap());
        assert!(store.history_acquisition_held(&unowed.id).unwrap());
        assert!(
            store
                .release_history_acquisition_hold(&unowed.id, &[1; 32])
                .unwrap()
        );
    }
}
