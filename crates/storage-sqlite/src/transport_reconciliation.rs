//! Durable, account-private NIP-77 set-reconciliation inventory.

use crate::{SqliteAccountStorage, SqliteResultExt, connection::retry_on_busy};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::params;

const INBOX_ROUTE_KIND: i64 = 0;
const GROUP_ROUTE_KIND: i64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportReconciliationRoute {
    Inbox,
    Group([u8; 32]),
}

impl TransportReconciliationRoute {
    fn storage_key(&self) -> (i64, &[u8]) {
        match self {
            Self::Inbox => (INBOX_ROUTE_KIND, &[]),
            Self::Group(route_id) => (GROUP_ROUTE_KIND, route_id),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportReconciliationItem {
    pub event_id: [u8; 32],
    pub created_at: u64,
}

impl SqliteAccountStorage {
    /// Remember one transport event in the exact set advertised during NIP-77
    /// reconciliation. The row is written only after the app confirms the
    /// delivery was durably retained; resource-refused input must remain absent
    /// so a later reconciliation fetches it again.
    pub fn record_transport_reconciliation_item(
        &self,
        route: &TransportReconciliationRoute,
        item: &TransportReconciliationItem,
    ) -> StorageResult<()> {
        let created_at = i64::try_from(item.created_at).map_err(|_| {
            StorageError::Serialization(
                "transport reconciliation timestamp exceeds SQLite range".to_owned(),
            )
        })?;
        let (route_kind, route_id) = route.storage_key();
        retry_on_busy(|| {
            self.connection
                .lock()?
                .execute(
                    "INSERT OR IGNORE INTO transport_reconciliation_items (
                         route_kind, route_id, event_id, created_at
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![route_kind, route_id, item.event_id.as_slice(), created_at],
                )
                .storage()?;
            Ok(())
        })
    }

    pub fn transport_reconciliation_items(
        &self,
        route: &TransportReconciliationRoute,
    ) -> StorageResult<Vec<TransportReconciliationItem>> {
        let (route_kind, route_id) = route.storage_key();
        let conn = self.connection.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT event_id, created_at
                 FROM transport_reconciliation_items
                 WHERE route_kind = ?1 AND route_id = ?2
                 ORDER BY created_at, event_id",
            )
            .storage()?;
        statement
            .query_map(params![route_kind, route_id], |row| {
                let event_id = row.get::<_, Vec<u8>>(0)?;
                let created_at = row.get::<_, i64>(1)?;
                Ok((event_id, created_at))
            })
            .storage()?
            .map(|row| {
                let (event_id, created_at) = row.storage()?;
                let event_id = event_id.try_into().map_err(|_| {
                    StorageError::Serialization(
                        "invalid transport reconciliation event id".to_owned(),
                    )
                })?;
                let created_at = u64::try_from(created_at).map_err(|_| {
                    StorageError::Serialization(
                        "invalid transport reconciliation timestamp".to_owned(),
                    )
                })?;
                Ok(TransportReconciliationItem {
                    event_id,
                    created_at,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconciliation_items_are_route_scoped_deduplicated_and_ordered() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let inbox = TransportReconciliationRoute::Inbox;
        let group = TransportReconciliationRoute::Group([0x44; 32]);
        let later = TransportReconciliationItem {
            event_id: [0x02; 32],
            created_at: 20,
        };
        let earlier = TransportReconciliationItem {
            event_id: [0x01; 32],
            created_at: 10,
        };

        store
            .record_transport_reconciliation_item(&group, &later)
            .unwrap();
        store
            .record_transport_reconciliation_item(&group, &earlier)
            .unwrap();
        store
            .record_transport_reconciliation_item(&group, &later)
            .unwrap();
        store
            .record_transport_reconciliation_item(&inbox, &later)
            .unwrap();

        assert_eq!(
            store.transport_reconciliation_items(&group).unwrap(),
            vec![earlier, later.clone()]
        );
        assert_eq!(
            store.transport_reconciliation_items(&inbox).unwrap(),
            vec![later]
        );
    }
}
