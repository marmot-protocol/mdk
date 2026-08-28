//! Durable, account-private NIP-77 set-reconciliation inventory.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{SqliteAccountStorage, SqliteResultExt, connection::retry_on_busy};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

const INBOX_ROUTE_KIND: i64 = 0;
const GROUP_ROUTE_KIND: i64 = 1;
/// A route advertises at most this many exact event ids to NIP-77. When the
/// bound is crossed, an entire authored-time bucket is retired and the durable
/// lower bound advances past it, so compacted ids cannot reappear as missing.
pub const TRANSPORT_RECONCILIATION_MAX_ITEMS_PER_ROUTE: usize = 16_384;
/// The correctness backstop is deliberately finite. Relays and clients may
/// retain more history, but automatic late-publication repair is guaranteed
/// only inside this rolling route-local window.
pub const TRANSPORT_RECONCILIATION_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportReconciliationInventory {
    pub since: u64,
    pub items: Vec<TransportReconciliationItem>,
}

fn unix_now_secs() -> StorageResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| StorageError::Backend(format!("system clock before Unix epoch: {error}")))
}

fn route_state_floor_tx(
    tx: &Transaction<'_>,
    route_kind: i64,
    route_id: &[u8],
    configured_floor: i64,
) -> StorageResult<i64> {
    tx.execute(
        "INSERT INTO transport_reconciliation_route_state (
             route_kind, route_id, inventory_since
         ) VALUES (?1, ?2, ?3)
         ON CONFLICT(route_kind, route_id) DO UPDATE SET
             inventory_since = MAX(inventory_since, excluded.inventory_since)",
        params![route_kind, route_id, configured_floor],
    )
    .storage()?;
    tx.execute(
        "DELETE FROM transport_reconciliation_items
         WHERE route_kind = ?1 AND route_id = ?2 AND created_at < ?3",
        params![route_kind, route_id, configured_floor],
    )
    .storage()?;
    tx.query_row(
        "SELECT inventory_since
         FROM transport_reconciliation_route_state
         WHERE route_kind = ?1 AND route_id = ?2",
        params![route_kind, route_id],
        |row| row.get(0),
    )
    .storage()
}

fn compact_route_tx(tx: &Transaction<'_>, route_kind: i64, route_id: &[u8]) -> StorageResult<()> {
    let overflow_cutoff = tx
        .query_row(
            "SELECT created_at
             FROM transport_reconciliation_items
             WHERE route_kind = ?1 AND route_id = ?2
             ORDER BY created_at DESC, event_id DESC
             LIMIT 1 OFFSET ?3",
            params![
                route_kind,
                route_id,
                i64::try_from(TRANSPORT_RECONCILIATION_MAX_ITEMS_PER_ROUTE).map_err(|_| {
                    StorageError::Serialization(
                        "transport reconciliation item bound exceeds SQLite range".to_owned(),
                    )
                })?
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .storage()?;
    let Some(overflow_cutoff) = overflow_cutoff else {
        return Ok(());
    };
    let compacted_floor = overflow_cutoff.saturating_add(1);
    tx.execute(
        "DELETE FROM transport_reconciliation_items
         WHERE route_kind = ?1 AND route_id = ?2 AND created_at < ?3",
        params![route_kind, route_id, compacted_floor],
    )
    .storage()?;
    tx.execute(
        "UPDATE transport_reconciliation_route_state
         SET inventory_since = MAX(inventory_since, ?3)
         WHERE route_kind = ?1 AND route_id = ?2",
        params![route_kind, route_id, compacted_floor],
    )
    .storage()?;
    Ok(())
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
        let configured_floor =
            unix_now_secs()?.saturating_sub(TRANSPORT_RECONCILIATION_RETENTION_SECS);
        let configured_floor = i64::try_from(configured_floor).map_err(|_| {
            StorageError::Serialization(
                "transport reconciliation retention floor exceeds SQLite range".to_owned(),
            )
        })?;
        let (route_kind, route_id) = route.storage_key();
        retry_on_busy(|| {
            let mut conn = self.connection.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            let inventory_since =
                route_state_floor_tx(&tx, route_kind, route_id, configured_floor)?;
            if created_at >= inventory_since {
                tx.execute(
                    "INSERT OR IGNORE INTO transport_reconciliation_items (
                         route_kind, route_id, event_id, created_at
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![route_kind, route_id, item.event_id.as_slice(), created_at],
                )
                .storage()?;
                compact_route_tx(&tx, route_kind, route_id)?;
            }
            tx.commit().storage()?;
            Ok(())
        })
    }

    pub fn transport_reconciliation_inventory(
        &self,
        route: &TransportReconciliationRoute,
        reconcile_until: u64,
    ) -> StorageResult<TransportReconciliationInventory> {
        let configured_floor =
            reconcile_until.saturating_sub(TRANSPORT_RECONCILIATION_RETENTION_SECS);
        let configured_floor = i64::try_from(configured_floor).map_err(|_| {
            StorageError::Serialization(
                "transport reconciliation retention floor exceeds SQLite range".to_owned(),
            )
        })?;
        let (route_kind, route_id) = route.storage_key();
        retry_on_busy(|| {
            let mut conn = self.connection.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            let inventory_since =
                route_state_floor_tx(&tx, route_kind, route_id, configured_floor)?;
            compact_route_tx(&tx, route_kind, route_id)?;
            let inventory_since = tx
                .query_row(
                    "SELECT inventory_since
                     FROM transport_reconciliation_route_state
                     WHERE route_kind = ?1 AND route_id = ?2",
                    params![route_kind, route_id],
                    |row| row.get::<_, i64>(0),
                )
                .storage()?
                .max(inventory_since);
            let mut statement = tx
                .prepare(
                    "SELECT event_id, created_at
                     FROM transport_reconciliation_items
                     WHERE route_kind = ?1 AND route_id = ?2 AND created_at >= ?3
                     ORDER BY created_at, event_id",
                )
                .storage()?;
            let items = statement
                .query_map(params![route_kind, route_id, inventory_since], |row| {
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
                .collect::<StorageResult<Vec<_>>>()?;
            drop(statement);
            tx.commit().storage()?;
            Ok(TransportReconciliationInventory {
                since: u64::try_from(inventory_since).map_err(|_| {
                    StorageError::Serialization(
                        "invalid transport reconciliation inventory floor".to_owned(),
                    )
                })?,
                items,
            })
        })
    }

    pub fn transport_reconciliation_route_cursor(
        &self,
    ) -> StorageResult<Option<TransportReconciliationRoute>> {
        let conn = self.connection.lock()?;
        let row = conn
            .query_row(
                "SELECT route_kind, route_id
                 FROM transport_reconciliation_scheduler
                 WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .storage()?;
        row.map(|(route_kind, route_id)| match route_kind {
            INBOX_ROUTE_KIND if route_id.is_empty() => Ok(TransportReconciliationRoute::Inbox),
            GROUP_ROUTE_KIND => route_id
                .try_into()
                .map(TransportReconciliationRoute::Group)
                .map_err(|_| {
                    StorageError::Serialization(
                        "invalid transport reconciliation route cursor".to_owned(),
                    )
                }),
            _ => Err(StorageError::Serialization(
                "invalid transport reconciliation route cursor".to_owned(),
            )),
        })
        .transpose()
    }

    pub fn advance_transport_reconciliation_route_cursor(
        &self,
        route: &TransportReconciliationRoute,
    ) -> StorageResult<()> {
        let (route_kind, route_id) = route.storage_key();
        retry_on_busy(|| {
            self.connection
                .lock()?
                .execute(
                    "INSERT INTO transport_reconciliation_scheduler (
                         singleton, route_kind, route_id
                     ) VALUES (1, ?1, ?2)
                     ON CONFLICT(singleton) DO UPDATE SET
                         route_kind = excluded.route_kind,
                         route_id = excluded.route_id",
                    params![route_kind, route_id],
                )
                .storage()?;
            Ok(())
        })
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
        let now = unix_now_secs().unwrap();
        let later = TransportReconciliationItem {
            event_id: [0x02; 32],
            created_at: now,
        };
        let earlier = TransportReconciliationItem {
            event_id: [0x01; 32],
            created_at: now - 1,
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
            store
                .transport_reconciliation_inventory(&group, now)
                .unwrap()
                .items,
            vec![earlier.clone(), later.clone()]
        );
        assert_eq!(
            store
                .transport_reconciliation_inventory(&inbox, now)
                .unwrap()
                .items,
            vec![later.clone()]
        );

        let stale = TransportReconciliationItem {
            event_id: [0x03; 32],
            created_at: now - TRANSPORT_RECONCILIATION_RETENTION_SECS - 1,
        };
        store
            .record_transport_reconciliation_item(&group, &stale)
            .unwrap();
        assert_eq!(
            store
                .transport_reconciliation_inventory(&group, now)
                .unwrap()
                .items,
            vec![earlier, later]
        );
    }

    #[test]
    fn reconciliation_inventory_compaction_is_bounded_and_advances_its_floor() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let route = TransportReconciliationRoute::Group([0x55; 32]);
        let now = unix_now_secs().unwrap();
        let start = now - TRANSPORT_RECONCILIATION_RETENTION_SECS + 1;
        let (route_kind, route_id) = route.storage_key();
        {
            let mut conn = store.connection.lock().unwrap();
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO transport_reconciliation_route_state (
                     route_kind, route_id, inventory_since
                 ) VALUES (?1, ?2, ?3)",
                params![route_kind, route_id, i64::try_from(start).unwrap()],
            )
            .unwrap();
            for offset in 0..=(TRANSPORT_RECONCILIATION_MAX_ITEMS_PER_ROUTE as u64) {
                let event_id = EventIdForTest::from_u64(offset);
                tx.execute(
                    "INSERT INTO transport_reconciliation_items (
                         route_kind, route_id, event_id, created_at
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        route_kind,
                        route_id,
                        event_id.as_slice(),
                        i64::try_from(start + offset).unwrap()
                    ],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        let inventory = store
            .transport_reconciliation_inventory(&route, now)
            .unwrap();
        assert_eq!(
            inventory.items.len(),
            TRANSPORT_RECONCILIATION_MAX_ITEMS_PER_ROUTE
        );
        assert_eq!(inventory.since, start + 1);
        assert!(
            inventory
                .items
                .iter()
                .all(|item| item.created_at >= inventory.since)
        );

        let reopened = store
            .transport_reconciliation_inventory(&route, now)
            .unwrap();
        assert_eq!(reopened, inventory);
    }

    #[test]
    fn reconciliation_route_cursor_is_durable_and_route_scoped() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        assert_eq!(store.transport_reconciliation_route_cursor().unwrap(), None);

        let group = TransportReconciliationRoute::Group([0x66; 32]);
        store
            .advance_transport_reconciliation_route_cursor(&group)
            .unwrap();
        assert_eq!(
            store.transport_reconciliation_route_cursor().unwrap(),
            Some(group)
        );
        store
            .advance_transport_reconciliation_route_cursor(&TransportReconciliationRoute::Inbox)
            .unwrap();
        assert_eq!(
            store.transport_reconciliation_route_cursor().unwrap(),
            Some(TransportReconciliationRoute::Inbox)
        );
    }

    struct EventIdForTest;

    impl EventIdForTest {
        fn from_u64(value: u64) -> [u8; 32] {
            let mut id = [0u8; 32];
            id[24..].copy_from_slice(&value.to_be_bytes());
            id
        }
    }
}
