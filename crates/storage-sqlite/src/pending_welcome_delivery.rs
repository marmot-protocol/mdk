use crate::{SqliteAccountStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::params;
use serde::{Deserialize, Serialize};

/// Durable pointer to a confirmed group create/invite whose welcome publish
/// failed, so the welcome can be re-delivered later (mdk#352). Keyed by
/// `message_id_hex`, the identity of the welcome message; re-recording the same
/// message updates the group/recipient/timestamp in place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWelcomeDeliveryRecord {
    pub message_id_hex: String,
    pub group_id_hex: String,
    pub recipient_hex: String,
    pub recorded_at: u64,
}

impl SqliteAccountStorage {
    /// Record (or re-record) a pending welcome delivery. Idempotent on
    /// `message_id_hex`: re-recording overwrites the group, recipient, and
    /// timestamp rather than inserting a duplicate.
    pub fn record_pending_welcome_delivery(
        &self,
        message_id_hex: &str,
        group_id_hex: &str,
        recipient_hex: &str,
        recorded_at: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO app_pending_welcome_delivery (
                    message_id_hex, group_id_hex, recipient_hex, recorded_at
                 )
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(message_id_hex) DO UPDATE SET
                    group_id_hex = excluded.group_id_hex,
                    recipient_hex = excluded.recipient_hex,
                    recorded_at = excluded.recorded_at",
                params![
                    message_id_hex,
                    group_id_hex,
                    recipient_hex,
                    u64_to_i64(recorded_at)?
                ],
            )
            .storage()?;
        Ok(())
    }

    /// List every pending welcome delivery in stable oldest-first order.
    pub fn list_pending_welcome_deliveries(
        &self,
    ) -> StorageResult<Vec<PendingWelcomeDeliveryRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT message_id_hex, group_id_hex, recipient_hex, recorded_at
                 FROM app_pending_welcome_delivery
                 ORDER BY recorded_at ASC, message_id_hex ASC",
            )
            .storage()?;
        let records = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get::<_, i64>(3)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        records
            .into_iter()
            .map(
                |(message_id_hex, group_id_hex, recipient_hex, recorded_at)| {
                    Ok(PendingWelcomeDeliveryRecord {
                        message_id_hex,
                        group_id_hex,
                        recipient_hex,
                        recorded_at: i64_to_u64(recorded_at)?,
                    })
                },
            )
            .collect()
    }

    /// Clear the pending welcome delivery for `message_id_hex`, if any.
    pub fn clear_pending_welcome_delivery(&self, message_id_hex: &str) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM app_pending_welcome_delivery WHERE message_id_hex = ?1",
                params![message_id_hex],
            )
            .storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_then_list_roundtrips_fields() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .record_pending_welcome_delivery("aa", "bb", "cc", 7)
            .unwrap();

        let records = store.list_pending_welcome_deliveries().unwrap();
        assert_eq!(
            records,
            vec![PendingWelcomeDeliveryRecord {
                message_id_hex: "aa".to_owned(),
                group_id_hex: "bb".to_owned(),
                recipient_hex: "cc".to_owned(),
                recorded_at: 7,
            }]
        );
    }

    #[test]
    fn re_record_same_message_updates_in_place() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .record_pending_welcome_delivery("aa", "bb", "cc", 7)
            .unwrap();
        store
            .record_pending_welcome_delivery("aa", "bb2", "cc2", 9)
            .unwrap();

        let records = store.list_pending_welcome_deliveries().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0],
            PendingWelcomeDeliveryRecord {
                message_id_hex: "aa".to_owned(),
                group_id_hex: "bb2".to_owned(),
                recipient_hex: "cc2".to_owned(),
                recorded_at: 9,
            }
        );
    }

    #[test]
    fn clear_removes_exactly_one() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .record_pending_welcome_delivery("aa", "bb", "cc", 1)
            .unwrap();
        store
            .record_pending_welcome_delivery("dd", "ee", "ff", 2)
            .unwrap();

        store.clear_pending_welcome_delivery("aa").unwrap();

        let records = store.list_pending_welcome_deliveries().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message_id_hex, "dd");
    }

    #[test]
    fn list_orders_by_recorded_at() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .record_pending_welcome_delivery("c", "g", "r", 30)
            .unwrap();
        store
            .record_pending_welcome_delivery("a", "g", "r", 10)
            .unwrap();
        store
            .record_pending_welcome_delivery("b", "g", "r", 20)
            .unwrap();

        let order: Vec<String> = store
            .list_pending_welcome_deliveries()
            .unwrap()
            .into_iter()
            .map(|record| record.message_id_hex)
            .collect();
        assert_eq!(order, vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]);
    }

    #[test]
    fn list_rejects_negative_recorded_at() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO app_pending_welcome_delivery
                 (message_id_hex, group_id_hex, recipient_hex, recorded_at)
                 VALUES ('aa', 'bb', 'cc', -1)",
                [],
            )
            .unwrap();

        let error = store.list_pending_welcome_deliveries().unwrap_err();
        assert!(matches!(
            error,
            cgka_traits::storage::StorageError::Serialization(_)
        ));
    }
}
