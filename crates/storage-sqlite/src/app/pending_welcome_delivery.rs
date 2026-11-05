#[cfg(test)]
use crate::SqliteAccountStorage;
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
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
    /// Coarse size refusal when proved; absent means Unknown, never delivered.
    #[serde(default)]
    pub size_class: Option<cgka_traits::EventSizeClass>,
}

impl SqliteAppStorage {
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
        self.record_pending_welcome_deliveries(&[PendingWelcomeDeliveryRecord {
            size_class: None,
            message_id_hex: message_id_hex.to_owned(),
            group_id_hex: group_id_hex.to_owned(),
            recipient_hex: recipient_hex.to_owned(),
            recorded_at,
        }])
    }

    /// Record a complete set of Welcome obligations atomically.
    ///
    /// A multi-member invite must never leave a prefix of repair handles if a
    /// later row fails: the associated MLS commit has not been exposed yet and
    /// will be rolled back as one unit.
    pub fn record_pending_welcome_deliveries(
        &self,
        records: &[PendingWelcomeDeliveryRecord],
    ) -> StorageResult<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        for record in records {
            tx.execute_cached(
                "INSERT INTO app_pending_welcome_delivery (
                    message_id_hex, group_id_hex, recipient_hex, recorded_at, size_class
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(message_id_hex) DO UPDATE SET
                    group_id_hex = excluded.group_id_hex,
                    recipient_hex = excluded.recipient_hex,
                    recorded_at = excluded.recorded_at,
                    size_class = excluded.size_class",
                params![
                    record.message_id_hex,
                    record.group_id_hex,
                    record.recipient_hex,
                    u64_to_i64(record.recorded_at)?,
                    record.size_class.map(cgka_traits::EventSizeClass::as_str)
                ],
            )
            .storage()?;
        }
        tx.commit().storage()?;
        Ok(())
    }

    /// Note a failed attempt without changing an existing repair handle's
    /// identity or oldest-first position. This annotation never owns retries.
    pub fn record_pending_welcome_delivery_failure(
        &self,
        record: &PendingWelcomeDeliveryRecord,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT INTO app_pending_welcome_delivery (
                    message_id_hex, group_id_hex, recipient_hex, recorded_at, size_class
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(message_id_hex) DO UPDATE SET size_class = excluded.size_class",
                params![
                    record.message_id_hex,
                    record.group_id_hex,
                    record.recipient_hex,
                    u64_to_i64(record.recorded_at)?,
                    record.size_class.map(cgka_traits::EventSizeClass::as_str)
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
            .prepare_cached(
                "SELECT message_id_hex, group_id_hex, recipient_hex, recorded_at, size_class
                 FROM app_pending_welcome_delivery
                 ORDER BY recorded_at ASC, message_id_hex ASC",
            )
            .storage()?;
        let records = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get::<_, i64>(3)?,
                    row.get_ref(4)?.as_str().ok().map(str::to_owned),
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        records
            .into_iter()
            .map(
                |(message_id_hex, group_id_hex, recipient_hex, recorded_at, size_class)| {
                    Ok(PendingWelcomeDeliveryRecord {
                        // Old rows and unknown future annotations keep their
                        // repair pointer; only the diagnosis becomes Unknown.
                        size_class: size_class
                            .and_then(|value| serde_json::from_value(value.into()).ok()),
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
        self.take_pending_welcome_delivery(message_id_hex)
            .map(|_| ())
    }

    /// True only when this call durably removed a pending obligation.
    pub fn take_pending_welcome_delivery(&self, message_id_hex: &str) -> StorageResult<bool> {
        let changed = self
            .lock()?
            .execute_cached(
                "DELETE FROM app_pending_welcome_delivery WHERE message_id_hex = ?1",
                params![message_id_hex],
            )
            .storage()?;
        Ok(changed != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_record_same_message_updates_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending.sqlite3");
        let key = crate::SqlCipherKey::raw([0xa3; 32]);
        let account = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let store = account.app_storage();
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
                size_class: None,
                message_id_hex: "aa".to_owned(),
                group_id_hex: "bb2".to_owned(),
                recipient_hex: "cc2".to_owned(),
                recorded_at: 9,
            }
        );
        let mut diagnosis = PendingWelcomeDeliveryRecord {
            message_id_hex: "aa".into(),
            group_id_hex: "must-not-replace-group".into(),
            recipient_hex: "must-not-replace-recipient".into(),
            recorded_at: 99,
            size_class: Some(cgka_traits::EventSizeClass::From128To256Kib),
        };
        store
            .record_pending_welcome_delivery_failure(&diagnosis)
            .unwrap();
        let mut expected = records[0].clone();
        expected.size_class = diagnosis.size_class;
        assert_eq!(
            store.list_pending_welcome_deliveries().unwrap(),
            [expected.clone()]
        );
        account.close().unwrap();
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let store = reopened.app_storage();
        assert_eq!(
            store.list_pending_welcome_deliveries().unwrap(),
            [expected],
            "a known diagnosis survives encrypted reopen"
        );
        diagnosis.size_class = None;
        store
            .record_pending_welcome_delivery_failure(&diagnosis)
            .unwrap();
        assert_eq!(store.list_pending_welcome_deliveries().unwrap(), records);
        for unknown in [
            rusqlite::types::Value::Text("future_unrecognized_class".into()),
            rusqlite::types::Value::Blob(vec![0xff]),
        ] {
            store.lock().unwrap().execute(
                "UPDATE app_pending_welcome_delivery SET size_class = ?1 WHERE message_id_hex = 'aa'", [unknown],
            ).unwrap();
            assert_eq!(
                store.list_pending_welcome_deliveries().unwrap(),
                records,
                "a future annotation must not hide the valid repair pointer"
            );
        }
    }

    #[test]
    fn batch_failure_rolls_back_every_welcome_intent() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let records = vec![
            PendingWelcomeDeliveryRecord {
                size_class: None,
                message_id_hex: "first".to_owned(),
                group_id_hex: "group".to_owned(),
                recipient_hex: "alice".to_owned(),
                recorded_at: 1,
            },
            PendingWelcomeDeliveryRecord {
                size_class: None,
                message_id_hex: "second".to_owned(),
                group_id_hex: "group".to_owned(),
                recipient_hex: "bob".to_owned(),
                recorded_at: u64::MAX,
            },
        ];

        store
            .record_pending_welcome_deliveries(&records)
            .expect_err("second row must fail integer conversion");
        assert!(
            store.list_pending_welcome_deliveries().unwrap().is_empty(),
            "the first row must roll back with the failed batch"
        );
    }

    #[test]
    fn clear_removes_exactly_one() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store
            .record_pending_welcome_delivery("aa", "bb", "cc", 1)
            .unwrap();
        store
            .record_pending_welcome_delivery("dd", "ee", "ff", 2)
            .unwrap();

        store.clear_pending_welcome_delivery("aa").unwrap();
        assert!(!store.take_pending_welcome_delivery("aa").unwrap());

        let records = store.list_pending_welcome_deliveries().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message_id_hex, "dd");
    }

    #[test]
    fn list_orders_by_recorded_at() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
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

        let error = store
            .app_storage()
            .list_pending_welcome_deliveries()
            .unwrap_err();
        assert!(matches!(
            error,
            cgka_traits::storage::StorageError::Serialization(_)
        ));
    }
}
