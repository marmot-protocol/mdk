//! Sealed history deliveries between this account's devices (mdk#2628 item
//! 4.2b): the histories this device owes its siblings, and the deliveries it
//! read before it held their chat. See migration 0149.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::params;

/// How long an owed or parked delivery is kept, in seconds.
pub const HISTORY_DELIVERY_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
/// The most parked deliveries kept; the oldest go first.
const MAX_PARKED_HISTORY_DELIVERIES: i64 = 1_024;

/// A chat's history this device owes a sibling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwedHistoryDelivery {
    pub group_id_hex: String,
    pub receiver_slot_hex: String,
    pub owed_at: u64,
    /// How many times it was owed again; a later one is a newer obligation.
    pub revision: u64,
}

/// A delivery read before this device held its chat, as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParkedHistoryDelivery {
    pub app_event_id: String,
    pub group_id_hex: String,
    pub sender_slot_hex: String,
    /// The sealed key and hash, opened again at import.
    pub sealed: Vec<u8>,
    /// The bundle ciphertext.
    pub bundle: Vec<u8>,
    pub received_at: u64,
}

impl SqliteAppStorage {
    /// Owe the sibling at `receiver_slot_hex` the history of the chat
    /// `group_id_hex` from `now`, whether or not it was owed or sent before.
    pub fn owe_history_delivery(
        &self,
        group_id_hex: &str,
        receiver_slot_hex: &str,
        now: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT INTO history_deliveries_owed
                     (group_id_hex, receiver_slot_hex, owed_at, sent_at)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT(group_id_hex, receiver_slot_hex) DO UPDATE SET
                     owed_at = excluded.owed_at,
                     sent_at = NULL,
                     revision = revision + 1",
                params![group_id_hex, receiver_slot_hex, u64_to_i64(now)?],
            )
            .storage()?;
        Ok(())
    }

    /// Remember that the delivery `app_event_id` carries the history of the
    /// chat `group_id_hex` to the sibling at `receiver_slot_hex`, before it is
    /// sent.
    pub fn record_history_delivery_send(
        &self,
        app_event_id: &str,
        group_id_hex: &str,
        receiver_slot_hex: &str,
        now: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT OR REPLACE INTO history_delivery_sends
                     (app_event_id, group_id_hex, receiver_slot_hex, recorded_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    app_event_id,
                    group_id_hex,
                    receiver_slot_hex,
                    u64_to_i64(now)?
                ],
            )
            .storage()?;
        Ok(())
    }

    /// The delivery `app_event_id` reaches no one, because branch selection
    /// withdrew it or its publish failed for good: owe its history again, as
    /// it was first owed. Returns false when this device sent no such
    /// delivery or no longer owes that history.
    pub fn owe_history_delivery_again(&self, app_event_id: &str) -> StorageResult<bool> {
        let changed = self
            .lock()?
            .execute_cached(
                "UPDATE history_deliveries_owed SET sent_at = NULL, revision = revision + 1
                 WHERE (group_id_hex, receiver_slot_hex) IN (
                     SELECT group_id_hex, receiver_slot_hex FROM history_delivery_sends
                     WHERE app_event_id = ?1
                 )",
                params![app_event_id],
            )
            .storage()?;
        Ok(changed > 0)
    }

    /// Every history still to be sent, oldest first.
    pub fn unsent_history_deliveries(&self) -> StorageResult<Vec<OwedHistoryDelivery>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT group_id_hex, receiver_slot_hex, owed_at, revision
                 FROM history_deliveries_owed WHERE sent_at IS NULL
                 ORDER BY owed_at, group_id_hex, receiver_slot_hex",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(group_id_hex, receiver_slot_hex, owed_at, revision)| {
                Ok(OwedHistoryDelivery {
                    group_id_hex,
                    receiver_slot_hex,
                    owed_at: i64_to_u64(owed_at)?,
                    revision: i64_to_u64(revision)?,
                })
            })
            .collect()
    }

    /// Mark `owed` sent at `now`, if it is still owed as it was read: a
    /// history owed again since, even while its deliveries went out, stays
    /// owed.
    pub fn mark_history_delivery_sent(
        &self,
        owed: &OwedHistoryDelivery,
        now: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE history_deliveries_owed SET sent_at = ?4
                 WHERE group_id_hex = ?1 AND receiver_slot_hex = ?2
                   AND revision = ?3 AND sent_at IS NULL",
                params![
                    owed.group_id_hex,
                    owed.receiver_slot_hex,
                    u64_to_i64(owed.revision)?,
                    u64_to_i64(now)?
                ],
            )
            .storage()?;
        Ok(())
    }

    /// Forget `owed`, if it is still owed as it was read, once it can no
    /// longer be sent.
    pub fn forget_history_delivery(&self, owed: &OwedHistoryDelivery) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM history_deliveries_owed
                 WHERE group_id_hex = ?1 AND receiver_slot_hex = ?2
                   AND revision = ?3 AND sent_at IS NULL",
                params![
                    owed.group_id_hex,
                    owed.receiver_slot_hex,
                    u64_to_i64(owed.revision)?
                ],
            )
            .storage()?;
        Ok(())
    }

    /// Keep a delivery until this device holds its chat. One already parked
    /// is kept as it was. All but the newest 1,024 go.
    pub fn park_history_delivery(&self, delivery: &ParkedHistoryDelivery) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "INSERT OR IGNORE INTO history_deliveries_parked
                     (app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, received_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    delivery.app_event_id,
                    delivery.group_id_hex,
                    delivery.sender_slot_hex,
                    delivery.sealed,
                    delivery.bundle,
                    u64_to_i64(delivery.received_at)?
                ],
            )
            .storage()?;
            conn.execute_cached(
                "DELETE FROM history_deliveries_parked WHERE rowid IN (
                     SELECT rowid FROM history_deliveries_parked
                     ORDER BY received_at DESC, rowid DESC
                     LIMIT -1 OFFSET ?1
                 )",
                params![MAX_PARKED_HISTORY_DELIVERIES],
            )
            .storage()?;
            Ok(())
        })
    }

    /// The chats that parked deliveries name.
    pub fn parked_history_delivery_chats(&self) -> StorageResult<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT DISTINCT group_id_hex FROM history_deliveries_parked
                 ORDER BY group_id_hex",
            )
            .storage()?;
        stmt.query_map([], |row| row.get::<_, String>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()
    }

    /// The deliveries parked for the chat `group_id_hex`, oldest first.
    pub fn parked_history_deliveries(
        &self,
        group_id_hex: &str,
    ) -> StorageResult<Vec<ParkedHistoryDelivery>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, received_at
                 FROM history_deliveries_parked WHERE group_id_hex = ?1
                 ORDER BY received_at, rowid",
            )
            .storage()?;
        let rows = stmt
            .query_map(params![group_id_hex], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(
                |(app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, received_at)| {
                    Ok(ParkedHistoryDelivery {
                        app_event_id,
                        group_id_hex,
                        sender_slot_hex,
                        sealed,
                        bundle,
                        received_at: i64_to_u64(received_at)?,
                    })
                },
            )
            .collect()
    }

    /// Forget a parked delivery once it was imported or refused.
    pub fn drop_parked_history_delivery(&self, app_event_id: &str) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM history_deliveries_parked WHERE app_event_id = ?1",
                params![app_event_id],
            )
            .storage()?;
        Ok(())
    }

    /// Drop owed, sent and parked deliveries a week old at `now`. Returns how
    /// many went.
    pub fn expire_history_deliveries(&self, now: u64) -> StorageResult<usize> {
        let before = u64_to_i64(now.saturating_sub(HISTORY_DELIVERY_RETENTION_SECS))?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let owed = conn
                .execute_cached(
                    "DELETE FROM history_deliveries_owed WHERE owed_at < ?1",
                    params![before],
                )
                .storage()?;
            let sent = conn
                .execute_cached(
                    "DELETE FROM history_delivery_sends WHERE recorded_at < ?1",
                    params![before],
                )
                .storage()?;
            let parked = conn
                .execute_cached(
                    "DELETE FROM history_deliveries_parked WHERE received_at < ?1",
                    params![before],
                )
                .storage()?;
            Ok(owed + sent + parked)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    const DAY: u64 = 24 * 60 * 60;

    fn parked(id: &str, chat: &str, at: u64) -> ParkedHistoryDelivery {
        ParkedHistoryDelivery {
            app_event_id: id.into(),
            group_id_hex: chat.into(),
            sender_slot_hex: "11".repeat(32),
            sealed: vec![1, 2],
            bundle: vec![3, 4],
            received_at: at,
        }
    }

    #[test]
    fn an_owed_history_stays_owed_until_sent_and_is_owed_again_on_withdrawal() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store.owe_history_delivery("bb", "s2", 20).unwrap();
        store.owe_history_delivery("aa", "s1", 10).unwrap();
        let owed = store.unsent_history_deliveries().unwrap();
        assert_eq!(
            owed.iter()
                .map(|owed| (owed.group_id_hex.as_str(), owed.owed_at))
                .collect::<Vec<_>>(),
            [("aa", 10), ("bb", 20)]
        );

        store.mark_history_delivery_sent(&owed[0], 30).unwrap();
        assert_eq!(
            store.unsent_history_deliveries().unwrap(),
            [owed[1].clone()]
        );
        // Sent, so not forgotten.
        store.forget_history_delivery(&owed[0]).unwrap();

        // Owed again by a new add while its send was out: it stays owed.
        store.owe_history_delivery("bb", "s2", 40).unwrap();
        store.mark_history_delivery_sent(&owed[1], 41).unwrap();
        assert_eq!(store.unsent_history_deliveries().unwrap()[0].owed_at, 40);

        store
            .record_history_delivery_send("e1", "aa", "s1", 30)
            .unwrap();
        assert!(store.owe_history_delivery_again("e1").unwrap());
        let again = store.unsent_history_deliveries().unwrap();
        assert_eq!(
            (again[0].group_id_hex.as_str(), again[0].owed_at),
            ("aa", 10),
            "owed again from the add"
        );
        // Owed again while its deliveries went out, as a withdrawal or
        // failure drained mid-send does: the send's mark leaves it owed.
        assert!(store.owe_history_delivery_again("e1").unwrap());
        store.mark_history_delivery_sent(&again[0], 42).unwrap();
        let again = store.unsent_history_deliveries().unwrap();
        assert_eq!(again[0].group_id_hex, "aa");
        // Not a delivery this device sent: nothing to owe again.
        assert!(!store.owe_history_delivery_again("e9").unwrap());
        assert_eq!(store.unsent_history_deliveries().unwrap().len(), 2);

        store.forget_history_delivery(&again[0]).unwrap();
        assert_eq!(store.unsent_history_deliveries().unwrap().len(), 1);
        assert!(!store.owe_history_delivery_again("e1").unwrap());
    }

    #[test]
    fn a_parked_delivery_is_kept_once_per_event_and_found_by_its_chat() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store
            .park_history_delivery(&parked("e1", "aa", 10))
            .unwrap();
        let mut duplicate = parked("e1", "aa", 11);
        duplicate.bundle = vec![9];
        store.park_history_delivery(&duplicate).unwrap();
        store
            .park_history_delivery(&parked("e2", "bb", 12))
            .unwrap();
        store
            .park_history_delivery(&parked("e3", "aa", 13))
            .unwrap();

        assert_eq!(store.parked_history_delivery_chats().unwrap(), ["aa", "bb"]);
        assert_eq!(
            store.parked_history_deliveries("aa").unwrap(),
            [parked("e1", "aa", 10), parked("e3", "aa", 13)]
        );
        store.drop_parked_history_delivery("e1").unwrap();
        assert_eq!(
            store.parked_history_deliveries("aa").unwrap(),
            [parked("e3", "aa", 13)]
        );
    }

    #[test]
    fn deliveries_go_after_a_week_and_parked_ones_beyond_the_cap() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store.owe_history_delivery("aa", "s1", DAY).unwrap();
        store.owe_history_delivery("bb", "s1", 2 * DAY).unwrap();
        store
            .park_history_delivery(&parked("old", "aa", DAY))
            .unwrap();
        store
            .park_history_delivery(&parked("kept", "aa", 2 * DAY))
            .unwrap();
        store
            .record_history_delivery_send("e1", "aa", "s1", DAY)
            .unwrap();
        assert_eq!(store.expire_history_deliveries(8 * DAY + 1).unwrap(), 3);
        assert!(!store.owe_history_delivery_again("e1").unwrap());
        assert_eq!(
            store.unsent_history_deliveries().unwrap()[0].group_id_hex,
            "bb"
        );
        assert_eq!(
            store.parked_history_deliveries("aa").unwrap(),
            [parked("kept", "aa", 2 * DAY)]
        );

        for index in 0..MAX_PARKED_HISTORY_DELIVERIES {
            store
                .park_history_delivery(&parked(&format!("e{index}"), "cc", 3 * DAY))
                .unwrap();
        }
        assert!(store.parked_history_deliveries("aa").unwrap().is_empty());
        assert_eq!(
            store.parked_history_deliveries("cc").unwrap().len() as i64,
            MAX_PARKED_HISTORY_DELIVERIES
        );
    }
}
