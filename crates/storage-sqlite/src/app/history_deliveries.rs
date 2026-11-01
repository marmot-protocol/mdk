//! Sealed history deliveries between this account's devices (mdk#2628 items
//! 4.2b and 4.2c): the histories this device owes its siblings, and the
//! deliveries it read before it held their chat or fetched their bundle. See
//! migrations 0149 and 0166.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension as _, params};

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
    /// When it next goes through Blossom, once it is too long to go inline.
    pub blossom_due_at: Option<u64>,
    /// How many of its Blossom uploads failed.
    pub blossom_attempts: u64,
}

/// A delivery read before this device held its chat or fetched its bundle,
/// as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParkedHistoryDelivery {
    pub app_event_id: String,
    pub group_id_hex: String,
    pub sender_slot_hex: String,
    /// The sealed key and hash, opened again at import.
    pub sealed: Vec<u8>,
    pub bundle: ParkedBundle,
    pub received_at: u64,
}

/// A chat that parked deliveries name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParkedHistoryChat {
    pub group_id_hex: String,
    /// A fetch of one of its Blossom deliveries failed.
    pub retrying: bool,
}

/// What a parked delivery carries of its bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParkedBundle {
    /// The bundle ciphertext.
    Inline(Vec<u8>),
    /// The Blossom servers that hold it, fetched from `fetch_due_at`;
    /// `fetch_attempts` fetches failed.
    Blossom {
        servers: Vec<String>,
        fetch_due_at: u64,
        fetch_attempts: u64,
    },
}

const OWED_COLUMNS: &str =
    "group_id_hex, receiver_slot_hex, owed_at, revision, blossom_due_at, blossom_attempts";
const PARKED_COLUMNS: &str = "app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, \
     blossom, received_at, fetch_due_at, fetch_attempts";

fn owed_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OwedRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

type OwedRow = (String, String, i64, i64, Option<i64>, i64);

fn owed_delivery(
    (group_id_hex, receiver_slot_hex, owed_at, revision, blossom_due_at, blossom_attempts): OwedRow,
) -> StorageResult<OwedHistoryDelivery> {
    Ok(OwedHistoryDelivery {
        group_id_hex,
        receiver_slot_hex,
        owed_at: i64_to_u64(owed_at)?,
        revision: i64_to_u64(revision)?,
        blossom_due_at: blossom_due_at.map(i64_to_u64).transpose()?,
        blossom_attempts: i64_to_u64(blossom_attempts)?,
    })
}

type ParkedRow = (
    String,
    String,
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<String>,
    i64,
    Option<i64>,
    i64,
);

fn parked_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ParkedRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn parked_delivery(
    (
        app_event_id,
        group_id_hex,
        sender_slot_hex,
        sealed,
        bundle,
        blossom,
        received_at,
        fetch_due_at,
        fetch_attempts,
    ): ParkedRow,
) -> StorageResult<ParkedHistoryDelivery> {
    let bundle = match (bundle, blossom, fetch_due_at) {
        (Some(bundle), None, None) => ParkedBundle::Inline(bundle),
        (None, Some(servers), Some(fetch_due_at)) => ParkedBundle::Blossom {
            servers: servers.split('\n').map(str::to_owned).collect(),
            fetch_due_at: i64_to_u64(fetch_due_at)?,
            fetch_attempts: i64_to_u64(fetch_attempts)?,
        },
        _ => {
            return Err(cgka_traits::storage::StorageError::Backend(
                "parked history delivery carries no bundle".into(),
            ));
        }
    };
    Ok(ParkedHistoryDelivery {
        app_event_id,
        group_id_hex,
        sender_slot_hex,
        sealed,
        bundle,
        received_at: i64_to_u64(received_at)?,
    })
}

impl SqliteAppStorage {
    /// Owe the sibling at `receiver_slot_hex` the history of the chat
    /// `group_id_hex` from `now`, whether or not it was owed or sent before,
    /// inline until it is found too long.
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
                     revision = revision + 1,
                     blossom_due_at = NULL,
                     blossom_attempts = 0",
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
    /// it was first owed, and return it as it now stands. A history going
    /// through Blossom keeps its upload time and failed attempts, for the
    /// caller to back off. `None` when this device sent no such delivery or
    /// no longer owes that history.
    pub fn owe_history_delivery_again(
        &self,
        app_event_id: &str,
    ) -> StorageResult<Option<OwedHistoryDelivery>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(&format!(
                "UPDATE history_deliveries_owed SET sent_at = NULL, revision = revision + 1
                 WHERE (group_id_hex, receiver_slot_hex) IN (
                     SELECT group_id_hex, receiver_slot_hex FROM history_delivery_sends
                     WHERE app_event_id = ?1
                 )
                 RETURNING {OWED_COLUMNS}"
            ))
            .storage()?;
        let row = stmt
            .query_row(params![app_event_id], owed_row)
            .optional()
            .storage()?;
        row.map(owed_delivery).transpose()
    }

    /// Every history still to be sent, oldest first.
    pub fn unsent_history_deliveries(&self) -> StorageResult<Vec<OwedHistoryDelivery>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(&format!(
                "SELECT {OWED_COLUMNS} FROM history_deliveries_owed WHERE sent_at IS NULL
                 ORDER BY owed_at, group_id_hex, receiver_slot_hex"
            ))
            .storage()?;
        let rows = stmt
            .query_map([], owed_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(owed_delivery).collect()
    }

    /// Send `owed` through Blossom from `now`, if it is still owed as it was
    /// read and goes inline.
    pub fn send_history_delivery_by_blossom(
        &self,
        owed: &OwedHistoryDelivery,
        now: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE history_deliveries_owed SET blossom_due_at = ?4
                 WHERE group_id_hex = ?1 AND receiver_slot_hex = ?2
                   AND revision = ?3 AND sent_at IS NULL AND blossom_due_at IS NULL",
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

    /// The histories to send through Blossom whose upload is due at `now`,
    /// soonest due first.
    pub fn due_blossom_history_deliveries(
        &self,
        now: u64,
    ) -> StorageResult<Vec<OwedHistoryDelivery>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(&format!(
                "SELECT {OWED_COLUMNS} FROM history_deliveries_owed
                 WHERE sent_at IS NULL AND blossom_due_at IS NOT NULL AND blossom_due_at <= ?1
                 ORDER BY blossom_due_at, owed_at, group_id_hex, receiver_slot_hex"
            ))
            .storage()?;
        let rows = stmt
            .query_map(params![u64_to_i64(now)?], owed_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(owed_delivery).collect()
    }

    /// A Blossom upload of `owed` failed: try again from `until`, if it is
    /// still owed as it was read.
    pub fn defer_blossom_history_delivery(
        &self,
        owed: &OwedHistoryDelivery,
        until: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE history_deliveries_owed
                 SET blossom_due_at = ?4, blossom_attempts = blossom_attempts + 1
                 WHERE group_id_hex = ?1 AND receiver_slot_hex = ?2
                   AND revision = ?3 AND sent_at IS NULL AND blossom_due_at IS NOT NULL",
                params![
                    owed.group_id_hex,
                    owed.receiver_slot_hex,
                    u64_to_i64(owed.revision)?,
                    u64_to_i64(until)?
                ],
            )
            .storage()?;
        Ok(())
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

    /// Keep a delivery until this device holds its chat and its bundle. One
    /// already parked is kept as it was. All but the newest 1,024 go.
    pub fn park_history_delivery(&self, delivery: &ParkedHistoryDelivery) -> StorageResult<()> {
        let (bundle, blossom, fetch_due_at, fetch_attempts) = match &delivery.bundle {
            ParkedBundle::Inline(bundle) => (Some(bundle.as_slice()), None, None, 0),
            ParkedBundle::Blossom {
                servers,
                fetch_due_at,
                fetch_attempts,
            } => (
                None,
                Some(servers.join("\n")),
                Some(u64_to_i64(*fetch_due_at)?),
                u64_to_i64(*fetch_attempts)?,
            ),
        };
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                &format!(
                    "INSERT OR IGNORE INTO history_deliveries_parked ({PARKED_COLUMNS})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
                ),
                params![
                    delivery.app_event_id,
                    delivery.group_id_hex,
                    delivery.sender_slot_hex,
                    delivery.sealed,
                    bundle,
                    blossom,
                    u64_to_i64(delivery.received_at)?,
                    fetch_due_at,
                    fetch_attempts
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

    /// Each chat parked deliveries name, and whether a fetch for one of them
    /// failed.
    pub fn parked_history_chats(&self) -> StorageResult<Vec<ParkedHistoryChat>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT group_id_hex, MAX(fetch_attempts > 0) FROM history_deliveries_parked
                 GROUP BY group_id_hex ORDER BY group_id_hex",
            )
            .storage()?;
        stmt.query_map([], |row| {
            Ok(ParkedHistoryChat {
                group_id_hex: row.get(0)?,
                retrying: row.get(1)?,
            })
        })
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
            .prepare_cached(&format!(
                "SELECT {PARKED_COLUMNS} FROM history_deliveries_parked WHERE group_id_hex = ?1
                 ORDER BY received_at, rowid"
            ))
            .storage()?;
        let rows = stmt
            .query_map(params![group_id_hex], parked_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(parked_delivery).collect()
    }

    /// Up to `limit` parked Blossom deliveries whose fetch is due at `now`,
    /// soonest due first.
    pub fn due_parked_history_fetches(
        &self,
        now: u64,
        limit: usize,
    ) -> StorageResult<Vec<ParkedHistoryDelivery>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(&format!(
                "SELECT {PARKED_COLUMNS} FROM history_deliveries_parked
                 WHERE fetch_due_at IS NOT NULL AND fetch_due_at <= ?1
                 ORDER BY fetch_due_at, rowid LIMIT ?2"
            ))
            .storage()?;
        let rows = stmt
            .query_map(
                params![u64_to_i64(now)?, i64::try_from(limit).unwrap_or(i64::MAX)],
                parked_row,
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(parked_delivery).collect()
    }

    /// A fetch of the parked delivery `app_event_id` failed: try again from
    /// `until`.
    pub fn defer_parked_history_fetch(&self, app_event_id: &str, until: u64) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE history_deliveries_parked
                 SET fetch_due_at = ?2, fetch_attempts = fetch_attempts + 1
                 WHERE app_event_id = ?1 AND fetch_due_at IS NOT NULL",
                params![app_event_id, u64_to_i64(until)?],
            )
            .storage()?;
        Ok(())
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
    /// many parked ones went, since a host shows those.
    pub fn expire_history_deliveries(&self, now: u64) -> StorageResult<usize> {
        let before = u64_to_i64(now.saturating_sub(HISTORY_DELIVERY_RETENTION_SECS))?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "DELETE FROM history_deliveries_owed WHERE owed_at < ?1",
                params![before],
            )
            .storage()?;
            conn.execute_cached(
                "DELETE FROM history_delivery_sends WHERE recorded_at < ?1",
                params![before],
            )
            .storage()?;
            conn.execute_cached(
                "DELETE FROM history_deliveries_parked WHERE received_at < ?1",
                params![before],
            )
            .storage()
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl SqliteAppStorage {
    /// Runs `sql` on the account connection, to break and then mend the
    /// schema under a test. Test support only.
    pub fn execute_batch_for_test(&self, sql: &str) -> StorageResult<()> {
        self.lock()?.execute_batch(sql).storage()
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
            bundle: ParkedBundle::Inline(vec![3, 4]),
            received_at: at,
        }
    }

    fn located(id: &str, chat: &str, at: u64) -> ParkedHistoryDelivery {
        ParkedHistoryDelivery {
            bundle: ParkedBundle::Blossom {
                servers: vec!["https://a.example/".into(), "https://b.example/".into()],
                fetch_due_at: at,
                fetch_attempts: 0,
            },
            ..parked(id, chat, at)
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
        assert!(store.owe_history_delivery_again("e1").unwrap().is_some());
        let again = store.unsent_history_deliveries().unwrap();
        assert_eq!(
            (again[0].group_id_hex.as_str(), again[0].owed_at),
            ("aa", 10),
            "owed again from the add"
        );
        // Owed again while its deliveries went out, as a withdrawal or
        // failure drained mid-send does: the send's mark leaves it owed.
        assert!(store.owe_history_delivery_again("e1").unwrap().is_some());
        store.mark_history_delivery_sent(&again[0], 42).unwrap();
        let again = store.unsent_history_deliveries().unwrap();
        assert_eq!(again[0].group_id_hex, "aa");
        // Not a delivery this device sent: nothing to owe again.
        assert!(store.owe_history_delivery_again("e9").unwrap().is_none());
        assert_eq!(store.unsent_history_deliveries().unwrap().len(), 2);

        store.forget_history_delivery(&again[0]).unwrap();
        assert_eq!(store.unsent_history_deliveries().unwrap().len(), 1);
        assert!(store.owe_history_delivery_again("e1").unwrap().is_none());
    }

    #[test]
    fn a_history_too_long_for_inline_goes_through_blossom_until_owed_afresh() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store.owe_history_delivery("aa", "s1", 10).unwrap();
        let owed = store.unsent_history_deliveries().unwrap().remove(0);
        assert_eq!((owed.blossom_due_at, owed.blossom_attempts), (None, 0));
        assert!(
            store
                .due_blossom_history_deliveries(100)
                .unwrap()
                .is_empty()
        );
        // Deferring goes only for a history that goes through Blossom.
        store.defer_blossom_history_delivery(&owed, 50).unwrap();
        assert_eq!(store.unsent_history_deliveries().unwrap()[0], owed);

        store.send_history_delivery_by_blossom(&owed, 20).unwrap();
        let blossom = store.due_blossom_history_deliveries(20).unwrap().remove(0);
        assert_eq!(blossom.blossom_due_at, Some(20));
        // Once by Blossom, it stays so.
        store
            .send_history_delivery_by_blossom(&blossom, 30)
            .unwrap();
        store.defer_blossom_history_delivery(&blossom, 90).unwrap();
        assert!(store.due_blossom_history_deliveries(89).unwrap().is_empty());
        let deferred = store.due_blossom_history_deliveries(90).unwrap().remove(0);
        assert_eq!(
            (deferred.blossom_due_at, deferred.blossom_attempts),
            (Some(90), 1)
        );

        // Owed again by a withdrawal, it still goes through Blossom; a defer
        // read before that leaves the newer obligation due.
        store
            .record_history_delivery_send("e1", "aa", "s1", 40)
            .unwrap();
        assert!(store.owe_history_delivery_again("e1").unwrap().is_some());
        store
            .defer_blossom_history_delivery(&deferred, 500)
            .unwrap();
        let again = store.due_blossom_history_deliveries(90).unwrap().remove(0);
        assert_eq!(again.revision, deferred.revision + 1);
        store.mark_history_delivery_sent(&again, 95).unwrap();
        assert!(
            store
                .due_blossom_history_deliveries(1_000)
                .unwrap()
                .is_empty()
        );

        // Owed afresh by a new add, it goes inline until found too long.
        store.owe_history_delivery("aa", "s1", 100).unwrap();
        let fresh = store.unsent_history_deliveries().unwrap().remove(0);
        assert_eq!((fresh.blossom_due_at, fresh.blossom_attempts), (None, 0));
    }

    #[test]
    fn a_parked_blossom_delivery_is_fetched_when_due_and_deferred_on_failure() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store
            .park_history_delivery(&parked("e1", "aa", 10))
            .unwrap();
        store
            .park_history_delivery(&located("e2", "aa", 12))
            .unwrap();
        store
            .park_history_delivery(&located("e3", "bb", 11))
            .unwrap();
        assert_eq!(
            store.parked_history_deliveries("aa").unwrap(),
            [parked("e1", "aa", 10), located("e2", "aa", 12)]
        );
        assert_eq!(
            store.due_parked_history_fetches(12, 8).unwrap(),
            [located("e3", "bb", 11), located("e2", "aa", 12)]
        );
        assert_eq!(store.due_parked_history_fetches(12, 1).unwrap().len(), 1);
        assert!(store.due_parked_history_fetches(10, 8).unwrap().is_empty());
        let chats = |retrying: [bool; 2]| {
            [("aa", retrying[0]), ("bb", retrying[1])].map(|(chat, retrying)| ParkedHistoryChat {
                group_id_hex: chat.into(),
                retrying,
            })
        };
        assert_eq!(store.parked_history_chats().unwrap(), chats([false; 2]));

        store.defer_parked_history_fetch("e2", 70).unwrap();
        // An inline delivery has no fetch to defer.
        store.defer_parked_history_fetch("e1", 70).unwrap();
        // One failed fetch marks its chat as retrying.
        assert_eq!(store.parked_history_chats().unwrap(), chats([true, false]));
        assert_eq!(
            store.due_parked_history_fetches(69, 8).unwrap(),
            [located("e3", "bb", 11)]
        );
        let ParkedBundle::Blossom {
            fetch_due_at,
            fetch_attempts,
            ..
        } = &store.due_parked_history_fetches(70, 8).unwrap()[1].bundle
        else {
            panic!("a Blossom delivery");
        };
        assert_eq!((*fetch_due_at, *fetch_attempts), (70, 1));
        assert_eq!(
            store.parked_history_deliveries("aa").unwrap()[0],
            parked("e1", "aa", 10)
        );
    }

    #[test]
    fn a_parked_delivery_is_kept_once_per_event_and_found_by_its_chat() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store
            .park_history_delivery(&parked("e1", "aa", 10))
            .unwrap();
        let mut duplicate = parked("e1", "aa", 11);
        duplicate.bundle = ParkedBundle::Inline(vec![9]);
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
        assert_eq!(store.expire_history_deliveries(8 * DAY + 1).unwrap(), 1);
        assert!(store.owe_history_delivery_again("e1").unwrap().is_none());
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
