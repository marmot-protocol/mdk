//! The kind of each device-group message this device sent or read whose
//! withdrawal a feature acts on (mdk#2628). The engine withdraws a message by
//! its message id alone (an own send's transport id, a received message's
//! content id), so this is how the app tells which feature's message it was.
//! See migration 0142 for the columns.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension, params};

/// How long a row is kept, in seconds.
const DEVICE_GROUP_MESSAGE_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
/// The most rows kept; the oldest go first.
const MAX_DEVICE_GROUP_MESSAGES: i64 = 4_096;

/// One recorded message: device group, app event id, message id (once
/// known) and kind.
#[cfg(any(test, feature = "test-support"))]
pub type RecordedDeviceGroupMessage = (String, String, Option<String>, u64);

impl SqliteAppStorage {
    /// Remember that the app event `app_event_id`, of `kind`, was sent or
    /// read in the device group `group_id_hex` at `now`, as the message
    /// `message_id_hex` when that is known. A known message id is
    /// never forgotten by a later call without one. Rows older than a week,
    /// and all but the newest 4,096, go.
    pub fn record_device_group_message(
        &self,
        group_id_hex: &str,
        app_event_id: &str,
        message_id_hex: Option<&str>,
        kind: u64,
        now: u64,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "INSERT INTO device_group_messages
                     (group_id_hex, app_event_id, message_id_hex, kind, recorded_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(group_id_hex, app_event_id) DO UPDATE SET
                     message_id_hex = COALESCE(excluded.message_id_hex,
                                               device_group_messages.message_id_hex),
                     kind = excluded.kind,
                     recorded_at = excluded.recorded_at",
                params![
                    group_id_hex,
                    app_event_id,
                    message_id_hex,
                    u64_to_i64(kind)?,
                    u64_to_i64(now)?
                ],
            )
            .storage()?;
            conn.execute_cached(
                "DELETE FROM device_group_messages WHERE recorded_at < ?1",
                params![u64_to_i64(
                    now.saturating_sub(DEVICE_GROUP_MESSAGE_RETENTION_SECS)
                )?],
            )
            .storage()?;
            conn.execute_cached(
                "DELETE FROM device_group_messages WHERE rowid IN (
                     SELECT rowid FROM device_group_messages
                     ORDER BY recorded_at DESC, rowid DESC
                     LIMIT -1 OFFSET ?1
                 )",
                params![MAX_DEVICE_GROUP_MESSAGES],
            )
            .storage()?;
            Ok(())
        })
    }

    /// Fill in the transport id each own send of `sent`, given as (device
    /// group, app event id, message id), became, where a row for it still
    /// lacks one. Messages with no row are not this device's to track.
    pub fn note_device_group_message_ids(
        &self,
        sent: &[(String, String, String)],
    ) -> StorageResult<()> {
        // Every drain comes here, chat sends included; most have nothing to
        // fill in, so they take no write lock.
        if sent.is_empty() {
            return Ok(());
        }
        let unidentified: bool = self
            .lock()?
            .query_row_cached(
                "SELECT EXISTS(
                     SELECT 1 FROM device_group_messages WHERE message_id_hex IS NULL
                 )",
                [],
                |row| row.get(0),
            )
            .storage()?;
        if !unidentified {
            return Ok(());
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for (group_id_hex, app_event_id, message_id_hex) in sent {
                conn.execute_cached(
                    "UPDATE device_group_messages SET message_id_hex = ?3
                     WHERE group_id_hex = ?1 AND app_event_id = ?2
                       AND message_id_hex IS NULL",
                    params![group_id_hex, app_event_id, message_id_hex],
                )
                .storage()?;
            }
            Ok(())
        })
    }

    /// The kind of the device-group message `message_id_hex` in
    /// `group_id_hex`, when this device recorded it.
    pub fn device_group_message_kind(
        &self,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> StorageResult<Option<u64>> {
        self.lock()?
            .query_row_cached(
                "SELECT kind FROM device_group_messages
                 WHERE group_id_hex = ?1 AND message_id_hex = ?2",
                params![group_id_hex, message_id_hex],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .storage()?
            .map(i64_to_u64)
            .transpose()
    }

    /// Every recorded message, oldest first. Test support only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn device_group_messages(&self) -> StorageResult<Vec<RecordedDeviceGroupMessage>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT group_id_hex, app_event_id, message_id_hex, kind
                 FROM device_group_messages ORDER BY recorded_at, rowid",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(group, event, message, kind)| Ok((group, event, message, i64_to_u64(kind)?)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    const DAY: u64 = 24 * 60 * 60;

    #[test]
    fn an_own_send_is_found_by_the_message_it_became_and_a_read_by_its_id() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store
            .record_device_group_message("aa", "e1", None, 475, 10)
            .unwrap();
        assert_eq!(store.device_group_message_kind("aa", "m1").unwrap(), None);
        store
            .note_device_group_message_ids(&[
                ("aa".into(), "e1".into(), "m1".into()),
                ("bb".into(), "e1".into(), "m9".into()),
            ])
            .unwrap();
        assert_eq!(
            store.device_group_message_kind("aa", "m1").unwrap(),
            Some(475)
        );
        assert_eq!(store.device_group_message_kind("bb", "m9").unwrap(), None);
        // A known message id stays.
        store
            .note_device_group_message_ids(&[("aa".into(), "e1".into(), "m2".into())])
            .unwrap();
        store
            .record_device_group_message("aa", "e1", None, 475, 11)
            .unwrap();
        assert_eq!(
            store.device_group_message_kind("aa", "m1").unwrap(),
            Some(475)
        );
        assert_eq!(store.device_group_message_kind("aa", "m2").unwrap(), None);

        store
            .record_device_group_message("aa", "e2", Some("m3"), 476, 12)
            .unwrap();
        assert_eq!(
            store.device_group_message_kind("aa", "m3").unwrap(),
            Some(476)
        );
        assert_eq!(store.device_group_message_kind("bb", "m3").unwrap(), None);
    }

    #[test]
    fn rows_go_after_a_week_and_beyond_the_cap() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store
            .record_device_group_message("aa", "old", Some("m0"), 475, DAY)
            .unwrap();
        store
            .record_device_group_message("aa", "kept", Some("m1"), 475, 2 * DAY)
            .unwrap();
        store
            .record_device_group_message("aa", "new", Some("m2"), 475, 8 * DAY + 1)
            .unwrap();
        assert_eq!(store.device_group_message_kind("aa", "m0").unwrap(), None);
        assert_eq!(
            store.device_group_message_kind("aa", "m1").unwrap(),
            Some(475)
        );

        for index in 0..MAX_DEVICE_GROUP_MESSAGES {
            store
                .record_device_group_message(
                    "aa",
                    &format!("e{index}"),
                    Some(&format!("n{index}")),
                    476,
                    9 * DAY,
                )
                .unwrap();
        }
        assert_eq!(store.device_group_message_kind("aa", "m2").unwrap(), None);
        assert_eq!(
            store.device_group_message_kind("aa", "n0").unwrap(),
            Some(476)
        );
    }
}
