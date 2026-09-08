use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Only metadata at upgrade: neither inventory nor serialized fanouts are
    // scanned on open. New accounts have no historical work to schedule.
    tx.execute_batch(
        "CREATE TABLE cgka_outbound_transport_receipt_ids (
             message_id BLOB PRIMARY KEY REFERENCES cgka_outbound_fanout(message_id) ON DELETE CASCADE,
             published_message_id BLOB NOT NULL
         );
         CREATE INDEX idx_outbound_transport_receipt_id
             ON cgka_outbound_transport_receipt_ids(published_message_id);
         CREATE TABLE app_historical_receipt_repair (
             account_label TEXT PRIMARY KEY REFERENCES account_state(label) ON DELETE CASCADE,
             fanout_after INTEGER NOT NULL DEFAULT 0,
             fanout_until INTEGER,
             fanout_done INTEGER NOT NULL DEFAULT 0,
             route_after BLOB NOT NULL DEFAULT x'',
             event_after BLOB NOT NULL DEFAULT x'',
             route_until BLOB,
             event_until BLOB
         );
         INSERT INTO app_historical_receipt_repair(account_label)
             SELECT label FROM account_state;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::{SqliteAccountStorage, SqliteStorageOptions, migrations, unix_now_seconds_i64};
    use rusqlite::{Connection, params};

    #[test]
    fn populated_pre_journal_and_chat_presentation_upgrade_preserves_history() {
        for version in [57, 59, 65] {
            let mut conn = Connection::open_in_memory().unwrap();
            conn.pragma_update(None, "foreign_keys", "ON").unwrap();
            migrations::run(&mut conn, &migrations::MIGRATIONS[..version]).unwrap();
            conn.execute_batch(
                "INSERT INTO account_state(label,updated_at) VALUES ('alice',0);
                INSERT INTO cgka_groups(id,epoch,record) VALUES (x'aa',3,x'00');",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cgka_transport_group_routes VALUES (?1,x'aa',2)",
                [&[1_u8; 32][..]],
            )
            .unwrap();
            for id in [1_u8, 2] {
                // One released wrapper and one accepted historical wrapper whose
                // outer marker never existed. Both have uncertain possession.
                conn.execute(
                    "INSERT INTO transport_reconciliation_items VALUES (1,?1,?2,?3)",
                    params![&[1_u8; 32][..], &[id; 32][..], unix_now_seconds_i64()],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO seen_events VALUES (?1,0)",
                    [hex::encode([id; 32])],
                )
                .unwrap();
            }
            conn.execute_batch("INSERT INTO cgka_messages(id,group_id,epoch,state,storage_format,payload)
                    VALUES (x'cc',x'aa',3,2,2,x'00');
                INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
                    VALUES ('aa','cc','received','sender','accepted historical message',9,'[]',1,1);").unwrap();
            if version == 65 {
                conn.execute("UPDATE chat_presentation_meta SET revision = 7", [])
                    .unwrap();
            }
            let store = SqliteAccountStorage::from_connection_with_options(
                conn,
                SqliteStorageOptions::default(),
            )
            .unwrap();
            assert!(
                store
                    .consume_released_transport_receipts()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                store
                    .lock()
                    .unwrap()
                    .query_row("SELECT count(*) FROM seen_events", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                2
            );
            let p = store.repair_uncertain_transport_receipts(1).unwrap();
            assert_eq!(p.repaired, 1);
            assert!(p.has_more);
            store.consume_released_transport_receipts().unwrap();
            assert_eq!(
                store
                    .repair_uncertain_transport_receipts(1)
                    .unwrap()
                    .repaired,
                1
            );
            store.consume_released_transport_receipts().unwrap();
            assert_eq!(
                migrations::applied_name(&store.lock().unwrap(), 65)
                    .unwrap()
                    .as_deref(),
                Some("0065_chat_presentation")
            );
            assert_eq!(
                migrations::applied_name(&store.lock().unwrap(), 66)
                    .unwrap()
                    .as_deref(),
                Some("0066_historical_receipt_repair")
            );
            if version == 65 {
                assert_eq!(
                    store
                        .lock()
                        .unwrap()
                        .query_row("SELECT revision FROM chat_presentation_meta", [], |r| r
                            .get::<_, i64>(0))
                        .unwrap(),
                    7
                );
            }
            let conn = store.lock().unwrap();
            assert_eq!(
                conn.query_row("SELECT count(*) FROM cgka_messages", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                conn.query_row("SELECT plaintext FROM app_events", [], |r| r
                    .get::<_, String>(0))
                    .unwrap(),
                "accepted historical message"
            );
        }
    }
}
