//! Migration 0166: history deliveries through Blossom (mdk#2628 item 4.2c,
//! D77).
//!
//! - `history_deliveries_owed` gains `blossom_due_at` and `blossom_attempts`.
//!   `blossom_due_at` is NULL while a history goes inline; once it is too
//!   long for inline deliveries, it is when the sender next uploads it, in
//!   seconds. `blossom_attempts` counts failed uploads, for backoff. Owing a
//!   history afresh clears both.
//! - `history_deliveries_parked` is rebuilt so a delivery parks either its
//!   inline `bundle` or the `blossom` servers that hold it, newline-separated,
//!   never both. A Blossom delivery is fetched from `fetch_due_at`, in
//!   seconds, and `fetch_attempts` counts failed fetches, for backoff. Parked
//!   rows keep their order.
//!
//! No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE history_deliveries_owed ADD COLUMN blossom_due_at INTEGER
            CHECK(blossom_due_at IS NULL OR blossom_due_at >= 0);
        ALTER TABLE history_deliveries_owed ADD COLUMN blossom_attempts INTEGER NOT NULL
            DEFAULT 0 CHECK(blossom_attempts >= 0);
        CREATE TABLE history_deliveries_parked_0166 (
            app_event_id TEXT PRIMARY KEY NOT NULL,
            group_id_hex TEXT NOT NULL,
            sender_slot_hex TEXT NOT NULL,
            sealed BLOB NOT NULL,
            bundle BLOB,
            blossom TEXT,
            received_at INTEGER NOT NULL CHECK(received_at >= 0),
            fetch_due_at INTEGER CHECK(fetch_due_at IS NULL OR fetch_due_at >= 0),
            fetch_attempts INTEGER NOT NULL DEFAULT 0 CHECK(fetch_attempts >= 0),
            CHECK((bundle IS NULL) <> (blossom IS NULL)),
            CHECK((blossom IS NULL) = (fetch_due_at IS NULL))
        );
        INSERT INTO history_deliveries_parked_0166
            (app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, received_at)
        SELECT app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, received_at
        FROM history_deliveries_parked ORDER BY rowid;
        DROP TABLE history_deliveries_parked;
        ALTER TABLE history_deliveries_parked_0166 RENAME TO history_deliveries_parked;
        CREATE INDEX history_deliveries_parked_group
            ON history_deliveries_parked(group_id_hex);",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

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

    /// Parked rows keep every value and their order as inline rows, owed
    /// rows start with no upload due, and a row parks a bundle or servers,
    /// never both or neither.
    #[test]
    fn parked_and_owed_rows_survive_the_rebuild() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 165).unwrap();
        conn.execute_batch(
            "INSERT INTO history_deliveries_parked
                (app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, received_at)
             VALUES ('b', '01', 'aa', x'01', x'02', 20), ('a', '02', 'bb', x'03', x'04', 10);
             INSERT INTO history_deliveries_owed
                (group_id_hex, receiver_slot_hex, owed_at, sent_at, revision)
             VALUES ('01', 'aa', 5, 6, 2);",
        )
        .unwrap();
        run_through(&mut conn, 166).unwrap();

        let parked = conn
            .prepare(
                "SELECT app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, blossom,
                        received_at, fetch_due_at, fetch_attempts
                 FROM history_deliveries_parked ORDER BY rowid",
            )
            .unwrap()
            .query_map([], |row| {
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
            })
            .unwrap()
            .collect::<Result<Vec<ParkedRow>, _>>()
            .unwrap();
        let inline = |id: &str, group: &str, slot: &str, sealed: u8, bundle: u8, at| {
            (
                id.to_owned(),
                group.to_owned(),
                slot.to_owned(),
                vec![sealed],
                Some(vec![bundle]),
                None,
                at,
                None,
                0,
            )
        };
        assert_eq!(
            parked,
            vec![
                inline("b", "01", "aa", 1, 2, 20),
                inline("a", "02", "bb", 3, 4, 10)
            ]
        );
        let owed: (i64, Option<i64>, i64, Option<i64>, i64) = conn
            .query_row(
                "SELECT owed_at, sent_at, revision, blossom_due_at, blossom_attempts
                 FROM history_deliveries_owed",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(owed, (5, Some(6), 2, None, 0));

        let park = |bundle: &str, blossom: &str, fetch_due_at: &str| {
            conn.execute_batch(&format!(
                "INSERT INTO history_deliveries_parked
                    (app_event_id, group_id_hex, sender_slot_hex, sealed, bundle, blossom,
                     received_at, fetch_due_at)
                 VALUES ('c', '03', 'cc', x'05', {bundle}, {blossom}, 30, {fetch_due_at})"
            ))
        };
        for (bundle, blossom, fetch_due_at) in [
            ("x'06'", "'https://b.example/'", "30"),
            ("NULL", "NULL", "NULL"),
            ("NULL", "'https://b.example/'", "NULL"),
            ("x'06'", "NULL", "30"),
        ] {
            let refused = park(bundle, blossom, fetch_due_at).unwrap_err();
            assert!(
                refused.to_string().starts_with("CHECK constraint failed"),
                "{bundle} {blossom} {fetch_due_at}: {refused}"
            );
        }
        park("NULL", "'https://b.example/'", "30").unwrap();
    }
}
