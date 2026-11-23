//! Migration 0220: re-sort the chat-list rows the old rule anchored at their
//! creation (mdk#3580). `conversation_created_at` now orders a chat only while
//! it has no activity. The old rule took the largest of the two, so a chat a
//! linked device or a restore stored after it began sorted at the time it was
//! stored, above its older imported history. Only a row whose stored key is
//! its creation time while it records older activity changes; it takes that
//! activity, as the projection freshness check computes it. Rows without a
//! recorded preview or read position keep their key.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
WITH activity AS (
    SELECT row.group_id_hex, MAX(
        row.retained_activity_sort_at,
        COALESCE(row.last_message_timeline_at, 0),
        COALESCE((
            SELECT read_state.last_read_timeline_at
            FROM conversation_read_state AS read_state
            WHERE read_state.group_id_hex = row.group_id_hex
        ), 0)
    ) AS at
    FROM chat_list_rows AS row
)
UPDATE chat_list_rows
   SET activity_sort_at = activity.at
  FROM activity
 WHERE activity.group_id_hex = chat_list_rows.group_id_hex
   AND chat_list_rows.activity_sort_at = chat_list_rows.conversation_created_at
   AND activity.at > 0
   AND activity.at < chat_list_rows.conversation_created_at;
"#,
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    #[test]
    fn creation_orders_only_a_chat_with_no_activity() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 219).unwrap();
        // '11'-'44' were written by the old rule, creation 1000 outranking
        // their activity. '55' sorts by newer activity, and '66' holds a key
        // with no recorded preview, so both keep theirs.
        conn.execute_batch(
            r#"
            INSERT INTO account_groups(group_id_hex, endpoint, updated_at)
            VALUES ('11', 'fixture', 0), ('22', 'fixture', 0), ('33', 'fixture', 0),
                   ('44', 'fixture', 0), ('55', 'fixture', 0), ('66', 'fixture', 0);
            INSERT INTO conversation_read_state(group_id_hex, last_read_timeline_at, initialized_at, updated_at)
            VALUES ('22', 30, 0, 0);
            INSERT INTO chat_list_rows(group_id_hex, conversation_created_at, activity_sort_at,
                                       retained_activity_sort_at, last_message_timeline_at, updated_at)
            VALUES ('11', 1000, 1000, 0, 20, 0),
                   ('22', 1000, 1000, 0, NULL, 0),
                   ('33', 1000, 1000, 40, NULL, 0),
                   ('44', 1000, 1000, 0, NULL, 0),
                   ('55', 10, 50, 0, 50, 0),
                   ('66', 10, 70, 0, NULL, 0);
            "#,
        )
        .unwrap();

        run_through(&mut conn, 220).unwrap();

        let rows = conn
            .prepare(
                "SELECT group_id_hex, activity_sort_at FROM chat_list_rows ORDER BY group_id_hex",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let expected = [
            ("11", 20),
            ("22", 30),
            ("33", 40),
            ("44", 1000),
            ("55", 50),
            ("66", 70),
        ]
        .map(|(id, at)| (id.to_owned(), at));
        assert_eq!(rows, expected);
    }
}
