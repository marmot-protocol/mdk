//! Fence presentation-role changes without copying source metadata into another index.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Existing rows need no backfill: page reads point-read their canonical source tags.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TRIGGER attachment_emoji_tags_changed AFTER UPDATE OF tags_json ON message_timeline
        WHEN OLD.tags_json IS NOT NEW.tags_json AND EXISTS (
            SELECT 1 FROM attachment_history WHERE group_id_hex=NEW.group_id_hex
                AND message_id_hex=NEW.message_id_hex AND visible=1
        ) BEGIN
            UPDATE attachment_history_versions SET revision=revision+1 WHERE group_id_hex=NEW.group_id_hex;
        END;") .storage()
}

#[cfg(test)]
mod tests {

    /// Upgrading a populated older database preserves slots and fences later tag edits.
    #[test]
    fn retained_slots_gain_role_invalidation_without_backfill() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::migrations::run(&mut conn, &crate::migrations::MIGRATIONS[..101]).unwrap();
        conn.execute_batch("INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,media_json)
            VALUES('aa','old','source','received','alice','private body',9,'[]',1,1,'[]','{\"imeta\":[[\"imeta\",\"v future\"]]}');").unwrap();
        crate::migrations::run_all(&mut conn).unwrap();
        assert_eq!(crate::migrations::run_all(&mut conn).unwrap(), 0);
        let revision: i64 = conn
            .query_row(
                "SELECT revision FROM attachment_history_versions WHERE group_id_hex='aa'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute_batch("UPDATE message_timeline SET tags_json='[[\"emoji\",\"wave\",\"https://example.com/a\"]]' WHERE message_id_hex='old';").unwrap();
        let after: i64 = conn
            .query_row(
                "SELECT revision FROM attachment_history_versions WHERE group_id_hex='aa'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(after > revision);
        let slots: i64 = conn
            .query_row(
                "SELECT count(*) FROM attachment_history WHERE message_id_hex='old'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(slots, 1);
    }
}
