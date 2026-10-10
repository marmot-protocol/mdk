//! Disposable complete roster and normalized literal text inputs for selection.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE chat_folder_rosters (
            group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
            group_id_hex TEXT NOT NULL UNIQUE,
            complete INTEGER NOT NULL CHECK(complete IN (0,1)),
            member_count INTEGER NOT NULL CHECK(member_count>=0)
            ,members_digest BLOB NOT NULL CHECK(length(members_digest)=32)
        );
        CREATE TABLE chat_folder_members (
            group_id BLOB NOT NULL REFERENCES chat_folder_rosters(group_id) ON DELETE CASCADE,
            member_id_hex TEXT NOT NULL CHECK(length(member_id_hex)=64),
            PRIMARY KEY(group_id,member_id_hex)
        ) WITHOUT ROWID;
        CREATE INDEX chat_folder_member_groups ON chat_folder_members(member_id_hex,group_id);
        CREATE INDEX idx_chat_folder_pending_submission ON local_message_submissions(group_id_hex) WHERE state=0;
        CREATE INDEX idx_chat_folder_pending_send ON message_timeline(group_id_hex)
            WHERE direction='sent' AND source_message_id_hex IS NULL AND invalidation_status IS NULL AND deleted=0;
        CREATE TABLE chat_folder_roster_work (
            group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE
        ) WITHOUT ROWID;
        INSERT INTO chat_folder_roster_work SELECT id FROM cgka_groups;
        CREATE TRIGGER chat_folder_group_inserted AFTER INSERT ON cgka_groups BEGIN
            INSERT INTO chat_folder_roster_work SELECT NEW.id
                WHERE NOT EXISTS(SELECT 1 FROM chat_folder_roster_work WHERE group_id=NEW.id);
        END;
        CREATE TRIGGER chat_folder_group_updated AFTER UPDATE OF id,record ON cgka_groups
        WHEN OLD.id IS NOT NEW.id OR OLD.record IS NOT NEW.record BEGIN
            INSERT INTO chat_folder_roster_work SELECT NEW.id
                WHERE NOT EXISTS(SELECT 1 FROM chat_folder_roster_work WHERE group_id=NEW.id);
        END;
        ALTER TABLE chat_list_rows ADD COLUMN folder_title_fold TEXT;
        ALTER TABLE chat_list_rows ADD COLUMN folder_description_fold TEXT;
        -- Existing selected values reprepare through the bounded presentation worker.
        UPDATE chat_list_rows SET presentation_json=NULL,
            presentation_source_revision=presentation_source_revision+1;
        CREATE TRIGGER chat_folder_description_changed AFTER UPDATE OF profile_description ON account_groups
        WHEN OLD.profile_description IS NOT NEW.profile_description BEGIN
            UPDATE chat_list_rows SET folder_description_fold=NULL,
                presentation_source_revision=presentation_source_revision+1
                WHERE group_id_hex=NEW.group_id_hex;
        END;",
    ).storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn populated_upgrade_is_atomic_and_invalidates_restore_and_description_inputs() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE cgka_groups(id BLOB PRIMARY KEY,record BLOB);
            CREATE TABLE account_groups(group_id_hex TEXT PRIMARY KEY,profile_description TEXT);
            CREATE TABLE local_message_submissions(group_id_hex TEXT,state INTEGER);
            CREATE TABLE message_timeline(group_id_hex TEXT,direction TEXT,source_message_id_hex TEXT,invalidation_status TEXT,deleted INTEGER);
            CREATE TABLE chat_list_rows(group_id_hex TEXT PRIMARY KEY,presentation_json BLOB,presentation_source_revision INTEGER);
            INSERT INTO cgka_groups VALUES(x'01',x'00');
            INSERT INTO account_groups VALUES('01','old');
            INSERT INTO chat_list_rows VALUES('01',x'7b7d',10);").unwrap();
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.rollback().unwrap();
        assert!(
            conn.prepare("SELECT folder_title_fold FROM chat_list_rows")
                .is_err()
        );
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.commit().unwrap();
        let source: (Option<Vec<u8>>, i64) = conn
            .query_row(
                "SELECT presentation_json,presentation_source_revision FROM chat_list_rows",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(source, (None, 11));
        assert_eq!(
            conn.query_row("SELECT count(*) FROM chat_folder_roster_work", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        conn.execute_batch(
            "INSERT INTO chat_folder_rosters VALUES(x'01','01',1,0,zeroblob(32));
            DELETE FROM chat_folder_roster_work;
            UPDATE cgka_groups SET record=x'01';
            -- The outer statement's conflict policy can override trigger OR IGNORE.
            INSERT INTO cgka_groups VALUES(x'01',x'02') ON CONFLICT(id) DO UPDATE SET record=excluded.record;
            INSERT OR REPLACE INTO cgka_groups VALUES(x'01',x'03');
            UPDATE account_groups SET profile_description='new';",
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM chat_folder_roster_work", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT presentation_source_revision FROM chat_list_rows",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            12
        );
        conn.execute("DELETE FROM cgka_groups", []).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM chat_folder_roster_work", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM chat_folder_rosters", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
