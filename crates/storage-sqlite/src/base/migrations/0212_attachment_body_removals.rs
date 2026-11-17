use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE attachment_body_removal_meta (
            id INTEGER PRIMARY KEY CHECK(id=1),
            high_water INTEGER NOT NULL DEFAULT 0 CHECK(high_water>=0)
        );
        INSERT INTO attachment_body_removal_meta(id) VALUES(1);
        CREATE TABLE attachment_body_removals (
            sequence INTEGER PRIMARY KEY,
            group_id_hex TEXT NOT NULL,
            message_id_hex TEXT NOT NULL,
            source_message_id_hex TEXT NOT NULL,
            attachment_index INTEGER NOT NULL CHECK(attachment_index>=0),
            state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3)
        );
        CREATE TRIGGER attachment_body_removal_bounded AFTER INSERT ON attachment_body_removals BEGIN
            UPDATE attachment_body_removal_meta SET high_water=NEW.sequence WHERE id=1;
            DELETE FROM attachment_body_removals WHERE sequence<=NEW.sequence-4096;
        END;
        CREATE TRIGGER attachment_body_removal_reset BEFORE UPDATE OF store_epoch ON chat_presentation_meta
        WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
            DELETE FROM attachment_body_removals;
        END;",
    ).storage()?;

    let legacy = "EXISTS(SELECT 1 FROM retained_attachment_bytes b WHERE b.token=q.token
        AND NOT EXISTS(SELECT 1 FROM retained_attachment_files f WHERE f.token=q.token AND f.completed=0))";
    let media = "EXISTS(SELECT 1 FROM media_file_refs mr JOIN media_files mf ON mf.id=mr.file_id
        WHERE mr.token=q.token AND mf.state=1)";
    let fields =
        "sequence,group_id_hex,message_id_hex,source_message_id_hex,attachment_index,state";
    // One high-water snapshot plus a row number also allocates multi-slot losses.
    let identity =
        "(SELECT high_water FROM attachment_body_removal_meta WHERE id=1)+row_number() OVER(),
        q.group_id_hex,q.message_id_hex,q.source_message_id_hex,q.attachment_index";

    // The parent is still present here. Child cascades see no acquisition and
    // cannot announce this same loss again, even when app_events was the parent.
    tx.execute_batch(&format!(
        "CREATE TRIGGER attachment_body_acquisition_removed BEFORE DELETE ON attachment_acquisition
        WHEN OLD.state=3 BEGIN
            INSERT INTO attachment_body_removals({fields})
            SELECT {identity},coalesce((SELECT CASE reason WHEN 1 THEN 0 ELSE 1 END
                FROM attachment_removal_suppression s WHERE s.group_id_hex=q.group_id_hex
                AND s.message_id_hex=q.message_id_hex AND s.attachment_index=q.attachment_index),3)
            FROM attachment_acquisition q WHERE q.token=OLD.token AND ({legacy} OR {media});
        END;
        CREATE TRIGGER attachment_body_source_hidden AFTER UPDATE OF visible ON attachment_history
        WHEN OLD.visible=1 AND NEW.visible=0 BEGIN
            INSERT INTO attachment_body_removals({fields})
            SELECT {identity},3 FROM attachment_acquisition q
            WHERE q.group_id_hex=NEW.group_id_hex AND q.message_id_hex=NEW.message_id_hex
                AND q.attachment_index=NEW.attachment_index AND q.state=3 AND ({legacy} OR {media});
        END;
        CREATE TRIGGER attachment_body_legacy_removed BEFORE DELETE ON retained_attachment_bytes BEGIN
            INSERT INTO attachment_body_removals({fields})
            SELECT {identity},3 FROM attachment_acquisition q
            WHERE q.token=OLD.token AND q.state=3 AND {legacy} AND NOT {media};
        END;
        CREATE TRIGGER attachment_body_file_removed AFTER DELETE ON retained_attachment_files
        WHEN OLD.completed=1 BEGIN
            INSERT INTO attachment_body_removals({fields})
            SELECT {identity},3 FROM attachment_acquisition q
            WHERE q.token=OLD.token AND q.state=3
                AND EXISTS(SELECT 1 FROM retained_attachment_bytes b WHERE b.token=q.token)
                AND NOT {media};
        END;
        CREATE TRIGGER attachment_body_media_detached BEFORE DELETE ON media_file_refs BEGIN
            INSERT INTO attachment_body_removals({fields})
            SELECT {identity},3 FROM attachment_acquisition q
            WHERE q.token=OLD.token AND q.state=3
                AND EXISTS(SELECT 1 FROM media_files mf WHERE mf.id=OLD.file_id AND mf.state=1)
                AND NOT {legacy};
        END;
        CREATE TRIGGER attachment_body_media_lost AFTER UPDATE OF state ON media_files
        WHEN OLD.state=1 AND NEW.state<>1 BEGIN
            INSERT INTO attachment_body_removals({fields})
            SELECT {identity},3 FROM media_file_refs mr JOIN attachment_acquisition q ON q.token=mr.token
            WHERE mr.file_id=NEW.id AND q.state=3 AND NOT {legacy};
        END;"
    )).storage()?;

    // A receipt during an active attempt is not a loss: publication can still
    // retain it. Announce only the transition to the settled, bodyless state.
    let settled = |row: &str| {
        format!(
        "{row}.automatic_history=1 AND {row}.body_completed=1 AND {row}.state NOT IN (1,3)
         AND {row}.cancelled=0 AND NOT ({row}.state=4 AND {row}.storage_blocked_headroom IS NOT NULL)"
    )
    };
    tx.execute_batch(&format!(
        "CREATE TRIGGER attachment_body_completed_unretained AFTER UPDATE ON attachment_acquisition
        WHEN ({new}) AND NOT ({old}) BEGIN
            INSERT INTO attachment_body_removals({fields})
            SELECT {identity},2 FROM attachment_acquisition q
            WHERE q.token=NEW.token AND NOT {legacy} AND NOT {media};
        END;",
        new = settled("NEW"),
        old = settled("OLD"),
    ))
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    #[test]
    fn migration_keep_bodies_receipts() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        run_through(&mut conn, 211).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES('aa','',0);
            INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
                VALUES('aa','m','received','author','',9,'[]',1,1);
            INSERT INTO attachment_acquisition(token,group_id_hex,message_id_hex,attachment_index,
                source_message_id_hex,source_epoch,slot_json,plaintext_digest,state,due,attempt,automatic_history,body_completed)
                VALUES(x'00000000000000000000000000000001','aa','m',0,'source',1,'[]',zeroblob(32),3,NULL,NULL,0,0),
                (x'00000000000000000000000000000002','aa','m',1,'source',1,'[]',zeroblob(32),1,10,zeroblob(16),0,0),
                (x'00000000000000000000000000000003','aa','m',2,'source',1,'[]',zeroblob(32),4,NULL,NULL,1,1);
            INSERT INTO retained_attachment_bytes(token,byte_len,bytes)
                VALUES(x'00000000000000000000000000000001',2,x'0102'),
                (x'00000000000000000000000000000002',0,x'');
            INSERT INTO attachment_chunk_bodies VALUES(zeroblob(16));
            INSERT INTO retained_attachment_files(token,nonce,attempt,byte_len,completed)
                VALUES(x'00000000000000000000000000000002',zeroblob(16),zeroblob(16),100,0);",
        ).unwrap();
        run_through(&mut conn, 212).unwrap();
        let body: Vec<u8> = conn.query_row(
            "SELECT bytes FROM retained_attachment_bytes WHERE token=x'00000000000000000000000000000001'",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(body, [1, 2]);
        assert_eq!(
            conn.query_row(
                "SELECT sum(body_completed) FROM attachment_acquisition",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM attachment_body_removals", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0,
            "installing the journal cannot announce historical losses"
        );
        conn.execute(
            "DELETE FROM attachment_acquisition WHERE attachment_index=1",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM attachment_body_removals", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0,
            "discarding an unfinished file is not a retained-body loss"
        );
    }
}
