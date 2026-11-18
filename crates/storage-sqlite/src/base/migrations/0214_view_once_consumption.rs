use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE view_once_clock (
        id INTEGER PRIMARY KEY CHECK(id=1), high_water INTEGER NOT NULL CHECK(high_water>=0)
    );
    INSERT INTO view_once_clock VALUES(1,0);
    CREATE TABLE view_once_consumption (
        group_id_hex TEXT NOT NULL,
        message_id_hex TEXT NOT NULL,
        attachment_index INTEGER NOT NULL CHECK(attachment_index=0),
        state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3),
        expires_at INTEGER NOT NULL CHECK(expires_at>=0),
        policy_expires_at INTEGER NOT NULL CHECK(policy_expires_at>=0),
        source_epoch INTEGER,
        source_message_id_hex TEXT,
        sender TEXT NOT NULL,
        eligible INTEGER NOT NULL DEFAULT 0 CHECK(eligible IN(0,1)),
        revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),
        PRIMARY KEY(group_id_hex,message_id_hex,attachment_index)
    ) WITHOUT ROWID;
    CREATE INDEX view_once_expiry ON view_once_consumption(expires_at) WHERE state=0;
    CREATE TRIGGER view_once_source_removed BEFORE DELETE ON app_events BEGIN
        UPDATE view_once_consumption SET revoked=1
        WHERE group_id_hex=OLD.group_id_hex AND message_id_hex=OLD.message_id_hex AND state=1;
    END;
    CREATE TRIGGER view_once_source_withdrawn AFTER UPDATE OF invalidated ON app_events
    WHEN NEW.invalidated!=0 BEGIN
        UPDATE view_once_consumption SET revoked=1
        WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex AND state=1;
    END;
    CREATE TRIGGER view_once_source_finalized AFTER UPDATE OF source_epoch,source_message_id_hex ON app_events BEGIN
        UPDATE view_once_consumption SET source_epoch=coalesce(source_epoch,NEW.source_epoch),
            source_message_id_hex=coalesce(source_message_id_hex,NEW.source_message_id_hex)
        WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex AND state IN(0,2);
    END;
    CREATE TRIGGER view_once_message_deleted AFTER UPDATE OF deleted ON message_timeline
    WHEN NEW.deleted!=0 BEGIN
        UPDATE view_once_consumption SET revoked=1
        WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex AND state=1;
    END;
    CREATE TRIGGER view_once_group_removed BEFORE DELETE ON account_groups BEGIN
        UPDATE view_once_consumption SET revoked=1
        WHERE group_id_hex=OLD.group_id_hex AND state=1;
    END;
    CREATE TRIGGER view_once_group_departed AFTER UPDATE OF self_membership ON account_groups
    WHEN NEW.self_membership!='member' BEGIN
        UPDATE view_once_consumption SET revoked=1
        WHERE group_id_hex=NEW.group_id_hex AND state=1;
    END;
    CREATE TRIGGER view_once_group_pending AFTER UPDATE OF pending_confirmation ON account_groups
    WHEN NEW.pending_confirmation!=0 BEGIN
        UPDATE view_once_consumption SET revoked=1
        WHERE group_id_hex=NEW.group_id_hex AND state=1;
    END;
    CREATE TRIGGER view_once_retention_finalized AFTER UPDATE OF retention_expires_at ON app_events
    WHEN NEW.retention_expires_at IS NOT NULL BEGIN
        UPDATE view_once_consumption SET expires_at=min(expires_at,NEW.retention_expires_at)
        WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex;
    END;
    CREATE TRIGGER view_once_no_history BEFORE INSERT ON attachment_history
    WHEN EXISTS(SELECT 1 FROM view_once_consumption v WHERE v.group_id_hex=NEW.group_id_hex AND v.message_id_hex=NEW.message_id_hex)
    BEGIN SELECT RAISE(IGNORE); END;
    CREATE TRIGGER view_once_no_acquisition BEFORE INSERT ON attachment_acquisition
    WHEN EXISTS(SELECT 1 FROM view_once_consumption v WHERE v.group_id_hex=NEW.group_id_hex AND v.message_id_hex=NEW.message_id_hex)
    BEGIN SELECT RAISE(ABORT,'view-once ordinary acquisition forbidden'); END;")
    .storage()?;
    // Earlier schemas could not honor this profile or persist a claim. A historical
    // marker cannot establish a fresh opening merely because the client upgraded.
    tx.execute(
        "INSERT INTO view_once_consumption(
            group_id_hex,message_id_hex,attachment_index,state,expires_at,policy_expires_at,
            source_epoch,source_message_id_hex,sender,revoked
        ) SELECT group_id_hex,message_id_hex,0,3,0,0,source_epoch,source_message_id_hex,sender,1
        FROM app_events WHERE EXISTS (
            SELECT 1 FROM json_each(app_events.tags_json) tag
            WHERE json_extract(tag.value,'$[0]')='view-once'
               OR (json_extract(tag.value,'$[0]')='imeta' AND EXISTS (
                    SELECT 1 FROM json_each(tag.value) field
                    WHERE substr(field.value,1,27)='v encrypted-media-view-once'
               ))
        )",
        [],
    )
    .storage()?;
    let reactions = serde_json::to_string(&crate::TimelineReactionSummary::default())
        .map_err(|error| cgka_traits::storage::StorageError::Serialization(error.to_string()))?;
    tx.execute("UPDATE message_timeline SET plaintext='',tags_json=json_array(json_array('view-once')),media_json=NULL,agent_stream_json=NULL,edit_json=NULL,reply_to_message_id_hex=NULL,reactions_json=?1 WHERE (group_id_hex,message_id_hex) IN (SELECT group_id_hex,message_id_hex FROM view_once_consumption)",[reactions]).storage()?;
    tx.execute("DELETE FROM attachment_history WHERE (group_id_hex,message_id_hex) IN (SELECT group_id_hex,message_id_hex FROM view_once_consumption)",[]).storage()?;
    tx.execute("UPDATE app_events SET plaintext='',tags_json=json_array(json_array('view-once')) WHERE (group_id_hex,message_id_hex) IN (SELECT group_id_hex,message_id_hex FROM view_once_consumption WHERE state=3)",[]).storage()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn old_profile_cannot_claim() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::base::migrations::run_through(&mut conn, 213).unwrap();
        conn.execute(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES('aa','',0)",
            [],
        )
        .unwrap();
        let event = cgka_traits::MarmotAppEvent::new(
            "11".repeat(32),
            10,
            9,
            vec![
                vec!["view-once".into(), "view-once-v1".into(), "100".into()],
                vec![
                    "imeta".into(),
                    "v encrypted-media-view-once-v1".into(),
                    "m image/png".into(),
                    "filename image.png".into(),
                    format!("plaintext_sha256 {}", "22".repeat(32)),
                    format!("ciphertext_sha256 {}", "33".repeat(32)),
                    format!("nonce {}", "44".repeat(12)),
                    format!("locator blossom-v1 https://example.com/{}", "33".repeat(32)),
                ],
            ],
            "",
        );
        conn.execute("INSERT INTO app_events(group_id_hex,message_id_hex,source_message_id_hex,source_epoch,direction,sender,plaintext,kind,tags_json,recorded_at,received_at) VALUES('aa',?1,?1,3,'received',?2,'',9,?3,10,11)", rusqlite::params![&event.id, &event.pubkey, serde_json::to_string(&event.tags).unwrap()]).unwrap();
        let ordinary =
            serde_json::json!([["imeta", "v encrypted-media-v2", "filename view-once.png"]])
                .to_string();
        conn.execute("INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at) VALUES('aa','ordinary-keyword','received','author','keep',9,?1,10,11)", [ordinary]).unwrap();
        crate::base::migrations::run_through(&mut conn, 214).unwrap();
        let state: (i64, i64) = conn
            .query_row(
                "SELECT state,revoked FROM view_once_consumption WHERE message_id_hex=?1",
                [&event.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, (3, 1));
        let tags: String = conn
            .query_row(
                "SELECT tags_json FROM app_events WHERE message_id_hex=?1",
                [&event.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&tags).unwrap(),
            serde_json::json!([["view-once"]])
        );
        let ordinary: String = conn
            .query_row(
                "SELECT plaintext FROM app_events WHERE message_id_hex='ordinary-keyword'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ordinary, "keep");
        let classified: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM view_once_consumption WHERE message_id_hex='ordinary-keyword')", [], |r| r.get(0)).unwrap();
        assert!(!classified);
    }

    #[test]
    fn old_markers_stay_unavailable() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::base::migrations::run_through(&mut conn, 213).unwrap();
        conn.execute(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES('aa','',0)",
            [],
        )
        .unwrap();
        let tags = serde_json::json!([
            [
                "imeta",
                "v encrypted-media-v2",
                "m image/png",
                "locator secret"
            ],
            ["view-once", "unknown", "100", "private-caption"]
        ])
        .to_string();
        let adjacent = serde_json::json!([[
            "imeta",
            "v encrypted-media-view-once-v2",
            "locator secret",
            "filename private.png",
            "nonce private"
        ]])
        .to_string();
        let bare = serde_json::json!([[
            "imeta",
            "v encrypted-media-view-once",
            "locator secret",
            "filename private.png",
            "nonce private"
        ]])
        .to_string();
        for (id, tags) in [
            ("once", tags),
            ("adjacent", adjacent),
            ("bare", bare),
            ("ordinary", "[]".into()),
        ] {
            conn.execute("INSERT INTO app_events(group_id_hex,message_id_hex,source_message_id_hex,source_epoch,direction,sender,plaintext,kind,tags_json,recorded_at,received_at) VALUES('aa',?1,?1,3,'received','author','caption',9,?2,10,11)",rusqlite::params![id,tags]).unwrap();
            conn.execute("INSERT INTO message_timeline(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,media_json) VALUES('aa',?1,'received','author','caption',9,?2,10,11,'{}','{\"filename\":\"private.png\"}')",rusqlite::params![id,tags]).unwrap();
        }
        crate::base::migrations::run_through(&mut conn, 214).unwrap();
        let state:(i64,i64)=conn.query_row("SELECT state,expires_at FROM view_once_consumption WHERE group_id_hex='aa' AND message_id_hex='once'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(state, (3, 0));
        let content:(String,String)=conn.query_row("SELECT plaintext,tags_json FROM app_events WHERE group_id_hex='aa' AND message_id_hex='once'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(content.0, "");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&content.1).unwrap(),
            serde_json::json!([["view-once"]])
        );
        assert_eq!(conn.query_row("SELECT plaintext FROM app_events WHERE group_id_hex='aa' AND message_id_hex='ordinary'",[],|r|r.get::<_,String>(0)).unwrap(),"caption");
        for id in ["once", "adjacent", "bare"] {
            let row: (i64,i64,i64,String,String,String,String,Option<String>) = conn.query_row("SELECT v.state,v.eligible,v.revoked,a.plaintext,a.tags_json,t.plaintext,t.tags_json,t.media_json FROM view_once_consumption v JOIN app_events a USING(group_id_hex,message_id_hex) JOIN message_timeline t USING(group_id_hex,message_id_hex) WHERE v.message_id_hex=?1", [id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?))).unwrap();
            assert_eq!(
                row,
                (
                    3,
                    0,
                    1,
                    String::new(),
                    "[[\"view-once\"]]".into(),
                    String::new(),
                    "[[\"view-once\"]]".into(),
                    None
                )
            );
        }
        assert_eq!(
            conn.query_row("SELECT count(*) FROM view_once_consumption", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            3
        );
    }
}
