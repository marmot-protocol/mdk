//! Frozen schema-208 comment projection and retained media-key references.
use crate::SqliteResultExt;
use crate::base::connection::CachedSql;
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params, types::ValueRef};
use serde_json::json;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    upgrade_attachment_sources(tx)?;
    repair_comments(tx, |tags| {
        tags.iter().any(|tag| {
            tag.first().is_some_and(|name| name == "k")
                && tag.get(1).is_some_and(|kind| kind.parse::<u64>().is_ok())
        })
    })
}

/// Project every stored kind-1111 event whose tags pass `recognized` as a
/// comment: parent, media, accepted edit and retained media-key references.
/// Migration 0217 reuses it for comments recognized by `e` alone.
pub(super) fn repair_comments(
    tx: &Transaction<'_>,
    recognized: impl Fn(&[Vec<String>]) -> bool,
) -> StorageResult<()> {
    let mut sources = tx
        .prepare(
            "SELECT e.group_id_hex, e.message_id_hex, e.tags_json, e.source_epoch,
                    e.plaintext, e.invalidated, t.deleted, t.invalidation_status, t.sender
             FROM app_events AS e
             LEFT JOIN message_timeline AS t
               ON t.group_id_hex = e.group_id_hex AND t.message_id_hex = e.message_id_hex
              AND t.kind = 1111
             WHERE e.kind = 1111",
        )
        .storage()?;
    let mut rows = sources.query([]).storage()?;
    while let Some(row) = rows.next().storage()? {
        // Damaged source tags decode as empty in the runtime. They cannot prove
        // comment recognition, and must not prevent the account from opening.
        let Some(tags) = tags(row, 2) else {
            continue;
        };
        if !recognized(&tags) {
            continue;
        }
        let group: String = row.get(0).storage()?;
        let message: String = row.get(1).storage()?;
        if let Some(epoch) = row
            .get::<_, Option<i64>>(3)
            .storage()?
            .filter(|epoch| *epoch >= 0)
        {
            backfill_media_references(tx, &group, &message, epoch, &tags)?;
        }
        let Some(deleted) = row.get::<_, Option<bool>>(6).storage()? else {
            // Retained source rows without a timeline row still own their keys.
            continue;
        };
        let invalidated = row.get::<_, i64>(5).storage()? != 0
            || !matches!(row.get_ref(7).storage()?, ValueRef::Null);
        let mut plaintext = if deleted {
            None
        } else {
            Some(row.get::<_, String>(4).storage()?)
        };
        let mut edit_json = None;
        if !deleted && !invalidated {
            let sender: String = row.get(8).storage()?;
            if let Some((text, summary)) = accepted_edit(tx, &group, &message, &sender)? {
                plaintext = Some(text);
                edit_json = Some(summary);
            }
        }
        // The first lowercase e is authoritative even when it lacks a value;
        // q is a body quote and must never become the parent.
        let parent = tags
            .iter()
            .find(|tag| tag.first().is_some_and(|name| name == "e"))
            .and_then(|tag| tag.get(1));
        let media_json = if deleted {
            None
        } else {
            let imeta: Vec<_> = tags
                .iter()
                .filter(|tag| tag.first().is_some_and(|name| name == "imeta"))
                .collect();
            (!imeta.is_empty()).then(|| json!({ "imeta": imeta }).to_string())
        };
        tx.execute_cached(
            "UPDATE message_timeline
             SET reply_to_message_id_hex = ?3, media_json = ?4, edit_json = ?5,
                 plaintext = CASE WHEN deleted = 0 THEN ?6 ELSE plaintext END
             WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND kind = 1111",
            params![group, message, parent, media_json, edit_json, plaintext],
        )
        .storage()?;
        // An already-correct media container need not fire the update trigger.
        // Populate only this recognized comment, leaving unrelated rows alone.
        tx.execute_cached(
            "INSERT OR IGNORE INTO attachment_history(group_id_hex,message_id_hex,attachment_index,
                 source_message_id_hex,source_epoch,sender,timeline_at,received_at,
                 order_class,order_primary,order_phase,order_at,slot_json,visible)
             SELECT * FROM chat_attachment_history_source
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![group, message],
        )
        .storage()?;
    }
    Ok(())
}

fn upgrade_attachment_sources(tx: &Transaction<'_>) -> StorageResult<()> {
    // The projector supplies media only for chats and recognized comments.
    // Keep recognition in Rust rather than approximating parse::<u64> in SQL.
    // The reaction view, union and its triggers remain unchanged.
    tx.execute_batch(r#"
        DROP TRIGGER attachment_source_insert;
        DROP VIEW chat_attachment_history_source;
        CREATE VIEW chat_attachment_history_source AS
        SELECT t.group_id_hex,t.message_id_hex,CAST(j.key AS INTEGER) AS attachment_index,
               COALESCE(t.source_message_id_hex,t.message_id_hex) AS source_message_id_hex,
               t.source_epoch,t.sender,t.timeline_at,t.received_at,
               t.timeline_order_class AS order_class,t.timeline_order_primary AS order_primary,
               t.timeline_order_phase AS order_phase,t.timeline_order_at AS order_at,
               CASE WHEN j.type IN ('array','object') THEN j.value
                    WHEN j.type IN ('true','false') THEN j.type
                    ELSE json_quote(j.value) END AS slot_json,
               (t.sender NOT IN (SELECT public_key FROM user_blocks)
                AND t.group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)) AS visible
        FROM message_timeline t, json_each(
            CASE WHEN t.media_json IS NULL THEN '[]'
                 WHEN NOT json_valid(t.media_json) THEN '[null]'
                 WHEN json_type(t.media_json) != 'object' THEN '[null]'
                 WHEN json_type(t.media_json,'$.imeta') IS NULL THEN '[]'
                 WHEN json_type(t.media_json,'$.imeta') != 'array' THEN '[null]'
                 ELSE json_extract(t.media_json,'$.imeta') END
        ) j
        WHERE t.kind IN (9,1111)
          AND (t.source_message_id_hex IS NOT NULL OR EXISTS(
              SELECT 1 FROM app_event_imports i
              WHERE i.group_id_hex=t.group_id_hex AND i.message_id_hex=t.message_id_hex))
          AND t.deleted=0 AND t.invalidation_status IS NULL;

        CREATE TRIGGER attachment_source_insert AFTER INSERT ON message_timeline
        WHEN NEW.kind IN (9,1111) AND NEW.media_json IS NOT NULL AND NEW.deleted=0 AND NEW.invalidation_status IS NULL
         AND (NEW.source_message_id_hex IS NOT NULL OR EXISTS(
             SELECT 1 FROM app_event_imports i
             WHERE i.group_id_hex=NEW.group_id_hex AND i.message_id_hex=NEW.message_id_hex)) BEGIN
            INSERT INTO attachment_history(group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
                source_epoch,sender,timeline_at,received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
            SELECT * FROM attachment_history_source WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex;
        END;
    "#).storage()
}

fn tags(row: &rusqlite::Row<'_>, index: usize) -> Option<Vec<Vec<String>>> {
    match row.get_ref(index).ok()? {
        ValueRef::Text(bytes) => serde_json::from_slice(bytes).ok(),
        _ => None,
    }
}

fn accepted_edit(
    tx: &Transaction<'_>,
    group: &str,
    message: &str,
    sender: &str,
) -> StorageResult<Option<(String, String)>> {
    let mut statement = tx
        .prepare_cached(
            "SELECT e.message_id_hex, e.plaintext, e.recorded_at, e.tags_json
         FROM message_modifier_edges AS edge
         CROSS JOIN app_events AS e
           ON e.group_id_hex = edge.group_id_hex AND e.message_id_hex = edge.modifier_message_id_hex
         WHERE edge.group_id_hex = ?1 AND edge.target_message_id_hex = ?2 AND edge.kind = 1009
           AND e.kind = 1009 AND e.invalidated = 0 AND e.sender = ?3
           AND NOT EXISTS (
               SELECT 1 FROM message_modifier_edges AS retraction
               JOIN app_events AS d
                 ON d.group_id_hex = retraction.group_id_hex
                AND d.message_id_hex = retraction.modifier_message_id_hex
               WHERE retraction.group_id_hex = e.group_id_hex
                 AND retraction.target_message_id_hex = e.message_id_hex
                 AND retraction.kind = 5 AND d.invalidated = 0 AND d.sender = e.sender)",
        )
        .storage()?;
    let mut rows = statement.query(params![group, message, sender]).storage()?;
    let mut count = 0_u64;
    let mut latest: Option<(u64, String, String)> = None;
    while let Some(row) = rows.next().storage()? {
        let Some(tags) = tags(row, 3) else {
            continue;
        };
        let mut targets = tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|name| name == "e"));
        if targets
            .next()
            .and_then(|tag| tag.get(1))
            .map(String::as_str)
            != Some(message)
            || targets.next().is_some()
        {
            continue;
        }
        count += 1;
        let at = u64::try_from(row.get::<_, i64>(2).storage()?).unwrap_or_default();
        let id: String = row.get(0).storage()?;
        if latest
            .as_ref()
            .is_none_or(|(time, message, _)| (at, &id) > (*time, message))
        {
            latest = Some((at, id, row.get(1).storage()?));
        }
    }
    Ok(latest.map(|(at, id, text)| {
        (
            text,
            json!({
                "edit_count": count,
                "latest_edit_message_id_hex": id,
                "edited_at": at,
            })
            .to_string(),
        )
    }))
}

fn backfill_media_references(
    tx: &Transaction<'_>,
    group: &str,
    message: &str,
    epoch: i64,
    tags: &[Vec<String>],
) -> StorageResult<()> {
    // These version strings and component ids are part of schema 208, not the
    // evolving live encrypted-media parser. Duplicate version fields are invalid.
    let mut components = [false; 2];
    for tag in tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|name| name == "imeta"))
    {
        let mut versions = tag
            .iter()
            .skip(1)
            .filter_map(|field| field.strip_prefix("v "));
        let Some(version) = versions.next() else {
            continue;
        };
        if versions.next().is_some() {
            continue;
        }
        match version {
            "encrypted-media-v1" => components[0] = true,
            "encrypted-media-v2" => components[1] = true,
            _ => {}
        }
    }
    for (present, component) in components.into_iter().zip([0x8008, 0x800b]) {
        if present {
            tx.execute_cached(
                "INSERT OR IGNORE INTO encrypted_media_epoch_secret_references
                     (group_id_hex, message_id_hex, component_id, source_epoch)
                 VALUES (?1, ?2, ?3, ?4)",
                params![group, message, component, epoch],
            )
            .storage()?;
        }
    }
    if components.into_iter().any(|present| present) {
        // Both formats share the exporter: all cached components for this epoch
        // become retention-managed, just as on a new app-event write.
        tx.execute_cached(
            "UPDATE encrypted_media_epoch_secrets SET retention_managed = 1
             WHERE group_id_hex = ?1 AND source_epoch = ?2 AND retention_managed = 0",
            params![group, epoch],
        )
        .storage()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;
    use serde_json::{Value, json};

    fn fixture() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 207).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('11', 'fixture', 0);",
        ).unwrap();
        conn
    }

    fn assert_source_unchanged(conn: &Connection) {
        for sql in [
            "SELECT count(*) FROM (SELECT * FROM app_events EXCEPT SELECT * FROM original_events)",
            "SELECT count(*) FROM (SELECT * FROM original_events EXCEPT SELECT * FROM app_events)",
        ] {
            assert_eq!(
                conn.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap(),
                0
            );
        }
    }

    #[test]
    fn populated_comment_upgrade() {
        let mut conn = fixture();
        conn.execute_batch(r#"
            INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
            VALUES ('11','target','received','alice','original',1111,'[["k","bad"],["k","+9"],["q","quote"],["E","root"],["e","parent"],["e","other"],["imeta","v encrypted-media-v1","url original"],["imeta","url unversioned"]]',1,1),
                   ('11','invalid-target','received','alice','invalid original',1111,'[["k","0"],["e","invalid-parent"],["imeta","v encrypted-media-v2"]]',1,1),
                   ('11','deleted','received','alice','secret original',1111,'[["k","9"],["e","deleted-parent"],["imeta","v encrypted-media-v1"]]',1,1),
                   ('11','missing-parent','received','alice','no parent',1111,'[["k","9"],["e"],["e","not-first"],["q","quote"]]',1,1),
                   ('11','quote-only','received','alice','quote only',1111,'[["k","9"],["q","quote"]]',1,1),
                   ('11','preprojected','received','alice','already projected',1111,'[["k","9"],["imeta","url existing"]]',1,1),
                   ('11','unmarked','received','alice','custom',1111,'[["k","-1"],["e","custom-parent"],["imeta","v encrypted-media-v1"]]',1,1),
                   ('11','other-custom','received','alice','custom',9000,'[["k","9"],["e","custom-parent"],["imeta","v encrypted-media-v1"]]',1,1),
                   ('11','corrupt','received','alice','corrupt source',1111,'{',1,1),
                   ('11','wrong-shape','received','alice','malformed source',1111,'[["k","9"],["imeta",7]]',1,1),
                   ('11','edit-a','received','alice','accepted earlier',1009,'[["e","target"]]',2,2),
                   ('11','edit-z','received','alice','accepted winner',1009,'[["e","target"],["imeta","url edit-must-not-replace-media"]]',2,2),
                   ('11','unauthorized','received','mallory','wrong author',1009,'[["e","target"]]',3,3),
                   ('11','invalid-edit','received','alice','invalid edit',1009,'[["e","target"]]',4,4),
                   ('11','multi-edit','received','alice','ambiguous edit',1009,'[["e","target"],["e","target"]]',5,5),
                   ('11','damaged-edit','received','alice','damaged edit',1009,'{',6,6),
                   ('11','retracted','received','alice','retracted edit',1009,'[["e","target"]]',7,7),
                   ('11','invalid-target-edit','received','alice','must not edit invalid target',1009,'[["e","invalid-target"]]',8,8),
                   ('11','deleted-edit','received','alice','must not revive',1009,'[["e","deleted"]]',8,8),
                   ('11','unmarked-edit','received','alice','must not edit custom',1009,'[["e","unmarked"]]',8,8),
                   ('11','retraction','received','alice','',5,'[["e","retracted"]]',9,9),
                   ('11','wrong-retraction','received','mallory','',5,'[["e","edit-a"]]',9,9),
                   ('11','invalid-retraction','received','alice','',5,'[["e","edit-z"]]',9,9),
                   ('11','delete-target','received','alice','',5,'[["e","deleted"]]',9,9);
            UPDATE app_events SET invalidated=1 WHERE message_id_hex IN ('invalid-target','invalid-edit','invalid-retraction');
            UPDATE app_events SET source_epoch=7 WHERE message_id_hex IN ('target','invalid-target','deleted');
            UPDATE app_events SET source_message_id_hex='source-'||message_id_hex WHERE kind IN (1111,9000);
            INSERT INTO message_modifier_edges(group_id_hex,modifier_message_id_hex,target_message_id_hex,kind,sender,recorded_at)
            SELECT group_id_hex,message_id_hex,
                   CASE message_id_hex WHEN 'invalid-target-edit' THEN 'invalid-target'
                        WHEN 'deleted-edit' THEN 'deleted' WHEN 'unmarked-edit' THEN 'unmarked' ELSE 'target' END,
                   kind,sender,recorded_at FROM app_events WHERE kind=1009;
            INSERT INTO message_modifier_edges(group_id_hex,modifier_message_id_hex,target_message_id_hex,kind,sender,recorded_at)
            VALUES ('11','retraction','retracted',5,'alice',9),
                   ('11','wrong-retraction','edit-a',5,'mallory',9),
                   ('11','invalid-retraction','edit-z',5,'alice',9),
                   ('11','delete-target','deleted',5,'alice',9);
            INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,source_epoch,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json)
            SELECT group_id_hex,message_id_hex,source_message_id_hex,source_epoch,direction,sender,plaintext,kind,
                   CASE WHEN message_id_hex IN ('corrupt','wrong-shape') THEN '[]' ELSE tags_json END,
                   recorded_at,received_at,'{"by_emoji":{},"user_reactions":[]}'
            FROM app_events WHERE kind IN (1111,9000);
            UPDATE message_timeline SET deleted=1,plaintext='',deleted_by_message_id_hex='delete-target',deletion_source='author'
            WHERE message_id_hex='deleted';
            UPDATE message_timeline SET invalidation_status='LosingBranch',plaintext='stale edit',edit_json='{"edit_count":99}'
            WHERE message_id_hex='invalid-target';
            UPDATE message_timeline SET reply_to_message_id_hex='preserve-parent',media_json='{"preserve":true}'
            WHERE message_id_hex IN ('unmarked','other-custom','corrupt','wrong-shape');
            UPDATE message_timeline SET media_json='{"imeta":[["imeta","url existing"]]}' WHERE message_id_hex='preprojected';
            CREATE TEMP TABLE original_events AS SELECT * FROM app_events;
            CREATE TEMP TABLE untouched AS SELECT * FROM message_timeline
                WHERE message_id_hex IN ('unmarked','other-custom','corrupt','wrong-shape');
        "#).unwrap();
        run_through(&mut conn, 208).unwrap();
        let (text, parent, media, edit): (String, String, String, String) = conn.query_row(
            "SELECT plaintext,reply_to_message_id_hex,media_json,edit_json FROM message_timeline WHERE message_id_hex='target'",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).unwrap();
        assert_eq!(
            (text.as_str(), parent.as_str()),
            ("accepted winner", "parent")
        );
        assert_eq!(
            serde_json::from_str::<Value>(&media).unwrap(),
            json!({"imeta":[
                ["imeta","v encrypted-media-v1","url original"],["imeta","url unversioned"]
            ]})
        );
        assert_eq!(
            serde_json::from_str::<Value>(&edit).unwrap(),
            json!({
                "edit_count":2,"latest_edit_message_id_hex":"edit-z","edited_at":2
            })
        );
        let invalid: (String, Option<String>, String, String) = conn.query_row(
            "SELECT plaintext,edit_json,invalidation_status,media_json FROM message_timeline WHERE message_id_hex='invalid-target'",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).unwrap();
        assert_eq!(
            (invalid.0.as_str(), invalid.1, invalid.2.as_str()),
            ("invalid original", None, "LosingBranch")
        );
        assert_eq!(
            serde_json::from_str::<Value>(&invalid.3).unwrap(),
            json!({"imeta":[["imeta","v encrypted-media-v2"]]})
        );
        let deleted: (String,bool,String,String,String,Option<String>,Option<String>) = conn.query_row(
            "SELECT plaintext,deleted,deleted_by_message_id_hex,deletion_source,reply_to_message_id_hex,media_json,edit_json
             FROM message_timeline WHERE message_id_hex='deleted'",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
        ).unwrap();
        assert_eq!(
            deleted,
            (
                String::new(),
                true,
                "delete-target".into(),
                "author".into(),
                "deleted-parent".into(),
                None,
                None
            )
        );
        assert_eq!(conn.query_row(
            "SELECT count(*) FROM encrypted_media_epoch_secret_references WHERE message_id_hex='deleted' AND component_id=32776 AND source_epoch=7",
            [], |row| row.get::<_,i64>(0),
        ).unwrap(),1);
        assert_eq!(conn.query_row(
            "SELECT count(*) FROM message_timeline WHERE message_id_hex IN ('missing-parent','quote-only') AND reply_to_message_id_hex IS NULL",
            [], |row| row.get::<_,i64>(0),
        ).unwrap(),2);
        assert_eq!(conn.query_row(
            "SELECT count(*) FROM (SELECT * FROM untouched EXCEPT SELECT * FROM message_timeline)",
            [], |row| row.get::<_,i64>(0),
        ).unwrap(),0);
        let slots: Vec<(String,i64,String,Option<i64>,String,bool)> = conn.prepare(
            "SELECT message_id_hex,attachment_index,source_message_id_hex,source_epoch,slot_json,visible
             FROM attachment_history ORDER BY message_id_hex,attachment_index",
        ).unwrap().query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?))).unwrap()
            .collect::<Result<_,_>>().unwrap();
        assert_eq!(
            slots,
            vec![
                (
                    "preprojected".into(),
                    0,
                    "source-preprojected".into(),
                    None,
                    "[\"imeta\",\"url existing\"]".into(),
                    true
                ),
                (
                    "target".into(),
                    0,
                    "source-target".into(),
                    Some(7),
                    "[\"imeta\",\"v encrypted-media-v1\",\"url original\"]".into(),
                    true
                ),
                (
                    "target".into(),
                    1,
                    "source-target".into(),
                    Some(7),
                    "[\"imeta\",\"url unversioned\"]".into(),
                    true
                ),
            ]
        );
        assert_source_unchanged(&conn);
    }

    #[test]
    fn comment_media_upgrade() {
        let mut conn = fixture();
        conn.execute_batch(r#"
            INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,source_epoch,recorded_at,received_at)
            VALUES ('11','v1','received','alice','',1111,'[["k","9"],["imeta","v encrypted-media-v1"]]',7,1,1),
                   ('11','v2','received','alice','',1111,'[["k","bad"],["k","+18446744073709551615"],["imeta","v encrypted-media-v2"],["imeta","v encrypted-media-v2"]]',7,1,1),
                   ('11','both','received','alice','',1111,'[["k","0"],["imeta","v encrypted-media-v1"],["imeta","v encrypted-media-v2"]]',7,1,1),
                   ('11','invalidated','received','alice','',1111,'[["k","9"],["imeta","v encrypted-media-v1"]]',7,1,1),
                   ('11','duplicate','received','alice','',1111,'[["k","9"],["imeta","v encrypted-media-v1","v encrypted-media-v1"]]',8,1,1),
                   ('11','mixed','received','alice','',1111,'[["k","9"],["imeta","v encrypted-media-v1","v encrypted-media-v2"]]',8,1,1),
                   ('11','unknown','received','alice','',1111,'[["k","9"],["imeta","v unknown"]]',8,1,1),
                   ('11','unversioned','received','alice','',1111,'[["k","9"],["imeta","url attachment"]]',8,1,1),
                   ('11','unmarked','received','alice','',1111,'[["imeta","v encrypted-media-v1"]]',8,1,1),
                   ('11','uppercase','received','alice','',1111,'[["K","9"],["imeta","v encrypted-media-v1"]]',8,1,1),
                   ('11','overflow','received','alice','',1111,'[["k","18446744073709551616"],["imeta","v encrypted-media-v1"]]',8,1,1),
                   ('11','negative','received','alice','',1111,'[["k","-1"],["imeta","v encrypted-media-v1"]]',8,1,1),
                   ('11','whitespace','received','alice','',1111,'[["k"," 9"],["imeta","v encrypted-media-v1"]]',8,1,1),
                   ('11','blob','received','alice','',1111,x'ff',8,1,1),
                   ('11','negative-epoch','received','alice','',1111,'[["k","9"],["imeta","v encrypted-media-v1"]]',-1,1,1),
                   ('11','no-epoch','received','alice','',1111,'[["k","9"],["imeta","v encrypted-media-v1"]]',NULL,1,1),
                   ('11','custom','received','alice','',9000,'[["k","9"],["imeta","v encrypted-media-v1"]]',8,1,1);
            UPDATE app_events SET invalidated=1 WHERE message_id_hex='invalidated';
            INSERT INTO encrypted_media_epoch_secrets(group_id_hex,component_id,source_epoch,secret,created_at_unix_seconds)
            VALUES ('11',32776,7,x'01',1),('11',32779,7,x'02',1),('11',999,7,x'03',1),('11',32776,8,x'04',1);
            CREATE TEMP TABLE original_events AS SELECT * FROM app_events;
        "#).unwrap();
        run_through(&mut conn, 208).unwrap();
        let references: Vec<(String,i64,i64)> = conn.prepare(
            "SELECT message_id_hex,component_id,source_epoch FROM encrypted_media_epoch_secret_references
             ORDER BY message_id_hex,component_id",
        ).unwrap().query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap()
            .collect::<Result<_,_>>().unwrap();
        assert_eq!(
            references,
            vec![
                ("both".into(), 32776, 7),
                ("both".into(), 32779, 7),
                ("invalidated".into(), 32776, 7),
                ("v1".into(), 32776, 7),
                ("v2".into(), 32779, 7),
            ]
        );
        let secrets: Vec<(i64,i64,Vec<u8>,bool)> = conn.prepare(
            "SELECT component_id,source_epoch,secret,retention_managed FROM encrypted_media_epoch_secrets
             ORDER BY source_epoch,component_id",
        ).unwrap().query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap()
            .collect::<Result<_,_>>().unwrap();
        assert_eq!(
            secrets,
            vec![
                (999, 7, vec![3], true),
                (32776, 7, vec![1], true),
                (32779, 7, vec![2], true),
                (32776, 8, vec![4], false)
            ]
        );
        assert_source_unchanged(&conn);
    }
}
