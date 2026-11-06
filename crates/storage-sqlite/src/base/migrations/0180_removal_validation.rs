//! Freeze original removal shape before lossy tag recovery can change it.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params, types::ValueRef};
use serde::Deserialize;

// Frozen v1 shape semantics. Historical upgrades must not change if the live
// reporting parser later gains a new decision version or validation rule.
fn removal_target(tags: &[Vec<String>], content: &str) -> Option<String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Decision {
        v: u8,
        action: String,
    }
    let decision: Decision = serde_json::from_str(content).ok()?;
    if decision.v != 1 || decision.action != "remove" {
        return None;
    }
    let mut targets = tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|s| s == "e"));
    let target = targets.next()?.get(1)?;
    if targets.next().is_some()
        || target.len() != 64
        || !target
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    Some(target.clone())
}

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE TABLE content_removal_validation (
        group_id_hex TEXT NOT NULL, message_id_hex TEXT NOT NULL,
        state INTEGER NOT NULL CHECK(state IN (0,1,2)), target_message_id_hex TEXT,
        CHECK((state=2 AND target_message_id_hex IS NOT NULL) OR (state!=2 AND target_message_id_hex IS NULL)),
        PRIMARY KEY(group_id_hex,message_id_hex),
        FOREIGN KEY(group_id_hex,message_id_hex) REFERENCES app_events(group_id_hex,message_id_hex) ON DELETE CASCADE
    );
    CREATE TABLE content_removal_legacy_holds (
        group_id_hex TEXT NOT NULL, message_id_hex TEXT NOT NULL, target_message_id_hex TEXT NOT NULL,
        PRIMARY KEY(group_id_hex,message_id_hex,target_message_id_hex),
        FOREIGN KEY(group_id_hex,message_id_hex) REFERENCES content_removal_validation(group_id_hex,message_id_hex) ON DELETE CASCADE
    );
    CREATE INDEX content_removal_valid_target ON content_removal_validation(group_id_hex,target_message_id_hex,message_id_hex) WHERE state=2;
    CREATE INDEX content_removal_held_target ON content_removal_legacy_holds(group_id_hex,target_message_id_hex,message_id_hex);").storage()?;
    let mut stmt = tx.prepare(
        "SELECT e.group_id_hex,e.message_id_hex,e.sender,e.recorded_at,e.plaintext,e.tags_json,
         EXISTS(SELECT 1 FROM content_pruned_controls p WHERE p.group_id_hex=e.group_id_hex AND p.message_id_hex=e.message_id_hex)
         FROM app_events e WHERE e.kind IN (5,1009,1984,1985,4891) AND e.kind=4891"
    ).storage()?;
    let mut rows = stmt.query([]).storage()?;
    while let Some(row) = rows.next().storage()? {
        let group: String = row.get(0).storage()?;
        let id: String = row.get(1).storage()?;
        let sender: String = row.get(2).storage()?;
        let at: i64 = row.get(3).storage()?;
        let content: String = row.get(4).storage()?;
        let tags: Option<Vec<Vec<String>>> = match row.get_ref(5).storage()? {
            ValueRef::Text(json) | ValueRef::Blob(json) => serde_json::from_slice(json).ok(),
            _ => None,
        };
        let pruned: bool = row.get(6).storage()?;
        let intact = tags.is_some() && !pruned;
        let candidate = match tags {
            Some(tags) => tags,
            None => {
                let mut edges = tx.prepare("SELECT target_message_id_hex FROM message_modifier_edges
                    WHERE group_id_hex=?1 AND modifier_message_id_hex=?2 ORDER BY target_message_id_hex").storage()?;
                edges
                    .query_map(params![group, id], |r| {
                        Ok(vec!["e".to_owned(), r.get::<_, String>(0)?])
                    })
                    .storage()?
                    .collect::<Result<Vec<_>, _>>()
                    .storage()?
            }
        };
        // A hash match proves the exact original payload. A mismatch does not
        // prove invalidity: valid optional tags/fields may have been discarded.
        let proven = intact
            || u64::try_from(at).ok().is_some_and(|at| {
                cgka_traits::app_event::canonical_event_id(&sender, at, 4891, &candidate, &content)
                    == id
            });
        let target = proven
            .then(|| removal_target(&candidate, &content))
            .flatten();
        let state = if !proven {
            0
        } else if target.is_some() {
            2
        } else {
            1
        };
        tx.execute(
            "INSERT INTO content_removal_validation VALUES(?1,?2,?3,?4)",
            params![group, id, state, target],
        )
        .storage()?;
    }
    // Snapshot once, before any future normalization or projection. Current
    // attribution is evidence of an existing hide, never original validity.
    tx.execute_batch(
        "INSERT INTO content_removal_legacy_holds
        SELECT v.group_id_hex,v.message_id_hex,t.message_id_hex
        FROM content_removal_validation v JOIN app_events e
          ON e.group_id_hex=v.group_id_hex AND e.message_id_hex=v.message_id_hex
        JOIN message_timeline t ON t.group_id_hex=v.group_id_hex
          AND t.deleted_by_message_id_hex=v.message_id_hex
        WHERE v.state=0 AND t.deleted=1 AND e.invalidated=0 AND e.moderation_grant=1;",
    )
    .storage()?;
    // Previously retained UNKNOWN payloads carry no trusted decision body.
    // Keep only the source metadata needed by authority invalidation and the
    // upgrade snapshot, never an arbitrary explanation/body indefinitely.
    tx.execute_batch("UPDATE app_events SET plaintext=zeroblob(length(plaintext))
        WHERE EXISTS(SELECT 1 FROM content_removal_validation v WHERE v.group_id_hex=app_events.group_id_hex
          AND v.message_id_hex=app_events.message_id_hex AND v.state=0)
        AND EXISTS(SELECT 1 FROM content_pruned_controls p WHERE p.group_id_hex=app_events.group_id_hex
          AND p.message_id_hex=app_events.message_id_hex);
        UPDATE app_events SET plaintext='',tags_json='[]'
        WHERE EXISTS(SELECT 1 FROM content_removal_validation v WHERE v.group_id_hex=app_events.group_id_hex
          AND v.message_id_hex=app_events.message_id_hex AND v.state=0)
        AND EXISTS(SELECT 1 FROM content_pruned_controls p WHERE p.group_id_hex=app_events.group_id_hex
          AND p.message_id_hex=app_events.message_id_hex);").storage()
}
