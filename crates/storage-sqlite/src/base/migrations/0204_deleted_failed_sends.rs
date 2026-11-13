//! Migration 0204: a deleted failed send leaves the timeline.
//!
//! An own send that reached no one and that the user then deleted has no
//! timeline row any more (`timeline::is_deleted_failed_send`): nobody else
//! holds it, so its "deleted" placeholder stood for nothing and its failed
//! state kept offering a retry. A peer's reaction proves receipt even after a
//! deletion cleared it from the row, so such a send is delivered instead and
//! keeps its placeholder.
//!
//! - Deleted failed sends with a live peer reaction (not invalidated, not
//!   retracted by its sender) or a kept receipt are settled as 0173 settles
//!   undeleted ones.
//! - The remaining deleted failed sends lose their timeline rows. `app_events`
//!   keeps the source rows. The attachment and unread triggers follow the
//!   delete, and the chat list notices the changed preview and rebuilds on open.
//!
//! Frozen schema-204 transformation: never call the evolving live projector.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    settle_and_drop_deleted_failed_sends(tx)
}

/// Split out so a test can check it against the live projector.
pub(super) fn settle_and_drop_deleted_failed_sends(tx: &rusqlite::Connection) -> StorageResult<()> {
    tx.execute_batch(
        "UPDATE message_timeline AS t
         SET invalidation_status = NULL,
             recipient_confirmed = 1
         WHERE t.deleted = 1
           AND t.direction = 'sent'
           AND t.source_message_id_hex IS NULL
           AND t.invalidation_status = 'local_publish_failed'
           AND (
               EXISTS (
                   SELECT 1 FROM kept_recipient_receipts AS kept
                   WHERE kept.group_id_hex = t.group_id_hex
                     AND kept.message_id_hex = t.message_id_hex
               )
               OR EXISTS (
                   SELECT 1
                   FROM message_modifier_edges AS edge
                   JOIN app_events AS reaction
                     ON reaction.group_id_hex = edge.group_id_hex
                    AND reaction.message_id_hex = edge.modifier_message_id_hex
                   WHERE edge.group_id_hex = t.group_id_hex
                     AND edge.target_message_id_hex = t.message_id_hex
                     AND edge.kind = 7
                     AND reaction.invalidated = 0
                     AND reaction.sender != t.sender
                     AND NOT EXISTS (
                         SELECT 1
                         FROM message_modifier_edges AS retraction
                         JOIN app_events AS retraction_event
                           ON retraction_event.group_id_hex = retraction.group_id_hex
                          AND retraction_event.message_id_hex = retraction.modifier_message_id_hex
                         WHERE retraction.group_id_hex = reaction.group_id_hex
                           AND retraction.target_message_id_hex = reaction.message_id_hex
                           AND retraction.kind = 5
                           AND retraction_event.invalidated = 0
                           AND retraction_event.sender = reaction.sender
                     )
               )
           );
         DELETE FROM message_timeline
         WHERE deleted = 1
           AND direction = 'sent'
           AND source_message_id_hex IS NULL
           AND invalidation_status = 'local_publish_failed';",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::{Connection, params};

    /// The migration runs on a schema-203 database and drops a deleted failed
    /// send with no confirmation; a delivered, pending, received or undeleted
    /// row stays. Settling is checked against the live projector in
    /// `timeline::tests`.
    #[test]
    fn drops_unconfirmed_deleted_failed_sends() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 203).unwrap();
        let failed = Some("local_publish_failed");
        for (id, direction, source, deleted, status) in [
            ("deleted_failed", "sent", None, true, failed),
            ("failed", "sent", None, false, failed),
            ("deleted_delivered", "sent", Some("src"), true, None),
            ("deleted_pending", "sent", None, true, None),
            ("deleted_received", "received", None, true, failed),
        ] {
            conn.execute(
                "INSERT INTO message_timeline (
                    group_id_hex, message_id_hex, source_message_id_hex, direction, sender,
                    plaintext, kind, tags_json, timeline_at, received_at, reactions_json,
                    deleted, invalidation_status
                 ) VALUES ('aa', ?1, ?2, ?3, 'me', 'hi', 9, '[]', 1, 1, '[]', ?4, ?5)",
                params![id, source, direction, deleted, status],
            )
            .unwrap();
        }
        run_through(&mut conn, 204).unwrap();
        let ids = conn
            .prepare("SELECT message_id_hex FROM message_timeline ORDER BY message_id_hex")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            ids,
            [
                "deleted_delivered",
                "deleted_pending",
                "deleted_received",
                "failed"
            ]
        );
    }
}
