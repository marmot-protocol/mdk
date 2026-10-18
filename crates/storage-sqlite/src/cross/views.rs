//! App reads of engine tables: the SQL the app's projections, chat list and
//! timeline use to see engine state, and the engine's chat-list helpers. The
//! app runs these in its own transactions. Step 8 replaces them with published
//! read views.

pub(crate) use crate::protocol::storage::disband_requests::{
    disband_requests_by_group_hex_tx, disbanding_group_ids_hex_tx,
    disbanding_group_ids_hex_with_requests_tx,
};
pub(crate) use crate::protocol::storage::leave_requests::pending_leave_requests_by_group_hex_tx;

/// A chat-list column: whether the engine holds a disband tombstone for the
/// row's group. Usable inside `concat!`.
macro_rules! disband_tombstone_exists_sql {
    () => {
        "EXISTS (
                SELECT 1 FROM cgka_disband_tombstones AS tomb
                WHERE lower(hex(tomb.group_id)) = lower(row.group_id_hex)
            )"
    };
}
pub(crate) use disband_tombstone_exists_sql;

/// Chat-list page columns from the engine's leave and disband state.
pub(crate) const CHAT_LIST_PAGE_ENGINE_COLUMNS: &str = "leave_request.record AS page_leave_record,
            disband_request.record AS page_disband_record,
            EXISTS(SELECT 1 FROM cgka_disband_candidates
                WHERE lower(hex(group_id)) = lower(row.group_id_hex)) AS page_candidate";

/// The joins `CHAT_LIST_PAGE_ENGINE_COLUMNS` reads.
pub(crate) const CHAT_LIST_PAGE_ENGINE_JOINS: &str =
    "LEFT JOIN cgka_leave_requests AS leave_request
            ON lower(hex(leave_request.group_id)) = lower(row.group_id_hex)
         LEFT JOIN cgka_disband_requests AS disband_request
            ON lower(hex(disband_request.group_id)) = lower(row.group_id_hex)";

/// Origin commits of live timeline rows whose engine message is in state `?1`.
pub(crate) const BRANCH_WITHDRAWAL_ORIGINS_SQL: &str = "SELECT DISTINCT app_events.origin_commit_id
             FROM app_events
             CROSS JOIN cgka_messages
               ON cgka_messages.id = unhex(app_events.origin_commit_id)
              AND lower(hex(cgka_messages.id)) = app_events.origin_commit_id
             WHERE app_events.origin_commit_id IS NOT NULL
               AND cgka_messages.state = ?1
               AND app_events.invalidated = 0
             ORDER BY app_events.origin_commit_id";

/// Origin commits of rows withdrawn for reason `?2` whose engine message is in state `?1`.
pub(crate) const BRANCH_REVIVAL_ORIGINS_SQL: &str = "SELECT DISTINCT app_events.origin_commit_id
             FROM app_events
             CROSS JOIN cgka_messages
               ON cgka_messages.id = unhex(app_events.origin_commit_id)
              AND lower(hex(cgka_messages.id)) = app_events.origin_commit_id
             WHERE app_events.origin_commit_id IS NOT NULL
               AND cgka_messages.state = ?1
               AND app_events.invalidated = 1
               AND app_events.invalidation_reason = ?2
             ORDER BY app_events.origin_commit_id";

/// A conversation's archive and admin state, and whether the engine holds a
/// pending leave request (`?2`) or a disband tombstone for it.
pub(crate) const CONVERSATION_GROUP_STATE_SQL: &str = "SELECT archived, admin_keys_hex,
             EXISTS(SELECT 1 FROM cgka_leave_requests WHERE group_id = ?2),
             EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE group_id = ?2)
         FROM account_groups WHERE group_id_hex = ?1";

/// The engine's Nostr routes for a group (`?1`).
pub(crate) const GROUP_ROUTE_IDS_SQL: &str = "SELECT transport_group_id
                         FROM cgka_transport_group_routes
                         WHERE group_id = ?1";

/// Clears a group's local-deletion frontier (`?1`) when the engine stored
/// message `?2` of group `?3` after it.
pub(crate) const CLEAR_DELETION_FRONTIER_IF_OLDER_SQL: &str =
    "DELETE FROM local_group_deletion_frontiers
                 WHERE group_id_hex = ?1
                   AND message_insert_order < (
                       SELECT insert_order
                       FROM cgka_messages
                       WHERE id = ?2 AND group_id = ?3
                   )";

/// Whether the engine stored message `?1` of group `?2` after insert order `?3`.
pub(crate) const MESSAGE_NEWER_THAN_FRONTIER_SQL: &str = "SELECT EXISTS(
                    SELECT 1
                    FROM cgka_messages
                    WHERE id = ?1 AND group_id = ?2 AND insert_order > ?3
                 )";

/// Whether a delivery is already in the seen ring (`?1`) and not journaled as
/// released by the engine (`?2`). Release journals the ID before the app's
/// seen ring is rewritten, so a journaled receipt still needs redelivery.
pub(crate) const DELIVERY_ALREADY_SEEN_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM seen_events WHERE event_id=?1)
            AND NOT EXISTS(SELECT 1 FROM cgka_released_transport_receipts WHERE id=?2)";
