//! Migration 0147: a chat this device was removed from while its account
//! stays in it (`self_membership = 'device_removed'`, mdk#2628 D62) lists
//! with the departed chats.
//!
//! Migration 0072's navigation triggers place a chat in the departed scope
//! when its membership is `left` or `removed`. Triggers cannot be altered, so
//! this drops each trigger that recomputes the scope and creates it again with
//! the same body, with `device_removed` added to that list. The pin-position
//! triggers do not read membership and stay as they are. No row holds
//! `device_removed` before this migration, so nothing is recomputed.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    let left = "COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed', 'device_removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex))
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = lower(chat_list_rows.group_id_hex)
            AND CASE WHEN json_valid(CAST(record AS TEXT))
                THEN COALESCE(json_extract(CAST(record AS TEXT), '$.status') = 'pending', 1)
                ELSE 1 END)";
    let archived = "COALESCE((SELECT archived FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), archived)";
    let pending = "COALESCE((SELECT pending_confirmation FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation)";
    let refresh = format!(
        "UPDATE chat_list_rows SET
        list_scope = CASE WHEN {left} THEN 2 WHEN {archived} != 0 THEN 1 ELSE 0 END,
        list_unread = ({pending} = 0 AND (unread_count > 0 OR manually_marked_unread != 0))"
    );
    let refresh_pins = "UPDATE chat_list_rows SET list_pin_ordinal = COALESCE((SELECT ordinal FROM chat_pin_positions WHERE group_id_hex = chat_list_rows.group_id_hex), -1),
        list_pin_position = (SELECT (SELECT count(*) FROM chat_pin_positions earlier WHERE earlier.ordinal < pin.ordinal) FROM chat_pin_positions pin WHERE pin.group_id_hex = chat_list_rows.group_id_hex)";

    // The scope-bearing sources of migration 0072, with its column lists.
    for (table, column, binary, updates) in [
        (
            "chat_list_rows",
            "group_id_hex",
            false,
            "group_id_hex, archived, pending_confirmation, self_membership, unread_count, manually_marked_unread",
        ),
        (
            "account_groups",
            "group_id_hex",
            false,
            "group_id_hex, archived, pending_confirmation, self_membership",
        ),
        ("cgka_leave_requests", "group_id", true, "group_id, record"),
        (
            "cgka_disband_requests",
            "group_id",
            true,
            "group_id, record",
        ),
        (
            "cgka_disband_candidates",
            "group_id",
            true,
            "group_id, commit_id",
        ),
        ("cgka_disband_tombstones", "group_id", true, "group_id"),
    ] {
        let key = |prefix: &str| {
            if binary {
                format!("lower(hex({prefix}.{column}))")
            } else {
                format!("{prefix}.{column}")
            }
        };
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            if table == "chat_list_rows" && operation == "DELETE" {
                continue;
            }
            let event = if operation == "UPDATE" {
                format!("UPDATE OF {updates}")
            } else {
                operation.to_owned()
            };
            let row_key = if binary {
                "lower(group_id_hex)"
            } else {
                "group_id_hex"
            };
            let filter = match operation {
                "INSERT" => format!("{row_key} = {}", key("NEW")),
                "DELETE" => format!("{row_key} = {}", key("OLD")),
                _ => format!("{row_key} IN ({}, {})", key("OLD"), key("NEW")),
            };
            let changed = if operation == "UPDATE" {
                format!(
                    "WHEN {}",
                    updates
                        .split(", ")
                        .map(|column| format!("OLD.{column} IS NOT NEW.{column}"))
                        .collect::<Vec<_>>()
                        .join(" OR ")
                )
            } else {
                String::new()
            };
            let pins = match (table, operation) {
                ("chat_list_rows", "INSERT") => format!("{refresh_pins} WHERE {filter};"),
                ("chat_list_rows", "UPDATE") => format!(
                    "{refresh_pins} WHERE {filter} AND OLD.group_id_hex IS NOT NEW.group_id_hex;"
                ),
                _ => String::new(),
            };
            tx.execute_batch(&format!(
                "DROP TRIGGER chat_list_keys_{table}_{operation};
                CREATE TRIGGER chat_list_keys_{table}_{operation}
                AFTER {event} ON {table} {changed} BEGIN {refresh} WHERE {filter}; {pins} END;"
            ))
            .storage()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run, run_through};
    use rusqlite::Connection;

    fn trigger_sql(conn: &Connection) -> Vec<(String, String)> {
        conn.prepare(
            "SELECT name, sql FROM sqlite_master
             WHERE type = 'trigger' AND name LIKE 'chat_list_keys_%' ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// Each recreated trigger differs from 0072's only in the membership
    /// list, and the pin-position triggers are untouched.
    #[test]
    fn the_triggers_change_only_in_the_departed_membership_list() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 146).unwrap();
        let before = trigger_sql(&conn);
        run(&mut conn, MIGRATIONS).unwrap();
        let after = trigger_sql(&conn);
        assert_eq!(
            before.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            after.iter().map(|(name, _)| name).collect::<Vec<_>>()
        );
        let normalize = |sql: &str| sql.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut changed = 0;
        for ((name, old), (_, new)) in before.iter().zip(&after) {
            let widened = normalize(old).replace(
                "IN ('left', 'removed')",
                "IN ('left', 'removed', 'device_removed')",
            );
            assert_eq!(widened, normalize(new), "{name}");
            if normalize(old) != normalize(new) {
                changed += 1;
            }
        }
        assert_eq!(changed, 17);
    }

    /// A chat this device was removed from lists with the departed chats,
    /// and a later return to `member` brings it back.
    #[test]
    fn a_device_removed_chat_lists_as_departed() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('01','',0);
            INSERT INTO chat_list_rows(group_id_hex, updated_at) VALUES ('01',0);",
        )
        .unwrap();
        let scope = |conn: &Connection| {
            conn.query_row("SELECT list_scope FROM chat_list_rows", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
        };
        assert_eq!(scope(&conn), 0);
        conn.execute_batch("UPDATE account_groups SET self_membership = 'device_removed'")
            .unwrap();
        assert_eq!(scope(&conn), 2);
        conn.execute_batch("UPDATE account_groups SET self_membership = 'member'")
            .unwrap();
        assert_eq!(scope(&conn), 0);
    }
}
