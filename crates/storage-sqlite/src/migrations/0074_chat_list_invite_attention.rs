//! Indexed invitation attention, independent of message-unread eligibility.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE chat_list_rows ADD COLUMN list_pending_invite INTEGER NOT NULL DEFAULT 0;",
    )
    .storage()?;
    // Account state is authoritative even before the display row is refreshed.
    // Like the M1 navigation keys, this is disposable query state, not another counter store.
    let refresh = "UPDATE chat_list_rows SET list_pending_invite =
        COALESCE((SELECT pending_confirmation FROM account_groups
            WHERE group_id_hex = chat_list_rows.group_id_hex), pending_confirmation) != 0";
    tx.execute_batch(&format!(
        "{refresh};
        CREATE INDEX idx_chat_list_invite_attention ON chat_list_rows(group_id_hex)
            WHERE list_scope = 0 AND list_pending_invite = 1;"
    ))
    .storage()?;
    for table in ["account_groups", "chat_list_rows"] {
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            if table == "chat_list_rows" && operation == "DELETE" {
                continue;
            }
            let event = if operation == "UPDATE" {
                "UPDATE OF group_id_hex, pending_confirmation"
            } else {
                operation
            };
            let filter = match operation {
                "INSERT" => "group_id_hex = NEW.group_id_hex",
                "DELETE" => "group_id_hex = OLD.group_id_hex",
                _ => "group_id_hex IN (OLD.group_id_hex, NEW.group_id_hex)",
            };
            let changed = if operation == "UPDATE" {
                "WHEN OLD.group_id_hex IS NOT NEW.group_id_hex OR OLD.pending_confirmation IS NOT NEW.pending_confirmation"
            } else {
                ""
            };
            tx.execute_batch(&format!(
                "CREATE TRIGGER chat_list_invite_{table}_{operation} AFTER {event} ON {table} {changed}
                 BEGIN {refresh} WHERE {filter}; END;"
            ))
            .storage()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    #[test]
    fn populated_upgrade_uses_authoritative_invites_and_does_not_reapply() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..73]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at, pending_confirmation)
                 VALUES ('01','',0,1), ('02','',0,0);
             INSERT INTO chat_list_rows(group_id_hex, updated_at, pending_confirmation)
                 VALUES ('01',0,0), ('02',0,1);",
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let eligible = |conn: &Connection| {
            conn.prepare(
                "SELECT group_id_hex FROM chat_list_rows INDEXED BY idx_chat_list_invite_attention
                 WHERE list_scope = 0 AND list_pending_invite = 1 ORDER BY group_id_hex",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        };
        assert_eq!(eligible(&conn), ["01"]);
        // Acceptance/reinvitation must win over stale display-row state.
        conn.execute_batch(
            "UPDATE account_groups SET pending_confirmation = 1 - pending_confirmation;",
        )
        .unwrap();
        assert_eq!(eligible(&conn), ["02"]);
        conn.execute_batch(
            "UPDATE chat_list_rows SET pending_confirmation = 1 - pending_confirmation;",
        )
        .unwrap();
        assert_eq!(eligible(&conn), ["02"]);
    }
}
