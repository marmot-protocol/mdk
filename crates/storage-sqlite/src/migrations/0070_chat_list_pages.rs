//! Rebuildable navigation keys on existing chat rows. Source tables remain authoritative.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE chat_list_rows ADD COLUMN list_scope INTEGER NOT NULL DEFAULT 0;
         ALTER TABLE chat_list_rows ADD COLUMN list_unread INTEGER NOT NULL DEFAULT 0;
         ALTER TABLE chat_list_rows ADD COLUMN list_pin_ordinal INTEGER NOT NULL DEFAULT -1;
         ALTER TABLE chat_list_rows ADD COLUMN list_pin_position INTEGER;
         ALTER TABLE chat_list_rows ADD COLUMN list_pin_section INTEGER
             GENERATED ALWAYS AS (list_pin_ordinal < 0) VIRTUAL;
         ALTER TABLE chat_list_rows ADD COLUMN list_pin_order INTEGER
             GENERATED ALWAYS AS (max(list_pin_ordinal, 0)) VIRTUAL;
         ALTER TABLE chat_list_rows ADD COLUMN list_activity_order INTEGER
             GENERATED ALWAYS AS (-max(activity_sort_at, 0)) VIRTUAL;
         CREATE INDEX idx_leave_requests_hex ON cgka_leave_requests(lower(hex(group_id)));
         CREATE INDEX idx_disband_requests_hex ON cgka_disband_requests(lower(hex(group_id)));
         CREATE INDEX idx_disband_candidates_hex ON cgka_disband_candidates(lower(hex(group_id)));
         CREATE TABLE chat_list_navigation_meta (
             id INTEGER PRIMARY KEY CHECK(id = 1),
             revision INTEGER NOT NULL DEFAULT 0
                 CHECK(typeof(revision) = 'integer' AND revision >= 0)
         );
         INSERT INTO chat_list_navigation_meta(id) VALUES(1);",
    )
    .storage()?;

    // JSON is the frozen durable record encoding. Missing status predates the field and
    // means Pending, matching serde(default). Invalid records stay conservatively gated;
    // decoding a returned row still reports the storage error.
    let left = "COALESCE((SELECT self_membership FROM account_groups WHERE group_id_hex = chat_list_rows.group_id_hex), self_membership) IN ('left', 'removed')
        OR EXISTS(SELECT 1 FROM cgka_leave_requests WHERE lower(hex(group_id)) = chat_list_rows.group_id_hex)
        OR EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE lower(hex(group_id)) = chat_list_rows.group_id_hex)
        OR EXISTS(SELECT 1 FROM cgka_disband_candidates WHERE lower(hex(group_id)) = chat_list_rows.group_id_hex)
        OR EXISTS(SELECT 1 FROM cgka_disband_requests WHERE lower(hex(group_id)) = chat_list_rows.group_id_hex
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
    tx.execute_batch(&format!("{refresh}; {refresh_pins};
        CREATE INDEX idx_chat_list_page ON chat_list_rows(list_scope, list_pin_section, list_pin_order, list_activity_order, group_id_hex);
        CREATE INDEX idx_chat_list_unread_page ON chat_list_rows(list_pin_section, list_pin_order, list_activity_order, group_id_hex)
            WHERE list_scope = 0 AND list_unread = 1;
        CREATE TRIGGER chat_list_navigation_changed AFTER UPDATE ON chat_list_rows
        WHEN OLD.list_scope != NEW.list_scope OR OLD.list_unread != NEW.list_unread
          OR OLD.list_pin_ordinal != NEW.list_pin_ordinal OR OLD.activity_sort_at != NEW.activity_sort_at
          OR OLD.group_id_hex != NEW.group_id_hex
        BEGIN UPDATE chat_list_navigation_meta SET revision = revision + 1 WHERE id = 1; END;
        CREATE TRIGGER chat_list_navigation_inserted AFTER INSERT ON chat_list_rows
        BEGIN UPDATE chat_list_navigation_meta SET revision = revision + 1 WHERE id = 1; END;
        CREATE TRIGGER chat_list_navigation_deleted AFTER DELETE ON chat_list_rows
        BEGIN UPDATE chat_list_navigation_meta SET revision = revision + 1 WHERE id = 1; END;"
    )).storage()?;

    // Engine writes, checkpoint restores, imports and ordinary app writes all pass through
    // these boundaries. Recompute only the affected ids; no subscriber/worker is required.
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
        (
            "chat_pin_positions",
            "group_id_hex",
            false,
            "group_id_hex, ordinal",
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
            // Updating navigation fields never re-enters the row-source trigger.
            let event = if operation == "UPDATE" {
                format!("UPDATE OF {updates}")
            } else {
                operation.to_owned()
            };
            let filter = match operation {
                "INSERT" => format!("group_id_hex = {}", key("NEW")),
                "DELETE" => format!("group_id_hex = {}", key("OLD")),
                _ => format!("group_id_hex IN ({}, {})", key("OLD"), key("NEW")),
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
                ("chat_pin_positions", _) | ("chat_list_rows", "INSERT") => {
                    format!("{refresh_pins} WHERE {filter};")
                }
                ("chat_list_rows", "UPDATE") => format!(
                    "{refresh_pins} WHERE {filter} AND OLD.group_id_hex IS NOT NEW.group_id_hex;"
                ),
                _ => String::new(),
            };
            tx.execute_batch(&format!(
                "CREATE TRIGGER chat_list_keys_{table}_{operation}
                AFTER {event} ON {table} {changed} BEGIN {refresh} WHERE {filter}; {pins} END;"
            ))
            .storage()?;
        }
    }
    tx.execute_batch(
        "CREATE INDEX idx_chat_list_pin_ordinal ON chat_list_rows(list_pin_ordinal);
        CREATE TRIGGER chat_list_pin_rank_insert AFTER INSERT ON chat_pin_positions BEGIN
            UPDATE chat_list_rows SET list_pin_position = list_pin_position + 1
                WHERE list_pin_ordinal > NEW.ordinal AND group_id_hex != NEW.group_id_hex;
        END;
        CREATE TRIGGER chat_list_pin_rank_delete AFTER DELETE ON chat_pin_positions BEGIN
            UPDATE chat_list_rows SET list_pin_position = list_pin_position - 1
                WHERE list_pin_ordinal > OLD.ordinal AND group_id_hex != OLD.group_id_hex;
        END;
        CREATE TRIGGER chat_list_pin_rank_update AFTER UPDATE OF ordinal ON chat_pin_positions BEGIN
            UPDATE chat_list_rows SET list_pin_position = list_pin_position - 1
                WHERE list_pin_ordinal > OLD.ordinal AND group_id_hex != NEW.group_id_hex;
            UPDATE chat_list_rows SET list_pin_position = list_pin_position + 1
                WHERE list_pin_ordinal > NEW.ordinal AND group_id_hex != NEW.group_id_hex;
        END;",
    )
    .storage()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    #[test]
    fn populated_upgrade_backfills_navigation_and_rolls_back_failed_migration() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        run(&mut conn, &MIGRATIONS[..69]).unwrap();
        conn.execute_batch("INSERT INTO account_groups(group_id_hex, endpoint, updated_at, archived, self_membership) VALUES
                ('01','',0,0,'member'), ('02','',0,1,'member'), ('03','',0,1,'removed'), ('04','',0,0,'member');
            INSERT INTO chat_list_rows(group_id_hex, updated_at, unread_count, manually_marked_unread)
                SELECT group_id_hex, 0, 0, 1 FROM account_groups;
            INSERT INTO chat_pin_positions VALUES ('01',7), ('04',99);
            INSERT INTO cgka_groups(id,epoch,record) VALUES(x'04',0,x'00');
            INSERT INTO cgka_leave_requests VALUES(x'04',CAST('{\"requested_at_ms\":123}' AS BLOB));
            CREATE TABLE chat_list_navigation_meta (collision INTEGER);").unwrap();
        assert!(run(&mut conn, MIGRATIONS).is_err());
        assert_eq!(conn.query_row("SELECT count(*) FROM pragma_table_xinfo('chat_list_rows') WHERE name = 'list_scope'", [], |r|r.get::<_,i64>(0)).unwrap(), 0);
        assert_eq!(
            conn.query_row("SELECT count(*) FROM chat_list_rows", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            4
        );
        conn.execute_batch("DROP TABLE chat_list_navigation_meta")
            .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let rows = conn.prepare("SELECT group_id_hex,list_scope,list_unread,list_pin_position FROM chat_list_rows ORDER BY group_id_hex").unwrap().query_map([], |r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,Option<i64>>(3)?))).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        assert_eq!(
            rows,
            vec![
                ("01".into(), 0, 1, Some(0)),
                ("02".into(), 1, 1, None),
                ("03".into(), 2, 1, None),
                ("04".into(), 2, 1, Some(1))
            ]
        );
        run(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(
            conn.query_row("SELECT revision FROM chat_list_navigation_meta", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }
}
