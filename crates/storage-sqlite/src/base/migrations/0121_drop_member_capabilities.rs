//! Migration 0121: drop the member-capability cache (mdk#2628).
//!
//! `cgka_member_capabilities` held one capability set per account and group.
//! An account with several devices has one leaf per device, so one device's
//! set stood in for every sibling's. The engine now reads each current leaf's
//! capabilities from the MLS tree, and nothing reads or writes the table.
//! Snapshots captured before this migration still carry its rows; decoding
//! skips them.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("DROP TABLE IF EXISTS cgka_member_capabilities;")
        .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    fn has_table(conn: &Connection, table: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// Cached rows go with the table; group rows stay.
    #[test]
    fn drops_cached_member_capabilities() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..120]).unwrap();
        conn.execute_batch(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES (x'01', 0, x'00');
             INSERT INTO cgka_member_capabilities(group_id, member_id, capabilities)
                 VALUES (x'01', x'07', x'00');",
        )
        .unwrap();

        run(&mut conn, &MIGRATIONS[..121]).unwrap();

        assert!(!has_table(&conn, "cgka_member_capabilities"));
        let groups: i64 = conn
            .query_row("SELECT COUNT(*) FROM cgka_groups", [], |row| row.get(0))
            .unwrap();
        assert_eq!(groups, 1);
    }
}
