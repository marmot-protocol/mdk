//! Migration 0206: each group's committed roster (mdk#3273 B).
//!
//! - `cgka_committed_rosters`: one row per group with a known committed
//!   roster, holding its revision.
//! - `cgka_committed_roster_members`: the distinct member account ids of that
//!   roster, one row each. A roster can hold none (a copy this device was
//!   removed from), which is known and differs from having no roster row.
//! - `cgka_committed_roster_revision`: the account-wide counter every
//!   revision is drawn from. It is never reset or deleted, so a revision is
//!   never handed out twice, even to a group forgotten and joined again.
//!
//! The engine writes a roster in the same transaction as every record write
//! that merges, clears or re-derives membership; staging and probes never
//! write one. The tables are outside every snapshot, so a rewind onto a
//! retained anchor leaves them alone, and deleting the group's record
//! deletes its roster.
//!
//! No rows are seeded: a stored record can hold a staged commit's projected
//! members, which this migration cannot tell apart from committed ones. The
//! engine fills each group's roster from its merged MLS state when it next
//! hydrates the group; until then the group's roster is unknown.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE cgka_committed_rosters (
            group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
            revision INTEGER NOT NULL CHECK (revision > 0)
        ) WITHOUT ROWID;
        CREATE TABLE cgka_committed_roster_members (
            group_id BLOB NOT NULL
                REFERENCES cgka_committed_rosters(group_id) ON DELETE CASCADE,
            member_id BLOB NOT NULL,
            PRIMARY KEY (group_id, member_id)
        ) WITHOUT ROWID;
        CREATE TABLE cgka_committed_roster_revision (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last INTEGER NOT NULL CHECK (last >= 0)
        );
        INSERT INTO cgka_committed_roster_revision (id, last) VALUES (1, 0);",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::{Connection, params};

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    /// Existing groups start with no roster, whatever their records hold, and
    /// a group's roster goes with its record.
    #[test]
    fn seeds_no_roster_and_drops_a_roster_with_its_group() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run_through(&mut conn, 205).unwrap();
        conn.execute(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES (?1, 7, x'00')",
            params![vec![1u8; 16]],
        )
        .unwrap();
        run_through(&mut conn, 206).unwrap();
        assert_eq!(
            count(&conn, "SELECT count(*) FROM cgka_committed_rosters"),
            0
        );
        assert_eq!(
            count(
                &conn,
                "SELECT last FROM cgka_committed_roster_revision WHERE id = 1"
            ),
            0
        );

        conn.execute(
            "INSERT INTO cgka_committed_rosters(group_id, revision) VALUES (?1, 1)",
            params![vec![1u8; 16]],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cgka_committed_roster_members(group_id, member_id) VALUES (?1, x'aa')",
            params![vec![1u8; 16]],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM cgka_groups WHERE id = ?1",
            params![vec![1u8; 16]],
        )
        .unwrap();
        assert_eq!(
            count(&conn, "SELECT count(*) FROM cgka_committed_rosters"),
            0
        );
        assert_eq!(
            count(&conn, "SELECT count(*) FROM cgka_committed_roster_members"),
            0
        );
    }
}
