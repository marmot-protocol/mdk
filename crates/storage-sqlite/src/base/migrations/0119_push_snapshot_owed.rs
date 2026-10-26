//! Migration 0119: the push snapshot a device owes a group (mdk#2611).
//!
//! `group_push_gossip_state.snapshot_owed_after_epoch` records, before a
//! Commit that adds leaves is published, the epoch that Commit starts from.
//! The device owes the group its token records and relayable tombstones once
//! its merged epoch passes that value, so a restart between the merge and the
//! send still sends them. NULL means nothing is owed. No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE group_push_gossip_state ADD COLUMN snapshot_owed_after_epoch INTEGER
            CHECK(snapshot_owed_after_epoch >= 0);",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// Existing gossip state keeps its times and owes nothing; an owed epoch
    /// cannot be negative.
    #[test]
    fn existing_gossip_state_owes_no_snapshot() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..118]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, self_membership, updated_at)
             VALUES ('aa', '', 'member', 0);
             INSERT INTO group_push_gossip_state(group_id_hex, joined_at_ms, last_announced_at_ms)
             VALUES ('aa', 1, 2);",
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let row: (i64, i64, Option<i64>) = conn
            .query_row(
                "SELECT joined_at_ms, last_announced_at_ms, snapshot_owed_after_epoch
                 FROM group_push_gossip_state",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, (1, 2, None));
        assert!(
            conn.execute(
                "UPDATE group_push_gossip_state SET snapshot_owed_after_epoch = -1",
                [],
            )
            .is_err()
        );
    }
}
