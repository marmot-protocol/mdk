//! Migration 0122: the push join window a device has open in a group
//! (mdk#2611).
//!
//! `group_push_gossip_state.joining_since_ms` records when a Welcome installed
//! this device's copy of the group. From then until the device announces at
//! the end of its join window, it sends no `have` there. The projection save
//! sets it in the same transaction as the group's row, so a restart keeps the
//! window and the announce it owes. NULL means no window: the device created
//! the group, joined it before this migration, or has announced since. No
//! rows are seeded, so existing groups have no window.
//!
//! `join_window_counted_ms` is the time since the join completed during which
//! the device could fetch the group's messages. The window ends once it
//! reaches T; time offline does not count. A new Welcome resets it to zero.
//!
//! The account worker looks for open windows on its maintenance tick, so a
//! partial index holds only the groups that have one.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE group_push_gossip_state ADD COLUMN joining_since_ms INTEGER;
        ALTER TABLE group_push_gossip_state
            ADD COLUMN join_window_counted_ms INTEGER NOT NULL DEFAULT 0;
        CREATE INDEX group_push_gossip_state_joining
            ON group_push_gossip_state(group_id_hex)
            WHERE joining_since_ms IS NOT NULL;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// Existing gossip state keeps its times and has no join window open.
    #[test]
    fn existing_gossip_state_has_no_join_window() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..121]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, self_membership, updated_at)
             VALUES ('aa', '', 'member', 0);
             INSERT INTO group_push_gossip_state(
                group_id_hex, joined_at_ms, last_announced_at_ms, snapshot_owed_after_epoch
             ) VALUES ('aa', 1, 2, 3);",
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let row: (i64, i64, i64, Option<i64>, i64) = conn
            .query_row(
                "SELECT joined_at_ms, last_announced_at_ms, snapshot_owed_after_epoch,
                        joining_since_ms, join_window_counted_ms
                 FROM group_push_gossip_state",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row, (1, 2, 3, None, 0));
    }
}
