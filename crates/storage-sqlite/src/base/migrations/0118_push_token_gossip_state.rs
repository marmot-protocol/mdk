//! Migration 0118: storage for push-token gossip (mdk#2611).
//!
//! - `group_push_token_tombstones` keeps the rest of the owner-signed removal
//!   (`token_fingerprint`, `owner_sig`), so any member can relay a tombstone
//!   unchanged in a kind 449 and the owner signature still verifies. Existing
//!   tombstones kept no signature: both columns stay NULL and the tombstone
//!   stays local-only. The two columns are set together or not at all.
//! - `group_push_gossip_state` holds this device's per-group gossip state for
//!   its current membership: when its join became final, the first snapshot
//!   that arrived, and when it last announced. No rows are seeded: a group
//!   joined before this migration has no recorded join and has never
//!   announced.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE group_push_token_tombstones ADD COLUMN token_fingerprint TEXT;
        ALTER TABLE group_push_token_tombstones ADD COLUMN owner_sig TEXT
            CHECK((owner_sig IS NULL) = (token_fingerprint IS NULL));
        CREATE TABLE group_push_gossip_state (
            group_id_hex TEXT PRIMARY KEY
                REFERENCES account_groups(group_id_hex) ON DELETE CASCADE,
            joined_at_ms INTEGER,
            snapshot_received_at_ms INTEGER,
            last_announced_at_ms INTEGER
        );",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    fn before_migration() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..117]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, self_membership, updated_at)
             VALUES ('aa', '', 'member', 0);
             INSERT INTO group_push_token_tombstones(
                group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex,
                owner_ts, record_digest, created_at_ms
             ) VALUES ('aa', 'bb', 1, 1, 'cc', 100, 'digest', 5);",
        )
        .unwrap();
        conn
    }

    /// An existing tombstone keeps its stamp and gains no signature, so it
    /// stays local-only. No gossip state is seeded for existing groups.
    #[test]
    fn existing_tombstones_stay_local_only() {
        let mut conn = before_migration();
        run(&mut conn, MIGRATIONS).unwrap();
        let row: (i64, String, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT owner_ts, record_digest, token_fingerprint, owner_sig
                 FROM group_push_token_tombstones",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(row, (100, "digest".to_owned(), None, None));
        let states: i64 = conn
            .query_row("SELECT COUNT(*) FROM group_push_gossip_state", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(states, 0);
    }

    /// A tombstone holds the whole removal proof or none of it.
    #[test]
    fn a_tombstone_cannot_hold_half_a_removal_proof() {
        let mut conn = before_migration();
        run(&mut conn, MIGRATIONS).unwrap();
        for (fingerprint, sig) in [(Some("fp"), None), (None, Some("sig"))] {
            assert!(
                conn.execute(
                    "UPDATE group_push_token_tombstones SET token_fingerprint = ?1, owner_sig = ?2",
                    rusqlite::params![fingerprint, sig],
                )
                .is_err()
            );
        }
        conn.execute(
            "UPDATE group_push_token_tombstones SET token_fingerprint = 'fp', owner_sig = 'sig'",
            [],
        )
        .unwrap();
    }

    /// Gossip state goes with its group's projection row.
    #[test]
    fn gossip_state_cascades_with_the_group() {
        let mut conn = before_migration();
        run(&mut conn, MIGRATIONS).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             INSERT INTO group_push_gossip_state(group_id_hex, joined_at_ms) VALUES ('aa', 1);
             DELETE FROM account_groups WHERE group_id_hex = 'aa';",
        )
        .unwrap();
        let states: i64 = conn
            .query_row("SELECT COUNT(*) FROM group_push_gossip_state", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(states, 0);
    }
}
