//! Migration 0120: `account_groups.member_count` counts accounts (mdk#2628, item 1.1).
//!
//! An account with several devices holds one leaf per device in a group. The
//! stored count used to be the leaf count, so a 1:1 chat with someone on two
//! devices read as a three-person group. It now counts member accounts. Chat
//! kinds and direct-chat lookups read this column, so rows written under the
//! old meaning are repaired here rather than waiting for the hydrated-open
//! reconcile, which only reaches live groups.
//!
//! Only rows whose engine record lists an account more than once can differ;
//! every other row already counts accounts. Unhydrated rows (`NULL`) and
//! records that do not decode are left alone. The `chat_presentation_group_changed`
//! trigger drops the repaired groups' selected presentation and peer evidence,
//! and the next projection save writes them again from the account roster.
use std::collections::HashSet;

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params};
use serde::Deserialize;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    let mut repairs = Vec::new();
    {
        let mut statement = tx
            .prepare(
                "SELECT account_group.group_id_hex, engine_group.record
                 FROM cgka_groups AS engine_group
                 JOIN account_groups AS account_group
                   ON account_group.group_id_hex = lower(hex(engine_group.id))
                 WHERE account_group.member_count IS NOT NULL",
            )
            .storage()?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .storage()?;
        for row in rows {
            let (group_id_hex, record) = row.storage()?;
            if let Some(accounts) = repeated_account_count(&record) {
                repairs.push((group_id_hex, accounts));
            }
        }
    }
    for (group_id_hex, accounts) in repairs {
        tx.execute(
            "UPDATE account_groups SET member_count = ?2
             WHERE group_id_hex = ?1 AND member_count IS NOT ?2",
            params![group_id_hex, accounts],
        )
        .storage()?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct EngineGroupRecord {
    members: Vec<EngineGroupMember>,
}

#[derive(Deserialize)]
struct EngineGroupMember {
    id: serde_json::Value,
}

/// The record's number of distinct member accounts, only when some account
/// holds more than one leaf.
fn repeated_account_count(record: &[u8]) -> Option<i64> {
    let record: EngineGroupRecord = serde_json::from_slice(record).ok()?;
    let accounts = record
        .members
        .iter()
        .map(|member| member.id.to_string())
        .collect::<HashSet<_>>()
        .len();
    (accounts < record.members.len())
        .then(|| i64::try_from(accounts).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::{Connection, params};

    fn record(member_bytes: &[u8]) -> Vec<u8> {
        let members = member_bytes
            .iter()
            .map(|byte| serde_json::json!({ "id": vec![*byte; 32], "credential": [] }))
            .collect::<Vec<_>>();
        serde_json::to_vec(&serde_json::json!({ "epoch": 3, "members": members })).unwrap()
    }

    fn insert(conn: &Connection, group: u8, member_count: Option<i64>, record: &[u8]) {
        let group_id = vec![group; 16];
        conn.execute(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES (?1, 3, ?2)",
            params![group_id, record],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at, member_count)
             VALUES (?1, '', 0, ?2)",
            params![hex::encode(&group_id), member_count],
        )
        .unwrap();
    }

    fn member_count(conn: &Connection, group: u8) -> Option<i64> {
        conn.query_row(
            "SELECT member_count FROM account_groups WHERE group_id_hex = ?1",
            params![hex::encode(vec![group; 16])],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// A stored leaf count becomes the account count; rows where every
    /// account has one leaf, unhydrated rows and undecodable records keep
    /// their value.
    #[test]
    fn leaf_counts_become_account_counts() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..119]).unwrap();
        // A 1:1 chat whose peer has two devices.
        insert(&conn, 0x01, Some(3), &record(&[0xaa, 0xbb, 0xbb]));
        // Two devices of one account and nobody else.
        insert(&conn, 0x02, Some(2), &record(&[0xaa, 0xaa]));
        insert(&conn, 0x03, Some(3), &record(&[0xaa, 0xbb, 0xcc]));
        insert(&conn, 0x04, None, &record(&[0xaa, 0xbb, 0xbb]));
        insert(&conn, 0x05, Some(3), b"not json");
        run(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(member_count(&conn, 0x01), Some(2));
        assert_eq!(member_count(&conn, 0x02), Some(1));
        assert_eq!(member_count(&conn, 0x03), Some(3));
        assert_eq!(member_count(&conn, 0x04), None);
        assert_eq!(member_count(&conn, 0x05), Some(3));
    }
}
