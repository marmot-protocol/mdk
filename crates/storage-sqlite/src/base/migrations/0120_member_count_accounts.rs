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
//! records that do not decode are left alone. A repaired group also gets the
//! member rows a projection save would write from its accounts: two accounts
//! make a two-person chat (and, unnamed, a Direct one), so its peer index and
//! presentation members are written here. A copy this device has left is
//! never reconciled, and a live one would otherwise show no peer until it is.
//! Its selected presentation is dropped so the next read selects it again.
use std::collections::BTreeSet;

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
            if let Some(accounts) = repeated_accounts(&record) {
                repairs.push((group_id_hex, accounts));
            }
        }
    }
    for (group_id_hex, accounts) in repairs {
        let account_count = i64::try_from(accounts.len()).unwrap_or(i64::MAX);
        tx.execute(
            "UPDATE account_groups SET member_count = ?2
             WHERE group_id_hex = ?1 AND member_count IS NOT ?2",
            params![group_id_hex, account_count],
        )
        .storage()?;
        for table in ["direct_conversation_members", "chat_presentation_members"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE group_id_hex = ?1"),
                params![group_id_hex],
            )
            .storage()?;
        }
        if accounts.len() == 2 && accounts.iter().all(|account| account.len() == 32) {
            for account in &accounts {
                let member_id_hex = hex::encode(account);
                tx.execute(
                    "INSERT INTO chat_presentation_members(group_id_hex, member_id_hex)
                     VALUES (?1, ?2)",
                    params![group_id_hex, member_id_hex],
                )
                .storage()?;
                tx.execute(
                    "INSERT INTO direct_conversation_members(group_id_hex, member_id_hex)
                     SELECT group_id_hex, ?2 FROM account_groups
                     WHERE group_id_hex = ?1 AND trim(profile_name) = ''",
                    params![group_id_hex, member_id_hex],
                )
                .storage()?;
            }
        }
        tx.execute(
            "UPDATE chat_list_rows SET presentation_json = NULL,
                 presentation_source_revision = presentation_source_revision + 1
             WHERE group_id_hex = ?1",
            params![group_id_hex],
        )
        .storage()?;
        tx.execute(
            "DELETE FROM chat_presentation_dependencies WHERE group_id_hex = ?1",
            params![group_id_hex],
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
    id: Vec<u8>,
}

/// The record's distinct member accounts, sorted, only when some account
/// holds more than one leaf.
fn repeated_accounts(record: &[u8]) -> Option<Vec<Vec<u8>>> {
    let record: EngineGroupRecord = serde_json::from_slice(record).ok()?;
    let accounts = record
        .members
        .iter()
        .map(|member| member.id.clone())
        .collect::<BTreeSet<_>>();
    (accounts.len() < record.members.len()).then(|| accounts.into_iter().collect())
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

    fn group_hex(group: u8) -> String {
        hex::encode(vec![group; 16])
    }

    fn account_hex(byte: u8) -> String {
        hex::encode(vec![byte; 32])
    }

    fn insert(conn: &Connection, group: u8, name: &str, member_count: Option<i64>, record: &[u8]) {
        conn.execute(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES (?1, 3, ?2)",
            params![vec![group; 16], record],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO account_groups(group_id_hex, endpoint, updated_at, member_count, profile_name)
             VALUES (?1, '', 0, ?2, ?3)",
            params![group_hex(group), member_count, name],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_list_rows(group_id_hex, updated_at, presentation_json)
             VALUES (?1, 0, X'7b7d')",
            params![group_hex(group)],
        )
        .unwrap();
    }

    fn member_count(conn: &Connection, group: u8) -> Option<i64> {
        conn.query_row(
            "SELECT member_count FROM account_groups WHERE group_id_hex = ?1",
            params![group_hex(group)],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn members_in(conn: &Connection, table: &str, group: u8) -> Vec<String> {
        conn.prepare(&format!(
            "SELECT member_id_hex FROM {table} WHERE group_id_hex = ?1 ORDER BY member_id_hex"
        ))
        .unwrap()
        .query_map(params![group_hex(group)], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
    }

    fn presentation_kept(conn: &Connection, group: u8) -> bool {
        conn.query_row(
            "SELECT presentation_json IS NOT NULL FROM chat_list_rows WHERE group_id_hex = ?1",
            params![group_hex(group)],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// A stored leaf count becomes the account count, and a repaired group
    /// gets the peer index and presentation members its accounts make. Rows
    /// where every account has one leaf, unhydrated rows and undecodable
    /// records are left alone.
    #[test]
    fn leaf_counts_become_account_counts() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..119]).unwrap();
        // An unnamed 1:1 whose peer has two devices.
        insert(&conn, 0x01, "", Some(3), &record(&[0xaa, 0xbb, 0xbb]));
        // Two devices of one account and nobody else, with the single peer
        // row the old two-leaf rule wrote.
        insert(&conn, 0x02, "", Some(2), &record(&[0xaa, 0xaa]));
        conn.execute(
            "INSERT INTO direct_conversation_members(group_id_hex, member_id_hex) VALUES (?1, ?2)",
            params![group_hex(0x02), account_hex(0xaa)],
        )
        .unwrap();
        insert(&conn, 0x03, "", Some(3), &record(&[0xaa, 0xbb, 0xcc]));
        insert(&conn, 0x04, "", None, &record(&[0xaa, 0xbb, 0xbb]));
        insert(&conn, 0x05, "", Some(3), b"not json");
        // A named two-person group whose peer has two devices.
        insert(&conn, 0x06, "team", Some(3), &record(&[0xaa, 0xbb, 0xbb]));
        insert(&conn, 0x07, "", Some(4), &record(&[0xaa, 0xaa, 0xbb, 0xcc]));
        run(&mut conn, MIGRATIONS).unwrap();

        let pair = vec![account_hex(0xaa), account_hex(0xbb)];
        let none = Vec::<String>::new();
        assert_eq!(member_count(&conn, 0x01), Some(2));
        assert_eq!(members_in(&conn, "direct_conversation_members", 0x01), pair);
        assert_eq!(members_in(&conn, "chat_presentation_members", 0x01), pair);
        assert!(!presentation_kept(&conn, 0x01));

        assert_eq!(member_count(&conn, 0x02), Some(1));
        assert_eq!(members_in(&conn, "direct_conversation_members", 0x02), none);
        assert_eq!(members_in(&conn, "chat_presentation_members", 0x02), none);

        assert_eq!(member_count(&conn, 0x03), Some(3));
        assert!(presentation_kept(&conn, 0x03));
        assert_eq!(member_count(&conn, 0x04), None);
        assert!(presentation_kept(&conn, 0x04));
        assert_eq!(member_count(&conn, 0x05), Some(3));
        assert!(presentation_kept(&conn, 0x05));

        assert_eq!(member_count(&conn, 0x06), Some(2));
        assert_eq!(members_in(&conn, "direct_conversation_members", 0x06), none);
        assert_eq!(members_in(&conn, "chat_presentation_members", 0x06), pair);

        assert_eq!(member_count(&conn, 0x07), Some(3));
        assert_eq!(members_in(&conn, "direct_conversation_members", 0x07), none);
        assert_eq!(members_in(&conn, "chat_presentation_members", 0x07), none);
    }
}
