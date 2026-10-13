use crate::{SqliteResultExt, codec::deserialize};
use cgka_traits::{group::Group, storage::StorageResult};
use rusqlite::{Transaction, params};
use std::collections::BTreeSet;

/// Correct the projected people count from the stored authoritative roster.
/// Counts, peer indexes, unread/base-row readiness and the migration ledger
/// commit together. Groups without a readable stored roster are repaired by hydration.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    let mut query = tx
        .prepare(
            "SELECT a.group_id_hex, g.record, a.profile_name, a.member_count
         FROM account_groups AS a JOIN cgka_groups AS g ON lower(hex(g.id)) = a.group_id_hex",
        )
        .storage()?;
    let rows = query
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })
        .storage()?;
    for row in rows {
        let (id, bytes, name, previous_count) = row.storage()?;
        // Hydration quarantines unreadable groups independently. A projection
        // repair must not prevent the remaining account from opening.
        let Ok(group) = deserialize::<Group>(&bytes) else {
            continue;
        };
        let accounts: BTreeSet<_> = group
            .members
            .iter()
            .map(|member| member.id.as_slice())
            .collect();
        tx.execute("UPDATE account_groups SET member_count = ?2 WHERE group_id_hex = ?1 AND member_count IS NOT ?2",
            params![id, accounts.len() as i64]).storage()?;
        // The count-change trigger clears presentation members before rebuilding.
        tx.execute(
            "DELETE FROM direct_conversation_members WHERE group_id_hex = ?1",
            [&id],
        )
        .storage()?;
        let ids: Vec<_> = accounts.iter().map(hex::encode).collect();
        let pair = ids.len() == 2 && accounts.iter().all(|id| id.len() == 32);
        if name.trim().is_empty()
            && (previous_count.is_none() || (previous_count == Some(2)) != (accounts.len() == 2))
        {
            // Unknown/Direct/Group transitions can change system-event eligibility.
            // A newer chat can leave preview/high-water checks valid, so explicitly
            // require unread and base-row preparation again in this transaction.
            tx.execute(
                "DELETE FROM chat_list_unread_ready_groups WHERE group_id_hex = ?1",
                [&id],
            )
            .storage()?;
            tx.execute(
                "INSERT OR IGNORE INTO chat_presentation_row_work(group_id_hex) VALUES(?1)",
                [&id],
            )
            .storage()?;
        }
        if pair && name.trim().is_empty() {
            for member in &ids {
                tx.execute("INSERT INTO direct_conversation_members(group_id_hex, member_id_hex) VALUES(?1, ?2)", params![id, member]).storage()?;
            }
        }
        crate::chat_presentation::replace_members_tx(tx, &id, if pair { &ids } else { &[] })?;
    }
    Ok(())
}
