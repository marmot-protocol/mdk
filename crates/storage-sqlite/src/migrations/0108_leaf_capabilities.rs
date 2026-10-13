//! Gate account-only readers before any leaf-aware capability write, including
//! snapshots/checkpoints. Bind unambiguous historical cache rows to their leaf.
use crate::{SqliteResultExt, deserialize};
use cgka_traits::group::Group;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Only capability-bearing groups need roster decoding. Unrelated group
    // records and historical message state remain opaque to this migration.
    let groups = {
        let mut statement = tx.prepare("SELECT record FROM cgka_groups WHERE EXISTS (SELECT 1 FROM cgka_member_capabilities WHERE group_id = cgka_groups.id)").storage()?;
        statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
    };
    for record in groups {
        let group: Group = deserialize(&record)?;
        crate::storage::capabilities::promote_legacy_capabilities(tx, &group)?;
    }
    Ok(())
}
