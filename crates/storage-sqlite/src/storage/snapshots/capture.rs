use super::rows::{
    MemberCapabilitiesSnapshot, OpenMlsValueSnapshot, OrderedMessage, OrderedQueuedOutbound,
    Snapshot,
};
use crate::openmls_storage::mls_group_key;
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::types::{GroupId, MemberId};
use rusqlite::{OptionalExtension, params};

pub(super) fn create(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
) -> StorageResult<()> {
    if store.connection.is_current_thread_transaction_owner() {
        let conn = store.lock()?;
        return create_on_connection(&conn, group_id, name);
    }

    let mut conn = store.lock()?;
    let tx = conn.transaction().storage()?;
    create_on_connection(&tx, group_id, name)?;
    tx.commit().storage()?;
    Ok(())
}

fn create_on_connection(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    name: &str,
) -> StorageResult<()> {
    let mls_group_key = mls_group_key(group_id)?;
    let group_blob: Vec<u8> = conn
        .query_row(
            "SELECT record FROM cgka_groups WHERE id = ?1",
            params![group_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .storage()?
        .ok_or(StorageError::NotFound)?;
    let group = deserialize(&group_blob)?;
    let messages = messages(conn, group_id)?;
    let queued_outbound = queued_outbound(conn, group_id)?;
    let member_caps = member_capabilities(conn, group_id)?;
    let convergence_policy = convergence_policy(conn, group_id)?;
    let validated_tree_marker = validated_tree_marker(conn, group_id)?;
    let openmls_values = openmls_values(conn, &mls_group_key)?;

    let snapshot = Snapshot {
        group,
        messages,
        queued_outbound,
        member_caps,
        convergence_policy,
        validated_tree_marker,
        openmls_values,
    };
    conn.execute(
        "INSERT OR REPLACE INTO cgka_group_snapshots (group_id, name, snapshot)
             VALUES (?1, ?2, ?3)",
        params![group_id.as_slice(), name, serialize(&snapshot)?],
    )
    .storage()?;
    Ok(())
}

fn messages(tx: &rusqlite::Connection, group_id: &GroupId) -> StorageResult<Vec<OrderedMessage>> {
    let mut stmt = tx
        .prepare(
            "SELECT insert_order, record FROM cgka_messages
             WHERE group_id = ?1
             ORDER BY insert_order",
        )
        .storage()?;
    let rows = stmt
        .query_map(params![group_id.as_slice()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    rows.into_iter()
        .map(|(insert_order, record)| {
            Ok(OrderedMessage {
                insert_order,
                record: deserialize(&record)?,
            })
        })
        .collect()
}

fn queued_outbound(
    tx: &rusqlite::Connection,
    group_id: &GroupId,
) -> StorageResult<Vec<OrderedQueuedOutbound>> {
    let mut stmt = tx
        .prepare(
            "SELECT insert_order, record FROM cgka_queued_outbound
             WHERE group_id = ?1
             ORDER BY insert_order",
        )
        .storage()?;
    let rows = stmt
        .query_map(params![group_id.as_slice()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    rows.into_iter()
        .map(|(insert_order, record)| {
            Ok(OrderedQueuedOutbound {
                insert_order,
                record: deserialize(&record)?,
            })
        })
        .collect()
}

fn member_capabilities(
    tx: &rusqlite::Connection,
    group_id: &GroupId,
) -> StorageResult<Vec<MemberCapabilitiesSnapshot>> {
    let mut stmt = tx
        .prepare(
            "SELECT member_id, capabilities FROM cgka_member_capabilities
             WHERE group_id = ?1",
        )
        .storage()?;
    let rows = stmt
        .query_map(params![group_id.as_slice()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    rows.into_iter()
        .map(|(member_id, capabilities)| {
            Ok(MemberCapabilitiesSnapshot {
                member_id: MemberId::new(member_id),
                capabilities: deserialize(&capabilities)?,
            })
        })
        .collect()
}

fn convergence_policy(
    tx: &rusqlite::Connection,
    group_id: &GroupId,
) -> StorageResult<Option<Vec<u8>>> {
    tx.query_row(
        "SELECT policy FROM cgka_convergence_policies WHERE group_id = ?1",
        params![group_id.as_slice()],
        |row| row.get(0),
    )
    .optional()
    .storage()
}

fn validated_tree_marker(
    tx: &rusqlite::Connection,
    group_id: &GroupId,
) -> StorageResult<Option<Vec<u8>>> {
    tx.query_row(
        "SELECT marker FROM cgka_member_validation_cache WHERE group_id = ?1",
        params![group_id.as_slice()],
        |row| row.get(0),
    )
    .optional()
    .storage()
}

fn openmls_values(
    tx: &rusqlite::Connection,
    mls_group_key: &[u8],
) -> StorageResult<Vec<OpenMlsValueSnapshot>> {
    let mut stmt = tx
        .prepare(
            "SELECT label, storage_key, group_key, value FROM openmls_values
             WHERE provider_version = ?1 AND group_key = ?2
             ORDER BY storage_key",
        )
        .storage()?;
    stmt.query_map(
        params![openmls_traits::storage::CURRENT_VERSION, mls_group_key],
        |row| {
            Ok(OpenMlsValueSnapshot {
                label: row.get(0)?,
                storage_key: row.get(1)?,
                group_key: row.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
                value: row.get(3)?,
            })
        },
    )
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()
}
