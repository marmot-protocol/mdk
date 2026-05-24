use super::rows::{
    MemberCapabilitiesSnapshot, OpenMlsValueSnapshot, OrderedMessage, OrderedQueuedOutbound,
    Snapshot,
};
use crate::openmls_storage::mls_group_key;
use crate::{
    SqliteResultExt, SqliteStorage, created_at_to_i64, deserialize, epoch_to_i64,
    message_state_to_i64, serialize,
};
use cgka_traits::group::Group;
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

pub(super) fn rollback(store: &SqliteStorage, group_id: &GroupId, name: &str) -> StorageResult<()> {
    let mls_group_key = mls_group_key(group_id)?;
    let mut conn = store.lock()?;
    let tx = conn.transaction().storage()?;
    let snapshot_blob: Vec<u8> = tx
        .query_row(
            "SELECT snapshot FROM cgka_group_snapshots
                 WHERE group_id = ?1 AND name = ?2",
            params![group_id.as_slice(), name],
            |row| row.get(0),
        )
        .optional()
        .storage()?
        .ok_or_else(|| StorageError::SnapshotMissing(name.to_string()))?;
    let snapshot: Snapshot = deserialize(&snapshot_blob)?;

    group(&tx, group_id, &snapshot.group)?;
    messages(&tx, group_id, &snapshot.messages)?;
    queued_outbound(&tx, group_id, &snapshot.queued_outbound)?;
    member_capabilities(&tx, group_id, &snapshot.member_caps)?;
    convergence_policy(&tx, group_id, snapshot.convergence_policy.as_deref())?;
    openmls_values(&tx, &mls_group_key, &snapshot.openmls_values)?;

    tx.commit().storage()?;
    Ok(())
}

fn group(tx: &rusqlite::Transaction<'_>, group_id: &GroupId, group: &Group) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO cgka_groups (id, epoch, record)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                epoch = excluded.epoch,
                record = excluded.record",
        params![
            group_id.as_slice(),
            epoch_to_i64(group.epoch)?,
            serialize(group)?
        ],
    )
    .storage()?;
    Ok(())
}

fn messages(
    tx: &rusqlite::Transaction<'_>,
    group_id: &GroupId,
    messages: &[OrderedMessage],
) -> StorageResult<()> {
    tx.execute(
        "DELETE FROM cgka_messages WHERE group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    for message in messages {
        tx.execute(
            "INSERT INTO cgka_messages
                (insert_order, id, group_id, epoch, state, record)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                message.insert_order,
                message.record.id.as_slice(),
                message.record.group_id.as_slice(),
                epoch_to_i64(message.record.epoch)?,
                message_state_to_i64(message.record.state),
                serialize(&message.record)?
            ],
        )
        .storage()?;
    }
    Ok(())
}

fn queued_outbound(
    tx: &rusqlite::Transaction<'_>,
    group_id: &GroupId,
    queued_outbound: &[OrderedQueuedOutbound],
) -> StorageResult<()> {
    tx.execute(
        "DELETE FROM cgka_queued_outbound WHERE group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    for queued in queued_outbound {
        tx.execute(
            "INSERT INTO cgka_queued_outbound
                (insert_order, id, group_id, created_at_ms, record)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                queued.insert_order,
                queued.record.id.as_slice(),
                queued.record.group_id.as_slice(),
                created_at_to_i64(queued.record.created_at_ms)?,
                serialize(&queued.record)?
            ],
        )
        .storage()?;
    }
    Ok(())
}

fn member_capabilities(
    tx: &rusqlite::Transaction<'_>,
    group_id: &GroupId,
    member_caps: &[MemberCapabilitiesSnapshot],
) -> StorageResult<()> {
    tx.execute(
        "DELETE FROM cgka_member_capabilities WHERE group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    for caps in member_caps {
        tx.execute(
            "INSERT INTO cgka_member_capabilities (group_id, member_id, capabilities)
             VALUES (?1, ?2, ?3)",
            params![
                group_id.as_slice(),
                caps.member_id.as_slice(),
                serialize(&caps.capabilities)?
            ],
        )
        .storage()?;
    }
    Ok(())
}

fn convergence_policy(
    tx: &rusqlite::Transaction<'_>,
    group_id: &GroupId,
    policy: Option<&[u8]>,
) -> StorageResult<()> {
    tx.execute(
        "DELETE FROM cgka_convergence_policies WHERE group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    if let Some(policy) = policy {
        tx.execute(
            "INSERT INTO cgka_convergence_policies (group_id, policy)
             VALUES (?1, ?2)",
            params![group_id.as_slice(), policy],
        )
        .storage()?;
    }
    Ok(())
}

fn openmls_values(
    tx: &rusqlite::Transaction<'_>,
    mls_group_key: &[u8],
    values: &[OpenMlsValueSnapshot],
) -> StorageResult<()> {
    tx.execute(
        "DELETE FROM openmls_values
         WHERE provider_version = ?1 AND group_key = ?2",
        params![openmls_traits::storage::CURRENT_VERSION, mls_group_key],
    )
    .storage()?;
    for value in values {
        tx.execute(
            "INSERT INTO openmls_values
                (provider_version, label, storage_key, group_key, value)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                openmls_traits::storage::CURRENT_VERSION,
                value.label,
                value.storage_key,
                value.group_key,
                value.value
            ],
        )
        .storage()?;
    }
    Ok(())
}
