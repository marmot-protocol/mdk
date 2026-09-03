use super::format as snapshot_format;
use super::rows::{
    GroupStateCheckpoint, MemberCapabilitiesSnapshot, OpenMlsValueSnapshot, OrderedMessage,
    OrderedQueuedOutbound, Snapshot,
};
#[cfg(feature = "test-conformance-replay")]
use super::rows::{REPLAY_SNAPSHOT_VERSION, ReplaySnapshot};
use crate::connection::CachedSql;
#[cfg(feature = "test-conformance-replay")]
use crate::deserialize;
use crate::openmls_storage::mls_group_key;
use crate::storage::messages::put_message_on_connection;
use crate::{
    SqliteAccountStorage, SqliteResultExt, codec::SensitiveBytes, connection::retry_on_busy,
    created_at_to_i64, epoch_to_i64, serialize,
};
use cgka_traits::group::Group;
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

#[derive(Clone, Copy)]
enum RestoreScope {
    Full,
    GroupState,
}

pub(super) fn rollback(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
) -> StorageResult<()> {
    rollback_with_scope(store, group_id, name, RestoreScope::Full)
}

pub(super) fn rollback_group_state(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
) -> StorageResult<()> {
    rollback_with_scope(store, group_id, name, RestoreScope::GroupState)
}

fn rollback_with_scope(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
    scope: RestoreScope,
) -> StorageResult<()> {
    if store.connection.is_current_thread_transaction_owner() {
        let conn = store.lock()?;
        return rollback_on_connection(&conn, group_id, name, scope);
    }

    retry_on_busy(|| {
        let mls_group_key = mls_group_key(group_id)?;
        let mut conn = store.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        rollback_snapshot(&tx, group_id, name, &mls_group_key, scope)?;
        tx.commit().storage()?;
        Ok(())
    })
}

fn rollback_on_connection(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    name: &str,
    scope: RestoreScope,
) -> StorageResult<()> {
    let mls_group_key = mls_group_key(group_id)?;
    rollback_snapshot(conn, group_id, name, &mls_group_key, scope)
}

fn rollback_snapshot(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    name: &str,
    mls_group_key: &[u8],
    scope: RestoreScope,
) -> StorageResult<()> {
    let snapshot_blob = SensitiveBytes::new(
        conn.query_row_cached(
            "SELECT snapshot FROM cgka_group_snapshots
                 WHERE group_id = ?1 AND name = ?2",
            params![group_id.as_slice(), name],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .storage()?
        .ok_or_else(|| StorageError::SnapshotMissing(name.to_string()))?,
    );
    let snapshot = snapshot_format::decode(snapshot_blob.as_slice())?;
    restore_snapshot(conn, group_id, &snapshot, mls_group_key, scope)
}

#[cfg(feature = "test-conformance-replay")]
pub(super) fn import(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    snapshot_blob: &[u8],
) -> StorageResult<()> {
    let snapshot: ReplaySnapshot = deserialize(snapshot_blob)?;
    if snapshot.version != REPLAY_SNAPSHOT_VERSION {
        return Err(StorageError::Serialization(format!(
            "unsupported conformance replay snapshot version {}",
            snapshot.version
        )));
    }
    if snapshot.group.group.id != *group_id {
        return Err(StorageError::Serialization(
            "conformance replay snapshot group id mismatch".to_string(),
        ));
    }
    retry_on_busy(|| {
        let mls_group_key = mls_group_key(group_id)?;
        let mut conn = store.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        restore_snapshot(
            &tx,
            group_id,
            &snapshot.group,
            &mls_group_key,
            RestoreScope::Full,
        )?;
        convergence_pass(&tx, group_id, snapshot.convergence_pass.as_ref())?;
        tx.commit().storage()?;
        Ok(())
    })
}

#[cfg(feature = "test-conformance-replay")]
fn convergence_pass(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    pass: Option<&cgka_traits::convergence_pass::DurableConvergencePass>,
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM cgka_convergence_passes WHERE group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    if let Some(pass) = pass {
        conn.execute_cached(
            "INSERT INTO cgka_convergence_passes (group_id, record) VALUES (?1, ?2)",
            params![group_id.as_slice(), serialize(pass)?],
        )
        .storage()?;
    }
    Ok(())
}

fn restore_snapshot(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    snapshot: &Snapshot,
    mls_group_key: &[u8],
    scope: RestoreScope,
) -> StorageResult<()> {
    group(conn, group_id, &snapshot.group)?;
    if matches!(scope, RestoreScope::Full) {
        // A state-scoped snapshot (`None`) never captured the message ledger
        // or outbound queue, so even full rollback leaves those live rows
        // alone rather than restoring an empty image.
        if let Some(snapshot_messages) = &snapshot.messages {
            messages(conn, group_id, snapshot_messages)?;
        }
        if let Some(snapshot_queued) = &snapshot.queued_outbound {
            queued_outbound(conn, group_id, snapshot_queued)?;
        }
    }
    member_capabilities(conn, group_id, &snapshot.member_caps)?;
    convergence_policy(conn, group_id, snapshot.convergence_policy.as_deref())?;
    validated_tree_marker(conn, group_id, snapshot.validated_tree_marker.as_deref())?;
    openmls_values(conn, mls_group_key, &snapshot.openmls_values)
}

pub(super) fn restore_group_state(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    checkpoint: &GroupStateCheckpoint,
) -> StorageResult<()> {
    let mls_group_key = mls_group_key(group_id)?;
    group(conn, group_id, &checkpoint.group)?;
    member_capabilities(conn, group_id, &checkpoint.member_caps)?;
    validated_tree_marker(conn, group_id, checkpoint.validated_tree_marker.as_deref())?;
    openmls_values(conn, &mls_group_key, &checkpoint.openmls_values)
}

fn group(conn: &rusqlite::Connection, group_id: &GroupId, group: &Group) -> StorageResult<()> {
    conn.execute_cached(
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
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    messages: &[OrderedMessage],
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM cgka_messages WHERE group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    for message in messages {
        put_message_on_connection(conn, Some(message.insert_order), &message.record)?;
    }
    // A full snapshot replaces this group's protocol messages. Preserve
    // pending application deliveries whose source messages were restored, but
    // remove outbox rows for messages that the rollback discarded.
    conn.execute_cached(
        "DELETE FROM pending_application_events
         WHERE group_id = ?1
           AND NOT EXISTS (
                SELECT 1
                FROM cgka_messages
                WHERE cgka_messages.id = pending_application_events.message_id
                  AND cgka_messages.group_id = pending_application_events.group_id
           )",
        params![group_id.as_slice()],
    )
    .storage()?;
    Ok(())
}

fn queued_outbound(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    queued_outbound: &[OrderedQueuedOutbound],
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM cgka_queued_outbound WHERE group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    for queued in queued_outbound {
        conn.execute_cached(
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
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    member_caps: &[MemberCapabilitiesSnapshot],
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM cgka_member_capabilities WHERE group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    for caps in member_caps {
        conn.execute_cached(
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
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    policy: Option<&[u8]>,
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM cgka_convergence_policies WHERE group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    if let Some(policy) = policy {
        conn.execute_cached(
            "INSERT INTO cgka_convergence_policies (group_id, policy)
             VALUES (?1, ?2)",
            params![group_id.as_slice(), policy],
        )
        .storage()?;
    }
    Ok(())
}

fn validated_tree_marker(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    marker: Option<&[u8]>,
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM cgka_member_validation_cache WHERE group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    if let Some(marker) = marker {
        conn.execute_cached(
            "INSERT INTO cgka_member_validation_cache (group_id, marker)
             VALUES (?1, ?2)",
            params![group_id.as_slice(), marker],
        )
        .storage()?;
    }
    Ok(())
}

fn openmls_values(
    conn: &rusqlite::Connection,
    mls_group_key: &[u8],
    values: &[OpenMlsValueSnapshot],
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM openmls_values
         WHERE provider_version = ?1 AND group_key = ?2",
        params![openmls_traits::storage::CURRENT_VERSION, mls_group_key],
    )
    .storage()?;
    for value in values {
        conn.execute_cached(
            "INSERT INTO openmls_values
                (provider_version, label, storage_key, group_key, value)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                openmls_traits::storage::CURRENT_VERSION,
                value.label,
                value.storage_key,
                value.group_key,
                value.value.as_slice()
            ],
        )
        .storage()?;
    }
    Ok(())
}
