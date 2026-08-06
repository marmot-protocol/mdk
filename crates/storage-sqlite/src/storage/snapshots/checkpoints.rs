use super::{capture, restore, rows::GroupStateCheckpoint};
use crate::{
    SqliteAccountStorage, SqliteResultExt,
    codec::{SensitiveBytes, serialize_sensitive},
    connection::retry_on_busy,
    deserialize, epoch_to_i64,
};
use cgka_traits::storage::{GroupStateCheckpointRef, StorageError, StorageResult};
use cgka_traits::types::{EpochId, GroupId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

pub(super) fn create_group_state_checkpoint(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    checkpoint: &GroupStateCheckpointRef,
) -> StorageResult<()> {
    if store.connection.is_current_thread_transaction_owner() {
        let conn = store.lock()?;
        return create_on_connection(&conn, group_id, checkpoint);
    }
    retry_on_busy(|| {
        let mut conn = store.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        create_on_connection(&tx, group_id, checkpoint)?;
        tx.commit().storage()
    })
}

fn create_on_connection(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    checkpoint: &GroupStateCheckpointRef,
) -> StorageResult<()> {
    let state = capture::capture_group_state(conn, group_id)?;
    let blob = serialize_sensitive(&state)?;
    let existing = conn
        .query_row(
            "SELECT resulting_epoch, checkpoint
             FROM cgka_group_state_checkpoints
             WHERE group_id = ?1 AND checkpoint_id = ?2",
            params![group_id.as_slice(), checkpoint.id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .storage()?;
    if let Some((resulting_epoch, existing_blob)) = existing {
        if resulting_epoch == epoch_to_i64(checkpoint.resulting_epoch)?
            && existing_blob == blob.as_slice()
        {
            return Ok(());
        }
        return Err(StorageError::AlreadyExists);
    }
    conn.execute(
        "INSERT INTO cgka_group_state_checkpoints
            (group_id, checkpoint_id, resulting_epoch, checkpoint)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            group_id.as_slice(),
            checkpoint.id,
            epoch_to_i64(checkpoint.resulting_epoch)?,
            blob.as_slice()
        ],
    )
    .storage()?;
    Ok(())
}

pub(super) fn restore_group_state_checkpoint(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    checkpoint_id: &str,
) -> StorageResult<()> {
    if store.connection.is_current_thread_transaction_owner() {
        let conn = store.lock()?;
        return restore_on_connection(&conn, group_id, checkpoint_id);
    }
    retry_on_busy(|| {
        let mut conn = store.lock()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .storage()?;
        restore_on_connection(&tx, group_id, checkpoint_id)?;
        tx.commit().storage()
    })
}

fn restore_on_connection(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
    checkpoint_id: &str,
) -> StorageResult<()> {
    let blob = SensitiveBytes::new(
        conn.query_row(
            "SELECT checkpoint FROM cgka_group_state_checkpoints
             WHERE group_id = ?1 AND checkpoint_id = ?2",
            params![group_id.as_slice(), checkpoint_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .storage()?
        .ok_or_else(|| StorageError::SnapshotMissing(checkpoint_id.to_owned()))?,
    );
    let checkpoint: GroupStateCheckpoint = deserialize(blob.as_slice())?;
    restore::restore_group_state(conn, group_id, &checkpoint)
}

pub(super) fn list_group_state_checkpoints(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
) -> StorageResult<Vec<GroupStateCheckpointRef>> {
    let conn = store.lock()?;
    let mut stmt = conn
        .prepare(
            "SELECT checkpoint_id, resulting_epoch
             FROM cgka_group_state_checkpoints
             WHERE group_id = ?1
             ORDER BY resulting_epoch, checkpoint_id",
        )
        .storage()?;
    stmt.query_map(params![group_id.as_slice()], |row| {
        let epoch = row.get::<_, i64>(1)?;
        Ok(GroupStateCheckpointRef {
            id: row.get(0)?,
            resulting_epoch: EpochId(u64::try_from(epoch).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?),
        })
    })
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()
}

pub(super) fn release_group_state_checkpoint(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    checkpoint_id: &str,
) -> StorageResult<()> {
    let delete = || {
        store
            .lock()?
            .execute(
                "DELETE FROM cgka_group_state_checkpoints
                 WHERE group_id = ?1 AND checkpoint_id = ?2",
                params![group_id.as_slice(), checkpoint_id],
            )
            .storage()?;
        Ok(())
    };
    if store.connection.is_current_thread_transaction_owner() {
        delete()
    } else {
        retry_on_busy(delete)
    }
}
