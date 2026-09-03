use super::{capture, format as snapshot_format, restore};
use crate::connection::CachedSql;
use crate::{
    SqliteAccountStorage, SqliteResultExt, codec::SensitiveBytes, connection::retry_on_busy,
    epoch_to_i64,
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
    let blob = snapshot_format::encode_checkpoint(&state)?;
    let existing = conn
        .query_row_cached(
            "SELECT resulting_epoch, checkpoint
             FROM cgka_group_state_checkpoints
             WHERE group_id = ?1 AND checkpoint_id = ?2",
            params![group_id.as_slice(), checkpoint.id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .storage()?;
    if let Some((resulting_epoch, existing_blob)) = existing {
        if resulting_epoch == epoch_to_i64(checkpoint.resulting_epoch)? {
            // Existing checkpoints can remain as untagged legacy JSON after
            // upgrade. Canonicalize their decoded state before comparing so
            // an exact retry stays idempotent across storage formats.
            let existing_state = snapshot_format::decode_checkpoint(&existing_blob)?;
            let existing_blob = snapshot_format::encode_checkpoint(&existing_state)?;
            if existing_blob.as_slice() == blob.as_slice() {
                return Ok(());
            }
        }
        return Err(StorageError::AlreadyExists);
    }
    conn.execute_cached(
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
    store.connection.note_openmls_write();
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
        conn.query_row_cached(
            "SELECT checkpoint FROM cgka_group_state_checkpoints
             WHERE group_id = ?1 AND checkpoint_id = ?2",
            params![group_id.as_slice(), checkpoint_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .storage()?
        .ok_or_else(|| StorageError::SnapshotMissing(checkpoint_id.to_owned()))?,
    );
    let checkpoint = snapshot_format::decode_checkpoint(blob.as_slice())?;
    restore::restore_group_state(conn, group_id, &checkpoint)
}

pub(super) fn list_group_state_checkpoints(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
) -> StorageResult<Vec<GroupStateCheckpointRef>> {
    let conn = store.lock()?;
    let mut stmt = conn
        .prepare_cached(
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
        let deleted = store
            .lock()?
            .execute_cached(
                "DELETE FROM cgka_group_state_checkpoints
                 WHERE group_id = ?1 AND checkpoint_id = ?2",
                params![group_id.as_slice(), checkpoint_id],
            )
            .storage()?;
        if deleted == 0 {
            return Err(StorageError::SnapshotMissing(checkpoint_id.to_owned()));
        }
        Ok(())
    };
    if store.connection.is_current_thread_transaction_owner() {
        delete()
    } else {
        retry_on_busy(delete)
    }
}
