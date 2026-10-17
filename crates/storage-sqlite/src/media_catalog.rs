//! The account database's side of the encrypted media store (mdk#2314).
//!
//! The `media-store` crate owns the files and the publish/delete/sweep
//! ordering; this module stores each file's random key and state
//! (`media_files`, migration 0110) and the slot references
//! (`media_file_refs`). It never reads or writes a media file.
//!
//! Every `PublishTarget` commit here is one transaction: the target's fences,
//! a presence-checked reuse decision, the ready mark and the reference. Use
//! [`commit_existing_in`] and [`commit_ready_in`] for new targets so every
//! use shares those rules.

use cgka_traits::storage::{StorageError, StorageResult};
use media_store::{
    CatalogError, CatalogResult, Category, ExistingOutcome, FileId, FilePresence, FileState,
    MediaCatalog, NewFile, Presence, PublishTarget, ReadyFile, ReadyOutcome,
};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::{SqliteAccountStorage, SqliteResultExt, u64_to_i64};

const STATE_PENDING: i64 = 0;
const STATE_READY: i64 = 1;
const STATE_LOST: i64 = 2;
pub(crate) const STATE_STAGED: i64 = 3;

fn category_sql(category: Category) -> i64 {
    match category {
        Category::Retained => 1,
        Category::Cache => 2,
    }
}

fn state_from_sql(state: i64) -> FileState {
    match state {
        STATE_PENDING => FileState::Pending,
        STATE_READY => FileState::Ready,
        STATE_STAGED => FileState::Staged,
        _ => FileState::Lost,
    }
}

/// Fixed, privacy-safe catalog errors.
pub(crate) fn catalog_error(error: StorageError) -> CatalogError {
    match error {
        StorageError::Closed(_) => CatalogError::Closed,
        StorageError::Capacity(_) => CatalogError::Capacity,
        _ => CatalogError::Backend("media catalog storage failed".into()),
    }
}

/// Maps a media store error into the storage error callers already handle.
pub fn media_storage_error(error: media_store::MediaError) -> StorageError {
    use media_store::MediaError;
    match error {
        MediaError::Closed => StorageError::Closed("media store is closed".into()),
        MediaError::Capacity => StorageError::Capacity("media store is full".into()),
        MediaError::InvalidBody(reason) => StorageError::InvalidAttachmentBody(reason),
        MediaError::Corruption(reason) => StorageError::Corruption(reason.into()),
        other => StorageError::Backend(other.to_string()),
    }
}

fn id_from_sql(bytes: Vec<u8>) -> StorageResult<FileId> {
    FileId::from_slice(&bytes)
        .ok_or_else(|| StorageError::Corruption("invalid media file id".into()))
}

/// `media_files` on one account database.
#[derive(Clone)]
pub struct SqliteMediaCatalog {
    storage: SqliteAccountStorage,
}

impl SqliteMediaCatalog {
    pub fn new(storage: SqliteAccountStorage) -> Self {
        Self { storage }
    }

    /// The account database handle this catalog uses.
    pub fn storage(&self) -> &SqliteAccountStorage {
        &self.storage
    }

    fn run<T>(&self, f: impl FnOnce(&Connection) -> StorageResult<T>) -> CatalogResult<T> {
        let conn = self.storage.lock().map_err(catalog_error)?;
        f(&conn).map_err(catalog_error)
    }
}

impl MediaCatalog for SqliteMediaCatalog {
    fn is_closed(&self) -> bool {
        self.storage.is_closed()
    }

    fn insert_pending(&self, file: &NewFile) -> CatalogResult<()> {
        self.run(|conn| {
            let now = u64_to_i64(file.created_at)?;
            conn.execute(
                "INSERT INTO media_files(id,file_key,state,category,byte_len,plaintext_digest,created_at,last_used_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?7)",
                params![
                    file.id.as_bytes().as_slice(),
                    file.key.as_bytes().as_slice(),
                    STATE_PENDING,
                    category_sql(file.category),
                    u64_to_i64(file.byte_len)?,
                    file.digest.as_slice(),
                    now
                ],
            )
            .storage()?;
            Ok(())
        })
    }

    fn abandon_pending(&self, id: FileId) -> CatalogResult<bool> {
        self.run(|conn| {
            Ok(conn
                .execute(
                    "DELETE FROM media_files WHERE id=?1 AND state=?2",
                    params![id.as_bytes().as_slice(), STATE_PENDING],
                )
                .storage()?
                == 1)
        })
    }

    fn ready_file(&self, id: FileId) -> CatalogResult<Option<ReadyFile>> {
        self.run(|conn| file_in_state(conn, id, STATE_READY))
    }

    fn staged_file(&self, id: FileId) -> CatalogResult<Option<ReadyFile>> {
        self.run(|conn| file_in_state(conn, id, STATE_STAGED))
    }

    fn abandon_unowned_staged(&self, id: FileId) -> CatalogResult<bool> {
        self.run(|conn| {
            Ok(conn
                .execute(
                    "DELETE FROM media_files WHERE id=?1 AND state=?2
                     AND NOT EXISTS(SELECT 1 FROM outgoing_attachment_uploads WHERE file_id=?1)",
                    params![id.as_bytes().as_slice(), STATE_STAGED],
                )
                .storage()?
                == 1)
        })
    }

    fn file_state(&self, id: FileId) -> CatalogResult<Option<FileState>> {
        self.run(|conn| {
            Ok(conn
                .query_row(
                    "SELECT state FROM media_files WHERE id=?1",
                    [id.as_bytes().as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .storage()?
                .map(state_from_sql))
        })
    }

    fn mark_lost(&self, id: FileId) -> CatalogResult<bool> {
        self.run(|conn| mark_lost_in(conn, id))
    }

    fn wire_partial_received(&self, id: FileId) -> CatalogResult<Option<u64>> {
        self.run(|conn| {
            conn.query_row(
                "SELECT received FROM attachment_partial WHERE wire_file_id=?1",
                [id.as_bytes().as_slice()],
                |row| crate::chat_presentation::nonnegative(row, 0),
            )
            .optional()
            .storage()
        })
    }

    fn page(&self, after: Option<FileId>, limit: usize) -> CatalogResult<Vec<(FileId, FileState)>> {
        self.run(|conn| {
            let after = after.map(|id| id.as_bytes().to_vec()).unwrap_or_default();
            let mut statement = conn
                .prepare("SELECT id,state FROM media_files WHERE id>?1 ORDER BY id LIMIT ?2")
                .storage()?;
            let rows = statement
                .query_map(params![after, limit as i64], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
                })
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?;
            rows.into_iter()
                .map(|(id, state)| Ok((id_from_sql(id)?, state_from_sql(state))))
                .collect()
        })
    }
}

/// Ready → lost, overwriting the key with zeroes.
/// The key and length of `id` when its row is in `state`.
fn file_in_state(conn: &Connection, id: FileId, state: i64) -> StorageResult<Option<ReadyFile>> {
    let row: Option<(Zeroizing<Vec<u8>>, i64)> = conn
        .query_row(
            "SELECT file_key,byte_len FROM media_files WHERE id=?1 AND state=?2",
            params![id.as_bytes().as_slice(), state],
            |row| Ok((Zeroizing::new(row.get(0)?), row.get(1)?)),
        )
        .optional()
        .storage()?;
    row.map(|(key, byte_len)| {
        u64::try_from(byte_len)
            .ok()
            .and_then(|byte_len| ReadyFile::from_key_bytes(&key, byte_len))
            .ok_or_else(|| StorageError::Corruption("invalid media file row".into()))
    })
    .transpose()
}

pub(crate) fn mark_lost_in(conn: &Connection, id: FileId) -> StorageResult<bool> {
    Ok(conn
        .execute(
            "UPDATE media_files SET state=?2,file_key=zeroblob(32) WHERE id=?1 AND state=?3",
            params![id.as_bytes().as_slice(), STATE_LOST, STATE_READY],
        )
        .storage()?
        == 1)
}

/// The ready file with this content other than `except`, and its length.
fn ready_twin(
    conn: &Connection,
    category: Category,
    digest: &[u8; 32],
    except: Option<FileId>,
) -> StorageResult<Option<(FileId, u64)>> {
    let except = except.map(|id| id.as_bytes().to_vec()).unwrap_or_default();
    conn.query_row(
        "SELECT id,byte_len FROM media_files WHERE category=?1 AND plaintext_digest=?2 AND state=?3 AND id<>?4",
        params![category_sql(category), digest.as_slice(), STATE_READY, except],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
    )
    .optional()
    .storage()?
    .map(|(id, byte_len)| {
        let byte_len = u64::try_from(byte_len)
            .map_err(|_| StorageError::Corruption("invalid media file length".into()))?;
        Ok((id_from_sql(id)?, byte_len))
    })
    .transpose()
}

/// Runs the store's presence check. Its error aborts the caller's
/// transaction, leaving the twin's row and key untouched.
fn check_presence(present: Presence<'_>, id: FileId, byte_len: u64) -> StorageResult<FilePresence> {
    present(id, byte_len)
        .map_err(|_| StorageError::Backend("media file presence check failed".into()))
}

/// Points slot `token` at a ready file. Re-pointing deletes the old reference
/// first, so the old file's last-reference trigger still fires.
pub(crate) fn attach_slot(conn: &Connection, token: &[u8], id: FileId) -> StorageResult<()> {
    let current: Option<Vec<u8>> = conn
        .query_row(
            "SELECT file_id FROM media_file_refs WHERE token=?1",
            [token],
            |row| row.get(0),
        )
        .optional()
        .storage()?;
    if current.as_deref() == Some(id.as_bytes().as_slice()) {
        return Ok(());
    }
    conn.execute("DELETE FROM media_file_refs WHERE token=?1", [token])
        .storage()?;
    conn.execute(
        "INSERT INTO media_file_refs(token,file_id) VALUES(?1,?2)",
        params![token, id.as_bytes().as_slice()],
    )
    .storage()?;
    Ok(())
}

/// `PublishTarget::commit_existing` for any target, inside the caller's
/// transaction. `superseded` is the target's fence; `attach` its reference.
pub(crate) fn commit_existing_in(
    conn: &Connection,
    category: Category,
    digest: &[u8; 32],
    present: Presence<'_>,
    superseded: &dyn Fn(&Connection) -> StorageResult<bool>,
    attach: &dyn Fn(&Connection, FileId) -> StorageResult<()>,
) -> StorageResult<ExistingOutcome> {
    let Some((twin, byte_len)) = ready_twin(conn, category, digest, None)? else {
        return Ok(ExistingOutcome::None);
    };
    if check_presence(present, twin, byte_len)? == FilePresence::Absent {
        mark_lost_in(conn, twin)?;
        return Ok(ExistingOutcome::None);
    }
    if superseded(conn)? {
        return Ok(ExistingOutcome::Superseded);
    }
    attach(conn, twin)?;
    Ok(ExistingOutcome::Attached(twin))
}

/// `PublishTarget::commit_ready` for any target, inside the caller's
/// transaction.
pub(crate) fn commit_ready_in(
    conn: &Connection,
    id: FileId,
    category: Category,
    digest: &[u8; 32],
    present: Presence<'_>,
    superseded: &dyn Fn(&Connection) -> StorageResult<bool>,
    attach: &dyn Fn(&Connection, FileId) -> StorageResult<()>,
) -> StorageResult<ReadyOutcome> {
    let pending: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM media_files WHERE id=?1 AND state=?2)",
            params![id.as_bytes().as_slice(), STATE_PENDING],
            |row| row.get(0),
        )
        .storage()?;
    if !pending || superseded(conn)? {
        return Ok(ReadyOutcome::Superseded);
    }
    if let Some((twin, byte_len)) = ready_twin(conn, category, digest, Some(id))? {
        if check_presence(present, twin, byte_len)? == FilePresence::Present {
            conn.execute(
                "DELETE FROM media_files WHERE id=?1",
                [id.as_bytes().as_slice()],
            )
            .storage()?;
            attach(conn, twin)?;
            return Ok(ReadyOutcome::Existing(twin));
        }
        mark_lost_in(conn, twin)?;
    }
    conn.execute(
        "UPDATE media_files SET state=?2 WHERE id=?1",
        params![id.as_bytes().as_slice(), STATE_READY],
    )
    .storage()?;
    attach(conn, id)?;
    Ok(ReadyOutcome::Ready)
}

/// Publication into one attachment slot (its acquisition token), fenced only
/// by the slot still existing. Domain targets add their own fences.
pub struct SlotPublication {
    storage: SqliteAccountStorage,
    token: Vec<u8>,
}

impl SlotPublication {
    pub fn new(storage: SqliteAccountStorage, token: Vec<u8>) -> Self {
        Self { storage, token }
    }

    fn slot_gone(&self, conn: &Connection) -> StorageResult<bool> {
        conn.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM attachment_acquisition WHERE token=?1)",
            [&self.token],
            |row| row.get(0),
        )
        .storage()
    }
}

impl PublishTarget for SlotPublication {
    fn superseded(&self) -> CatalogResult<bool> {
        let conn = self.storage.lock().map_err(catalog_error)?;
        self.slot_gone(&conn).map_err(catalog_error)
    }

    fn commit_existing(
        &self,
        category: Category,
        digest: &[u8; 32],
        present: Presence<'_>,
    ) -> CatalogResult<ExistingOutcome> {
        self.storage
            .connection
            .with_transaction(|| {
                let conn = self.storage.lock()?;
                commit_existing_in(
                    &conn,
                    category,
                    digest,
                    present,
                    &|conn| self.slot_gone(conn),
                    &|conn, id| attach_slot(conn, &self.token, id),
                )
            })
            .map_err(catalog_error)
    }

    fn commit_ready(
        &self,
        id: FileId,
        category: Category,
        digest: &[u8; 32],
        present: Presence<'_>,
    ) -> CatalogResult<ReadyOutcome> {
        self.storage
            .connection
            .with_transaction(|| {
                let conn = self.storage.lock()?;
                commit_ready_in(
                    &conn,
                    id,
                    category,
                    digest,
                    present,
                    &|conn| self.slot_gone(conn),
                    &|conn, id| attach_slot(conn, &self.token, id),
                )
            })
            .map_err(catalog_error)
    }
}

impl SqliteAccountStorage {
    /// Removes slot `token`'s media reference. Returns the ids whose rows
    /// (keys) the removal deleted, for the store to unlink once this commits.
    pub fn release_media_reference(&self, token: &[u8]) -> StorageResult<Vec<FileId>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let file: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT file_id FROM media_file_refs WHERE token=?1",
                    [token],
                    |row| row.get(0),
                )
                .optional()
                .storage()?;
            let Some(file) = file else {
                return Ok(Vec::new());
            };
            conn.execute("DELETE FROM media_file_refs WHERE token=?1", [token])
                .storage()?;
            let gone: bool = conn
                .query_row(
                    "SELECT NOT EXISTS(SELECT 1 FROM media_files WHERE id=?1)",
                    [&file],
                    |row| row.get(0),
                )
                .storage()?;
            Ok(if gone {
                vec![id_from_sql(file)?]
            } else {
                Vec::new()
            })
        })
    }
}

#[cfg(test)]
#[path = "media_catalog_tests.rs"]
mod tests;
