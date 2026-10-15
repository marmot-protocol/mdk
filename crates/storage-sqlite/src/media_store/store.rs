//! The encrypted per-file media store: one file per body under
//! `<account>/media/<shard>/<id>`, one `media_files` row per file holding its
//! random key and state.
//!
//! The database row is the authority and the only place writers serialize;
//! files take no locks. Every change follows the intent-first order:
//!
//! - **Publish:** (1) insert a `pending` row with a fresh id and key; (2)
//!   exclusively create `<id>` at mode 0600, write it, sync it once; (3) one
//!   transaction marks the row `ready` (and runs the caller's commit, such as
//!   attaching a slot reference). No temporary name, rename or directory sync:
//!   the `pending` row already marks the file unfinished.
//! - **Delete:** commit the row deletion (the key, erased by `secure_delete`)
//!   first, then unlink the file best effort.
//! - **Sweep:** a `pending` row no live publish owns is deleted with its file;
//!   a file with no row is unlinked; a `ready` row whose file is gone becomes
//!   `lost`. A file is only ever created after its row commits, so the
//!   database alone decides. Batches stay within their limit, even inside
//!   one shard.
//! - **Reuse:** identical content is stored once, but a ready row is reused
//!   only if its file is on disk; a missing one is marked `lost` instead.
//!
//! Live publishes register their id in the storage handle's in-flight set so
//! a concurrent sweep leaves their `pending` row alone. The set is per process
//! and empty after a restart, which is exactly when abandoned `pending` rows
//! must be reclaimed.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::format::{
    FILE_ID_BYTES, FILE_KEY_BYTES, FileKey, MediaFileReader, MediaFileWriter, MediaFormatError,
};
use crate::{SqliteAccountStorage, SqliteResultExt, u64_to_i64};

const COPY_CHUNK_BYTES: usize = 1024 * 1024;
const STATE_PENDING: i64 = 0;
const STATE_READY: i64 = 1;
const STATE_LOST: i64 = 2;
const TRACE_TARGET: &str = "storage_sqlite::media_store";

/// Random 16-byte file id. It names the file and says nothing about the
/// message, group or content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MediaFileId([u8; FILE_ID_BYTES]);

impl MediaFileId {
    fn random() -> StorageResult<Self> {
        let mut id = [0; FILE_ID_BYTES];
        openssl::rand::rand_bytes(&mut id)
            .map_err(|_| backend("media file id generation failed"))?;
        Ok(Self(id))
    }

    pub fn as_bytes(&self) -> &[u8; FILE_ID_BYTES] {
        &self.0
    }

    fn from_slice(bytes: &[u8]) -> StorageResult<Self> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| StorageError::Corruption("invalid media file id".into()))
    }

    fn parse_hex(name: &str) -> Option<Self> {
        if name.len() != FILE_ID_BYTES * 2 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        hex::decode(name)
            .ok()
            .and_then(|bytes| bytes.try_into().ok().map(Self))
    }
}

/// What a stored body is for. Retained media is never deleted automatically;
/// the cache category (category 2) is reserved for avatars and group images.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaCategory {
    Retained,
}

impl MediaCategory {
    fn sql(self) -> i64 {
        match self {
            Self::Retained => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaFileState {
    Pending,
    Ready,
    /// The row was ready but its file is gone (crash or external deletion).
    /// Distinct from deliberate removal, which deletes the row.
    Lost,
}

/// Result of a publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaPublishOutcome {
    /// The body was written to a new file.
    Published(MediaFileId),
    /// A ready file with the same digest already existed; nothing was written.
    Existing(MediaFileId),
    /// A store reset removed the pending row mid-write; nothing was kept.
    Superseded,
}

/// Aggregate counts from one sweep batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MediaSweepReport {
    pub rows_checked: u64,
    pub files_checked: u64,
    pub pending_removed: u64,
    pub orphans_unlinked: u64,
    pub lost_marked: u64,
    /// The batch finished a full pass over rows and shard directories.
    pub complete: bool,
}

/// Per-account state shared by every clone of a storage handle.
#[derive(Default)]
pub(crate) struct MediaStoreShared {
    in_flight: Mutex<HashSet<MediaFileId>>,
    sweep: Mutex<SweepCursor>,
}

#[derive(Default)]
struct SweepCursor {
    /// Last row id checked in the current pass.
    row: Option<MediaFileId>,
    rows_done: bool,
    /// Next shard directory to list.
    shard: u16,
    /// Last file name checked in that shard, when it needs more batches.
    name: Option<String>,
}

/// Removes a live publish from the in-flight set however it ends.
struct InFlight {
    shared: Arc<MediaStoreShared>,
    id: MediaFileId,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        lock(&self.shared.in_flight).remove(&self.id);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn backend(message: &str) -> StorageError {
    StorageError::Backend(message.into())
}

/// I/O errors carry no path: their messages are fixed and aggregate.
fn io_error(error: &io::Error) -> StorageError {
    match error.kind() {
        io::ErrorKind::StorageFull => StorageError::Capacity("media store is full".into()),
        _ => backend("media file I/O failed"),
    }
}

fn format_error(error: MediaFormatError) -> StorageError {
    match error {
        MediaFormatError::Io(error) => io_error(&error),
        MediaFormatError::Backend => backend("media file cipher failed"),
        _ => StorageError::Corruption("media file failed verification".into()),
    }
}

/// Makes a file's contents durable. Apple platforms use plain `fsync`,
/// SQLite's own durability there; Rust's `sync_all` is `F_FULLFSYNC`, which
/// costs about 7 ms per file on an iPhone (mdk#2314 step 0).
pub(crate) fn sync_file(file: &File) -> io::Result<()> {
    #[cfg(target_vendor = "apple")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: `file` owns a valid open descriptor for the call.
        if unsafe { libc::fsync(file.as_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        file.sync_all()
    }
}

fn remove_if_present(path: &Path) -> io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

struct FileRow {
    key: FileKey,
    byte_len: u64,
}

/// Encrypted file store for one account. Cheap to clone; clones of the same
/// storage handle share in-flight publishes and the sweep cursor.
#[derive(Clone)]
pub struct MediaFileStore {
    storage: SqliteAccountStorage,
    root: PathBuf,
}

impl MediaFileStore {
    /// `root` is the account's `media/` directory, next to its database. It
    /// is created privately on first write. The host must exclude it from
    /// cloud and device backups.
    pub fn new(storage: SqliteAccountStorage, root: impl Into<PathBuf>) -> Self {
        Self {
            storage,
            root: root.into(),
        }
    }

    fn shared(&self) -> &Arc<MediaStoreShared> {
        &self.storage.media
    }

    /// Media I/O stops with the database: after terminal close every new
    /// operation fails with `StorageError::Closed`, and nothing reopens.
    fn ensure_open(&self) -> StorageResult<()> {
        if self.storage.is_closed() {
            return Err(StorageError::Closed("media store is closed".into()));
        }
        Ok(())
    }

    fn shard_dir(&self, shard: u8) -> PathBuf {
        self.root.join(format!("{shard:02x}"))
    }

    pub(crate) fn path(&self, id: &MediaFileId) -> PathBuf {
        self.shard_dir(id.0[0]).join(hex::encode(id.0))
    }

    /// The ready file with this content, if any.
    pub fn ready_file_by_digest(
        &self,
        category: MediaCategory,
        digest: &[u8; 32],
    ) -> StorageResult<Option<MediaFileId>> {
        self.ensure_open()?;
        let conn = self.storage.lock()?;
        self.reusable_by_digest(&conn, category, digest)
    }

    /// The ready file with this content, but only if its file is on disk. A
    /// ready row whose file is gone is marked lost on `conn` and not reused,
    /// so the body in hand is kept instead of being dropped for a missing one.
    pub(crate) fn reusable_by_digest(
        &self,
        conn: &Connection,
        category: MediaCategory,
        digest: &[u8; 32],
    ) -> StorageResult<Option<MediaFileId>> {
        let Some(id) = ready_by_digest(conn, category, digest)? else {
            return Ok(None);
        };
        match std::fs::symlink_metadata(self.path(&id)) {
            Ok(_) => Ok(Some(id)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                mark_lost_on(conn, &id)?;
                Ok(None)
            }
            Err(error) => Err(io_error(&error)),
        }
    }

    pub fn file_state(&self, id: &MediaFileId) -> StorageResult<Option<MediaFileState>> {
        self.ensure_open()?;
        let conn = self.storage.lock()?;
        let state: Option<i64> = conn
            .query_row(
                "SELECT state FROM media_files WHERE id=?1",
                [id.0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        Ok(state.map(|state| match state {
            STATE_PENDING => MediaFileState::Pending,
            STATE_READY => MediaFileState::Ready,
            _ => MediaFileState::Lost,
        }))
    }

    /// Publishes `byte_len` bytes of verified plaintext from `reader`. The
    /// body must hash to `digest`; a ready file with that digest is reused
    /// without writing.
    pub fn publish_from_reader(
        &self,
        category: MediaCategory,
        reader: &mut dyn Read,
        byte_len: u64,
        digest: [u8; 32],
        now: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> StorageResult<MediaPublishOutcome> {
        self.publish_with(
            category,
            reader,
            byte_len,
            digest,
            now,
            cancelled,
            &mut |_, _| Ok(()),
        )
    }

    /// Like `publish_from_reader`, but `commit` runs inside the transaction
    /// that makes the file ready, or that observes an existing ready file
    /// with the same digest. A `commit` error rolls that transaction back and
    /// discards the new file.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_with(
        &self,
        category: MediaCategory,
        reader: &mut dyn Read,
        byte_len: u64,
        digest: [u8; 32],
        now: u64,
        cancelled: &dyn Fn() -> bool,
        commit: &mut dyn FnMut(&Connection, MediaFileId) -> StorageResult<()>,
    ) -> StorageResult<MediaPublishOutcome> {
        self.ensure_open()?;
        if let Some(existing) = self.commit_existing(category, &digest, commit)? {
            return Ok(MediaPublishOutcome::Existing(existing));
        }
        let (id, key, _in_flight) = self.insert_pending(category, byte_len, &digest, now)?;
        let result = self
            .write_body(&id, &key, reader, byte_len, &digest, cancelled)
            .and_then(|()| self.mark_ready(&id, category, &digest, commit));
        match result {
            Ok(MediaPublishOutcome::Published(id)) => Ok(MediaPublishOutcome::Published(id)),
            Ok(other) => {
                // The row is gone (store reset) or another file won the
                // digest; only this file remains to remove.
                let _ = remove_if_present(&self.path(&id));
                Ok(other)
            }
            Err(error) => {
                self.abandon(&id);
                Err(error)
            }
        }
    }

    fn commit_existing(
        &self,
        category: MediaCategory,
        digest: &[u8; 32],
        commit: &mut dyn FnMut(&Connection, MediaFileId) -> StorageResult<()>,
    ) -> StorageResult<Option<MediaFileId>> {
        self.storage.connection.with_transaction(|| {
            let conn = self.storage.lock()?;
            let Some(existing) = self.reusable_by_digest(&conn, category, digest)? else {
                return Ok(None);
            };
            commit(&conn, existing)?;
            Ok(Some(existing))
        })
    }

    /// Step 1: the intent row, registered as in flight before it commits.
    fn insert_pending(
        &self,
        category: MediaCategory,
        byte_len: u64,
        digest: &[u8; 32],
        now: u64,
    ) -> StorageResult<(MediaFileId, FileKey, InFlight)> {
        let id = MediaFileId::random()?;
        let mut key = Zeroizing::new([0; FILE_KEY_BYTES]);
        openssl::rand::rand_bytes(key.as_mut())
            .map_err(|_| backend("media file key generation failed"))?;
        let in_flight = InFlight {
            shared: self.shared().clone(),
            id,
        };
        lock(&self.shared().in_flight).insert(id);
        let now = u64_to_i64(now)?;
        self.storage.lock()?.execute(
            "INSERT INTO media_files(id,file_key,state,category,byte_len,plaintext_digest,created_at,last_used_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?7)",
            params![
                id.0.as_slice(),
                key.as_slice(),
                STATE_PENDING,
                category.sql(),
                u64_to_i64(byte_len)?,
                digest.as_slice(),
                now
            ],
        )
        .storage()?;
        Ok((id, FileKey::from_bytes(*key), in_flight))
    }

    /// Step 2: create the file, stream the body through the format while
    /// hashing it, and sync once.
    fn write_body(
        &self,
        id: &MediaFileId,
        key: &FileKey,
        reader: &mut dyn Read,
        byte_len: u64,
        digest: &[u8; 32],
        cancelled: &dyn Fn() -> bool,
    ) -> StorageResult<()> {
        fs_private::create_dir_all_private(&self.shard_dir(id.0[0])).map_err(|e| io_error(&e))?;
        let file = fs_private::create_new_private(&self.path(id)).map_err(|e| io_error(&e))?;
        let mut writer = MediaFileWriter::new(file, key, &id.0).map_err(format_error)?;
        let mut hasher = Sha256::new();
        let mut buffer = Zeroizing::new(vec![0; COPY_CHUNK_BYTES]);
        let mut written = 0_u64;
        loop {
            if cancelled() {
                return Err(backend("media publish cancelled"));
            }
            self.ensure_open()?;
            let read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error(&error)),
            };
            written += read as u64;
            if written > byte_len {
                return Err(backend("media body longer than declared"));
            }
            hasher.update(&buffer[..read]);
            writer
                .write_all(&buffer[..read])
                .map_err(|e| io_error(&e))?;
        }
        if written != byte_len {
            return Err(backend("media body shorter than declared"));
        }
        if <[u8; 32]>::from(hasher.finalize()) != *digest {
            return Err(StorageError::Corruption(
                "media body digest mismatch".into(),
            ));
        }
        let file = writer.finish().map_err(format_error)?;
        sync_file(&file).map_err(|e| io_error(&e))
    }

    /// Step 3: one transaction makes the file ready and runs `commit`. If a
    /// concurrent publish already made the same content ready, this row is
    /// dropped and `commit` attaches to that file instead.
    fn mark_ready(
        &self,
        id: &MediaFileId,
        category: MediaCategory,
        digest: &[u8; 32],
        commit: &mut dyn FnMut(&Connection, MediaFileId) -> StorageResult<()>,
    ) -> StorageResult<MediaPublishOutcome> {
        self.ensure_open()?;
        self.storage.connection.with_transaction(|| {
            let conn = self.storage.lock()?;
            let pending: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM media_files WHERE id=?1 AND state=?2)",
                    params![id.0.as_slice(), STATE_PENDING],
                    |row| row.get(0),
                )
                .storage()?;
            if !pending {
                return Ok(MediaPublishOutcome::Superseded);
            }
            if let Some(existing) = self.reusable_by_digest(&conn, category, digest)? {
                conn.execute("DELETE FROM media_files WHERE id=?1", [id.0.as_slice()])
                    .storage()?;
                commit(&conn, existing)?;
                return Ok(MediaPublishOutcome::Existing(existing));
            }
            conn.execute(
                "UPDATE media_files SET state=?2 WHERE id=?1",
                params![id.0.as_slice(), STATE_READY],
            )
            .storage()?;
            commit(&conn, *id)?;
            Ok(MediaPublishOutcome::Published(*id))
        })
    }

    /// Failed publish: drop the row (and key) first, then the file. Anything
    /// left behind is reclaimed by the sweep after the in-flight entry clears.
    fn abandon(&self, id: &MediaFileId) {
        let deleted = self.storage.lock().and_then(|conn| {
            conn.execute(
                "DELETE FROM media_files WHERE id=?1 AND state=?2",
                params![id.0.as_slice(), STATE_PENDING],
            )
            .storage()
        });
        if deleted.is_ok() {
            let _ = remove_if_present(&self.path(id));
        }
    }

    fn ready_row(&self, id: &MediaFileId) -> StorageResult<Option<FileRow>> {
        let conn = self.storage.lock()?;
        conn.query_row(
            "SELECT file_key,byte_len FROM media_files WHERE id=?1 AND state=?2",
            params![id.0.as_slice(), STATE_READY],
            |row| {
                let key = Zeroizing::new(row.get::<_, Vec<u8>>(0)?);
                let byte_len: i64 = row.get(1)?;
                Ok((key, byte_len))
            },
        )
        .optional()
        .storage()?
        .map(|(key, byte_len)| {
            let key: [u8; FILE_KEY_BYTES] = key
                .as_slice()
                .try_into()
                .map_err(|_| StorageError::Corruption("invalid media file key".into()))?;
            Ok(FileRow {
                key: FileKey::from_bytes(key),
                byte_len: u64::try_from(byte_len)
                    .map_err(|_| StorageError::Corruption("invalid media file length".into()))?,
            })
        })
        .transpose()
    }

    /// Opens a ready file for offset reads. `None` means there is no ready
    /// file; a ready row whose file is missing is marked lost first. The
    /// reader stops with the database: after terminal close every read fails
    /// with `StorageError::Closed`, including reads of a cached segment.
    pub fn open_reader(&self, id: &MediaFileId) -> StorageResult<Option<MediaStoreReader>> {
        self.ensure_open()?;
        let Some(row) = self.ready_row(id)? else {
            return Ok(None);
        };
        let file = match File::open(self.path(id)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.mark_lost(id)?;
                return Ok(None);
            }
            Err(error) => return Err(io_error(&error)),
        };
        let reader = MediaFileReader::open(file, &row.key, &id.0).map_err(format_error)?;
        if reader.plaintext_bytes() != row.byte_len {
            return Err(StorageError::Corruption(
                "media file length differs from its row".into(),
            ));
        }
        Ok(Some(MediaStoreReader {
            storage: self.storage.clone(),
            reader,
            position: 0,
        }))
    }

    /// Reads plaintext at `offset` into `out`. `None` means no ready file.
    pub fn read_at(
        &self,
        id: &MediaFileId,
        offset: u64,
        out: &mut [u8],
    ) -> StorageResult<Option<usize>> {
        let Some(mut reader) = self.open_reader(id)? else {
            return Ok(None);
        };
        reader.read_at(offset, out).map(Some)
    }

    fn mark_lost(&self, id: &MediaFileId) -> StorageResult<bool> {
        let conn = self.storage.lock()?;
        mark_lost_on(&conn, id)
    }

    /// Attaches the slot identified by an acquisition `token` to a ready file.
    /// Re-pointing a slot deletes its old reference first, so the old file's
    /// last-reference trigger still fires. Callers unlink nothing here: an old
    /// file whose row went with it is reclaimed by the sweep.
    pub(crate) fn attach(conn: &Connection, token: &[u8], id: MediaFileId) -> StorageResult<()> {
        let current: Option<Vec<u8>> = conn
            .query_row(
                "SELECT file_id FROM media_file_refs WHERE token=?1",
                [token],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        if current.as_deref() == Some(id.0.as_slice()) {
            return Ok(());
        }
        conn.execute("DELETE FROM media_file_refs WHERE token=?1", [token])
            .storage()?;
        conn.execute(
            "INSERT INTO media_file_refs(token,file_id) VALUES(?1,?2)",
            params![token, id.0.as_slice()],
        )
        .storage()?;
        Ok(())
    }

    /// Points the slot identified by an acquisition `token` at a ready file.
    /// Publishing callers attach inside the ready commit instead.
    pub fn attach_reference(&self, token: &[u8], id: MediaFileId) -> StorageResult<()> {
        self.ensure_open()?;
        self.storage.connection.with_transaction(|| {
            let conn = self.storage.lock()?;
            Self::attach(&conn, token, id)
        })
    }

    /// Removes a slot's reference. When it was the file's last reference the
    /// row and key are deleted in the same transaction, and the file is then
    /// unlinked. Returns whether a reference existed.
    pub fn remove_reference(&self, token: &[u8]) -> StorageResult<bool> {
        self.ensure_open()?;
        let removed = self.storage.connection.with_transaction(|| {
            let conn = self.storage.lock()?;
            let file: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT file_id FROM media_file_refs WHERE token=?1",
                    [token],
                    |row| row.get(0),
                )
                .optional()
                .storage()?;
            let Some(file) = file else {
                return Ok(None);
            };
            conn.execute("DELETE FROM media_file_refs WHERE token=?1", [token])
                .storage()?;
            let row_left: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM media_files WHERE id=?1)",
                    [&file],
                    |row| row.get(0),
                )
                .storage()?;
            Ok(Some((MediaFileId::from_slice(&file)?, row_left)))
        })?;
        match removed {
            None => Ok(false),
            Some((id, row_left)) => {
                if !row_left {
                    let _ = remove_if_present(&self.path(&id));
                }
                Ok(true)
            }
        }
    }

    /// One bounded sweep batch: up to `limit` rows, then shard directories
    /// until `limit` entries were listed (a started shard is finished). Runs
    /// at worker start until `complete` and then on the maintenance tick.
    pub fn sweep(&self, limit: usize) -> StorageResult<MediaSweepReport> {
        self.ensure_open()?;
        let limit = limit.max(1);
        let mut report = MediaSweepReport::default();
        let mut cursor = lock(&self.shared().sweep);
        if !cursor.rows_done {
            self.sweep_rows(&mut cursor, limit, &mut report)?;
        }
        if cursor.rows_done {
            self.sweep_files(&mut cursor, limit, &mut report)?;
        }
        if report.pending_removed + report.orphans_unlinked + report.lost_marked > 0 {
            tracing::info!(
                target: TRACE_TARGET,
                method = "sweep",
                pending_removed = report.pending_removed,
                orphans_unlinked = report.orphans_unlinked,
                lost_marked = report.lost_marked,
                "media store sweep reclaimed state"
            );
        }
        Ok(report)
    }

    fn sweep_rows(
        &self,
        cursor: &mut SweepCursor,
        limit: usize,
        report: &mut MediaSweepReport,
    ) -> StorageResult<()> {
        let after = cursor.row.map(|id| id.0.to_vec()).unwrap_or_default();
        let rows: Vec<(Vec<u8>, i64)> = {
            let conn = self.storage.lock()?;
            let mut statement = conn
                .prepare("SELECT id,state FROM media_files WHERE id>?1 ORDER BY id LIMIT ?2")
                .storage()?;
            statement
                .query_map(params![after, limit as i64], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .storage()?
                .collect::<Result<_, _>>()
                .storage()?
        };
        for (id, state) in &rows {
            self.ensure_open()?;
            let id = MediaFileId::from_slice(id)?;
            cursor.row = Some(id);
            report.rows_checked += 1;
            if lock(&self.shared().in_flight).contains(&id) {
                continue;
            }
            match *state {
                STATE_PENDING => {
                    let deleted = self
                        .storage
                        .lock()?
                        .execute(
                            "DELETE FROM media_files WHERE id=?1 AND state=?2",
                            params![id.0.as_slice(), STATE_PENDING],
                        )
                        .storage()?;
                    if deleted == 1 {
                        remove_if_present(&self.path(&id)).map_err(|e| io_error(&e))?;
                        report.pending_removed += 1;
                    }
                }
                STATE_READY => match std::fs::symlink_metadata(self.path(&id)) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        if self.mark_lost(&id)? {
                            report.lost_marked += 1;
                        }
                    }
                    Err(error) => return Err(io_error(&error)),
                },
                _ => {}
            }
        }
        if rows.len() < limit {
            cursor.rows_done = true;
            cursor.row = None;
        }
        Ok(())
    }

    /// Checks up to `limit` of this store's file names, resuming inside a
    /// shard that needs more than one batch. Listing a shard is a directory
    /// read; database lookups and unlinks stay within `limit`.
    fn sweep_files(
        &self,
        cursor: &mut SweepCursor,
        limit: usize,
        report: &mut MediaSweepReport,
    ) -> StorageResult<()> {
        let mut budget = limit;
        while cursor.shard <= u8::MAX as u16 && budget > 0 {
            self.ensure_open()?;
            let shard = cursor.shard as u8;
            let entries = match std::fs::read_dir(self.shard_dir(shard)) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    cursor.shard += 1;
                    cursor.name = None;
                    continue;
                }
                Err(error) => return Err(io_error(&error)),
            };
            // Only names this store creates are its to judge.
            let mut names = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|e| io_error(&e))?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let ours = MediaFileId::parse_hex(&name).is_some_and(|id| id.0[0] == shard);
                if ours && cursor.name.as_ref().is_none_or(|after| &name > after) {
                    names.push(name);
                }
            }
            names.sort_unstable();
            let take = names.len().min(budget);
            for name in &names[..take] {
                let id = MediaFileId::parse_hex(name).expect("filtered to valid ids");
                budget -= 1;
                report.files_checked += 1;
                cursor.name = Some(name.clone());
                let has_row: bool = self
                    .storage
                    .lock()?
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM media_files WHERE id=?1)",
                        [id.0.as_slice()],
                        |row| row.get(0),
                    )
                    .storage()?;
                if !has_row && remove_if_present(&self.path(&id)).map_err(|e| io_error(&e))? {
                    report.orphans_unlinked += 1;
                }
            }
            if take == names.len() {
                cursor.shard += 1;
                cursor.name = None;
            }
        }
        if cursor.shard > u8::MAX as u16 {
            *cursor = SweepCursor::default();
            report.complete = true;
        }
        Ok(())
    }
}

/// An open media file that refuses reads once the account database closes.
pub struct MediaStoreReader {
    storage: SqliteAccountStorage,
    reader: MediaFileReader<File>,
    position: u64,
}

impl MediaStoreReader {
    pub fn plaintext_bytes(&self) -> u64 {
        self.reader.plaintext_bytes()
    }

    /// Fills `out` from plaintext `offset`; returns 0 at or past the end.
    pub fn read_at(&mut self, offset: u64, out: &mut [u8]) -> StorageResult<usize> {
        if self.storage.is_closed() {
            return Err(StorageError::Closed("media store is closed".into()));
        }
        self.reader.read_at(offset, out).map_err(format_error)
    }
}

impl Read for MediaStoreReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self
            .read_at(self.position, out)
            .map_err(|error| io::Error::other(error.to_string()))?;
        self.position += read as u64;
        Ok(read)
    }
}

/// Marks a ready row lost and zeroes its key.
fn mark_lost_on(conn: &Connection, id: &MediaFileId) -> StorageResult<bool> {
    Ok(conn
        .execute(
            "UPDATE media_files SET state=?2,file_key=zeroblob(32) WHERE id=?1 AND state=?3",
            params![id.0.as_slice(), STATE_LOST, STATE_READY],
        )
        .storage()?
        == 1)
}

fn ready_by_digest(
    conn: &Connection,
    category: MediaCategory,
    digest: &[u8; 32],
) -> StorageResult<Option<MediaFileId>> {
    let id: Option<Vec<u8>> = conn
        .query_row(
            "SELECT id FROM media_files WHERE category=?1 AND plaintext_digest=?2 AND state=?3",
            params![category.sql(), digest.as_slice(), STATE_READY],
            |row| row.get(0),
        )
        .optional()
        .storage()?;
    id.map(|id| MediaFileId::from_slice(&id)).transpose()
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
