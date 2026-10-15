//! The file lifecycle: one file per body under `<root>/<shard>/<id>`, one
//! catalog row per file holding its random key and state.
//!
//! The catalog row is the authority and the only place writers serialize;
//! files take no locks. Every change follows the intent-first order:
//!
//! - **Publish:** (1) insert a `pending` row with a fresh id and key; (2)
//!   exclusively create `<id>` at mode 0600, write it, sync it once; (3) one
//!   transaction (the target's `commit_ready`) marks it `ready` and attaches
//!   it. No temporary name, rename or directory sync: the `pending` row
//!   already marks the file unfinished.
//! - **Delete:** the catalog deletes the row (the key) first; the store then
//!   unlinks the file best effort.
//! - **Sweep:** a `pending` row no live publish owns is deleted with its file;
//!   a file with no row is unlinked; a `ready` row whose file is gone becomes
//!   `lost`. A file is only ever created after its row commits, so the
//!   catalog alone decides. Batches stay within their limit, even inside one
//!   shard.
//! - **Reuse:** identical content is stored once, but a ready row is reused
//!   only if its file is on disk; a missing one is marked `lost` instead.
//!
//! Live publishes register their id in the store's in-flight set so a
//! concurrent sweep leaves their `pending` row alone. The set lives in this
//! process and is empty after a restart, which is exactly when abandoned
//! `pending` rows must be reclaimed. Use one `MediaStore` (and its clones)
//! per account.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::catalog::{
    Category, ExistingOutcome, FileId, FileState, MediaCatalog, NewFile, PublishTarget,
    ReadyOutcome,
};
use crate::error::{MediaError, MediaResult, io_error};
use crate::format::{FILE_ID_BYTES, FILE_KEY_BYTES, FileKey, MediaFileReader, MediaFileWriter};

const COPY_CHUNK_BYTES: usize = 1024 * 1024;
const TRACE_TARGET: &str = "media_store";

/// Directory name of the store inside an account directory.
pub const MEDIA_DIRECTORY: &str = "media";

/// Result of a publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The body was written to a new file.
    Published(FileId),
    /// A ready file with the same content was attached; nothing was kept.
    Existing(FileId),
    /// The publication no longer owns its slot, or a reset removed the row;
    /// nothing was kept.
    Superseded,
}

/// Aggregate counts from one sweep batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub rows_checked: u64,
    pub files_checked: u64,
    pub pending_removed: u64,
    pub orphans_unlinked: u64,
    pub lost_marked: u64,
    /// The batch finished a full pass over rows and shard directories.
    pub complete: bool,
}

#[derive(Default)]
struct SweepCursor {
    /// Last row id checked in the current pass.
    row: Option<FileId>,
    rows_done: bool,
    /// Next shard directory to list.
    shard: u16,
    /// Last file name checked in that shard, when it needs more batches.
    name: Option<String>,
}

struct Inner<C> {
    root: PathBuf,
    catalog: C,
    closed: AtomicBool,
    in_flight: Mutex<HashSet<FileId>>,
    sweep: Mutex<SweepCursor>,
}

impl<C: MediaCatalog> Inner<C> {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.catalog.is_closed()
    }

    fn ensure_open(&self) -> MediaResult<()> {
        if self.is_closed() {
            return Err(MediaError::Closed);
        }
        Ok(())
    }
}

/// Encrypted file store for one account. Synchronous and blocking: run it on
/// a blocking thread pool, never on an async task. Cheap to clone; clones
/// share the close latch, in-flight publishes and the sweep cursor.
pub struct MediaStore<C> {
    inner: Arc<Inner<C>>,
}

impl<C> Clone for MediaStore<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// In-flight registration, removed however the publish ends.
pub(crate) struct InFlight<'a> {
    set: &'a Mutex<HashSet<FileId>>,
    id: FileId,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        lock(self.set).remove(&self.id);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn random<const N: usize>() -> MediaResult<[u8; N]> {
    let mut bytes = [0; N];
    openssl::rand::rand_bytes(&mut bytes).map_err(|_| MediaError::Random)?;
    Ok(bytes)
}

/// Makes a file's contents durable. Apple platforms use plain `fsync`,
/// SQLite's own durability there; Rust's `sync_all` is `F_FULLFSYNC`, which
/// costs about 7 ms per file on an iPhone (mdk#2314 step 0).
pub fn sync_file(file: &File) -> io::Result<()> {
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

impl<C: MediaCatalog> MediaStore<C> {
    /// `root` is the account's `media/` directory, next to its database. It
    /// is created privately on first write. Hosts must exclude the account
    /// directory from cloud and device backups.
    pub fn new(root: impl Into<PathBuf>, catalog: C) -> Self {
        Self {
            inner: Arc::new(Inner {
                root: root.into(),
                catalog,
                closed: AtomicBool::new(false),
                in_flight: Mutex::new(HashSet::new()),
                sweep: Mutex::new(SweepCursor::default()),
            }),
        }
    }

    pub fn catalog(&self) -> &C {
        &self.inner.catalog
    }

    /// Terminal: every later call, including reads through open readers,
    /// fails with `MediaError::Closed`. Closing the catalog's database has
    /// the same effect. Media files hold no locks, so there is nothing else
    /// to release.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
    }

    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    fn shard_dir(&self, shard: u8) -> PathBuf {
        self.inner.root.join(format!("{shard:02x}"))
    }

    /// The file's path. Never log it.
    pub fn path(&self, id: &FileId) -> PathBuf {
        self.shard_dir(id.0[0]).join(hex::encode(id.0))
    }

    fn present(&self, id: FileId) -> bool {
        std::fs::symlink_metadata(self.path(&id)).is_ok()
    }

    pub fn file_state(&self, id: &FileId) -> MediaResult<Option<FileState>> {
        self.inner.ensure_open()?;
        Ok(self.inner.catalog.file_state(*id)?)
    }

    /// Publishes `byte_len` bytes of plaintext from `body`, which must hash
    /// to `digest`, for `target`. A present ready file with the same content
    /// is attached instead, without reading `body`.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        &self,
        target: &dyn PublishTarget,
        category: Category,
        body: &mut dyn Read,
        byte_len: u64,
        digest: [u8; 32],
        now: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> MediaResult<PublishOutcome> {
        self.inner.ensure_open()?;
        if target.superseded()? {
            return Ok(PublishOutcome::Superseded);
        }
        match target.commit_existing(category, &digest, &|id| self.present(id))? {
            ExistingOutcome::Attached(id) => return Ok(PublishOutcome::Existing(id)),
            ExistingOutcome::Superseded => return Ok(PublishOutcome::Superseded),
            ExistingOutcome::None => {}
        }
        let (id, key, _in_flight) = self.insert_pending(category, byte_len, &digest, now)?;
        let result = self
            .write_body(&id, &key, body, byte_len, &digest, cancelled)
            .and_then(|()| {
                self.inner.ensure_open()?;
                Ok(target.commit_ready(id, category, &digest, &|twin| self.present(twin))?)
            });
        match result {
            Ok(ReadyOutcome::Ready) => Ok(PublishOutcome::Published(id)),
            Ok(ReadyOutcome::Existing(twin)) => {
                // The target deleted this row; only the file remains.
                let _ = remove_if_present(&self.path(&id));
                Ok(PublishOutcome::Existing(twin))
            }
            Ok(ReadyOutcome::Superseded) => {
                self.abandon(&id);
                Ok(PublishOutcome::Superseded)
            }
            Err(error) => {
                self.abandon(&id);
                Err(error)
            }
        }
    }

    /// Step 1: the intent row, registered as in flight before it commits.
    pub(crate) fn insert_pending(
        &self,
        category: Category,
        byte_len: u64,
        digest: &[u8; 32],
        now: u64,
    ) -> MediaResult<(FileId, FileKey, InFlight<'_>)> {
        let id = FileId(random::<FILE_ID_BYTES>()?);
        let key = Zeroizing::new(random::<FILE_KEY_BYTES>()?);
        let in_flight = InFlight {
            set: &self.inner.in_flight,
            id,
        };
        lock(&self.inner.in_flight).insert(id);
        self.inner.catalog.insert_pending(&NewFile {
            id,
            key: FileKey::from_bytes(*key),
            category,
            byte_len,
            digest: *digest,
            created_at: now,
        })?;
        Ok((id, FileKey::from_bytes(*key), in_flight))
    }

    /// Step 2: create the file, stream the body through the format while
    /// hashing it, and sync once.
    pub(crate) fn write_body(
        &self,
        id: &FileId,
        key: &FileKey,
        body: &mut dyn Read,
        byte_len: u64,
        digest: &[u8; 32],
        cancelled: &dyn Fn() -> bool,
    ) -> MediaResult<()> {
        fs_private::create_dir_all_private(&self.shard_dir(id.0[0])).map_err(|e| io_error(&e))?;
        let file = fs_private::create_new_private(&self.path(id)).map_err(|e| io_error(&e))?;
        let mut writer = MediaFileWriter::new(file, key, &id.0)?;
        let mut hasher = Sha256::new();
        let mut buffer = Zeroizing::new(vec![0; COPY_CHUNK_BYTES]);
        let mut written = 0_u64;
        loop {
            if cancelled() {
                return Err(MediaError::Cancelled);
            }
            self.inner.ensure_open()?;
            let read = match body.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error(&error)),
            };
            written += read as u64;
            if written > byte_len {
                return Err(MediaError::InvalidBody("media body longer than declared"));
            }
            hasher.update(&buffer[..read]);
            writer
                .write_all(&buffer[..read])
                .map_err(|e| io_error(&e))?;
        }
        if written != byte_len {
            return Err(MediaError::InvalidBody("media body shorter than declared"));
        }
        if <[u8; 32]>::from(hasher.finalize()) != *digest {
            return Err(MediaError::InvalidBody("media body digest mismatch"));
        }
        let file = writer.finish()?;
        sync_file(&file).map_err(|e| io_error(&e))
    }

    /// Failed publish: drop the row (and key) first, then the file. Anything
    /// left behind is reclaimed by the sweep after the in-flight entry clears.
    /// Nothing runs after close: the next process's sweep reclaims the rest.
    fn abandon(&self, id: &FileId) {
        if self.inner.is_closed() {
            return;
        }
        if self.inner.catalog.abandon_pending(*id).is_ok() {
            let _ = remove_if_present(&self.path(id));
        }
    }

    /// Opens a ready file for offset reads. `None` means there is no ready
    /// file; a ready row whose file is missing is marked lost first.
    pub fn open_reader(&self, id: &FileId) -> MediaResult<Option<MediaReader<C>>> {
        self.inner.ensure_open()?;
        let Some(row) = self.inner.catalog.ready_file(*id)? else {
            return Ok(None);
        };
        let file = match File::open(self.path(id)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.inner.catalog.mark_lost(*id)?;
                return Ok(None);
            }
            Err(error) => return Err(io_error(&error)),
        };
        let reader = MediaFileReader::open(file, &row.key, &id.0)?;
        if reader.plaintext_bytes() != row.byte_len {
            return Err(MediaError::Corruption(
                "media file length differs from its row",
            ));
        }
        Ok(Some(MediaReader {
            inner: self.inner.clone(),
            reader,
            position: 0,
        }))
    }

    /// Reads plaintext at `offset` into `out`. `None` means no ready file.
    pub fn read_at(&self, id: &FileId, offset: u64, out: &mut [u8]) -> MediaResult<Option<usize>> {
        let Some(mut reader) = self.open_reader(id)? else {
            return Ok(None);
        };
        reader.read_at(offset, out).map(Some)
    }

    /// Unlinks the files of `ids` whose rows are gone. Callers pass the ids a
    /// committed deletion released; the sweep removes anything missed.
    pub fn unlink_released(&self, ids: &[FileId]) {
        for id in ids {
            if matches!(self.inner.catalog.file_state(*id), Ok(None)) {
                let _ = remove_if_present(&self.path(id));
            }
        }
    }

    /// One bounded sweep batch: up to `limit` rows, then up to `limit` of
    /// this store's file names. Run batches at startup until `complete`, then
    /// on a maintenance tick.
    pub fn sweep(&self, limit: usize) -> MediaResult<SweepReport> {
        self.inner.ensure_open()?;
        let limit = limit.max(1);
        let mut report = SweepReport::default();
        let mut cursor = lock(&self.inner.sweep);
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
        report: &mut SweepReport,
    ) -> MediaResult<()> {
        let rows = self.inner.catalog.page(cursor.row, limit)?;
        for (id, state) in &rows {
            self.inner.ensure_open()?;
            cursor.row = Some(*id);
            report.rows_checked += 1;
            if lock(&self.inner.in_flight).contains(id) {
                continue;
            }
            match state {
                FileState::Pending => {
                    if self.inner.catalog.abandon_pending(*id)? {
                        remove_if_present(&self.path(id)).map_err(|e| io_error(&e))?;
                        report.pending_removed += 1;
                    }
                }
                FileState::Ready => match std::fs::symlink_metadata(self.path(id)) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        if self.inner.catalog.mark_lost(*id)? {
                            report.lost_marked += 1;
                        }
                    }
                    Err(error) => return Err(io_error(&error)),
                },
                FileState::Lost => {}
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
    /// read; catalog lookups and unlinks stay within `limit`.
    fn sweep_files(
        &self,
        cursor: &mut SweepCursor,
        limit: usize,
        report: &mut SweepReport,
    ) -> MediaResult<()> {
        let mut budget = limit;
        while cursor.shard <= u8::MAX as u16 && budget > 0 {
            self.inner.ensure_open()?;
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
                let ours = FileId::parse_hex(&name).is_some_and(|id| id.0[0] == shard);
                if ours && cursor.name.as_ref().is_none_or(|after| &name > after) {
                    names.push(name);
                }
            }
            names.sort_unstable();
            let take = names.len().min(budget);
            for name in &names[..take] {
                let Some(id) = FileId::parse_hex(name) else {
                    continue;
                };
                budget -= 1;
                report.files_checked += 1;
                cursor.name = Some(name.clone());
                if self.inner.catalog.file_state(id)?.is_none()
                    && remove_if_present(&self.path(&id)).map_err(|e| io_error(&e))?
                {
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

/// An open media file that refuses reads once the store or its catalog
/// closes, including reads of a segment it already decrypted.
pub struct MediaReader<C> {
    inner: Arc<Inner<C>>,
    reader: MediaFileReader<File>,
    position: u64,
}

impl<C: MediaCatalog> MediaReader<C> {
    pub fn plaintext_bytes(&self) -> u64 {
        self.reader.plaintext_bytes()
    }

    /// Fills `out` from plaintext `offset`; returns 0 at or past the end.
    pub fn read_at(&mut self, offset: u64, out: &mut [u8]) -> MediaResult<usize> {
        self.inner.ensure_open()?;
        Ok(self.reader.read_at(offset, out)?)
    }
}

impl<C: MediaCatalog> Read for MediaReader<C> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self
            .read_at(self.position, out)
            .map_err(|error| io::Error::other(error.to_string()))?;
        self.position += read as u64;
        Ok(read)
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
