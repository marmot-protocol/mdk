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
//! - **Staged publication (outgoing):** like publish, but the third step
//!   marks the row `staged` under an owner (an outgoing upload) instead of
//!   `ready`. The file is complete and survives restarts while its owner
//!   exists; promotion later makes it `ready` and attaches slots, in one
//!   transaction. An owner that goes away releases its staged row (key first,
//!   then the file); the sweep backstops an unowned staged row.
//! - **Download checkpoints:** a resumable download's ciphertext goes to an
//!   append-only `<shard>/<id>.wire` file through a [`CheckpointTarget`]. The
//!   row commits before its file exists and is deleted before the file is.
//!   Each append is synced before the row records it, so the file can be at
//!   most one append ([`CHECKPOINT_APPEND_MAX`]) longer than recorded. A
//!   refused or failed append is cut off again at once; opening a checkpoint
//!   and the sweep cut off a tail a crash left. Operations on one checkpoint
//!   serialize in the store.
//!
//! Live publishes register their id in the store's in-flight set so a
//! concurrent sweep leaves their `pending` row alone. The set lives in this
//! process and is empty after a restart, which is exactly when abandoned
//! `pending` rows must be reclaimed. Use one `MediaStore` (and its clones)
//! per account.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::catalog::{
    CatalogError, CatalogResult, Category, CheckpointTarget, ExistingOutcome, FileId, FilePresence,
    FileState, MediaCatalog, NewFile, PromoteTarget, PromotedOutcome, PublishTarget, ReadyOutcome,
    StageTarget, StagedOutcome,
};
use crate::error::{MediaError, MediaResult, io_error};
use crate::format::{
    FILE_ID_BYTES, FILE_KEY_BYTES, FileKey, MediaFileReader, MediaFileWriter, file_bytes,
};

const COPY_CHUNK_BYTES: usize = 1024 * 1024;
/// Open readers kept for sequential offset reads (`read_attachment_asset`
/// reads at most 1 MiB per call), so each window skips the key lookup and the
/// file open. Small, and dropped after a short idle time so a cached key does
/// not outlive its use.
const READER_CACHE_ENTRIES: usize = 4;
const READER_CACHE_IDLE: Duration = Duration::from_secs(30);
const TRACE_TARGET: &str = "media_store";

/// Directory name of the store inside an account directory.
pub const MEDIA_DIRECTORY: &str = "media";

/// Largest single checkpoint append. It bounds what a crash between an
/// append and its record can leave on disk unrecorded: callers that measure
/// free space against a checkpoint's recorded length allow this much slack.
pub const CHECKPOINT_APPEND_MAX: usize = 1024 * 1024;
/// Suffix of a download checkpoint's wire file, beside the store's files.
const WIRE_SUFFIX: &str = ".wire";

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

/// The result of [`MediaStore::stage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageOutcome {
    /// The body is staged in `id` under its owner; `digest` is its SHA-256,
    /// computed while sealing.
    Staged { id: FileId, digest: [u8; 32] },
    /// The owner no longer accepts the body; nothing was kept.
    Superseded,
}

/// The result of [`MediaStore::promote`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromoteOutcome {
    /// The staged file is ready and attached.
    Ready,
    /// An identical ready file was attached instead; the staged copy is gone.
    Existing(FileId),
    /// Nothing was attached; a staged file is kept for its owner.
    Superseded,
    /// Every slot already held its body; the owner and its staged copy are
    /// gone.
    Released,
}

/// Aggregate counts from one sweep batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub rows_checked: u64,
    pub files_checked: u64,
    pub pending_removed: u64,
    pub orphans_unlinked: u64,
    pub lost_marked: u64,
    /// Staged rows no owner held any more, deleted with their files.
    pub staged_released: u64,
    /// Wire checkpoints cut back to their recorded length.
    pub wire_tails_trimmed: u64,
    /// The batch finished a full pass over rows and shard directories.
    pub complete: bool,
}

#[derive(Default)]
struct SweepCursor {
    /// Last row id checked in the current pass.
    row: Option<FileId>,
    rows_done: bool,
    /// Shard directory being listed.
    shard: u16,
    /// Its open listing, kept across batches so each entry is visited once
    /// per pass. Holds a directory handle, not a lock; close drops it.
    entries: Option<std::fs::ReadDir>,
}

struct CachedReader {
    id: FileId,
    reader: MediaFileReader<File>,
    used: Instant,
}

struct Inner<C> {
    root: PathBuf,
    catalog: C,
    closed: AtomicBool,
    in_flight: Mutex<HashSet<FileId>>,
    sweep: Mutex<SweepCursor>,
    readers: Mutex<Vec<CachedReader>>,
    /// Keys of checkpoints an operation holds; see [`CheckpointLock`].
    checkpoints: Mutex<Vec<Vec<u8>>>,
    checkpoint_released: Condvar,
    #[cfg(any(test, feature = "test-support"))]
    full_disk_for_test: AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    full_wire_for_test: AtomicBool,
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

    /// Drops a cached reader (and the key it holds) for `id`.
    fn forget_reader(&self, id: &FileId) {
        lock(&self.readers).retain(|cached| cached.id != *id);
    }

    /// A ready file failed verification: it can never be read, so mark its
    /// row lost (zeroing the key) and drop its cached reader, so reuse stops
    /// attaching it. I/O and cipher errors are not this: they may pass.
    fn lose(&self, id: &FileId) {
        self.forget_reader(id);
        let _ = self.catalog.mark_lost(*id);
    }

    /// Marks `id` lost when `result` is a verification failure.
    fn lose_on_corruption<T>(&self, id: &FileId, result: MediaResult<T>) -> MediaResult<T> {
        if let Err(MediaError::Corruption(_)) = &result {
            self.lose(id);
        }
        result
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
                readers: Mutex::new(Vec::new()),
                checkpoints: Mutex::new(Vec::new()),
                checkpoint_released: Condvar::new(),
                #[cfg(any(test, feature = "test-support"))]
                full_disk_for_test: AtomicBool::new(false),
                #[cfg(any(test, feature = "test-support"))]
                full_wire_for_test: AtomicBool::new(false),
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
        lock(&self.inner.readers).clear();
        *lock(&self.inner.sweep) = SweepCursor::default();
    }

    /// Makes every publication fail as if the disk were full, until reset.
    /// Test support only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn simulate_full_disk_for_test(&self, full: bool) {
        self.inner.full_disk_for_test.store(full, Ordering::Release);
    }

    /// Makes every checkpoint append fail as if the disk filled midway:
    /// half the chunk reaches the file, then the write is refused. Until
    /// reset. Test support only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn simulate_full_wire_for_test(&self, full: bool) {
        self.inner.full_wire_for_test.store(full, Ordering::Release);
    }

    fn forget_reader(&self, id: &FileId) {
        self.inner.forget_reader(id);
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

    /// One `stat`: the only file I/O a catalog transaction may wait on. A
    /// file is present only with the exact length its row implies; a missing
    /// or wrong-length file is absent (its cached reader dropped first), and
    /// any other failure is an error that must leave the row untouched.
    pub(crate) fn present(&self, id: FileId, byte_len: u64) -> CatalogResult<FilePresence> {
        match std::fs::symlink_metadata(self.path(&id)) {
            Ok(metadata) if metadata.is_file() && metadata.len() == file_bytes(byte_len) => {
                Ok(FilePresence::Present)
            }
            Ok(_) => {
                self.forget_reader(&id);
                Ok(FilePresence::Absent)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.forget_reader(&id);
                Ok(FilePresence::Absent)
            }
            Err(_) => Err(CatalogError::Backend(
                "media file presence check failed".into(),
            )),
        }
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
        if let Some(outcome) = self.attach_existing(target, category, &digest)? {
            return Ok(outcome);
        }
        let (id, key, _in_flight) = self.insert_pending(category, byte_len, &digest, now)?;
        let result = self
            .write_body(&id, &key, body, byte_len, &digest, cancelled)
            .and_then(|()| {
                self.inner.ensure_open()?;
                Ok(
                    target.commit_ready(id, category, &digest, &|twin, byte_len| {
                        self.present(twin, byte_len)
                    })?,
                )
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

    /// Attaches `target` to a ready file with this content whose file is on
    /// disk, writing nothing: the check before downloading a body. `None`
    /// means there is no such file and the body is needed.
    pub fn attach_existing(
        &self,
        target: &dyn PublishTarget,
        category: Category,
        digest: &[u8; 32],
    ) -> MediaResult<Option<PublishOutcome>> {
        self.inner.ensure_open()?;
        if target.superseded()? {
            return Ok(Some(PublishOutcome::Superseded));
        }
        Ok(
            match target
                .commit_existing(category, digest, &|id, byte_len| self.present(id, byte_len))?
            {
                ExistingOutcome::Attached(id) => Some(PublishOutcome::Existing(id)),
                ExistingOutcome::Superseded => Some(PublishOutcome::Superseded),
                ExistingOutcome::None => None,
            },
        )
    }

    /// Stages an outgoing body: the intent row, then the sealed and synced
    /// file, then one transaction that marks the row `staged` under
    /// `target`'s owner. The digest is computed while sealing, since a host
    /// source has none to trust until it has been read. Unlike [`publish`]
    /// there is no content reuse here: an identical ready file is attached
    /// at promotion. A failed or refused step abandons the row, then the
    /// file. A full volume or database is [`MediaError::Capacity`].
    ///
    /// [`publish`]: Self::publish
    pub fn stage(
        &self,
        target: &dyn StageTarget,
        category: Category,
        body: &mut dyn Read,
        byte_len: u64,
        now: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> MediaResult<StageOutcome> {
        self.inner.ensure_open()?;
        // The pending row's digest is unknown until the body is read; the
        // staged commit records the real one. Pending rows are never twins.
        let (id, key, _in_flight) = self.insert_pending(category, byte_len, &[0; 32], now)?;
        let result = self
            .write_body_hashed(&id, &key, body, byte_len, cancelled)
            .and_then(|digest| {
                self.inner.ensure_open()?;
                Ok((target.commit_staged(id, &digest)?, digest))
            });
        match result {
            Ok((StagedOutcome::Staged, digest)) => Ok(StageOutcome::Staged { id, digest }),
            Ok((StagedOutcome::Superseded, _)) => {
                self.abandon(&id);
                Ok(StageOutcome::Superseded)
            }
            Err(error) => {
                self.abandon(&id);
                Err(error)
            }
        }
    }

    /// Promotes the staged (or already promoted) file `id` into `target`'s
    /// slots in one transaction, reusing a present identical ready file when
    /// there is one. A replaced staged copy is unlinked after the commit.
    pub fn promote(&self, target: &dyn PromoteTarget, id: FileId) -> MediaResult<PromoteOutcome> {
        self.inner.ensure_open()?;
        match target.commit_promoted(id, &|twin, byte_len| self.present(twin, byte_len))? {
            PromotedOutcome::Ready => Ok(PromoteOutcome::Ready),
            PromotedOutcome::Existing(twin) => {
                // The target deleted the staged row; only its file remains.
                self.forget_reader(&id);
                let _ = remove_if_present(&self.path(&id));
                Ok(PromoteOutcome::Existing(twin))
            }
            PromotedOutcome::Superseded => Ok(PromoteOutcome::Superseded),
            PromotedOutcome::Released => {
                // The target deleted the staged row with its owner.
                self.forget_reader(&id);
                let _ = remove_if_present(&self.path(&id));
                Ok(PromoteOutcome::Released)
            }
        }
    }

    /// Releases the staged file `id` from `target`'s owner: the row (key)
    /// first, then the file. Returns whether a staged row was deleted. The
    /// sweep removes a file this misses.
    pub fn release_staged(&self, target: &dyn StageTarget, id: FileId) -> MediaResult<bool> {
        self.inner.ensure_open()?;
        if !target.release_staged(id)? {
            return Ok(false);
        }
        self.forget_reader(&id);
        let _ = remove_if_present(&self.path(&id));
        Ok(true)
    }

    /// Opens a staged file for reading, as an upload streams it. `None`
    /// means `id` is not staged (released, promoted or never staged). The
    /// reader holds the key and refuses reads once the store closes.
    pub fn open_staged_reader(&self, id: &FileId) -> MediaResult<Option<MediaReader<C>>> {
        self.inner.ensure_open()?;
        let Some(row) = self.inner.catalog.staged_file(*id)? else {
            return Ok(None);
        };
        let file = match File::open(self.path(id)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(MediaError::Corruption("staged media file is missing"));
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
            id: *id,
            reader,
            position: 0,
        }))
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
        if self.write_body_hashed(id, key, body, byte_len, cancelled)? != *digest {
            return Err(MediaError::InvalidBody("media body digest mismatch"));
        }
        Ok(())
    }

    /// [`Self::write_body`] without an expected digest: seals and syncs the
    /// body and returns the SHA-256 it computed. A length mismatch is
    /// rejected here; a digest mismatch is the caller's to judge.
    pub(crate) fn write_body_hashed(
        &self,
        id: &FileId,
        key: &FileKey,
        body: &mut dyn Read,
        byte_len: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> MediaResult<[u8; 32]> {
        #[cfg(any(test, feature = "test-support"))]
        if self.inner.full_disk_for_test.load(Ordering::Acquire) {
            return Err(MediaError::Capacity);
        }
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
        let file = writer.finish()?;
        sync_file(&file).map_err(|e| io_error(&e))?;
        Ok(hasher.finalize().into())
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
    /// file; a ready row whose file is missing is marked lost first. The
    /// reader holds the file's key, so its reads need no catalog lookup.
    pub fn open_reader(&self, id: &FileId) -> MediaResult<Option<MediaReader<C>>> {
        Ok(self.open_file_reader(id)?.map(|reader| MediaReader {
            inner: self.inner.clone(),
            id: *id,
            reader,
            position: 0,
        }))
    }

    fn open_file_reader(&self, id: &FileId) -> MediaResult<Option<MediaFileReader<File>>> {
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
        let verified = MediaFileReader::open(file, &row.key, &id.0)
            .map_err(MediaError::from)
            .and_then(|reader| {
                if reader.plaintext_bytes() == row.byte_len {
                    Ok(reader)
                } else {
                    Err(MediaError::Corruption(
                        "media file length differs from its row",
                    ))
                }
            });
        self.inner.lose_on_corruption(id, verified).map(Some)
    }

    /// Reads plaintext at `offset` into `out`. `None` means no ready file.
    ///
    /// Callers authorize every read in the catalog's domain first (for an
    /// attachment, the database locates the slot's ready file). Consecutive
    /// reads of one file reuse a cached open reader and its key, skipping the
    /// catalog lookup; the cache is small, idles out after 30 s, and is
    /// dropped on close, release, loss and any read error.
    pub fn read_at(&self, id: &FileId, offset: u64, out: &mut [u8]) -> MediaResult<Option<usize>> {
        self.inner.ensure_open()?;
        let cached = {
            let mut readers = lock(&self.inner.readers);
            readers.retain(|cached| cached.used.elapsed() < READER_CACHE_IDLE);
            readers
                .iter()
                .position(|cached| cached.id == *id)
                .map(|index| readers.remove(index).reader)
        };
        let mut reader = match cached {
            Some(reader) => reader,
            None => match self.open_file_reader(id)? {
                Some(reader) => reader,
                None => return Ok(None),
            },
        };
        let read = self
            .inner
            .lose_on_corruption(id, reader.read_at(offset, out).map_err(MediaError::from))?;
        // Read outside the lock; return the reader only after success.
        let mut readers = lock(&self.inner.readers);
        if !self.inner.is_closed() {
            readers.insert(
                0,
                CachedReader {
                    id: *id,
                    reader,
                    used: Instant::now(),
                },
            );
            readers.truncate(READER_CACHE_ENTRIES);
        }
        Ok(Some(read))
    }

    /// A download checkpoint's wire file. Never log it.
    pub fn wire_path(&self, id: &FileId) -> PathBuf {
        wire_path(&self.inner.root, id)
    }

    /// Appends `bytes` at `offset` to `target`'s checkpoint and records the
    /// new length. Offset zero begins a new checkpoint, replacing any earlier
    /// one: its row commits before its wire file is created, and the replaced
    /// checkpoint's file is unlinked. Otherwise the checkpoint must already
    /// hold exactly `offset` recorded bytes.
    ///
    /// The bytes are synced before the row records them. If the append or
    /// the record fails, or the target refuses the record, the file is cut
    /// back to `offset` before this returns, so no unrecorded bytes hold
    /// disk. `false` means the target no longer owns a checkpoint at
    /// `offset`. A full volume or database is [`MediaError::Capacity`].
    pub fn checkpoint_append(
        &self,
        target: &dyn CheckpointTarget,
        offset: u64,
        bytes: &[u8],
    ) -> MediaResult<bool> {
        self.inner.ensure_open()?;
        if bytes.len() > CHECKPOINT_APPEND_MAX {
            return Err(MediaError::InvalidBody("checkpoint append too large"));
        }
        if bytes.is_empty() {
            return Ok(false);
        }
        let _held = self.lock_checkpoint(target.key());
        let (id, mut wire) = if offset == 0 {
            let Some(start) = target.begin()? else {
                return Ok(false);
            };
            if let Some(replaced) = start.replaced {
                self.remove_wire(&replaced);
            }
            (start.wire, self.create_wire(&start.wire)?)
        } else {
            match target.current()? {
                Some((id, received)) if received == offset => match self.open_wire(&id, offset)? {
                    Some(wire) => (id, wire),
                    None => return Ok(false),
                },
                _ => return Ok(false),
            }
        };
        if let Err(error) = wire.append(bytes) {
            let _ = wire.truncate(offset);
            return Err(error);
        }
        let received = offset.saturating_add(bytes.len() as u64);
        match target.record(id, received) {
            Ok(true) => Ok(true),
            Ok(false) => {
                let _ = wire.truncate(offset);
                Ok(false)
            }
            Err(error) => {
                let _ = wire.truncate(offset);
                Err(error.into())
            }
        }
    }

    /// Copies `target`'s recorded checkpoint into `out` and returns its
    /// length. Bytes past the recorded length are cut off first. A wire file
    /// that is missing or shorter than recorded cannot resume: the checkpoint
    /// is cleared (row, then file) and this returns `None`, as it does when
    /// the target owns no checkpoint.
    pub fn checkpoint_restore(
        &self,
        target: &dyn CheckpointTarget,
        out: &mut dyn Write,
    ) -> MediaResult<Option<u64>> {
        self.inner.ensure_open()?;
        let _held = self.lock_checkpoint(target.key());
        let Some((id, received)) = target.current()? else {
            return Ok(None);
        };
        let Some(mut wire) = self.open_wire(&id, received)? else {
            if let Some(cleared) = target.clear()? {
                self.remove_wire(&cleared);
            }
            return Ok(None);
        };
        wire.copy_to(out).map(Some)
    }

    /// Opens `target`'s recorded checkpoint for reading from the start, for
    /// verifying and publishing a finished download after its attempt stopped
    /// writing it. The checkpoint lock is held only while the row is resolved
    /// and the file opened; a file that cannot resume is discarded, as by
    /// [`Self::checkpoint_restore`]. The reader keeps the file open and in
    /// flight, so the sweep leaves it alone and a later unlink (a clear, a
    /// replacing checkpoint, the domain deleting the row) does not cut it
    /// short. It reads exactly the recorded bytes, and stops once the store
    /// or its catalog closes.
    pub fn checkpoint_reader(
        &self,
        target: &dyn CheckpointTarget,
    ) -> MediaResult<Option<CheckpointReader<C>>> {
        self.inner.ensure_open()?;
        let _held = self.lock_checkpoint(target.key());
        let Some((id, received)) = target.current()? else {
            return Ok(None);
        };
        let Some(mut wire) = self.open_wire(&id, received)? else {
            if let Some(cleared) = target.clear()? {
                self.remove_wire(&cleared);
            }
            return Ok(None);
        };
        wire.file
            .seek(io::SeekFrom::Start(0))
            .map_err(|e| io_error(&e))?;
        Ok(Some(CheckpointReader { wire, position: 0 }))
    }

    /// Deletes `target`'s checkpoint: the row, then its wire file. The sweep
    /// removes a file this misses.
    pub fn checkpoint_clear(&self, target: &dyn CheckpointTarget) -> MediaResult<()> {
        self.inner.ensure_open()?;
        let _held = self.lock_checkpoint(target.key());
        if let Some(id) = target.clear()? {
            self.remove_wire(&id);
        }
        Ok(())
    }

    /// Waits until no other operation holds the checkpoint `key`.
    fn lock_checkpoint(&self, key: &[u8]) -> CheckpointLock<'_, C> {
        let mut held = lock(&self.inner.checkpoints);
        while held.iter().any(|other| other.as_slice() == key) {
            held = self
                .inner
                .checkpoint_released
                .wait(held)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        held.push(key.to_vec());
        CheckpointLock {
            inner: &self.inner,
            key: key.to_vec(),
        }
    }

    /// Creates the wire file for a checkpoint row that has just committed,
    /// replacing anything left at that name.
    fn create_wire(&self, id: &FileId) -> MediaResult<WireFile<C>> {
        fs_private::create_dir_all_private(&self.shard_dir(id.0[0])).map_err(|e| io_error(&e))?;
        let path = self.wire_path(id);
        remove_if_present(&path).map_err(|e| io_error(&e))?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        fs_private::set_private_file_mode(&mut options);
        let file = options.open(&path).map_err(|e| io_error(&e))?;
        Ok(WireFile {
            inner: self.inner.clone(),
            id: self.wire_in_flight(id),
            file,
            len: 0,
        })
    }

    /// Opens a checkpoint's wire file at its recorded length. Bytes past
    /// `received` were never recorded and are dropped. `None` means the file
    /// is missing or shorter than recorded: the checkpoint cannot resume.
    fn open_wire(&self, id: &FileId, received: u64) -> MediaResult<Option<WireFile<C>>> {
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.wire_path(id))
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(&error)),
        };
        let on_disk = file.metadata().map_err(|e| io_error(&e))?.len();
        if on_disk < received {
            return Ok(None);
        }
        if on_disk > received {
            file.set_len(received).map_err(|e| io_error(&e))?;
        }
        Ok(Some(WireFile {
            inner: self.inner.clone(),
            id: self.wire_in_flight(id),
            file,
            len: received,
        }))
    }

    /// Marks the wire file `id` as open for writing, so the sweep leaves its
    /// tail alone. Taken before the handle can append, under the in-flight
    /// lock that the sweep holds from its check through any trim, so a trim
    /// never cuts bytes a live handle wrote.
    fn wire_in_flight(&self, id: &FileId) -> FileId {
        lock(&self.inner.in_flight).insert(*id);
        *id
    }

    /// Unlinks a wire file whose checkpoint row is already gone. Best
    /// effort: the sweep removes anything left.
    fn remove_wire(&self, id: &FileId) {
        let _ = remove_if_present(&self.wire_path(id));
    }

    /// Unlinks the files of `ids` whose rows are gone. Callers pass the ids a
    /// committed deletion released; the sweep removes anything missed.
    pub fn unlink_released(&self, ids: &[FileId]) {
        for id in ids {
            self.forget_reader(id);
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
        if report.pending_removed
            + report.orphans_unlinked
            + report.lost_marked
            + report.staged_released
            + report.wire_tails_trimmed
            > 0
        {
            tracing::info!(
                target: TRACE_TARGET,
                method = "sweep",
                pending_removed = report.pending_removed,
                orphans_unlinked = report.orphans_unlinked,
                lost_marked = report.lost_marked,
                staged_released = report.staged_released,
                wire_tails_trimmed = report.wire_tails_trimmed,
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
                        self.forget_reader(id);
                        if self.inner.catalog.mark_lost(*id)? {
                            report.lost_marked += 1;
                        }
                    }
                    Err(error) => return Err(io_error(&error)),
                },
                FileState::Lost => {}
                // An owned staged row is kept across restarts; only one no
                // owner holds is released, key first.
                FileState::Staged => {
                    if self.inner.catalog.abandon_unowned_staged(*id)? {
                        self.forget_reader(id);
                        remove_if_present(&self.path(id)).map_err(|e| io_error(&e))?;
                        report.staged_released += 1;
                    }
                }
            }
        }
        if rows.len() < limit {
            cursor.rows_done = true;
            cursor.row = None;
        }
        Ok(())
    }

    /// Visits up to `limit` directory entries, resuming the open listing of
    /// a shard across batches: each entry is listed once per pass, and every
    /// entry visited (foreign names included) counts against `limit`.
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
            if cursor.entries.is_none() {
                match std::fs::read_dir(self.shard_dir(shard)) {
                    Ok(entries) => cursor.entries = Some(entries),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        cursor.shard += 1;
                        continue;
                    }
                    Err(error) => return Err(io_error(&error)),
                }
            }
            let mut exhausted = false;
            while budget > 0 {
                let Some(entries) = cursor.entries.as_mut() else {
                    break;
                };
                let Some(entry) = entries.next() else {
                    exhausted = true;
                    break;
                };
                let entry = entry.map_err(|e| io_error(&e))?;
                budget -= 1;
                report.files_checked += 1;
                // Only names this store creates are its to judge.
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if let Some(id) = name
                    .strip_suffix(WIRE_SUFFIX)
                    .and_then(FileId::parse_hex)
                    .filter(|id| id.0[0] == shard)
                {
                    // A checkpoint row is written before its wire file and
                    // deleted before it: no row means nothing will resume it.
                    // Bytes past the recorded length (a crash between append
                    // and record) are dropped, unless a writer holds the file.
                    let in_flight = lock(&self.inner.in_flight);
                    if in_flight.contains(&id) {
                        continue;
                    }
                    match self.inner.catalog.wire_partial_received(id)? {
                        None => {
                            if remove_if_present(&self.wire_path(&id)).map_err(|e| io_error(&e))? {
                                report.orphans_unlinked += 1;
                            }
                        }
                        Some(received) => {
                            if trim_wire(&self.wire_path(&id), received)
                                .map_err(|e| io_error(&e))?
                            {
                                report.wire_tails_trimmed += 1;
                            }
                        }
                    }
                    drop(in_flight);
                    continue;
                }
                let Some(id) = FileId::parse_hex(name).filter(|id| id.0[0] == shard) else {
                    continue;
                };
                if self.inner.catalog.file_state(id)?.is_none() {
                    self.forget_reader(&id);
                    if remove_if_present(&self.path(&id)).map_err(|e| io_error(&e))? {
                        report.orphans_unlinked += 1;
                    }
                }
            }
            if exhausted {
                cursor.entries = None;
                cursor.shard += 1;
            }
        }
        if cursor.shard > u8::MAX as u16 {
            *cursor = SweepCursor::default();
            report.complete = true;
        }
        Ok(())
    }
}

/// Held while one operation works on a checkpoint, from the row lookup
/// through the file change and the record: a stale attempt's operation can
/// then never act on a recorded length a newer one has moved.
struct CheckpointLock<'a, C> {
    inner: &'a Inner<C>,
    key: Vec<u8>,
}

impl<C> Drop for CheckpointLock<'_, C> {
    fn drop(&mut self) {
        let mut held = lock(&self.inner.checkpoints);
        if let Some(index) = held.iter().position(|other| *other == self.key) {
            held.swap_remove(index);
        }
        self.inner.checkpoint_released.notify_all();
    }
}

/// An append-only download checkpoint: the wire ciphertext exactly as
/// received. Its identity and recorded length live in the catalog's
/// checkpoint row, which is written before the file and deleted before it.
/// Every operation stops once the store or its catalog closes.
struct WireFile<C> {
    inner: Arc<Inner<C>>,
    /// Held in the in-flight set until this handle drops.
    id: FileId,
    file: File,
    len: u64,
}

impl<C> Drop for WireFile<C> {
    fn drop(&mut self) {
        lock(&self.inner.in_flight).remove(&self.id);
    }
}

/// Cuts a wire file longer than `received` back to it. A missing or shorter
/// file is left for the next open to discard.
fn trim_wire(path: &Path, received: u64) -> io::Result<bool> {
    let file = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() <= received {
        return Ok(false);
    }
    file.set_len(received)?;
    Ok(true)
}

impl<C: MediaCatalog> WireFile<C> {
    /// Appends `bytes` and syncs them, so they are durable before the caller
    /// records the new length in the checkpoint row.
    fn append(&mut self, bytes: &[u8]) -> MediaResult<()> {
        self.inner.ensure_open()?;
        // A short write: part of the chunk reaches the file, then the volume
        // refuses the rest.
        #[cfg(any(test, feature = "test-support"))]
        if self.inner.full_wire_for_test.load(Ordering::Acquire) {
            let _ = self
                .file
                .seek(io::SeekFrom::Start(self.len))
                .and_then(|_| self.file.write_all(&bytes[..bytes.len() / 2]));
            return Err(MediaError::Capacity);
        }
        self.file
            .seek(io::SeekFrom::Start(self.len))
            .and_then(|_| self.file.write_all(bytes))
            .map_err(|e| io_error(&e))?;
        sync_file(&self.file).map_err(|e| io_error(&e))?;
        self.len += bytes.len() as u64;
        Ok(())
    }

    /// Drops bytes past `len` that the caller could not record, so they stop
    /// taking disk space. This cuts the file itself, not just this handle's
    /// length: a failed `append` may have left part of its chunk on disk
    /// without advancing the handle. `len` past the handle's length is a
    /// no-op.
    fn truncate(&mut self, len: u64) -> MediaResult<()> {
        self.inner.ensure_open()?;
        if len <= self.len {
            self.file.set_len(len).map_err(|e| io_error(&e))?;
            self.len = len;
        }
        Ok(())
    }

    /// Copies the whole checkpoint into `out`.
    fn copy_to(&mut self, out: &mut dyn Write) -> MediaResult<u64> {
        self.inner.ensure_open()?;
        self.file
            .seek(io::SeekFrom::Start(0))
            .map_err(|e| io_error(&e))?;
        let copied =
            io::copy(&mut (&mut self.file).take(self.len), out).map_err(|e| io_error(&e))?;
        if copied != self.len {
            return Err(MediaError::Corruption(
                "wire checkpoint shorter than recorded",
            ));
        }
        Ok(copied)
    }
}

/// Where the wire file of checkpoint `id` lives under the store `root`.
fn wire_path(root: &Path, id: &FileId) -> PathBuf {
    root.join(format!("{:02x}", id.0[0]))
        .join(format!("{}{WIRE_SUFFIX}", hex::encode(id.0)))
}

/// A finished checkpoint's recorded bytes, from
/// [`MediaStore::checkpoint_reader`]. Never reads past the recorded length;
/// reads fail once the store or its catalog closes.
pub struct CheckpointReader<C> {
    wire: WireFile<C>,
    position: u64,
}

impl<C: MediaCatalog> CheckpointReader<C> {
    /// The recorded length.
    pub fn len(&self) -> u64 {
        self.wire.len
    }

    pub fn is_empty(&self) -> bool {
        self.wire.len == 0
    }

    /// Done reading: closes the file and unlinks it if its checkpoint row
    /// is gone (the domain deleted it, as a published download's is), so a
    /// finished body's ciphertext does not wait for the sweep. A file whose
    /// row remains is kept for the attempt that owns it.
    pub fn finish(self) -> MediaResult<()> {
        let inner = self.wire.inner.clone();
        let id = self.wire.id;
        drop(self);
        inner.ensure_open()?;
        // Like the sweep: decide under the in-flight lock, so a handle that
        // opens this file meanwhile keeps it.
        let in_flight = lock(&inner.in_flight);
        if !in_flight.contains(&id) && inner.catalog.wire_partial_received(id)?.is_none() {
            remove_if_present(&wire_path(&inner.root, &id)).map_err(|e| io_error(&e))?;
        }
        Ok(())
    }

    /// Starts reading from the first byte again.
    pub fn rewind(&mut self) -> MediaResult<()> {
        self.wire.inner.ensure_open()?;
        self.wire
            .file
            .seek(io::SeekFrom::Start(0))
            .map_err(|e| io_error(&e))?;
        self.position = 0;
        Ok(())
    }
}

impl<C: MediaCatalog> Read for CheckpointReader<C> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.wire.inner.is_closed() {
            return Err(io::Error::other("media store is closed"));
        }
        let left = self.wire.len.saturating_sub(self.position);
        let want = out.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        if want == 0 {
            return Ok(0);
        }
        let read = self.wire.file.read(&mut out[..want])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "wire checkpoint shorter than recorded",
            ));
        }
        self.position += read as u64;
        Ok(read)
    }
}

/// An open media file that refuses reads once the store or its catalog
/// closes, including reads of a segment it already decrypted.
pub struct MediaReader<C> {
    inner: Arc<Inner<C>>,
    id: FileId,
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
        let read = self.reader.read_at(offset, out).map_err(MediaError::from);
        self.inner.lose_on_corruption(&self.id, read)
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
