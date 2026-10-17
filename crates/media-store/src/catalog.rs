//! The metadata side of the store, implemented outside this crate.
//!
//! Each file's key, state, length, digest and references live in the
//! account's SQLCipher database: the keys need its protection, and references
//! must commit atomically with message slots. The store drives the lifecycle
//! and the crash ordering; a catalog only stores rows, and a publish target
//! makes one publication's ready commit atomic.

use crate::format::{FILE_ID_BYTES, FILE_KEY_BYTES, FileKey};

/// Random 16-byte file id. It names the file and says nothing about the
/// message, group or content.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId(pub [u8; FILE_ID_BYTES]);

impl FileId {
    pub fn as_bytes(&self) -> &[u8; FILE_ID_BYTES] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }

    pub(crate) fn parse_hex(name: &str) -> Option<Self> {
        if name.len() != FILE_ID_BYTES * 2 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        hex::decode(name)
            .ok()
            .and_then(|bytes| Self::from_slice(&bytes))
    }
}

/// Ids are random but still identify one file; keep them out of logs.
impl std::fmt::Debug for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileId(..)")
    }
}

/// What a stored body is for. Retained media is never deleted automatically;
/// the cache category is for re-fetchable images (avatars, group images).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    Retained,
    Cache,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileState {
    /// The row exists and the file may be partly written.
    Pending,
    Ready,
    /// The row was ready but its file is gone (crash or external deletion).
    /// Distinct from deliberate removal, which deletes the row.
    Lost,
    /// The file is complete and synced, and a domain row (an outgoing upload)
    /// owns it, but no slot references it yet. It survives restarts while
    /// its owner exists and becomes `Ready` when promoted.
    Staged,
}

/// A pending row to insert before its file exists.
pub struct NewFile {
    pub id: FileId,
    pub key: FileKey,
    pub category: Category,
    pub byte_len: u64,
    pub digest: [u8; 32],
    pub created_at: u64,
}

/// What a read needs from a ready row.
pub struct ReadyFile {
    pub key: FileKey,
    pub byte_len: u64,
}

impl ReadyFile {
    pub fn from_key_bytes(key: &[u8], byte_len: u64) -> Option<Self> {
        let key: [u8; FILE_KEY_BYTES] = key.try_into().ok()?;
        Some(Self {
            key: FileKey::from_bytes(key),
            byte_len,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    /// The catalog's database closed; terminal for the store.
    #[error("media catalog is closed")]
    Closed,
    #[error("media catalog is full")]
    Capacity,
    /// A fixed, privacy-safe description; never ids, paths or SQL.
    #[error("media catalog failed: {0}")]
    Backend(String),
}

pub type CatalogResult<T> = Result<T, CatalogError>;

/// Store-wide metadata rows. Each method is one short transaction.
pub trait MediaCatalog: Send + Sync {
    /// True once the catalog's database closed. The store then refuses all
    /// work, so closing the database closes the media store with it.
    fn is_closed(&self) -> bool;
    /// Step 1 of publish: commit a `pending` row (with its key) before the
    /// file exists.
    fn insert_pending(&self, file: &NewFile) -> CatalogResult<()>;
    /// Deletes the row only if it is still pending. Returns whether it did.
    fn abandon_pending(&self, id: FileId) -> CatalogResult<bool>;
    fn ready_file(&self, id: FileId) -> CatalogResult<Option<ReadyFile>>;
    fn file_state(&self, id: FileId) -> CatalogResult<Option<FileState>>;
    /// Ready or staged → lost, overwriting the key: the file is gone or
    /// failed verification. Returns whether it changed.
    fn mark_lost(&self, id: FileId) -> CatalogResult<bool>;
    /// Rows in id order after `after`, for the sweep.
    fn page(&self, after: Option<FileId>, limit: usize) -> CatalogResult<Vec<(FileId, FileState)>>;
    /// The recorded length of the download checkpoint that owns the wire
    /// file `id`, or `None` when no row does. The row is written before its
    /// `.wire` file exists and deleted before the file is, so the sweep
    /// unlinks a wire file only when this is `None`, and trims a file longer
    /// than the recorded length back to it.
    fn wire_partial_received(&self, id: FileId) -> CatalogResult<Option<u64>>;
    /// What a read of a staged file needs: its key and length. `None` when
    /// `id` is not staged.
    fn staged_file(&self, id: FileId) -> CatalogResult<Option<ReadyFile>>;
    /// Deletes the row only if it is staged and no domain row owns it: the
    /// sweep's backstop for an owner that went away without releasing it.
    /// Returns whether it did.
    fn abandon_unowned_staged(&self, id: FileId) -> CatalogResult<bool>;
}

/// What one existence check found for a ready file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilePresence {
    /// The file is on disk with exactly the length its row implies.
    Present,
    /// Confirmed absent, or a length its row cannot have (a torn or
    /// replaced file). The catalog marks the row lost; the store has already
    /// dropped any cached reader for it.
    Absent,
}

/// The store's view of the disk for reuse decisions, given a ready file's id
/// and its row's plaintext length. It is a single existence check (one
/// `stat`), and the only file I/O a catalog performs inside a transaction:
/// call it at most once per commit, for the one ready twin, and do no other
/// file work while the transaction is open. An `Err` means the check itself
/// failed (permission, I/O): the catalog must return it, rolling back, and
/// leave the twin's row and key untouched.
pub type Presence<'a> = &'a dyn Fn(FileId, u64) -> CatalogResult<FilePresence>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExistingOutcome {
    /// No reusable ready file with this content.
    None,
    /// The target now references this ready file; nothing is written.
    Attached(FileId),
    /// The publication no longer owns its slot.
    Superseded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadyOutcome {
    /// The file is ready and attached.
    Ready,
    /// A present ready twin was attached instead and this file's row deleted.
    Existing(FileId),
    /// The publication no longer owns its slot, or the row is gone (reset).
    /// The store abandons the row if it is still pending and unlinks the file.
    Superseded,
}

/// One publication's domain side: an attachment slot, an outgoing upload, an
/// avatar. Each method is **one transaction** in the catalog's database, and
/// calls `present` at most once, for the ready twin (see [`Presence`]).
pub trait PublishTarget {
    /// Cheap fence before any byte is written.
    fn superseded(&self) -> CatalogResult<bool>;
    /// Finds a ready file with this category and digest. Reuses it only if
    /// `present` reports it `Present`; `Absent` marks it lost (overwriting its
    /// key) and returns `None`; a presence error is returned unchanged. When
    /// reusing, applies the target's fences and attaches.
    fn commit_existing(
        &self,
        category: Category,
        digest: &[u8; 32],
        present: Presence<'_>,
    ) -> CatalogResult<ExistingOutcome>;
    /// Step 3 of publish. If `id` is no longer pending → `Superseded`. Apply
    /// the target's fences (refused → `Superseded`, row left pending). If a
    /// ready twin with this category and digest is `Present`, delete `id`'s
    /// row and attach the twin → `Existing(twin)`; an `Absent` twin is marked
    /// lost; a presence error is returned and nothing changes. Otherwise mark
    /// `id` ready and attach it → `Ready`.
    fn commit_ready(
        &self,
        id: FileId,
        category: Category,
        digest: &[u8; 32],
        present: Presence<'_>,
    ) -> CatalogResult<ReadyOutcome>;
}

/// A checkpoint that [`CheckpointTarget::begin`] started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointStart {
    /// The new checkpoint's wire file, not created yet.
    pub wire: FileId,
    /// The wire file of the checkpoint it replaced, if there was one. Its row
    /// is already gone; the store unlinks the file.
    pub replaced: Option<FileId>,
}

/// One download checkpoint's domain side: its row, under the fences of the
/// attempt that owns it (store generation, attempt, lease, source). The store
/// drives the file and the ordering through
/// [`MediaStore::checkpoint_append`](crate::MediaStore::checkpoint_append) and
/// its siblings; a target only reads and writes the row. Each method is **one
/// transaction** and does no file I/O.
///
/// A target that is no longer the checkpoint's owner (a newer attempt, a
/// cancelled job, a different identity) answers `None` or `false`; it never
/// changes another owner's row.
pub trait CheckpointTarget {
    /// Names the checkpoint, so the store serializes operations on it.
    /// Opaque; never logged.
    fn key(&self) -> &[u8];
    /// The checkpoint this target owns: its wire file and the bytes recorded
    /// as durable in it.
    fn current(&self) -> CatalogResult<Option<(FileId, u64)>>;
    /// Starts a new checkpoint with nothing recorded, replacing any earlier
    /// one, and commits it before its wire file exists.
    fn begin(&self) -> CatalogResult<Option<CheckpointStart>>;
    /// Records that `wire` durably holds the first `received` bytes. Only
    /// growth of this target's own checkpoint is accepted.
    fn record(&self, wire: FileId, received: u64) -> CatalogResult<bool>;
    /// Deletes this target's checkpoint row and returns its wire file, which
    /// the store unlinks after the commit.
    fn clear(&self) -> CatalogResult<Option<FileId>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagedOutcome {
    /// The file is staged and recorded on its owner.
    Staged,
    /// The owner no longer accepts the file. The row is left pending; the
    /// store abandons it.
    Superseded,
}

/// One staged body's owner: an outgoing upload that keeps its file local
/// before and during the upload. Each method is **one transaction** and does
/// no file I/O.
pub trait StageTarget {
    /// If `id` is still pending and the owner still accepts it, records the
    /// body's `digest`, marks the row staged and records `id` on the owner.
    fn commit_staged(&self, id: FileId, digest: &[u8; 32]) -> CatalogResult<StagedOutcome>;
    /// Detaches the owner from its staged file `id` and deletes that row (its
    /// key). Returns whether it deleted one; the store unlinks the file. A
    /// file already promoted to ready is not deleted.
    fn release_staged(&self, id: FileId) -> CatalogResult<bool>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromotedOutcome {
    /// `id` is ready and attached to the target's slots.
    Ready,
    /// A present ready twin with the same content was attached instead, and
    /// `id`'s staged row deleted; the store unlinks its file.
    Existing(FileId),
    /// Nothing to attach: the target refused (fences, removal) or `id` is no
    /// longer its file. A staged row is left as it is.
    Superseded,
    /// Every slot already held its body, so the owner had nothing left to
    /// fill: it was consumed, and the staged row deleted with it. The store
    /// unlinks the file.
    Released,
}

/// Promotion of a staged (or already promoted) file into the slots of a
/// published message. One transaction, calling `present` at most once, for
/// the ready twin (see [`Presence`]).
pub trait PromoteTarget {
    /// If `id` is staged: apply the target's fences; when a ready twin with
    /// the row's category and digest is `Present`, attach the twin and delete
    /// `id`'s row (`Existing`); an `Absent` twin is marked lost; otherwise
    /// mark `id` ready and attach it (`Ready`). If `id` is already ready,
    /// attach it without a twin check (`Ready`). If every slot already holds
    /// its body and the owner is consumed, a still-staged `id` goes with it
    /// (`Released`). A presence error is returned and nothing changes.
    fn commit_promoted(&self, id: FileId, present: Presence<'_>) -> CatalogResult<PromotedOutcome>;
}
