//! Account-local encoded avatar bytes. No network or engine work occurs here.
//!
//! The app supplies an authoritative owner/source key and verifies image format,
//! dimensions and (for encrypted images) authentication before publication. This
//! storage boundary enforces bounds and integrity, not image decoding. C7-B owns
//! that acquisition boundary; these methods alone do not maintain screen sources.

use std::fmt;

use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::app::chat_presentation::nonnegative;
use crate::{SqliteAppStorage, SqliteResultExt, u64_to_i64};

pub const MAX_AVATAR_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_AVATAR_CACHE_BYTES: u64 = 128 * 1024 * 1024;
/// Bounds missing source mappings as well as populated images.
pub const MAX_AVATAR_CACHE_ENTRIES: u64 = 2048;
pub const MAX_AVATAR_DIMENSION: u32 = 4096;
/// Maximum explicit identity registrations returned in one maintenance page.
pub const AVATAR_IDENTITY_BATCH_LIMIT: usize = 64;
const MAX_KEY_BYTES: usize = 512;

/// A source generation, scoped to the existing account store epoch. Neither the
/// owner key nor image material is exposed. A reference is not an authorization
/// grant: callers must still select the correct account using the host contract.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AvatarAssetRef {
    store_epoch: Vec<u8>,
    token: Vec<u8>,
}

impl fmt::Debug for AvatarAssetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvatarAssetRef").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvatarImageFormat {
    Png,
    Jpeg,
    Gif,
    Webp,
}

impl AvatarImageFormat {
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "image/png" => Some(Self::Png),
            "image/jpeg" => Some(Self::Jpeg),
            "image/gif" => Some(Self::Gif),
            "image/webp" => Some(Self::Webp),
            _ => None,
        }
    }
}

/// Encoded bytes with caller-verified image metadata, held in a wiping buffer.
/// Construction only checks storage limits; it does not decode or authenticate.
#[derive(Clone, PartialEq, Eq)]
pub struct AvatarImage {
    bytes: Zeroizing<Vec<u8>>,
    format: AvatarImageFormat,
    width: u32,
    height: u32,
}

impl AvatarImage {
    pub fn new(
        bytes: Vec<u8>,
        format: AvatarImageFormat,
        width: u32,
        height: u32,
    ) -> StorageResult<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > MAX_AVATAR_BYTES || !valid_dimensions(width, height) {
            return Err(invalid("avatar exceeds storage image bounds"));
        }
        Ok(Self {
            bytes,
            format,
            width,
            height,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn format(&self) -> AvatarImageFormat {
        self.format
    }
    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
}

impl fmt::Debug for AvatarImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvatarImage")
            .field("byte_count", &self.bytes.len())
            .field("format", &self.format)
            .field("width", &self.width)
            .field("height", &self.height)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AvatarAvailability {
    Missing,
    Ready,
    Stale,
    Invalidated,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AvatarAssetStatus {
    pub availability: AvatarAvailability,
    /// Use together with the source reference to key a decoded-image cache.
    /// Every publication increments this value, including same-URL refreshes.
    pub content_revision: u64,
    pub byte_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvatarAssetRead {
    /// This read discarded corrupt stored bytes. Ordinary cache misses are false.
    pub repaired: bool,
    pub status: AvatarAssetStatus,
    /// A database-held image. A file-backed one is in `file` instead.
    pub image: Option<AvatarImage>,
    /// A file-backed image: the caller reads it from the media store and
    /// reports a missing or corrupt file with
    /// [`SqliteAppStorage::discard_avatar_file`].
    pub file: Option<AvatarStoredFile>,
}

/// A file-backed avatar image to read from the media store.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AvatarStoredFile {
    pub id: media_store::FileId,
    pub byte_len: u64,
    pub format: AvatarImageFormat,
    pub width: u32,
    pub height: u32,
}

impl fmt::Debug for AvatarStoredFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvatarStoredFile")
            .field("byte_len", &self.byte_len)
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvatarPublishResult {
    Published {
        content_revision: u64,
    },
    /// Source/account changed, entry was evicted, or another completion won.
    Superseded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AvatarCacheUsage {
    pub entries: u64,
    pub byte_count: u64,
}

#[derive(Clone, Copy)]
struct Limits {
    entries: u64,
    bytes: u64,
}
const LIMITS: Limits = Limits {
    entries: MAX_AVATAR_CACHE_ENTRIES,
    bytes: MAX_AVATAR_CACHE_BYTES,
};

impl SqliteAppStorage {
    /// Bind one logical subject (e.g. a chat or identity) to its selected source.
    /// Rebinding erases its previous bytes; repeating the same binding preserves
    /// the reference and bytes. Keys are opaque, bounded, app-derived identifiers,
    /// not raw URLs or serialized key material. Sharing across views uses the same
    /// owner key; this first slice does not deduplicate bytes across owners.
    pub fn bind_avatar_source(&self, owner: &str, source: &str) -> StorageResult<AvatarAssetRef> {
        self.bind_avatar_source_with_limits(owner, source, LIMITS)
    }

    fn bind_avatar_source_with_limits(
        &self,
        owner: &str,
        source: &str,
        limits: Limits,
    ) -> StorageResult<AvatarAssetRef> {
        validate_key(owner)?;
        validate_key(source)?;
        self.connection.with_transaction(|| {
            let tx = self.lock()?;
            let accessed = next_access(&tx)?;
            let unchanged: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM avatar_assets WHERE owner_key = ?1 AND source_key = ?2)",
            params![owner, source], |r| r.get(0),
        ).storage()?;
            if !unchanged {
                tx.execute(
                    "INSERT INTO avatar_assets(owner_key, source_key, token)
                 VALUES(?1, ?2, randomblob(16))
                 ON CONFLICT(owner_key) DO UPDATE SET
                    token = excluded.token, source_key = excluded.source_key,
                    content_revision = 0, bytes = NULL, digest = NULL, media_type = NULL,
                    width = NULL, height = NULL, refresh_at = NULL, byte_len = NULL",
                    params![owner, source],
                )
                .storage()?;
            }
            let reference = reference_for_owner(&tx, owner)?
                .ok_or_else(|| invalid("avatar binding missing"))?;
            touch_access(&tx, &reference.token, accessed)?;
            // Repeated bindings cannot grow the cache: avoid scanning usage or
            // rewriting a blob just because another screen asks for the same source.
            if unchanged {
                return Ok(reference);
            }
            evict(&tx, &reference.token, limits)?;
            Ok(reference)
        })
    }

    /// Metadata-only lookup. It neither creates demand nor changes recency.
    pub fn avatar_reference(&self, owner: &str) -> StorageResult<Option<AvatarAssetRef>> {
        validate_key(owner)?;
        reference_for_owner(&*self.lock()?, owner)
    }

    /// Metadata-only status; does not load bytes or trigger a refresh.
    /// `now` and `refresh_at` use Unix seconds. None means no timed expiry.
    pub fn avatar_status(
        &self,
        reference: &AvatarAssetRef,
        now: u64,
    ) -> StorageResult<AvatarAssetStatus> {
        status(&*self.lock()?, reference, now)
    }

    /// Atomic compare-and-publish. Acquisition must capture content_revision
    /// before fetching, then pass that revision here. No failed or older fetch
    /// can replace a newer publication. The caller validates bytes before this
    /// call; no HTTP, crypto or image decoding takes place under the store lock.
    pub fn publish_avatar(
        &self,
        reference: &AvatarAssetRef,
        expected_content_revision: u64,
        image: &AvatarImage,
        refresh_at: Option<u64>,
    ) -> StorageResult<AvatarPublishResult> {
        self.publish_avatar_with_limits(
            reference,
            expected_content_revision,
            image,
            refresh_at,
            LIMITS,
        )
    }

    fn publish_avatar_with_limits(
        &self,
        reference: &AvatarAssetRef,
        expected: u64,
        image: &AvatarImage,
        refresh_at: Option<u64>,
        limits: Limits,
    ) -> StorageResult<AvatarPublishResult> {
        let expected = u64_to_i64(expected)?;
        let refresh_at = refresh_at.map(u64_to_i64).transpose()?;
        if image.bytes.len() as u64 > limits.bytes {
            return Err(invalid("avatar exceeds cache capacity"));
        }
        let digest = Sha256::digest(image.bytes());
        self.connection.with_transaction(|| {
            let tx = self.lock()?;
            let changed = tx
                .execute(
                    "UPDATE avatar_assets SET bytes = ?1, digest = ?2, media_type = ?3,
                width = ?4, height = ?5, refresh_at = ?6, byte_len = NULL,
                content_revision = content_revision + 1
             WHERE token = ?7 AND content_revision = ?8
                AND (SELECT store_epoch FROM chat_presentation_meta WHERE id = 1) = ?9",
                    params![
                        image.bytes(),
                        digest.as_slice(),
                        image.format.media_type(),
                        image.width,
                        image.height,
                        refresh_at,
                        reference.token,
                        expected,
                        reference.store_epoch
                    ],
                )
                .storage()?;
            if changed == 0 {
                return Ok(AvatarPublishResult::Superseded);
            }
            // A database-held image replaces a file-backed one: its reference
            // goes, and with the last one the file's key; the sweep unlinks it.
            tx.execute(
                "DELETE FROM avatar_file_refs WHERE token = ?1",
                [&reference.token],
            )
            .storage()?;
            let accessed = next_access(&tx)?;
            touch_access(&tx, &reference.token, accessed)?;
            evict(&tx, &reference.token, limits)?;
            Ok(AvatarPublishResult::Published {
                content_revision: expected as u64 + 1,
            })
        })
    }

    /// One bounded local byte read. Ready/stale hits update LRU recency; status
    /// lookups do not. Corrupt bytes are atomically discarded and become a miss.
    /// This is blocking storage I/O: native callers must dispatch off the UI thread.
    pub fn read_avatar(
        &self,
        reference: &AvatarAssetRef,
        now: u64,
    ) -> StorageResult<AvatarAssetRead> {
        self.read_avatar_bounded(reference, now, MAX_AVATAR_BYTES as u64)
    }

    /// A budget miss returns ready/stale metadata with no image and does not
    /// read the BLOB, touch recency, or invalidate usable bytes.
    pub fn read_avatar_bounded(
        &self,
        reference: &AvatarAssetRef,
        now: u64,
        max_bytes: u64,
    ) -> StorageResult<AvatarAssetRead> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let mut state = status(&tx, reference, now)?;
        if state.byte_count > max_bytes && state.byte_count <= MAX_AVATAR_BYTES as u64 {
            return Ok(AvatarAssetRead {
                status: state,
                image: None,
                file: None,
                repaired: false,
            });
        }
        let mut image = None;
        let mut file = None;
        let mut repaired = false;
        if matches!(
            state.availability,
            AvatarAvailability::Ready | AvatarAvailability::Stale
        ) && let Some(stored) = stored_file(&tx, &reference.token)?
        {
            match stored {
                StoredFile::Ready(stored) => {
                    let accessed = next_access(&tx)?;
                    touch_access(&tx, &reference.token, accessed)?;
                    file = Some(stored);
                }
                // A lost file (or an unreadable row) is a corrupt image:
                // cleared and fetched again, as a bad database body is.
                StoredFile::Gone => {
                    clear_image(&tx, &reference.token)?;
                    state = status(&tx, reference, now)?;
                    repaired = true;
                }
            }
        } else if matches!(
            state.availability,
            AvatarAvailability::Ready | AvatarAvailability::Stale
        ) {
            let decoded = tx
                .query_row(
                    "SELECT CASE WHEN length(bytes) <= ?1 THEN bytes ELSE NULL END,
                    digest, media_type, width, height FROM avatar_assets WHERE token = ?2",
                    params![MAX_AVATAR_BYTES as i64, reference.token],
                    |row| {
                        let bytes: Option<Vec<u8>> = row.get(0)?;
                        let digest: Vec<u8> = row.get(1)?;
                        let media_type: String = row.get(2)?;
                        let width: u32 = row.get(3)?;
                        let height: u32 = row.get(4)?;
                        Ok(bytes.and_then(|bytes| {
                            let bytes = Zeroizing::new(bytes);
                            if Sha256::digest(&bytes).as_slice() != digest
                                || !valid_dimensions(width, height)
                            {
                                return None;
                            }
                            let format = AvatarImageFormat::parse(&media_type)?;
                            Some(AvatarImage {
                                bytes,
                                format,
                                width,
                                height,
                            })
                        }))
                    },
                )
                .storage()?;
            if let Some(value) = decoded {
                let accessed = next_access(&tx)?;
                touch_access(&tx, &reference.token, accessed)?;
                image = Some(value);
            } else {
                clear_image(&tx, &reference.token)?;
                state = status(&tx, reference, now)?;
                repaired = true;
            }
        }
        tx.commit().storage()?;
        Ok(AvatarAssetRead {
            repaired,
            status: state,
            image,
            file,
        })
    }

    /// Reports that file `id`, returned by a read of `reference`, is missing
    /// or failed authentication. The file is marked lost, so every owner
    /// sharing it refetches; this owner's image is cleared at once. Returns
    /// whether the image was cleared and the ids whose rows (keys) the
    /// clearing deleted, for the store to unlink once this commits.
    pub fn discard_avatar_file(
        &self,
        reference: &AvatarAssetRef,
        id: media_store::FileId,
    ) -> StorageResult<(bool, Vec<media_store::FileId>)> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            // Only a report about this owner's current cache file counts: a
            // stale id must not destroy a file another owner still reads.
            let current = conn
                .query_row(
                    "SELECT 1 FROM avatar_file_refs r JOIN media_files f ON f.id = r.file_id
                     WHERE r.token = ?1 AND r.file_id = ?2 AND f.category = 2
                        AND (SELECT store_epoch FROM chat_presentation_meta WHERE id = 1) = ?3",
                    params![
                        reference.token,
                        id.as_bytes().as_slice(),
                        reference.store_epoch
                    ],
                    |_| Ok(()),
                )
                .optional()
                .storage()?
                .is_some();
            if !current {
                return Ok((false, Vec::new()));
            }
            crate::app::media_catalog::mark_lost_in(&conn, id)?;
            clear_image(&conn, &reference.token)?;
            Ok((true, released_if_gone(&conn, [id])?))
        })
    }

    /// Removes only this generation. Stale cleanup cannot erase its replacement.
    pub fn remove_avatar_source(&self, reference: &AvatarAssetRef) -> StorageResult<bool> {
        self.lock()?
            .execute(
                "DELETE FROM avatar_assets WHERE token = ?1
             AND (SELECT store_epoch FROM chat_presentation_meta WHERE id = 1) = ?2",
                params![reference.token, reference.store_epoch],
            )
            .storage()
            .map(|count| count != 0)
    }

    /// Discard all account avatar bytes/mappings. Existing references and late
    /// completions become invalid; rebinding creates new random generations.
    pub fn clear_avatar_cache(&self) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute("DELETE FROM avatar_assets", []).storage()?;
            conn.execute("DELETE FROM avatar_identity_demand", [])
                .storage()?;
            conn.execute("DELETE FROM avatar_acquisition_bootstrap", [])
                .storage()?;
            Ok(())
        })
    }

    pub fn avatar_cache_usage(&self) -> StorageResult<AvatarCacheUsage> {
        usage(&*self.lock()?)
    }
}

fn invalid(message: &str) -> StorageError {
    StorageError::Serialization(message.into())
}
fn validate_key(key: &str) -> StorageResult<()> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        Err(invalid("avatar key exceeds storage bounds"))
    } else {
        Ok(())
    }
}
fn valid_dimensions(width: u32, height: u32) -> bool {
    (1..=MAX_AVATAR_DIMENSION).contains(&width) && (1..=MAX_AVATAR_DIMENSION).contains(&height)
}
fn next_access(conn: &Connection) -> StorageResult<i64> {
    conn.query_row("UPDATE avatar_cache_meta SET access_seq = access_seq + 1 WHERE id = 1 RETURNING access_seq", [], |r| r.get(0)).storage()
}
fn touch_access(conn: &Connection, token: &[u8], accessed: i64) -> StorageResult<()> {
    conn.execute(
        "INSERT INTO avatar_access(token, accessed) VALUES(?1, ?2)
         ON CONFLICT(token) DO UPDATE SET accessed = excluded.accessed",
        params![token, accessed],
    )
    .storage()?;
    Ok(())
}
fn reference_for_owner(conn: &Connection, owner: &str) -> StorageResult<Option<AvatarAssetRef>> {
    conn.query_row(
        "SELECT store_epoch, token FROM avatar_assets CROSS JOIN chat_presentation_meta WHERE owner_key = ?1 AND id = 1",
        [owner], |r| Ok(AvatarAssetRef { store_epoch: r.get(0)?, token: r.get(1)? }),
    ).optional().storage()
}
// Both screen metadata and byte reads derive availability from the same columns.
fn status_columns(
    row: &rusqlite::Row<'_>,
    first: usize,
    now: u64,
) -> rusqlite::Result<AvatarAssetStatus> {
    let content_revision = nonnegative(row, first)?;
    let byte_count = nonnegative(row, first + 1)?;
    let refresh_at = row
        .get::<_, Option<i64>>(first + 2)?
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(first + 2, value))
        })
        .transpose()?;
    Ok(AvatarAssetStatus {
        availability: if byte_count == 0 {
            AvatarAvailability::Missing
        } else if refresh_at.is_some_and(|deadline| now >= deadline) {
            AvatarAvailability::Stale
        } else {
            AvatarAvailability::Ready
        },
        content_revision,
        byte_count,
    })
}
fn status(
    conn: &Connection,
    reference: &AvatarAssetRef,
    now: u64,
) -> StorageResult<AvatarAssetStatus> {
    let result = conn
        .query_row(
            "SELECT content_revision, coalesce(length(bytes), byte_len, 0), refresh_at FROM avatar_assets
         WHERE token = ?1 AND (SELECT store_epoch FROM chat_presentation_meta WHERE id = 1) = ?2",
            params![reference.token, reference.store_epoch],
            |r| status_columns(r, 0, now),
        )
        .optional()
        .storage()?;
    Ok(result.unwrap_or(AvatarAssetStatus {
        availability: AvatarAvailability::Invalidated,
        content_revision: 0,
        byte_count: 0,
    }))
}
/// Entries are owner rows. Bytes count database-held images plus each ready
/// cache file once, however many owners share it.
pub(crate) fn usage(conn: &Connection) -> StorageResult<AvatarCacheUsage> {
    conn.query_row(
        "SELECT count(*), coalesce(sum(length(bytes)), 0)
            + (SELECT coalesce(sum(byte_len), 0) FROM media_files WHERE category = 2 AND state = 1)
         FROM avatar_assets",
        [],
        |r| {
            Ok(AvatarCacheUsage {
                entries: nonnegative(r, 0)?,
                byte_count: nonnegative(r, 1)?,
            })
        },
    )
    .storage()
}
/// Least recently used owners go first. A shared file frees its bytes only
/// with its last owner, so usage is measured again after each removal.
/// Returns the file ids whose rows (keys) the eviction deleted, for the store
/// to unlink after commit; a caller that drops them leaves them to the sweep.
fn evict(
    conn: &Connection,
    protected: &[u8],
    limits: Limits,
) -> StorageResult<Vec<media_store::FileId>> {
    let mut released = Vec::new();
    loop {
        let size = usage(conn)?;
        if size.entries <= limits.entries && size.byte_count <= limits.bytes {
            return Ok(released);
        }
        let victim: Option<(Vec<u8>, Option<Vec<u8>>)> = conn
            .query_row(
                "SELECT a.token, f.file_id FROM avatar_access r
             JOIN avatar_assets a ON a.token = r.token
             LEFT JOIN avatar_file_refs f ON f.token = a.token WHERE a.token != ?1
             ORDER BY r.accessed, r.token LIMIT 1",
                [protected],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .storage()?;
        let Some((token, file)) = victim else {
            return Err(invalid("avatar exceeds cache capacity"));
        };
        conn.execute("DELETE FROM avatar_assets WHERE token = ?1", [token])
            .storage()?;
        if let Some(file) = file {
            released.extend(released_if_gone(conn, [file_id(file)?])?);
        }
    }
}

fn file_id(bytes: Vec<u8>) -> StorageResult<media_store::FileId> {
    media_store::FileId::from_slice(&bytes)
        .ok_or_else(|| StorageError::Corruption("invalid media file id".into()))
}

/// The ids among `ids` whose `media_files` rows no longer exist.
fn released_if_gone(
    conn: &Connection,
    ids: impl IntoIterator<Item = media_store::FileId>,
) -> StorageResult<Vec<media_store::FileId>> {
    let mut gone = Vec::new();
    for id in ids {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM media_files WHERE id = ?1)",
                [id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .storage()?;
        if !exists {
            gone.push(id);
        }
    }
    Ok(gone)
}

/// Clears an owner's image in either layout and drops its file reference.
/// Clearing `digest` schedules a refetch.
fn clear_image(conn: &Connection, token: &[u8]) -> StorageResult<()> {
    conn.execute("DELETE FROM avatar_file_refs WHERE token = ?1", [token])
        .storage()?;
    conn.execute(
        "UPDATE avatar_assets SET bytes = NULL, digest = NULL, media_type = NULL,
            width = NULL, height = NULL, refresh_at = NULL, byte_len = NULL,
            content_revision = content_revision + 1 WHERE token = ?1",
        [token],
    )
    .storage()?;
    Ok(())
}

enum StoredFile {
    Ready(AvatarStoredFile),
    Gone,
}

/// `byte_len`, file id, file state, media type, width, height.
type StoredFileRow = (
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<String>,
    Option<u32>,
    Option<u32>,
);

/// `None` for a database-held image. A file-backed image whose file row is
/// ready is `Ready`; one that is lost or missing is `Gone`.
fn stored_file(conn: &Connection, token: &[u8]) -> StorageResult<Option<StoredFile>> {
    let row: Option<StoredFileRow> = conn
        .query_row(
            "SELECT a.byte_len, r.file_id, f.state, a.media_type, a.width, a.height
             FROM avatar_assets a LEFT JOIN avatar_file_refs r ON r.token = a.token
             LEFT JOIN media_files f ON f.id = r.file_id WHERE a.token = ?1",
            [token],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .optional()
        .storage()?;
    let Some((Some(byte_len), file, state, media_type, width, height)) = row else {
        return Ok(None);
    };
    let ready = (|| {
        let id = media_store::FileId::from_slice(&file?)?;
        if state? != 1 {
            return None;
        }
        let (width, height) = (width?, height?);
        if !valid_dimensions(width, height) {
            return None;
        }
        Some(AvatarStoredFile {
            id,
            byte_len: u64::try_from(byte_len).ok()?,
            format: AvatarImageFormat::parse(&media_type?)?,
            width,
            height,
        })
    })();
    Ok(Some(ready.map_or(StoredFile::Gone, StoredFile::Ready)))
}

#[cfg(test)]
mod tests;

mod acquisition;
pub use acquisition::{AvatarAcquisition, AvatarAcquisitionState, AvatarIdentityDemand};

pub(crate) mod access;
pub use access::{AvatarAssetPresentation, AvatarAssetTarget};

mod files;
pub use files::{AvatarFileImage, AvatarPublication, DatabaseAvatar, DatabaseAvatarBody};
