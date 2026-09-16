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

use crate::chat_presentation::nonnegative;
use crate::{SqliteAccountStorage, SqliteResultExt, u64_to_i64};

pub const MAX_AVATAR_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_AVATAR_CACHE_BYTES: u64 = 128 * 1024 * 1024;
/// Bounds missing source mappings as well as populated images.
pub const MAX_AVATAR_CACHE_ENTRIES: u64 = 2048;
pub const MAX_AVATAR_DIMENSION: u32 = 4096;
const MAX_KEY_BYTES: usize = 512;

/// A source generation, scoped to the existing account store epoch. Neither the
/// owner key nor image material is exposed. A reference is not an authorization
/// grant: callers must still select the correct account using the host contract.
#[derive(Clone, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvatarAvailability {
    Missing,
    Ready,
    Stale,
    Invalidated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvatarAssetStatus {
    pub availability: AvatarAvailability,
    /// Use together with the source reference to key a decoded-image cache.
    /// Every publication increments this value, including same-URL refreshes.
    pub content_revision: u64,
    pub byte_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvatarAssetRead {
    pub status: AvatarAssetStatus,
    pub image: Option<AvatarImage>,
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

impl SqliteAccountStorage {
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
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
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
                    width = NULL, height = NULL, refresh_at = NULL",
                params![owner, source],
            )
            .storage()?;
        }
        let reference =
            reference_for_owner(&tx, owner)?.ok_or_else(|| invalid("avatar binding missing"))?;
        touch_access(&tx, &reference.token, accessed)?;
        // Repeated bindings cannot grow the cache: avoid scanning usage or
        // rewriting a blob just because another screen asks for the same source.
        if unchanged {
            tx.commit().storage()?;
            return Ok(reference);
        }
        evict(&tx, &reference.token, limits)?;
        tx.commit().storage()?;
        Ok(reference)
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
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let accessed = next_access(&tx)?;
        let changed = tx
            .execute(
                "UPDATE avatar_assets SET bytes = ?1, digest = ?2, media_type = ?3,
                width = ?4, height = ?5, refresh_at = ?6,
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
        touch_access(&tx, &reference.token, accessed)?;
        evict(&tx, &reference.token, limits)?;
        tx.commit().storage()?;
        Ok(AvatarPublishResult::Published {
            content_revision: expected as u64 + 1,
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
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let mut state = status(&tx, reference, now)?;
        let mut image = None;
        if matches!(
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
                tx.execute(
                    "UPDATE avatar_assets SET bytes = NULL, digest = NULL, media_type = NULL,
                        width = NULL, height = NULL, refresh_at = NULL,
                        content_revision = content_revision + 1 WHERE token = ?1",
                    [&reference.token],
                )
                .storage()?;
                state = status(&tx, reference, now)?;
            }
        }
        tx.commit().storage()?;
        Ok(AvatarAssetRead {
            status: state,
            image,
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
        self.lock()?
            .execute("DELETE FROM avatar_assets", [])
            .storage()?;
        Ok(())
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
fn status(
    conn: &Connection,
    reference: &AvatarAssetRef,
    now: u64,
) -> StorageResult<AvatarAssetStatus> {
    let result = conn
        .query_row(
            "SELECT content_revision, coalesce(length(bytes), 0), refresh_at FROM avatar_assets
         WHERE token = ?1 AND (SELECT store_epoch FROM chat_presentation_meta WHERE id = 1) = ?2",
            params![reference.token, reference.store_epoch],
            |r| {
                let content_revision = nonnegative(r, 0)?;
                let byte_count = nonnegative(r, 1)?;
                let refresh_at = r
                    .get::<_, Option<i64>>(2)?
                    .map(|v| {
                        u64::try_from(v).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, v))
                    })
                    .transpose()?;
                let availability = if byte_count == 0 {
                    AvatarAvailability::Missing
                } else if refresh_at.is_some_and(|deadline| now >= deadline) {
                    AvatarAvailability::Stale
                } else {
                    AvatarAvailability::Ready
                };
                Ok(AvatarAssetStatus {
                    availability,
                    content_revision,
                    byte_count,
                })
            },
        )
        .optional()
        .storage()?;
    Ok(result.unwrap_or(AvatarAssetStatus {
        availability: AvatarAvailability::Invalidated,
        content_revision: 0,
        byte_count: 0,
    }))
}
fn usage(conn: &Connection) -> StorageResult<AvatarCacheUsage> {
    conn.query_row(
        "SELECT count(*), coalesce(sum(length(bytes)), 0) FROM avatar_assets",
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
fn evict(conn: &Connection, protected: &[u8], limits: Limits) -> StorageResult<()> {
    let mut size = usage(conn)?;
    while size.entries > limits.entries || size.byte_count > limits.bytes {
        let victim: Option<(Vec<u8>, u64)> = conn
            .query_row(
                "SELECT a.token, coalesce(length(a.bytes), 0) FROM avatar_access r
             JOIN avatar_assets a ON a.token = r.token WHERE a.token != ?1
             ORDER BY r.accessed, r.token LIMIT 1",
                [protected],
                |r| Ok((r.get(0)?, nonnegative(r, 1)?)),
            )
            .optional()
            .storage()?;
        let Some((token, bytes)) = victim else {
            return Err(invalid("avatar exceeds cache capacity"));
        };
        conn.execute("DELETE FROM avatar_assets WHERE token = ?1", [token])
            .storage()?;
        size.entries -= 1;
        size.byte_count -= bytes;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
