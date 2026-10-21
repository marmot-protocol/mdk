//! File-backed avatar publication into the media store's cache category
//! (mdk#2314 step 9). The store writes the file; this target's commit is one
//! transaction: the compare-and-publish fence, the presence-checked reuse of
//! an identical image, the ready mark, the owner's reference, recency and
//! eviction.

use std::cell::RefCell;
use std::sync::Mutex;

use cgka_traits::storage::StorageResult;
use media_store::{
    CatalogResult, Category, ExistingOutcome, FileId, Presence, PublishTarget, ReadyOutcome,
};
use rusqlite::{Connection, OptionalExtension, params};

use super::{
    AvatarAcquisition, AvatarAssetRef, AvatarImage, AvatarImageFormat, LIMITS, Limits,
    MAX_AVATAR_BYTES, clear_image, evict, file_id, invalid, next_access, released_if_gone,
    touch_access, valid_dimensions,
};
use crate::app::media_catalog::{catalog_error, commit_existing_in, commit_ready_in};
use crate::{SqliteAppStorage, SqliteResultExt, u64_to_i64};

/// What an image is, checked before any byte is written. The bytes
/// themselves were verified by the caller, as for a database-held image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AvatarFileImage {
    byte_len: u64,
    format: AvatarImageFormat,
    width: u32,
    height: u32,
}

impl AvatarFileImage {
    pub fn new(
        byte_len: u64,
        format: AvatarImageFormat,
        width: u32,
        height: u32,
    ) -> StorageResult<Self> {
        if byte_len == 0 || byte_len > MAX_AVATAR_BYTES as u64 || !valid_dimensions(width, height) {
            return Err(invalid("avatar exceeds storage bounds"));
        }
        Ok(Self {
            byte_len,
            format,
            width,
            height,
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

/// Publishes one image for one source generation, fenced by the content
/// revision captured before fetching: no failed or older fetch can replace
/// a newer publication. After `MediaStore::publish` returns, read
/// [`published_revision`](Self::published_revision) and unlink
/// [`take_released`](Self::take_released).
pub struct AvatarPublication {
    storage: SqliteAppStorage,
    reference: AvatarAssetRef,
    expected_revision: i64,
    image: AvatarFileImage,
    refresh_at: Option<i64>,
    limits: Limits,
    mode: Mode,
    outcome: Mutex<Committed>,
}

/// What else a publication is fenced on and settles.
enum Mode {
    /// The revision fence only.
    Publish,
    /// A claimed fetch: its attempt must still be current, and the commit
    /// settles it (schedules the next refresh) with the image.
    Acquisition { attempt: Vec<u8> },
    /// Moving a database-held image into a file: the row must still hold
    /// those bytes. Nothing a viewer sees changes, so the content revision
    /// and recency stay, and nothing is evicted.
    Migration,
}

#[derive(Default)]
struct Committed {
    revision: Option<u64>,
    released: Vec<FileId>,
}

impl AvatarPublication {
    pub fn new(
        storage: SqliteAppStorage,
        reference: AvatarAssetRef,
        expected_content_revision: u64,
        image: AvatarFileImage,
        refresh_at: Option<u64>,
    ) -> StorageResult<Self> {
        Self::with_limits(
            storage,
            reference,
            expected_content_revision,
            image,
            refresh_at,
            LIMITS,
        )
    }

    pub(super) fn with_limits(
        storage: SqliteAppStorage,
        reference: AvatarAssetRef,
        expected_content_revision: u64,
        image: AvatarFileImage,
        refresh_at: Option<u64>,
        limits: Limits,
    ) -> StorageResult<Self> {
        if image.byte_len > limits.bytes {
            return Err(invalid("avatar exceeds cache capacity"));
        }
        Ok(Self {
            storage,
            reference,
            expected_revision: u64_to_i64(expected_content_revision)?,
            image,
            refresh_at: refresh_at.map(u64_to_i64).transpose()?,
            limits,
            mode: Mode::Publish,
            outcome: Mutex::new(Committed::default()),
        })
    }

    /// Publication of a claimed fetch's result. It is refused if the attempt
    /// is no longer current (restart, source change, eviction, store reset);
    /// committing settles the attempt with the next refresh due at
    /// `refresh_at`. Settle a refused one with
    /// [`SqliteAppStorage::settle_avatar_acquisition`].
    pub fn for_acquisition(
        storage: SqliteAppStorage,
        job: &AvatarAcquisition,
        image: AvatarFileImage,
        refresh_at: Option<u64>,
    ) -> StorageResult<Self> {
        let mut publication = Self::new(
            storage,
            job.reference.clone(),
            job.revision(),
            image,
            refresh_at,
        )?;
        publication.mode = Mode::Acquisition {
            attempt: job.attempt().to_vec(),
        };
        Ok(publication)
    }

    /// Moves database-held image `avatar`, whose bytes were read as `image`,
    /// into a file.
    pub fn for_migration(
        storage: SqliteAppStorage,
        avatar: &DatabaseAvatar,
        image: &AvatarImage,
    ) -> StorageResult<Self> {
        let file = AvatarFileImage::new(
            image.bytes().len() as u64,
            image.format(),
            image.width(),
            image.height(),
        )?;
        let mut publication = Self::new(
            storage,
            avatar.reference.clone(),
            avatar.revision,
            file,
            avatar.refresh_at,
        )?;
        publication.mode = Mode::Migration;
        Ok(publication)
    }

    /// The new content revision once a publication committed.
    pub fn published_revision(&self) -> Option<u64> {
        self.lock_outcome().revision
    }

    /// File ids whose rows (keys) a committed publication deleted: the
    /// owner's previous file and evicted owners' files.
    pub fn take_released(&self) -> Vec<FileId> {
        std::mem::take(&mut self.lock_outcome().released)
    }

    fn lock_outcome(&self) -> std::sync::MutexGuard<'_, Committed> {
        self.outcome
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn superseded_in(&self, conn: &Connection) -> StorageResult<bool> {
        let current: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM avatar_assets
                WHERE token = ?1 AND content_revision = ?2
                AND (SELECT store_epoch FROM chat_presentation_meta WHERE id = 1) = ?3
                AND (?4 = 0 OR bytes IS NOT NULL))",
                params![
                    self.reference.token,
                    self.expected_revision,
                    self.reference.store_epoch,
                    matches!(self.mode, Mode::Migration)
                ],
                |row| row.get(0),
            )
            .storage()?;
        if !current {
            return Ok(true);
        }
        match &self.mode {
            Mode::Acquisition { attempt } => Ok(!super::acquisition::attempt_current_in(
                conn,
                &self.reference.token,
                attempt,
            )?),
            Mode::Publish | Mode::Migration => Ok(false),
        }
    }

    /// Points the owner at ready file `id` and publishes its metadata.
    fn attach_in(
        &self,
        conn: &Connection,
        id: FileId,
        digest: &[u8; 32],
        committed: &RefCell<Committed>,
    ) -> StorageResult<()> {
        let token = self.reference.token.as_slice();
        let previous: Option<Vec<u8>> = conn
            .query_row(
                "SELECT file_id FROM avatar_file_refs WHERE token = ?1",
                [token],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        let previous = previous.map(file_id).transpose()?;
        let mut released = Vec::new();
        if previous != Some(id) {
            conn.execute("DELETE FROM avatar_file_refs WHERE token = ?1", [token])
                .storage()?;
            conn.execute(
                "INSERT INTO avatar_file_refs(token, file_id) VALUES(?1, ?2)",
                params![token, id.as_bytes().as_slice()],
            )
            .storage()?;
            released.extend(released_if_gone(conn, previous)?);
        }
        let byte_len: i64 = conn
            .query_row(
                "SELECT byte_len FROM media_files WHERE id = ?1",
                [id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .storage()?;
        if byte_len != self.image.byte_len as i64 {
            return Err(invalid("avatar file length does not match its image"));
        }
        let migrating = matches!(self.mode, Mode::Migration);
        conn.execute(
            "UPDATE avatar_assets SET bytes = NULL, digest = ?1, media_type = ?2, width = ?3,
                height = ?4, refresh_at = ?5, byte_len = ?6,
                content_revision = content_revision + (1 - ?8)
             WHERE token = ?7",
            params![
                digest.as_slice(),
                self.image.format.media_type(),
                self.image.width,
                self.image.height,
                self.refresh_at,
                byte_len,
                token,
                migrating
            ],
        )
        .storage()?;
        if !migrating {
            let accessed = next_access(conn)?;
            touch_access(conn, token, accessed)?;
            released.extend(evict(conn, token, self.limits)?);
        }
        if let Mode::Acquisition { attempt } = &self.mode {
            super::acquisition::settle_attempt_in(conn, token, attempt, self.refresh_at)?;
        }
        let mut committed = committed.borrow_mut();
        committed.revision = Some(self.expected_revision as u64 + u64::from(!migrating));
        committed.released = released;
        Ok(())
    }

    /// Runs one commit; its outcome is kept only if the transaction commits.
    fn commit<T>(
        &self,
        run: impl FnOnce(&Connection, &RefCell<Committed>) -> StorageResult<T>,
    ) -> CatalogResult<T> {
        let committed = RefCell::new(Committed::default());
        let value = self
            .storage
            .connection
            .with_transaction(|| {
                let conn = self.storage.lock()?;
                run(&conn, &committed)
            })
            .map_err(catalog_error)?;
        let committed = committed.into_inner();
        if committed.revision.is_some() {
            *self.lock_outcome() = committed;
        }
        Ok(value)
    }
}

/// An image still held in the database, which the migration moves into a
/// cache file.
#[derive(Clone)]
pub struct DatabaseAvatar {
    reference: AvatarAssetRef,
    revision: u64,
    byte_len: u64,
    refresh_at: Option<u64>,
}

impl std::fmt::Debug for DatabaseAvatar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseAvatar")
            .field("byte_len", &self.byte_len)
            .finish_non_exhaustive()
    }
}

impl DatabaseAvatar {
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

/// `bytes`, `digest`, media type, width, height.
type HeldImageRow = (Vec<u8>, Vec<u8>, String, u32, u32);

/// A database-held image as the migration reads it.
#[derive(Debug)]
pub enum DatabaseAvatarBody {
    Image(AvatarImage),
    /// The row no longer holds these bytes (republished, evicted, reset).
    Changed,
    /// The bytes fail their digest or metadata.
    Corrupt,
}

impl SqliteAppStorage {
    /// Up to `limit` images still held in the database, smallest first.
    pub fn database_held_avatars(&self, limit: usize) -> StorageResult<Vec<DatabaseAvatar>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT a.token, m.store_epoch, a.content_revision, length(a.bytes), a.refresh_at
                 FROM avatar_assets a CROSS JOIN chat_presentation_meta m
                 WHERE m.id = 1 AND a.bytes IS NOT NULL
                 ORDER BY length(a.bytes), a.token LIMIT ?1",
            )
            .storage()?;
        let rows = statement
            .query_map([limit as i64], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })
            .storage()?;
        rows.map(|row| {
            let (token, store_epoch, revision, byte_len, refresh_at) = row.storage()?;
            let unsigned =
                |value: i64| u64::try_from(value).map_err(|_| invalid("invalid avatar row"));
            Ok(DatabaseAvatar {
                reference: AvatarAssetRef { store_epoch, token },
                revision: unsigned(revision)?,
                byte_len: unsigned(byte_len)?,
                refresh_at: refresh_at.map(unsigned).transpose()?,
            })
        })
        .collect()
    }

    /// The bytes of `avatar`, if the row still holds them unchanged.
    pub fn database_avatar_body(
        &self,
        avatar: &DatabaseAvatar,
    ) -> StorageResult<DatabaseAvatarBody> {
        let row: Option<HeldImageRow> = self
            .lock()?
            .query_row(
                "SELECT bytes, digest, media_type, width, height FROM avatar_assets
                 WHERE token = ?1 AND content_revision = ?2 AND bytes IS NOT NULL
                    AND (SELECT store_epoch FROM chat_presentation_meta WHERE id = 1) = ?3",
                params![
                    avatar.reference.token,
                    u64_to_i64(avatar.revision)?,
                    avatar.reference.store_epoch
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .storage()?;
        let Some((bytes, digest, media_type, width, height)) = row else {
            return Ok(DatabaseAvatarBody::Changed);
        };
        let bytes = zeroize::Zeroizing::new(bytes);
        let image = (|| {
            use sha2::Digest;
            if sha2::Sha256::digest(&bytes).as_slice() != digest {
                return None;
            }
            let format = AvatarImageFormat::parse(&media_type)?;
            AvatarImage::new(bytes.to_vec(), format, width, height).ok()
        })();
        Ok(image.map_or(DatabaseAvatarBody::Corrupt, DatabaseAvatarBody::Image))
    }

    /// Clears a database-held image whose bytes are corrupt; it is fetched
    /// again, as after a corrupt read. `false` when the row changed.
    pub fn drop_corrupt_database_avatar(&self, avatar: &DatabaseAvatar) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let current: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM avatar_assets
                     WHERE token = ?1 AND content_revision = ?2 AND bytes IS NOT NULL
                        AND (SELECT store_epoch FROM chat_presentation_meta WHERE id = 1) = ?3)",
                    params![
                        avatar.reference.token,
                        u64_to_i64(avatar.revision)?,
                        avatar.reference.store_epoch
                    ],
                    |row| row.get(0),
                )
                .storage()?;
            if current {
                clear_image(&conn, &avatar.reference.token)?;
            }
            Ok(current)
        })
    }

    /// Bytes of images still held in the database.
    pub fn database_avatar_bytes(&self) -> StorageResult<u64> {
        let bytes: i64 = self
            .lock()?
            .query_row(
                "SELECT coalesce(sum(length(bytes)), 0) FROM avatar_assets",
                [],
                |row| row.get(0),
            )
            .storage()?;
        Ok(u64::try_from(bytes).unwrap_or(0))
    }
}

impl PublishTarget for AvatarPublication {
    fn superseded(&self) -> CatalogResult<bool> {
        let conn = self.storage.lock().map_err(catalog_error)?;
        self.superseded_in(&conn).map_err(catalog_error)
    }

    fn commit_existing(
        &self,
        category: Category,
        digest: &[u8; 32],
        present: Presence<'_>,
    ) -> CatalogResult<ExistingOutcome> {
        self.commit(|conn, committed| {
            commit_existing_in(
                conn,
                category,
                digest,
                present,
                &|conn| self.superseded_in(conn),
                &|conn, id| self.attach_in(conn, id, digest, committed),
            )
        })
    }

    fn commit_ready(
        &self,
        id: FileId,
        category: Category,
        digest: &[u8; 32],
        present: Presence<'_>,
    ) -> CatalogResult<ReadyOutcome> {
        self.commit(|conn, committed| {
            commit_ready_in(
                conn,
                id,
                category,
                digest,
                present,
                &|conn| self.superseded_in(conn),
                &|conn, id| self.attach_in(conn, id, digest, committed),
            )
        })
    }
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
