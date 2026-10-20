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
    AvatarAssetRef, AvatarImageFormat, LIMITS, Limits, MAX_AVATAR_BYTES, evict, file_id, invalid,
    next_access, released_if_gone, touch_access, valid_dimensions,
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
    outcome: Mutex<Committed>,
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
            outcome: Mutex::new(Committed::default()),
        })
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
        conn.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM avatar_assets
                WHERE token = ?1 AND content_revision = ?2
                AND (SELECT store_epoch FROM chat_presentation_meta WHERE id = 1) = ?3)",
            params![
                self.reference.token,
                self.expected_revision,
                self.reference.store_epoch
            ],
            |row| row.get(0),
        )
        .storage()
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
        conn.execute(
            "UPDATE avatar_assets SET bytes = NULL, digest = ?1, media_type = ?2, width = ?3,
                height = ?4, refresh_at = ?5, byte_len = ?6,
                content_revision = content_revision + 1
             WHERE token = ?7",
            params![
                digest.as_slice(),
                self.image.format.media_type(),
                self.image.width,
                self.image.height,
                self.refresh_at,
                byte_len,
                token
            ],
        )
        .storage()?;
        let accessed = next_access(conn)?;
        touch_access(conn, token, accessed)?;
        released.extend(evict(conn, token, self.limits)?);
        let mut committed = committed.borrow_mut();
        committed.revision = Some(self.expected_revision as u64 + 1);
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
