//! The database side of moving legacy attachment bodies into the encrypted
//! media store (mdk#2314 step 6).
//!
//! A legacy body is a completed retained body still held in SQLCipher rows:
//! one `retained_attachment_bytes` row, or that row plus a completed chunked
//! file. The caller streams it out with [`LegacyBodyReader`], publishes it
//! through the media store with [`LegacyBodyPublication`], and then drops the
//! rows with [`SqliteAppStorage::drop_migrated_legacy_body`]. Selection is
//! simply "has a legacy body", so there is no cursor: a moved body loses its
//! rows. A crash between the publish and the drop leaves both copies; reads
//! already prefer the file, and the next batch only drops the rows.
//!
//! Legacy outgoing uploads are not moved: they promote through their own path
//! within their TTL and then become ordinary legacy bodies here.
use std::io;

use media_store::{
    CatalogResult, Category, ExistingOutcome, FileId, Presence, PublishTarget, ReadyOutcome,
};

use super::*;
use crate::app::media_catalog::{attach_slot, catalog_error, commit_existing_in, commit_ready_in};

/// Plaintext length of legacy body `b` (with its chunked file `f`, if any).
/// Rows from before migration 0104 carry a -1 sentinel length.
const LEGACY_BODY_LEN: &str = "CASE WHEN f.token IS NOT NULL THEN f.byte_len
     WHEN b.byte_len>=0 THEN b.byte_len ELSE length(b.bytes) END";
/// Completed legacy bodies: a chunked import still in progress is not one.
const LEGACY_BODIES: &str = "retained_attachment_bytes b
     JOIN attachment_acquisition q ON q.token=b.token
     LEFT JOIN retained_attachment_files f ON f.token=b.token
     WHERE f.token IS NULL OR f.completed=1";

/// Where moving legacy attachment bodies into the media store stands.
///
/// The database alone knows [`Self::NotNeeded`] and [`Self::Running`]; the
/// app runtime reports [`Self::Paused`] and [`Self::Complete`] from what its
/// migration batches saw.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttachmentMigrationState {
    /// No legacy bodies remain, and this runtime moved none.
    #[default]
    NotNeeded,
    /// Legacy bodies are being moved; `remaining_bytes` are still in the
    /// database.
    Running { remaining_bytes: u64 },
    /// The smallest remaining body does not fit on the volume: the move
    /// resumes once `needed_bytes` more are free. Deleting attachments frees
    /// space (file-backed ones at once) or shrinks what is left to move.
    Paused { needed_bytes: u64 },
    /// This runtime moved the last legacy body.
    Complete,
}

/// One completed legacy body, chosen for a move.
#[derive(Clone)]
pub struct LegacyAttachmentBody {
    token: Vec<u8>,
    row_id: i64,
    byte_len: u64,
    digest: Option<[u8; 32]>,
    media_file: Option<FileId>,
}

impl std::fmt::Debug for LegacyAttachmentBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyAttachmentBody")
            .field("byte_len", &self.byte_len)
            .finish_non_exhaustive()
    }
}

impl LegacyAttachmentBody {
    /// Plaintext bytes.
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// The slot's plaintext digest, which the body must hash to. `None`
    /// when the stored digest is malformed: the body cannot be verified.
    pub fn digest(&self) -> Option<[u8; 32]> {
        self.digest
    }

    /// The ready media file the slot already references, if a move
    /// published it but did not get to drop the rows.
    pub fn media_file(&self) -> Option<FileId> {
        self.media_file
    }
}

impl SqliteAppStorage {
    /// Up to `limit` (1..=64) completed legacy bodies, smallest first, so a
    /// body that does not fit means none of the rest fits either.
    pub fn legacy_attachment_bodies(
        &self,
        limit: usize,
    ) -> StorageResult<Vec<LegacyAttachmentBody>> {
        if limit == 0 || limit > ATTACHMENT_ACQUISITION_BATCH_LIMIT {
            return Err(invalid("invalid legacy attachment batch limit"));
        }
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(&format!(
                "SELECT b.token,b.rowid,{LEGACY_BODY_LEN} AS len,q.plaintext_digest,
                   (SELECT mr.file_id FROM media_file_refs mr JOIN media_files mf ON mf.id=mr.file_id
                    WHERE mr.token=b.token AND mf.state=1)
                 FROM {LEGACY_BODIES}
                 ORDER BY len,b.token LIMIT ?1"
            ))
            .storage()?;
        statement
            .query_map([limit as i64], |row| {
                Ok(LegacyAttachmentBody {
                    token: row.get(0)?,
                    row_id: row.get(1)?,
                    byte_len: nonnegative(row, 2)?,
                    digest: row
                        .get::<_, Option<Vec<u8>>>(3)?
                        .and_then(|digest| digest.as_slice().try_into().ok()),
                    media_file: row
                        .get::<_, Option<Vec<u8>>>(4)?
                        .and_then(|id| FileId::from_slice(&id)),
                })
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()
    }

    /// Plaintext bytes of every completed legacy body still in the database.
    pub fn legacy_attachment_bytes(&self) -> StorageResult<u64> {
        legacy_attachment_bytes_in(&*self.lock()?)
    }

    /// A reader that streams `body` from its rows, one bounded window per
    /// read. It fails if the rows change underneath it.
    pub fn legacy_attachment_reader(&self, body: &LegacyAttachmentBody) -> LegacyBodyReader {
        LegacyBodyReader {
            storage: self.clone(),
            token: body.token.clone(),
            row_id: body.row_id,
            byte_len: body.byte_len,
            offset: 0,
            invalid: false,
        }
    }

    /// The media store target that moves `body` into its slot, fenced on
    /// the legacy rows still being the ones selected.
    pub fn legacy_attachment_publication(
        &self,
        body: &LegacyAttachmentBody,
    ) -> LegacyBodyPublication<'_> {
        LegacyBodyPublication {
            storage: self,
            token: body.token.clone(),
            row_id: body.row_id,
        }
    }

    /// Deletes `body`'s rows, in one transaction, once its slot references
    /// a ready media file. `false` when the rows changed or no such file is
    /// referenced.
    pub fn drop_migrated_legacy_body(&self, body: &LegacyAttachmentBody) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            Ok(self
                .lock()?
                .execute(
                    "DELETE FROM retained_attachment_bytes WHERE token=?1 AND rowid=?2
                     AND EXISTS(SELECT 1 FROM media_file_refs mr JOIN media_files mf ON mf.id=mr.file_id
                         WHERE mr.token=?1 AND mf.state=1)",
                    params![body.token, body.row_id],
                )
                .storage()?
                == 1)
        })
    }

    /// Deletes `body`'s rows, in one transaction, because the body cannot be
    /// read back as stored or fails its digest. The slot keeps its completed
    /// acquisition without a body, which shows as previously acquired and
    /// unavailable with download-again allowed, as a lost media file does.
    /// `false` when the rows changed.
    pub fn drop_corrupt_legacy_body(&self, body: &LegacyAttachmentBody) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            Ok(self
                .lock()?
                .execute(
                    "DELETE FROM retained_attachment_bytes WHERE token=?1 AND rowid=?2",
                    params![body.token, body.row_id],
                )
                .storage()?
                == 1)
        })
    }
}

pub(super) fn legacy_attachment_bytes_in(conn: &Connection) -> StorageResult<u64> {
    conn.query_row(
        &format!("SELECT coalesce(sum({LEGACY_BODY_LEN}),0) FROM {LEGACY_BODIES}"),
        [],
        |row| nonnegative(row, 0),
    )
    .storage()
}

/// Streams one legacy body from its rows. Each read is one short read
/// transaction of at most [`MAX_ATTACHMENT_LOCAL_READ_BYTES`], fenced on the
/// rows still being the ones selected.
pub struct LegacyBodyReader {
    storage: SqliteAppStorage,
    token: Vec<u8>,
    row_id: i64,
    byte_len: u64,
    offset: u64,
    invalid: bool,
}

impl std::fmt::Debug for LegacyBodyReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyBodyReader")
            .field("byte_len", &self.byte_len)
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

impl LegacyBodyReader {
    /// Whether a read failed because the stored body itself is malformed
    /// (broken or missing chunks, or fewer bytes than recorded). Completed
    /// bodies are immutable, so retrying cannot repair it.
    pub fn body_invalid(&self) -> bool {
        self.invalid
    }

    fn window(&self, limit: usize) -> StorageResult<Zeroizing<Vec<u8>>> {
        let offset = usize::try_from(self.offset)
            .map_err(|_| invalid("invalid legacy attachment offset"))?;
        self.storage.connection.with_deferred_read(|conn| {
            let current: Option<i64> = conn
                .query_row(
                    "SELECT rowid FROM retained_attachment_bytes WHERE token=?1",
                    [&self.token],
                    |row| row.get(0),
                )
                .optional()
                .storage()?;
            if current != Some(self.row_id) {
                return Err(invalid("legacy attachment body changed"));
            }
            read_legacy_body(conn, &self.token, self.row_id, offset, limit)
        })
    }
}

impl io::Read for LegacyBodyReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let remaining = self.byte_len.saturating_sub(self.offset);
        if remaining == 0 || out.is_empty() {
            return Ok(0);
        }
        let limit = out
            .len()
            .min(MAX_ATTACHMENT_LOCAL_READ_BYTES)
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let bytes = match self.window(limit) {
            Ok(bytes) => bytes,
            Err(StorageError::InvalidAttachmentBody(reason)) => {
                self.invalid = true;
                return Err(io::Error::other(reason));
            }
            Err(_) => return Err(io::Error::other("legacy attachment read failed")),
        };
        if bytes.is_empty() {
            // The rows hold fewer bytes than their recorded length.
            self.invalid = true;
            return Err(io::Error::other("legacy attachment body truncated"));
        }
        out[..bytes.len()].copy_from_slice(&bytes);
        self.offset += bytes.len() as u64;
        Ok(bytes.len())
    }
}

/// Publication of one legacy body into its own slot. Fenced on the legacy
/// rows still being the ones selected, so a removal (or a replaced body)
/// supersedes it; the slot then references the file as a download would.
pub struct LegacyBodyPublication<'a> {
    storage: &'a SqliteAppStorage,
    token: Vec<u8>,
    row_id: i64,
}

impl LegacyBodyPublication<'_> {
    fn superseded_in(&self, conn: &Connection) -> StorageResult<bool> {
        conn.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM retained_attachment_bytes WHERE token=?1 AND rowid=?2)",
            params![self.token, self.row_id],
            |row| row.get(0),
        )
        .storage()
    }
}

impl PublishTarget for LegacyBodyPublication<'_> {
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
        self.storage
            .connection
            .with_transaction(|| {
                let conn = self.storage.lock()?;
                commit_existing_in(
                    &conn,
                    category,
                    digest,
                    present,
                    &|conn| self.superseded_in(conn),
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
                    &|conn| self.superseded_in(conn),
                    &|conn, id| attach_slot(conn, &self.token, id),
                )
            })
            .map_err(catalog_error)
    }
}
