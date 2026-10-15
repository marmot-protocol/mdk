//! Downloaded bodies retained in the encrypted media store (mdk#2314 step 2).
//!
//! A claimed job publishes through `media_store::MediaStore::publish` with an
//! [`AttachmentPublication`] target. Its fences are the database paths' own:
//! store generation, attempt, lease, source, acceptance and expiry. The
//! retained-byte budget is not applied: free disk, checked by the caller, is
//! the only limit on retained media.
use media_store::{
    CatalogResult, Category, ExistingOutcome, FileId, Presence, PublishTarget, ReadyOutcome,
};

use super::*;
use crate::media_catalog::{attach_slot, catalog_error, commit_existing_in, commit_ready_in};

/// One claimed acquisition's publication into the media store.
pub struct AttachmentPublication<'a> {
    storage: &'a SqliteAccountStorage,
    job: &'a AttachmentAcquisition,
    clock: &'a dyn Fn() -> u64,
}

impl SqliteAccountStorage {
    /// Whether a ready media file already holds this job's content, from the
    /// database alone (no file check). A scheduler can then attach it before
    /// download-only gates; the blocking reuse attempt confirms the file.
    pub fn attachment_media_twin_recorded(
        &self,
        reference: &AttachmentAssetRef,
    ) -> StorageResult<bool> {
        self.lock()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM attachment_acquisition q
                 JOIN media_files mf ON mf.plaintext_digest=q.plaintext_digest
                 WHERE q.token=?1 AND mf.state=1 AND mf.category=1)",
                [&reference.token],
                |row| row.get(0),
            )
            .storage()
    }

    /// The media store target for `job`. `clock` gives Unix seconds for the
    /// lease fence at each commit; it must not block.
    pub fn attachment_publication<'a>(
        &'a self,
        job: &'a AttachmentAcquisition,
        clock: &'a dyn Fn() -> u64,
    ) -> AttachmentPublication<'a> {
        AttachmentPublication {
            storage: self,
            job,
            clock,
        }
    }
}

impl AttachmentPublication<'_> {
    fn superseded_in(&self, conn: &Connection) -> StorageResult<bool> {
        publication_superseded(conn, self.job, u64_to_i64((self.clock)())?)
    }

    /// Points the job's slot at the file and marks the job retained.
    fn retain(&self, conn: &Connection, id: FileId) -> StorageResult<()> {
        attach_slot(conn, &self.job.reference.token, id)?;
        conn.execute(
            "UPDATE attachment_acquisition SET state=3,due=NULL,attempt=NULL,storage_blocked_headroom=NULL,storage_park_count=0 WHERE token=?1",
            [&self.job.reference.token],
        )
        .storage()?;
        Ok(())
    }
}

impl PublishTarget for AttachmentPublication<'_> {
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
                    &|conn, id| self.retain(conn, id),
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
                    &|conn, id| self.retain(conn, id),
                )
            })
            .map_err(catalog_error)
    }
}

impl AttachmentAcquisition {
    /// The job's plaintext digest, which the media store verifies the body
    /// against.
    pub fn plaintext_digest(&self) -> StorageResult<[u8; 32]> {
        self.digest
            .as_slice()
            .try_into()
            .map_err(|_| invalid("invalid attachment digest"))
    }
}

#[cfg(test)]
#[path = "media_tests.rs"]
mod tests;
