//! A claimed download's checkpoint as the media store's
//! [`CheckpointTarget`] (mdk#2314 step 2b). The store owns the wire file and
//! the order of every step; this target only reads and writes the job's
//! `attachment_partial` row, each call one transaction under the attempt's
//! fences, so a stale or cancelled attempt can never change a newer one's
//! checkpoint.
use crate::SqliteAppStorage;
use media_store::{CatalogResult, CheckpointStart, CheckpointTarget, FileId};

use super::*;
use crate::app::media_catalog::catalog_error;

/// What a checkpoint target may touch.
enum Scope {
    /// One representation: the identity a download is saving.
    Identity(AttachmentPartialIdentity),
    /// Whatever checkpoint the job holds for these ciphertext and locator
    /// digests, or any checkpoint when `None`. Restores and clears only.
    Matching(Option<([u8; 32], [u8; 32])>),
}

/// One claimed acquisition's download checkpoint.
pub struct AttachmentCheckpoint {
    storage: SqliteAppStorage,
    job: AttachmentAcquisition,
    scope: Scope,
    clock: fn() -> u64,
}

impl SqliteAppStorage {
    /// The checkpoint `job` is saving for `identity`. `clock` gives Unix
    /// seconds for the attempt fences at each call; it must not block.
    pub fn attachment_checkpoint(
        &self,
        job: &AttachmentAcquisition,
        identity: AttachmentPartialIdentity,
        clock: fn() -> u64,
    ) -> AttachmentCheckpoint {
        AttachmentCheckpoint {
            storage: self.clone(),
            job: job.clone(),
            scope: Scope::Identity(identity),
            clock,
        }
    }

    /// The checkpoint `job` holds for the expected ciphertext and locator
    /// digests (any checkpoint when `None`), for restoring or clearing it.
    /// It cannot begin or grow a checkpoint.
    pub fn attachment_checkpoint_matching(
        &self,
        job: &AttachmentAcquisition,
        expected: Option<([u8; 32], [u8; 32])>,
        clock: fn() -> u64,
    ) -> AttachmentCheckpoint {
        AttachmentCheckpoint {
            storage: self.clone(),
            job: job.clone(),
            scope: Scope::Matching(expected),
            clock,
        }
    }
}

impl AttachmentCheckpoint {
    fn expected(&self) -> Option<(&[u8; 32], &[u8; 32])> {
        match &self.scope {
            Scope::Identity(identity) => {
                Some((&identity.ciphertext_digest, &identity.locator_digest))
            }
            Scope::Matching(expected) => expected.as_ref().map(|(c, l)| (c, l)),
        }
    }

    fn identity(&self) -> Option<&AttachmentPartialIdentity> {
        match &self.scope {
            Scope::Identity(identity) => Some(identity),
            Scope::Matching(_) => None,
        }
    }
}

impl CheckpointTarget for AttachmentCheckpoint {
    fn key(&self) -> &[u8] {
        &self.job.reference.token
    }

    fn current(&self) -> CatalogResult<Option<(FileId, u64)>> {
        self.storage
            .current_attachment_partial(&self.job, (self.clock)(), self.expected(), self.identity())
            .map_err(catalog_error)
    }

    fn begin(&self) -> CatalogResult<Option<CheckpointStart>> {
        let Some(identity) = self.identity() else {
            return Ok(None);
        };
        self.storage
            .begin_attachment_partial(&self.job, identity, (self.clock)())
            .map_err(catalog_error)
    }

    fn record(&self, wire: FileId, received: u64) -> CatalogResult<bool> {
        let Some(identity) = self.identity() else {
            return Ok(false);
        };
        self.storage
            .record_attachment_partial(&self.job, identity, &wire, received, (self.clock)())
            .map_err(catalog_error)
    }

    fn clear(&self) -> CatalogResult<Option<FileId>> {
        self.storage
            .clear_attachment_partial(&self.job, (self.clock)(), self.expected())
            .map_err(catalog_error)
    }
}
