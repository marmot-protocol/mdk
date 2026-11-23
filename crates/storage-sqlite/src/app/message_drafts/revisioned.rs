//! Selected composer metadata and revision-checked mutations.
use super::*;
use crate::SqliteAppStorage;

#[derive(Clone, PartialEq, Eq)]
pub struct MessageDraftRevision {
    store_epoch: Vec<u8>,
    group_id_hex: String,
    revision: i64,
}

/// Read-only chat-row metadata. It cannot authorize a draft mutation.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChatListDraftVersion {
    store_epoch: Vec<u8>,
    group_id_hex: String,
    revision: i64,
}

impl std::fmt::Debug for ChatListDraftVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatListDraftVersion")
            .finish_non_exhaustive()
    }
}

impl MessageDraftRevision {
    /// Whether this read-only version belongs to the same store/group and is
    /// no newer than this selected revision. This comparison never clears a draft.
    pub fn includes_chat_list_version(&self, version: &ChatListDraftVersion) -> bool {
        version.store_epoch == self.store_epoch
            && version.group_id_hex == self.group_id_hex
            && version.revision <= self.revision
    }

    #[cfg(test)]
    fn chat_list_version(&self) -> ChatListDraftVersion {
        ChatListDraftVersion {
            store_epoch: self.store_epoch.clone(),
            group_id_hex: self.group_id_hex.clone(),
            revision: self.revision,
        }
    }

    pub fn group_id_hex(&self) -> &str {
        &self.group_id_hex
    }

    /// Whether `other` names the same store and group, at any revision.
    pub(crate) fn same_store(&self, other: &Self) -> bool {
        self.store_epoch == other.store_epoch && self.group_id_hex == other.group_id_hex
    }

    /// Device-local idempotency binding. Never send or log this value.
    #[doc(hidden)]
    pub fn local_submission_binding(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"mdk-local-draft-submission-v1");
        hash.update(&self.store_epoch);
        hash.update(self.group_id_hex.as_bytes());
        hash.update(self.revision.to_be_bytes());
        hash.finalize().into()
    }
}

#[derive(Clone)]
pub struct SelectedMessageDraft {
    pub revision: MessageDraftRevision,
    pub draft: Option<SelectedMessageDraftContent>,
}

#[derive(Clone, PartialEq)]
pub struct SelectedMessageDraftAttachment {
    pub id: String,
    pub file_name: String,
    pub media_type: String,
    pub plaintext_size: u64,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
    pub duration_seconds: Option<f64>,
    pub waveform_samples: Vec<f64>,
    /// The bytes live in a staged media-store file rather than the database:
    /// read them in chunks or through a handoff, never as one buffer.
    pub file_backed: bool,
}

#[derive(Clone, PartialEq)]
pub struct SelectedMessageDraftContent {
    pub group_id_hex: String,
    pub content: String,
    pub reply_to_message_id_hex: Option<String>,
    pub media_attachments: Vec<SelectedMessageDraftAttachment>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum MessageDraftRevisionError {
    #[error("message draft revision no longer matches")]
    Conflict,
    #[error("message draft not found in this conversation")]
    UnknownDraft,
    /// A request the current draft cannot satisfy; retrying it unchanged fails again.
    #[error("invalid message draft: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl SqliteAppStorage {
    /// One read snapshot, keyed by group; never hydrates attachment plaintext.
    pub fn selected_message_draft(&self, group: &str) -> StorageResult<SelectedMessageDraft> {
        self.connection
            .with_deferred_read(|conn| selected_tx(conn, group))
    }

    /// Hash ordered plaintext in the caller's draft-admission snapshot. Ordinary
    /// selected-draft reads remain metadata-only; attachment bytes are borrowed
    /// one row at a time and never copied into a hydrated draft. A file-backed
    /// attachment reports the digest recorded when its file was staged.
    #[doc(hidden)]
    pub fn message_draft_plaintext_hashes(
        &self,
        expected: &MessageDraftRevision,
    ) -> Result<Vec<[u8; 32]>, MessageDraftRevisionError> {
        use sha2::{Digest, Sha256};
        self.connection.with_deferred_read(|conn| {
            check_revision_tx(conn, expected)?;
            let mut statement = conn
                .prepare_cached(
                    "SELECT a.plaintext, m.plaintext_digest
                     FROM message_draft_attachments a LEFT JOIN media_files m ON m.id = a.file_id
                     WHERE a.draft_id = (SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1 AND active = 1) ORDER BY a.position ASC",
                )
                .storage()?;
            let mut rows = statement.query([&expected.group_id_hex]).storage()?;
            let mut hashes = Vec::new();
            while let Some(row) = rows.next().storage()? {
                if let Some(digest) = row.get::<_, Option<Vec<u8>>>(1).storage()? {
                    hashes.push(digest.try_into().map_err(|_| {
                        StorageError::Backend("invalid draft attachment digest".into())
                    })?);
                    continue;
                }
                let plaintext = row.get_ref(0).storage()?;
                let plaintext = plaintext
                    .as_blob()
                    .map_err(rusqlite::Error::from)
                    .storage()?;
                hashes.push(Sha256::digest(plaintext).into());
            }
            Ok(hashes)
        })
    }

    /// Replace the draft if `expected` is still current. Each attachment is
    /// either new inline bytes or a [`StoredMessageDraftAttachmentInput::Retained`]
    /// id of an attachment already in this draft, kept as stored (a
    /// file-backed one keeps its file). An attachment left out is deleted,
    /// and a file it owned is released.
    pub fn save_message_draft_if_revision(
        &self,
        expected: &MessageDraftRevision,
        content: &str,
        reply: Option<&str>,
        attachments: &[StoredMessageDraftAttachmentInput],
    ) -> Result<SelectedMessageDraft, MessageDraftRevisionError> {
        self.write_message_draft_if_revision(expected, content, reply, attachments, false)
    }

    /// [`Self::save_message_draft_if_revision`], except that an attachment
    /// the draft holds and the save does not name stays: a save never drops
    /// one its caller did not know about. Name one
    /// [`StoredMessageDraftAttachmentInput::Removed`] to delete it. The named attachments come first, in
    /// order, then the kept ones in their stored order. Removing an id the
    /// draft does not hold changes nothing.
    pub fn update_message_draft_if_revision(
        &self,
        expected: &MessageDraftRevision,
        content: &str,
        reply: Option<&str>,
        attachments: &[StoredMessageDraftAttachmentInput],
    ) -> Result<SelectedMessageDraft, MessageDraftRevisionError> {
        self.write_message_draft_if_revision(expected, content, reply, attachments, true)
    }

    fn write_message_draft_if_revision(
        &self,
        expected: &MessageDraftRevision,
        content: &str,
        reply: Option<&str>,
        attachments: &[StoredMessageDraftAttachmentInput],
        keep_unnamed: bool,
    ) -> Result<SelectedMessageDraft, MessageDraftRevisionError> {
        let named = attachments
            .iter()
            .map(|attachment| match attachment {
                StoredMessageDraftAttachmentInput::Inline(attachment) => attachment.id.as_str(),
                StoredMessageDraftAttachmentInput::Retained(id)
                | StoredMessageDraftAttachmentInput::Removed(id) => id,
            })
            .collect::<HashSet<_>>();
        let kept = attachments
            .iter()
            .filter_map(DraftAttachmentInput::kept)
            .collect::<Vec<_>>();
        validate_waveform_samples(kept.iter().filter_map(DraftAttachmentInput::inline))?;
        self.connection.with_transaction(|| {
            let stored = {
                let conn = self.lock()?;
                check_revision_tx(&conn, expected)?;
                draft_attachment_ids_tx(&conn, &expected.group_id_hex)?
            };
            if kept.iter().any(|attachment| {
                matches!(attachment, DraftAttachmentInput::Retained(id) if !stored.iter().any(|stored| stored == id))
            }) {
                return Err(MessageDraftRevisionError::Invalid(
                    "a retained attachment is not in the draft",
                ));
            }
            let mut kept = kept.clone();
            if keep_unnamed {
                kept.extend(
                    stored
                        .iter()
                        .filter(|id| !named.contains(id.as_str()))
                        .map(|id| DraftAttachmentInput::Retained(id)),
                );
            }
            self.write_message_draft(&expected.group_id_hex, content, reply, &kept)?;
            Ok(self.selected_message_draft(&expected.group_id_hex)?)
        })
    }

    pub fn clear_message_draft_if_revision(
        &self,
        expected: &MessageDraftRevision,
    ) -> Result<SelectedMessageDraft, MessageDraftRevisionError> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            check_revision_tx(&conn, expected)?;
            end_composition_tx(&conn, &expected.group_id_hex)?;
            Ok(selected_tx(&conn, &expected.group_id_hex)?)
        })
    }

    /// Hydrate only the requested attachment, guarded by the selected revision.
    /// A file-backed attachment is refused: read it in chunks instead.
    pub fn message_draft_attachment_if_revision(
        &self,
        expected: &MessageDraftRevision,
        attachment_id: &str,
    ) -> Result<Option<Vec<u8>>, MessageDraftRevisionError> {
        self.connection.with_deferred_read(|conn| {
            check_revision_tx(conn, expected)?;
            let row: Option<(Vec<u8>, bool)> = conn
                .query_row_cached(
                    "SELECT plaintext, file_id IS NOT NULL FROM message_draft_attachments
                WHERE draft_id = (SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1 AND active = 1)
                    AND attachment_id = ?2",
                    params![expected.group_id_hex, attachment_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .storage()?;
            match row {
                Some((_, true)) => Err(MessageDraftRevisionError::Invalid(
                    "file-backed draft attachments are read in chunks",
                )),
                row => Ok(row.map(|(bytes, _)| bytes)),
            }
        })
    }

    /// Bind one submitted revision to the exact outgoing event. This is not
    /// acceptance and retains draft bytes. Only the existing outbox write can
    /// consume this binding, in the same transaction as accepting its payload.
    #[doc(hidden)]
    pub fn stage_message_draft_submission(
        &self,
        expected: &MessageDraftRevision,
        app_event_id: &str,
        payload: &[u8],
    ) -> Result<(), MessageDraftRevisionError> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(payload);
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            check_revision_tx(&conn, expected)?;
            let staged = conn
                .execute_cached(
                    "INSERT INTO message_draft_submissions
                    (group_id_hex, revision, app_event_id, payload_hash, draft_id, content_revision)
                 SELECT group_id_hex, ?2, ?3, ?4, draft_id, content_revision
                 FROM message_drafts WHERE group_id_hex = ?1 AND active = 1
                 ON CONFLICT(group_id_hex, revision) DO UPDATE SET
                    app_event_id = excluded.app_event_id, payload_hash = excluded.payload_hash,
                    draft_id = excluded.draft_id, content_revision = excluded.content_revision",
                    params![
                        expected.group_id_hex,
                        expected.revision,
                        app_event_id,
                        &hash[..]
                    ],
                )
                .storage()?;
            if staged == 0 {
                return Err(MessageDraftRevisionError::Conflict);
            }
            Ok(())
        })
    }
    #[doc(hidden)]
    pub fn cancel_message_draft_submission(
        &self,
        expected: &MessageDraftRevision,
        app_event_id: &str,
    ) -> StorageResult<()> {
        let conn = self.lock()?;
        let epoch: Vec<u8> = conn
            .query_row_cached(
                "SELECT store_epoch FROM chat_presentation_meta WHERE id=1",
                [],
                |r| r.get(0),
            )
            .storage()?;
        if epoch != expected.store_epoch {
            return Ok(());
        }
        conn.execute_cached(
            "DELETE FROM message_draft_submissions
             WHERE group_id_hex = ?1 AND revision = ?2 AND app_event_id = ?3",
            params![expected.group_id_hex, expected.revision, app_event_id],
        )
        .storage()?;
        Ok(())
    }
}

/// Ends the group's composition: deletes its draft, if any, and moves the
/// composition so a file still being staged into it never joins the next
/// one. The trigger on `message_drafts` moves it when a row goes; a
/// composer with no row yet is moved here.
pub(super) fn end_composition_tx(conn: &Connection, group: &str) -> StorageResult<()> {
    let deleted = conn
        .execute_cached(
            "DELETE FROM message_drafts WHERE group_id_hex = ?1 AND active = 1",
            [group],
        )
        .storage()?;
    if deleted == 0 {
        conn.execute_cached(
            "UPDATE message_draft_revision_clock SET revision = revision + 1",
            [],
        )
        .storage()?;
        conn.execute_cached(
            "UPDATE message_draft_revisions
                SET composition = (SELECT revision FROM message_draft_revision_clock)
              WHERE group_id_hex = ?1",
            [group],
        )
        .storage()?;
    }
    Ok(())
}

/// The group's composition: a revision-clock value taken when its row was
/// created and whenever a draft ended ([`end_composition_tx`] or a deleted
/// draft row), so no two compositions, of one group or its recreation, share
/// it.
pub(super) fn composition_tx(conn: &Connection, group: &str) -> StorageResult<i64> {
    conn.query_row_cached(
        "SELECT composition FROM message_draft_revisions WHERE group_id_hex = ?1",
        [group],
        |row| row.get(0),
    )
    .optional()
    .storage()?
    .ok_or(StorageError::NotFound)
}

pub(super) fn revision_tx(conn: &Connection, group: &str) -> StorageResult<MessageDraftRevision> {
    conn.query_row_cached(
        "SELECT m.store_epoch, r.revision FROM message_draft_revisions r
         CROSS JOIN chat_presentation_meta m WHERE r.group_id_hex = ?1 AND m.id = 1",
        [group],
        |row| {
            Ok(MessageDraftRevision {
                store_epoch: row.get(0)?,
                group_id_hex: group.to_owned(),
                revision: row.get(1)?,
            })
        },
    )
    .optional()
    .storage()?
    .ok_or(StorageError::NotFound)
}

/// Read only revision metadata in the row's existing read transaction. Does
/// not hydrate draft text, attachment metadata or attachment plaintext.
pub(crate) fn chat_list_version_tx(
    conn: &Connection,
    group: &str,
    store_epoch: &[u8],
) -> StorageResult<Option<ChatListDraftVersion>> {
    let revision = conn
        .query_row_cached(
            "SELECT revision FROM message_draft_revisions WHERE group_id_hex = ?1",
            [group],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .storage()?;
    Ok(revision.map(|revision| ChatListDraftVersion {
        store_epoch: store_epoch.to_vec(),
        group_id_hex: group.to_owned(),
        revision,
    }))
}

pub(super) fn check_revision_tx(
    conn: &Connection,
    expected: &MessageDraftRevision,
) -> Result<(), MessageDraftRevisionError> {
    if revision_tx(conn, &expected.group_id_hex)? != *expected {
        return Err(MessageDraftRevisionError::Conflict);
    }
    Ok(())
}

pub(crate) fn selected_tx(conn: &Connection, group: &str) -> StorageResult<SelectedMessageDraft> {
    let revision = revision_tx(conn, group)?;
    let mut draft = conn
        .query_row_cached(
            "SELECT content, reply_to_message_id_hex, created_at_ms, updated_at_ms, draft_id
         FROM message_drafts WHERE group_id_hex = ?1 AND active = 1",
            [group],
            |row| {
                Ok((
                    row.get::<_, [u8; 16]>(4)?,
                    SelectedMessageDraftContent {
                        group_id_hex: group.to_owned(),
                        content: row.get(0)?,
                        reply_to_message_id_hex: row.get(1)?,
                        created_at_ms: row.get(2)?,
                        updated_at_ms: row.get(3)?,
                        media_attachments: vec![],
                    },
                ))
            },
        )
        .optional()
        .storage()?;
    if let Some((id, content)) = &mut draft {
        content.media_attachments = selected_attachments_tx(conn, id)?;
    }
    Ok(SelectedMessageDraft {
        revision,
        draft: draft.map(|(_, content)| content),
    })
}

pub(crate) const SELECTED_ATTACHMENTS_SQL: &str = "SELECT attachment_id, file_name, media_type,
        CASE WHEN file_id IS NULL THEN length(plaintext)
            ELSE (SELECT m.byte_len FROM media_files m WHERE m.id = file_id) END,
        dim, thumbhash, duration_seconds, waveform_samples_json, file_id IS NOT NULL
        FROM message_draft_attachments
        WHERE draft_id = ?1 ORDER BY position";

pub(super) fn selected_attachments_tx(
    conn: &Connection,
    draft_id: &[u8; 16],
) -> StorageResult<Vec<SelectedMessageDraftAttachment>> {
    let mut statement = conn.prepare_cached(SELECTED_ATTACHMENTS_SQL).storage()?;
    let rows = statement
        .query_map([draft_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get::<_, Option<i64>>(3)?.unwrap_or_default(),
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get::<_, String>(7)?,
                row.get(8)?,
            ))
        })
        .storage()?;
    rows.map(|row| {
        let (
            id,
            file_name,
            media_type,
            size,
            dim,
            thumbhash,
            duration_seconds,
            waveform,
            file_backed,
        ) = row.storage()?;
        Ok(SelectedMessageDraftAttachment {
            id,
            file_name,
            media_type,
            plaintext_size: u64::try_from(size)
                .map_err(|_| StorageError::Backend("invalid draft attachment length".into()))?,
            dim,
            thumbhash,
            duration_seconds,
            waveform_samples: serde_json::from_str(&waveform)
                .map_err(|_| StorageError::Serialization("invalid draft waveform".into()))?,
            file_backed,
        })
    })
    .collect()
}

pub(crate) enum DraftAcceptance<'a> {
    Payload(&'a [u8]),
    Event(&'a str),
}
/// Called only inside the same transaction that persists the accepted queue or
/// fanout. Failure rolls back both writes; later delivery failures cannot revive
/// a submitted composer. A newer composer is never cleared.
pub(crate) fn accept_submission_tx(
    conn: &Connection,
    group: &str,
    accepted: DraftAcceptance<'_>,
) -> StorageResult<bool> {
    use sha2::{Digest, Sha256};
    let (field, value) = match accepted {
        DraftAcceptance::Payload(payload) => (
            "payload_hash",
            rusqlite::types::Value::Blob(Sha256::digest(payload).to_vec()),
        ),
        DraftAcceptance::Event(id) => ("app_event_id", rusqlite::types::Value::Text(id.to_owned())),
    };
    let changed = conn
        .execute_cached(
            &format!(
                "DELETE FROM message_drafts WHERE group_id_hex = ?1
             AND EXISTS (
                SELECT 1 FROM message_draft_submissions s
                WHERE s.group_id_hex = ?1 AND s.{field} = ?2
                  AND s.draft_id = message_drafts.draft_id
                  AND s.content_revision = message_drafts.content_revision
             )"
            ),
            params![group, value],
        )
        .storage()?
        > 0;
    conn.execute_cached(
        &format!("DELETE FROM message_draft_submissions WHERE group_id_hex = ?1 AND {field} = ?2"),
        params![group, value],
    )
    .storage()?;
    Ok(changed)
}

impl std::fmt::Debug for MessageDraftRevision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageDraftRevision")
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for SelectedMessageDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedMessageDraft")
            .field("revision", &self.revision)
            .field("draft", &self.draft)
            .finish()
    }
}
impl std::fmt::Debug for SelectedMessageDraftContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedMessageDraftContent")
            .field("content_len", &self.content.len())
            .field("attachment_count", &self.media_attachments.len())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for SelectedMessageDraftAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedMessageDraftAttachment")
            .field("plaintext_size", &self.plaintext_size)
            .field("waveform_sample_count", &self.waveform_samples.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
