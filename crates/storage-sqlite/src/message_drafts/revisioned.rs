//! Selected composer metadata and revision-checked mutations.
use super::*;

#[derive(Clone, PartialEq, Eq)]
pub struct MessageDraftRevision {
    store_epoch: Vec<u8>,
    group_id_hex: String,
    revision: i64,
}

impl MessageDraftRevision {
    pub fn group_id_hex(&self) -> &str {
        &self.group_id_hex
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
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl SqliteAccountStorage {
    /// One read snapshot, keyed by group; never hydrates attachment plaintext.
    pub fn selected_message_draft(&self, group: &str) -> StorageResult<SelectedMessageDraft> {
        self.connection
            .with_deferred_read(|conn| selected_tx(conn, group))
    }

    pub fn save_message_draft_if_revision(
        &self,
        expected: &MessageDraftRevision,
        content: &str,
        reply: Option<&str>,
        attachments: &[StoredMessageDraftAttachment],
    ) -> Result<SelectedMessageDraft, MessageDraftRevisionError> {
        validate_waveform_samples(attachments)?;
        self.connection.with_transaction(|| {
            {
                let conn = self.lock()?;
                check_revision_tx(&conn, expected)?;
            }
            self.write_message_draft(&expected.group_id_hex, content, reply, attachments)?;
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
            conn.execute_cached(
                "DELETE FROM message_drafts WHERE group_id_hex = ?1",
                [&expected.group_id_hex],
            )
            .storage()?;
            Ok(selected_tx(&conn, &expected.group_id_hex)?)
        })
    }

    /// Hydrate only the requested attachment, guarded by the selected revision.
    pub fn message_draft_attachment_if_revision(
        &self,
        expected: &MessageDraftRevision,
        attachment_id: &str,
    ) -> Result<Option<Vec<u8>>, MessageDraftRevisionError> {
        self.connection.with_deferred_read(|conn| {
            check_revision_tx(conn, expected)?;
            let bytes = conn
                .query_row_cached(
                    "SELECT plaintext FROM message_draft_attachments
                WHERE group_id_hex = ?1 AND attachment_id = ?2",
                    params![expected.group_id_hex, attachment_id],
                    |row| row.get(0),
                )
                .optional()
                .storage()?;
            Ok(bytes)
        })
    }

    /// Install the app owner's coalesced wakeup. The callback must not panic.
    /// Nested writes defer notification until the outer transaction commits.
    #[doc(hidden)]
    pub fn set_message_draft_commit_observer(&self, observer: MessageDraftCommitObserver) {
        *self
            .draft_commit_observer
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(observer);
    }
    pub(crate) fn notify_message_draft_committed(&self, group: &str) {
        let observer = self
            .draft_commit_observer
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(observer) = observer {
            let group = group.to_owned();
            self.connection.after_commit(move || observer(&group));
        }
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
            let present: bool = conn.query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM message_drafts WHERE group_id_hex = ?1)",
                [&expected.group_id_hex],
                |row| row.get(0),
            ).storage()?;
            if !present {
                return Err(MessageDraftRevisionError::Conflict);
            }
            conn.execute_cached(
                "INSERT INTO message_draft_submissions(group_id_hex, revision, app_event_id, payload_hash)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT(group_id_hex) DO UPDATE SET
                 revision=excluded.revision, app_event_id=excluded.app_event_id, payload_hash=excluded.payload_hash",
                params![expected.group_id_hex, expected.revision, app_event_id, &hash[..]],
            ).storage()?;
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

fn revision_tx(conn: &Connection, group: &str) -> StorageResult<MessageDraftRevision> {
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

fn check_revision_tx(
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
            "SELECT content, reply_to_message_id_hex, created_at_ms, updated_at_ms
         FROM message_drafts WHERE group_id_hex = ?1",
            [group],
            |row| {
                Ok(SelectedMessageDraftContent {
                    group_id_hex: group.to_owned(),
                    content: row.get(0)?,
                    reply_to_message_id_hex: row.get(1)?,
                    created_at_ms: row.get(2)?,
                    updated_at_ms: row.get(3)?,
                    media_attachments: vec![],
                })
            },
        )
        .optional()
        .storage()?;
    if let Some(draft) = &mut draft {
        draft.media_attachments = selected_attachments_tx(conn, group)?;
    }
    Ok(SelectedMessageDraft { revision, draft })
}

pub(crate) const SELECTED_ATTACHMENTS_SQL: &str =
    "SELECT attachment_id, file_name, media_type, length(plaintext),
        dim, thumbhash, duration_seconds, waveform_samples_json FROM message_draft_attachments
        WHERE group_id_hex = ?1 ORDER BY position";

fn selected_attachments_tx(
    conn: &Connection,
    group: &str,
) -> StorageResult<Vec<SelectedMessageDraftAttachment>> {
    let mut statement = conn.prepare_cached(SELECTED_ATTACHMENTS_SQL).storage()?;
    let rows = statement
        .query_map([group], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get::<_, i64>(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .storage()?;
    rows.map(|row| {
        let (id, file_name, media_type, size, dim, thumbhash, duration_seconds, waveform) =
            row.storage()?;
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
        })
    })
    .collect()
}

/// Post-commit wakeup only; consumers reload the durable selected revision.
pub type MessageDraftCommitObserver = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

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
    let revision: Option<i64> = conn
        .query_row_cached(
            &format!(
                "SELECT revision FROM message_draft_submissions
                  WHERE group_id_hex = ?1 AND {field} = ?2"
            ),
            params![group, value],
            |row| row.get(0),
        )
        .optional()
        .storage()?;
    let Some(revision) = revision else {
        return Ok(false);
    };
    let changed = conn.execute_cached(
        "DELETE FROM message_drafts WHERE group_id_hex = ?1
         AND EXISTS(SELECT 1 FROM message_draft_revisions WHERE group_id_hex = ?1 AND revision = ?2)",
        params![group, revision],
    ).storage()? > 0;
    conn.execute_cached(
        "DELETE FROM message_draft_submissions WHERE group_id_hex = ?1 AND revision = ?2",
        params![group, revision],
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
