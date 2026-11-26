use super::revisioned::{check_revision_tx, revision_tx, selected_attachments_tx, selected_tx};
use super::*;
use cgka_traits::storage::StorageResult;

/// Opaque local draft identifier. Every lookup also requires the owning account and group.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MessageDraftId([u8; 16]);

impl MessageDraftId {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for MessageDraftId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageDraftId")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredMessageDraftState {
    Active,
    Saved,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredIdentifiedMessageDraft {
    pub id: MessageDraftId,
    pub state: StoredMessageDraftState,
    /// Version of the hydrated content and attachments, unchanged by selection.
    pub content_revision: i64,
    pub content: SelectedMessageDraftContent,
}

/// Bounded metadata for rendering one row of a conversation's draft list.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredIdentifiedMessageDraftSummary {
    pub id: MessageDraftId,
    pub state: StoredMessageDraftState,
    pub summary: StoredMessageDraftSummary,
}

const PREVIEW_CHARS: usize = 1024;
const MAX_SAVED_DRAFTS: i64 = 16;
const MAX_DRAFT_ATTACHMENTS: i64 = 64;
const MAX_GROUP_ATTACHMENTS: i64 = 256;
const MAX_DRAFT_BYTES: i64 = 900 * 1024 * 1024;
const MAX_GROUP_BYTES: i64 = 2 * 1024 * 1024 * 1024;

pub(super) struct DraftQuotaUsage {
    group_count: i64,
    active_count: i64,
    group_bytes: i64,
    active_bytes: i64,
}

impl DraftQuotaUsage {
    pub(super) fn read(conn: &Connection, group: &str) -> StorageResult<Self> {
        conn.query_row_cached(
            "SELECT coalesce(sum(attachments), 0),
                    coalesce(sum(attachments) FILTER (WHERE active = 1), 0),
                    coalesce(sum(bytes), 0),
                    coalesce(sum(bytes) FILTER (WHERE active = 1), 0)
             FROM (
                 SELECT d.active, count(a.draft_id) AS attachments,
                        d.content_bytes +
                        coalesce(sum(CASE WHEN a.file_id IS NULL THEN length(a.plaintext)
                                          ELSE m.byte_len END), 0) AS bytes
                 FROM message_drafts d
                 LEFT JOIN message_draft_attachments a ON a.draft_id = d.draft_id
                 LEFT JOIN media_files m ON m.id = a.file_id
                 WHERE d.group_id_hex = ?1
                 GROUP BY d.draft_id
             )",
            [group],
            |row| {
                Ok(Self {
                    group_count: row.get(0)?,
                    active_count: row.get(1)?,
                    group_bytes: row.get(2)?,
                    active_bytes: row.get(3)?,
                })
            },
        )
        .storage()
    }

    /// Keep migrated overages editable. Each limit can rise only up to its cap.
    pub(super) fn check_growth_from(&self, before: &Self) -> StorageResult<()> {
        if self.group_count > MAX_GROUP_ATTACHMENTS.max(before.group_count)
            || self.active_count > MAX_DRAFT_ATTACHMENTS.max(before.active_count)
            || self.group_bytes > MAX_GROUP_BYTES.max(before.group_bytes)
            || self.active_bytes > MAX_DRAFT_BYTES.max(before.active_bytes)
        {
            return Err(StorageError::MessageDraftQuotaExceeded);
        }
        Ok(())
    }
}

pub(super) fn check_attachment_limits(
    conn: &Connection,
    group: &str,
    added_attachments: i64,
    added_bytes: i64,
) -> StorageResult<()> {
    let before = DraftQuotaUsage::read(conn, group)?;
    DraftQuotaUsage {
        group_count: before.group_count.saturating_add(added_attachments),
        active_count: before.active_count.saturating_add(added_attachments),
        group_bytes: before.group_bytes.saturating_add(added_bytes),
        active_bytes: before.active_bytes.saturating_add(added_bytes),
    }
    .check_growth_from(&before)
}

fn read_state(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessageDraftState> {
    Ok(if row.get(1)? {
        StoredMessageDraftState::Active
    } else {
        StoredMessageDraftState::Saved
    })
}

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredIdentifiedMessageDraft> {
    Ok(StoredIdentifiedMessageDraft {
        id: MessageDraftId(row.get(0)?),
        state: read_state(row)?,
        content_revision: row.get(7)?,
        content: SelectedMessageDraftContent {
            group_id_hex: row.get(2)?,
            content: row.get(3)?,
            reply_to_message_id_hex: row.get(4)?,
            created_at_ms: row.get(5)?,
            updated_at_ms: row.get(6)?,
            media_attachments: Vec::new(),
        },
    })
}

impl SqliteAppStorage {
    /// A single group's active and saved drafts. Attachment bytes never enter this result.
    pub fn group_message_drafts(
        &self,
        group: &str,
    ) -> StorageResult<Vec<StoredIdentifiedMessageDraftSummary>> {
        self.connection.with_deferred_read(|conn| {
            revision_tx(conn, group)?;
            let mut statement = conn
                .prepare_cached(
                    "SELECT draft_id, active, content_preview,
                            reply_to_message_id_hex, created_at_ms, updated_at_ms
                     FROM message_drafts
                     WHERE group_id_hex = ?1 ORDER BY updated_at_ms DESC, draft_id",
                )
                .storage()?;
            let rows = statement
                .query_map([group], |row| {
                    let prefix: Vec<u8> = row.get(2)?;
                    Ok(StoredIdentifiedMessageDraftSummary {
                        id: MessageDraftId(row.get(0)?),
                        state: read_state(row)?,
                        summary: StoredMessageDraftSummary {
                            group_id_hex: group.to_owned(),
                            // A 4-byte-per-character prefix guarantees that a split
                            // UTF-8 scalar falls beyond the rendered character bound.
                            content: String::from_utf8_lossy(&prefix)
                                .chars()
                                .take(PREVIEW_CHARS)
                                .collect(),
                            reply_to_message_id_hex: row.get(3)?,
                            created_at_ms: row.get(4)?,
                            updated_at_ms: row.get(5)?,
                            media_attachments: Vec::new(),
                        },
                    })
                })
                .storage()?;
            rows.map(|row| {
                let mut draft = row.storage()?;
                draft.summary.media_attachments =
                    load_message_draft_attachment_summaries(conn, draft.id.as_bytes())?;
                Ok(draft)
            })
            .collect()
        })
    }

    /// Restore one identified draft's content and descriptors without changing selection.
    pub fn identified_message_draft(
        &self,
        group: &str,
        id: MessageDraftId,
    ) -> Result<StoredIdentifiedMessageDraft, MessageDraftRevisionError> {
        self.connection.with_deferred_read(|conn| {
            revision_tx(conn, group)?;
            let mut draft = conn
                .query_row_cached(
                    "SELECT draft_id, active, group_id_hex, coalesce(content, ''), reply_to_message_id_hex,
                            created_at_ms, updated_at_ms, content_revision
                     FROM message_drafts LEFT JOIN message_draft_bodies USING (draft_rowid)
                     WHERE group_id_hex = ?1 AND draft_id = ?2",
                    params![group, id.as_bytes()],
                    read_row,
                )
                .optional()
                .storage()?
                .ok_or(MessageDraftRevisionError::UnknownDraft)?;
            draft.content.media_attachments = selected_attachments_tx(conn, id.as_bytes())?;
            Ok(draft)
        })
    }

    /// Read one attachment from the version returned by the identified draft read.
    pub fn read_identified_message_draft_attachment(
        &self,
        group: &str,
        id: MessageDraftId,
        content_revision: i64,
        attachment_id: &str,
        offset: u64,
        limit: usize,
    ) -> Result<Option<MessageDraftAttachmentRead>, MessageDraftRevisionError> {
        self.connection.with_deferred_read(|conn| {
            revision_tx(conn, group)?;
            let current: i64 = conn.query_row_cached(
                "SELECT content_revision FROM message_drafts WHERE group_id_hex = ?1 AND draft_id = ?2",
                params![group, id.as_bytes()],
                |row| row.get(0),
            ).optional().storage()?.ok_or(MessageDraftRevisionError::UnknownDraft)?;
            if current != content_revision {
                return Err(MessageDraftRevisionError::Conflict);
            }
            files::read_draft_attachment_tx(conn, id.as_bytes(), attachment_id, offset, limit)
        })
    }

    /// Park the exact active revision, leaving its attachments under the same owner.
    pub fn archive_message_draft(
        &self,
        expected: &MessageDraftRevision,
    ) -> Result<MessageDraftId, MessageDraftRevisionError> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            check_revision_tx(&conn, expected)?;
            let group = expected.group_id_hex();
            let saved: i64 = conn
                .query_row_cached(
                    "SELECT count(*) FROM message_drafts WHERE group_id_hex = ?1 AND active = 0",
                    [group],
                    |row| row.get(0),
                )
                .storage()?;
            if saved >= MAX_SAVED_DRAFTS {
                return Err(StorageError::MessageDraftQuotaExceeded.into());
            }
            conn.query_row_cached(
                "UPDATE message_drafts SET active = 0 WHERE group_id_hex = ?1 AND active = 1
                 RETURNING draft_id",
                [group],
                |row| row.get(0).map(MessageDraftId),
            )
            .optional()
            .storage()?
            .ok_or(MessageDraftRevisionError::Invalid(
                "no active draft to save",
            ))
        })
    }

    /// Park the current revision and select the requested draft in one write.
    pub fn activate_message_draft(
        &self,
        expected: &MessageDraftRevision,
        id: MessageDraftId,
    ) -> Result<SelectedMessageDraft, MessageDraftRevisionError> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let group = expected.group_id_hex();
            check_revision_tx(&conn, expected)?;
            let active: bool = conn
                .query_row_cached(
                    "SELECT active FROM message_drafts WHERE group_id_hex = ?1 AND draft_id = ?2",
                    params![group, id.as_bytes()],
                    |row| row.get(0),
                )
                .optional()
                .storage()?
                .ok_or(MessageDraftRevisionError::UnknownDraft)?;
            if !active {
                // Keep the API atomic even when called inside and caught by an outer writer.
                let mut conn = conn;
                let tx = conn.savepoint().storage()?;
                tx.execute_cached(
                    "UPDATE message_drafts SET active = 0 WHERE group_id_hex = ?1 AND active = 1",
                    [group],
                )
                .storage()?;
                tx.execute_cached(
                    "UPDATE message_drafts SET active = 1 WHERE draft_id = ?1",
                    [id.as_bytes()],
                )
                .storage()?;
                let selected = selected_tx(&tx, group)?;
                tx.commit().storage()?;
                return Ok(selected);
            }
            Ok(selected_tx(&conn, group)?)
        })
    }

    /// Delete one saved draft. A draft selected since the caller listed it is protected.
    pub fn delete_saved_message_draft(
        &self,
        group: &str,
        id: MessageDraftId,
    ) -> Result<(), MessageDraftRevisionError> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            revision_tx(&conn, group)?;
            let deleted = conn
                .execute_cached(
                    "DELETE FROM message_drafts WHERE group_id_hex = ?1 AND draft_id = ?2 AND active = 0",
                    params![group, id.as_bytes()],
                )
                .storage()?;
            if deleted == 0 {
                return Err(MessageDraftRevisionError::UnknownDraft);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    fn seed(store: &SqliteAccountStorage) {
        store
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at)
                 VALUES ('chat','',0), ('other','',0);",
            )
            .unwrap();
    }

    #[test]
    fn saved_message_drafts_preserve_siblings_and_reject_stale_claims() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store);
        let drafts = store.app_storage();
        let attachment = StoredMessageDraftAttachment {
            id: "attach".into(),
            file_name: "note.txt".into(),
            media_type: "text/plain".into(),
            plaintext: b"local only".to_vec(),
            dim: None,
            thumbhash: None,
            duration_seconds: None,
            waveform_samples: vec![],
        };
        let reply = "ab".repeat(32);
        let old = drafts
            .save_message_draft("chat", "long", Some(&reply), &[attachment])
            .unwrap();
        let old_selected = drafts.selected_message_draft("chat").unwrap();

        let saved = drafts
            .archive_message_draft(&old_selected.revision)
            .unwrap();
        assert!(drafts.message_drafts().unwrap().is_empty());
        assert!(drafts.message_draft("chat").unwrap().is_none());
        assert!(matches!(
            drafts.clear_message_draft_if_revision(&old_selected.revision),
            Err(MessageDraftRevisionError::Conflict)
        ));
        let retained = drafts.identified_message_draft("chat", saved).unwrap();
        assert!(matches!(
            drafts.identified_message_draft("missing", saved),
            Err(MessageDraftRevisionError::Storage(StorageError::NotFound))
        ));
        assert_eq!(retained.state, StoredMessageDraftState::Saved);
        assert_eq!(retained.content.content, old.content);
        assert_eq!(retained.content.reply_to_message_id_hex, Some(reply));
        assert_eq!(retained.content.created_at_ms, old.created_at_ms);
        assert_eq!(retained.content.updated_at_ms, old.updated_at_ms);
        assert_eq!(retained.content.media_attachments[0].plaintext_size, 10);
        assert!(matches!(
            drafts.read_identified_message_draft_attachment("chat", saved, retained.content_revision, "attach", 6, 4).unwrap(),
            Some(MessageDraftAttachmentRead::Bytes(bytes)) if bytes == b"only"
        ));

        drafts
            .save_message_draft("chat", "interruption", None, &[])
            .unwrap();
        let before = drafts.selected_message_draft("chat").unwrap();
        let other = drafts.selected_message_draft("other").unwrap();
        assert!(matches!(
            drafts.activate_message_draft(&other.revision, saved),
            Err(MessageDraftRevisionError::UnknownDraft)
        ));
        store
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER fail_activate BEFORE UPDATE OF active ON message_drafts
             WHEN NEW.active = 1 BEGIN SELECT RAISE(ABORT,'injected'); END;",
            )
            .unwrap();
        assert!(
            drafts
                .activate_message_draft(&before.revision, saved)
                .is_err()
        );
        let after = drafts.selected_message_draft("chat").unwrap();
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.draft, before.draft);
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_activate;")
            .unwrap();

        let restored = drafts
            .activate_message_draft(&before.revision, saved)
            .unwrap();
        assert_eq!(restored.draft.unwrap().content, "long");
        assert_ne!(restored.revision, before.revision);
        assert_eq!(
            drafts
                .activate_message_draft(&restored.revision, saved)
                .unwrap()
                .revision,
            restored.revision
        );
        assert_eq!(drafts.message_drafts().unwrap().len(), 1);
        let group = drafts.group_message_drafts("chat").unwrap();
        assert_eq!(group.len(), 2);
        let parked = group.into_iter().find(|draft| draft.id != saved).unwrap();
        assert_eq!(parked.state, StoredMessageDraftState::Saved);
        assert_eq!(parked.summary.content, "interruption");
        assert!(matches!(
            drafts.delete_saved_message_draft("chat", saved),
            Err(MessageDraftRevisionError::UnknownDraft)
        ));
        drafts
            .delete_saved_message_draft("chat", parked.id)
            .unwrap();
        assert_eq!(
            drafts.selected_message_draft("chat").unwrap().revision,
            restored.revision
        );

        drafts.archive_message_draft(&restored.revision).unwrap();
        drafts.delete_message_draft("chat").unwrap();
        assert_eq!(drafts.group_message_drafts("chat").unwrap().len(), 1);
    }

    #[test]
    fn saved_attachment_ranges_refuse_replaced_bytes_after_activation() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store);
        let drafts = store.app_storage();
        let mut attachment = StoredMessageDraftAttachment {
            id: "same-id".into(),
            file_name: "note.txt".into(),
            media_type: "text/plain".into(),
            plaintext: b"AABB".to_vec(),
            dim: None,
            thumbhash: None,
            duration_seconds: None,
            waveform_samples: vec![],
        };
        drafts
            .save_message_draft("chat", "text", None, &[attachment.clone()])
            .unwrap();
        let selected = drafts.selected_message_draft("chat").unwrap();
        let id = drafts.archive_message_draft(&selected.revision).unwrap();
        let version = drafts
            .identified_message_draft("chat", id)
            .unwrap()
            .content_revision;
        let read = |revision, offset| {
            drafts.read_identified_message_draft_attachment(
                "chat", id, revision, "same-id", offset, 2,
            )
        };
        assert!(
            matches!(read(version, 0).unwrap(), Some(MessageDraftAttachmentRead::Bytes(bytes)) if bytes == b"AA")
        );

        let empty = drafts.selected_message_draft("chat").unwrap();
        drafts.activate_message_draft(&empty.revision, id).unwrap();
        assert!(
            matches!(read(version, 2).unwrap(), Some(MessageDraftAttachmentRead::Bytes(bytes)) if bytes == b"BB")
        );
        attachment.plaintext = b"CCDD".to_vec();
        drafts
            .save_message_draft("chat", "text", None, &[attachment])
            .unwrap();
        assert!(matches!(
            read(version, 2),
            Err(MessageDraftRevisionError::Conflict)
        ));
        let new_version = drafts
            .identified_message_draft("chat", id)
            .unwrap()
            .content_revision;
        assert!(
            matches!(read(new_version, 2).unwrap(), Some(MessageDraftAttachmentRead::Bytes(bytes)) if bytes == b"DD")
        );
    }

    #[test]
    fn legacy_draft_overage_can_be_kept_but_not_increased() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store);
        let drafts = store.app_storage();
        // Seed the post-upgrade state of a draft that predates attachment quotas.
        store
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO message_drafts(group_id_hex, created_at_ms, updated_at_ms)
                VALUES ('chat',1,1);
             INSERT INTO message_draft_bodies SELECT draft_rowid, 'old' FROM message_drafts;
             WITH RECURSIVE slots(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM slots WHERE n < 256)
             INSERT INTO message_draft_attachments
                (draft_id, position, attachment_id, file_name, media_type, plaintext)
             SELECT draft_id, n, CAST(n AS TEXT), 'legacy.txt', 'text/plain', x'01'
             FROM message_drafts, slots;",
            )
            .unwrap();

        let old = drafts.selected_message_draft("chat").unwrap();
        let edited = drafts
            .update_message_draft_if_revision(&old.revision, "edit", None, &[])
            .unwrap();
        assert_eq!(edited.draft.as_ref().unwrap().media_attachments.len(), 257);
        let saved = drafts.archive_message_draft(&edited.revision).unwrap();
        drafts
            .save_message_draft("chat", "separate reply", None, &[])
            .unwrap();
        let reply = drafts.selected_message_draft("chat").unwrap();
        let restored = drafts
            .activate_message_draft(&reply.revision, saved)
            .unwrap();
        let edited = drafts
            .update_message_draft_if_revision(&restored.revision, "edit again", None, &[])
            .unwrap();
        assert_eq!(edited.draft.as_ref().unwrap().media_attachments.len(), 257);

        let new = StoredMessageDraftAttachmentInput::Inline(StoredMessageDraftAttachment {
            id: "new".into(),
            file_name: "note.txt".into(),
            media_type: "text/plain".into(),
            plaintext: vec![1],
            dim: None,
            thumbhash: None,
            duration_seconds: None,
            waveform_samples: vec![],
        });
        assert!(matches!(
            drafts.update_message_draft_if_revision(&edited.revision, "edit again", None, &[new]),
            Err(MessageDraftRevisionError::Storage(
                StorageError::MessageDraftQuotaExceeded
            ))
        ));
        assert_eq!(
            drafts.selected_message_draft("chat").unwrap().revision,
            edited.revision
        );
    }

    #[test]
    fn saved_message_drafts_refuse_quota_without_evicting_or_switching() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store);
        let drafts = store.app_storage();
        for n in 0..MAX_SAVED_DRAFTS {
            drafts
                .save_message_draft("chat", &format!("draft {n}"), None, &[])
                .unwrap();
            let selected = drafts.selected_message_draft("chat").unwrap();
            drafts.archive_message_draft(&selected.revision).unwrap();
        }
        drafts
            .save_message_draft("chat", "needs room", None, &[])
            .unwrap();
        let selected = drafts.selected_message_draft("chat").unwrap();
        assert!(matches!(
            drafts.archive_message_draft(&selected.revision),
            Err(MessageDraftRevisionError::Storage(
                StorageError::MessageDraftQuotaExceeded
            ))
        ));
        let after = drafts.selected_message_draft("chat").unwrap();
        assert_eq!(after.revision, selected.revision);
        assert_eq!(after.draft, selected.draft);
        assert!(matches!(
            check_attachment_limits(&store.lock().unwrap(), "chat", 0, MAX_DRAFT_BYTES),
            Err(StorageError::MessageDraftQuotaExceeded)
        ));
        let attachments: Vec<_> = (0..=MAX_DRAFT_ATTACHMENTS)
            .map(|n| {
                StoredMessageDraftAttachmentInput::Inline(StoredMessageDraftAttachment {
                    id: n.to_string(),
                    file_name: "note.txt".into(),
                    media_type: "text/plain".into(),
                    plaintext: vec![1],
                    dim: None,
                    thumbhash: None,
                    duration_seconds: None,
                    waveform_samples: vec![],
                })
            })
            .collect();
        assert!(matches!(
            drafts.save_message_draft_if_revision(&after.revision, "too many", None, &attachments),
            Err(MessageDraftRevisionError::Storage(
                StorageError::MessageDraftQuotaExceeded
            ))
        ));
        let after_refusal = drafts.selected_message_draft("chat").unwrap();
        assert_eq!(after_refusal.revision, after.revision);
        assert_eq!(after_refusal.draft, after.draft);

        let long_text = "🦀".repeat(PREVIEW_CHARS + 1);
        drafts
            .save_message_draft("chat", &long_text, None, &[])
            .unwrap();
        let selected = drafts.selected_message_draft("chat").unwrap();
        let all = drafts.group_message_drafts("chat").unwrap();
        assert_eq!(all.len(), MAX_SAVED_DRAFTS as usize + 1);
        let active = all
            .iter()
            .find(|draft| draft.state == StoredMessageDraftState::Active)
            .unwrap();
        assert_eq!(active.summary.content, "🦀".repeat(PREVIEW_CHARS));
        assert_eq!(
            drafts
                .identified_message_draft("chat", active.id)
                .unwrap()
                .content
                .content,
            long_text
        );
        let parked = all
            .into_iter()
            .find(|draft| draft.state == StoredMessageDraftState::Saved)
            .unwrap();
        drafts
            .activate_message_draft(&selected.revision, parked.id)
            .unwrap();
        assert_eq!(
            drafts.group_message_drafts("chat").unwrap().len(),
            MAX_SAVED_DRAFTS as usize + 1
        );
    }
}
