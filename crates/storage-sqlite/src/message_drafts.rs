use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::{SqliteAccountStorage, SqliteResultExt, connection::retry_on_busy, unix_now_ms};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

/// Fully hydrated attachment row from the encrypted account database.
#[derive(Clone, PartialEq)]
pub struct StoredMessageDraftAttachment {
    pub id: String,
    pub file_name: String,
    pub media_type: String,
    pub plaintext: Vec<u8>,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
    pub duration_seconds: Option<f64>,
    pub waveform_samples: Vec<f64>,
}

impl fmt::Debug for StoredMessageDraftAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredMessageDraftAttachment")
            .field("plaintext_len", &self.plaintext.len())
            .field("waveform_sample_count", &self.waveform_samples.len())
            .finish()
    }
}

/// Fully hydrated composer draft row and its ordered attachments.
#[derive(Clone, PartialEq)]
pub struct StoredMessageDraft {
    pub group_id_hex: String,
    pub content: String,
    pub reply_to_message_id_hex: Option<String>,
    pub media_attachments: Vec<StoredMessageDraftAttachment>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl fmt::Debug for StoredMessageDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attachment_bytes = self
            .media_attachments
            .iter()
            .map(|attachment| attachment.plaintext.len())
            .sum::<usize>();
        formatter
            .debug_struct("StoredMessageDraft")
            .field("content_len", &self.content.len())
            .field("attachment_count", &self.media_attachments.len())
            .field("attachment_bytes", &attachment_bytes)
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .finish()
    }
}

/// Attachment preview metadata that deliberately omits the plaintext BLOB.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredMessageDraftAttachmentSummary {
    pub id: String,
    pub file_name: String,
    pub media_type: String,
    pub plaintext_size: u64,
}

impl fmt::Debug for StoredMessageDraftAttachmentSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredMessageDraftAttachmentSummary")
            .field("plaintext_size", &self.plaintext_size)
            .finish()
    }
}

/// Metadata-only draft-list row used to avoid materializing every attachment.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredMessageDraftSummary {
    pub group_id_hex: String,
    pub content: String,
    pub reply_to_message_id_hex: Option<String>,
    pub media_attachments: Vec<StoredMessageDraftAttachmentSummary>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl fmt::Debug for StoredMessageDraftSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attachment_bytes = self
            .media_attachments
            .iter()
            .map(|attachment| attachment.plaintext_size)
            .sum::<u64>();
        formatter
            .debug_struct("StoredMessageDraftSummary")
            .field("content_len", &self.content.len())
            .field("attachment_count", &self.media_attachments.len())
            .field("attachment_bytes", &attachment_bytes)
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .finish()
    }
}

impl SqliteAccountStorage {
    /// List draft preview metadata newest-first without loading attachment BLOBs.
    pub fn message_drafts(&self) -> StorageResult<Vec<StoredMessageDraftSummary>> {
        let conn = self.lock()?;
        let mut drafts = {
            let mut statement = conn
                .prepare(
                    "SELECT group_id_hex, content, reply_to_message_id_hex,
                            created_at_ms, updated_at_ms
                     FROM message_drafts
                     ORDER BY updated_at_ms DESC",
                )
                .storage()?;
            statement
                .query_map([], |row| {
                    Ok(StoredMessageDraftSummary {
                        group_id_hex: row.get(0)?,
                        content: row.get(1)?,
                        reply_to_message_id_hex: row.get(2)?,
                        media_attachments: Vec::new(),
                        created_at_ms: row.get(3)?,
                        updated_at_ms: row.get(4)?,
                    })
                })
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?
        };

        for draft in &mut drafts {
            draft.media_attachments =
                load_message_draft_attachment_summaries(&conn, &draft.group_id_hex)?;
        }
        Ok(drafts)
    }

    /// Load one fully hydrated draft for a group.
    pub fn message_draft(&self, group_id_hex: &str) -> StorageResult<Option<StoredMessageDraft>> {
        let conn = self.lock()?;
        load_message_draft(&conn, group_id_hex)
    }

    /// Transactionally validate the group and upsert a draft plus its ordered
    /// attachments, preserving unchanged attachment rows.
    pub fn save_message_draft(
        &self,
        group_id_hex: &str,
        content: &str,
        reply_to_message_id_hex: Option<&str>,
        media_attachments: &[StoredMessageDraftAttachment],
    ) -> StorageResult<StoredMessageDraft> {
        validate_waveform_samples(media_attachments)?;
        let now_ms = unix_now_ms();
        retry_on_busy(|| {
            let mut conn = self.lock()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            let group_exists = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM account_groups WHERE group_id_hex = ?1)",
                    params![group_id_hex],
                    |row| row.get::<_, bool>(0),
                )
                .storage()?;
            if !group_exists {
                return Err(StorageError::NotFound);
            }
            tx.execute(
                "INSERT INTO message_drafts (
                    group_id_hex, content, reply_to_message_id_hex, created_at_ms, updated_at_ms
                 )
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(group_id_hex) DO UPDATE SET
                    content = excluded.content,
                    reply_to_message_id_hex = excluded.reply_to_message_id_hex,
                    updated_at_ms = excluded.updated_at_ms",
                params![group_id_hex, content, reply_to_message_id_hex, now_ms],
            )
            .storage()?;
            sync_message_draft_attachments(&tx, group_id_hex, media_attachments)?;
            let saved = load_message_draft(&tx, group_id_hex)?.ok_or_else(|| {
                StorageError::Backend("saved message draft could not be reloaded".to_owned())
            })?;
            tx.commit().storage()?;
            Ok(saved)
        })
    }

    /// Delete one draft and its cascading attachment rows.
    pub fn delete_message_draft(&self, group_id_hex: &str) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM message_drafts WHERE group_id_hex = ?1",
                params![group_id_hex],
            )
            .storage()?;
        Ok(())
    }
}

fn validate_waveform_samples(attachments: &[StoredMessageDraftAttachment]) -> StorageResult<()> {
    if attachments
        .iter()
        .flat_map(|attachment| &attachment.waveform_samples)
        .any(|sample| !sample.is_finite())
    {
        return Err(StorageError::Serialization(
            "message draft waveform samples must be finite".to_owned(),
        ));
    }
    Ok(())
}

fn load_message_draft_attachment_summaries(
    conn: &Connection,
    group_id_hex: &str,
) -> StorageResult<Vec<StoredMessageDraftAttachmentSummary>> {
    let mut statement = conn
        .prepare(
            "SELECT attachment_id, file_name, media_type, length(plaintext)
             FROM message_draft_attachments
             WHERE group_id_hex = ?1
             ORDER BY position ASC",
        )
        .storage()?;
    let rows = statement
        .query_map(params![group_id_hex], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .storage()?;
    let mut attachments = Vec::new();
    for row in rows {
        let (id, file_name, media_type, plaintext_size) = row.storage()?;
        let plaintext_size = u64::try_from(plaintext_size).map_err(|_| {
            StorageError::Backend("invalid message draft attachment byte length".to_owned())
        })?;
        attachments.push(StoredMessageDraftAttachmentSummary {
            id,
            file_name,
            media_type,
            plaintext_size,
        });
    }
    Ok(attachments)
}

fn sync_message_draft_attachments(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    incoming: &[StoredMessageDraftAttachment],
) -> StorageResult<()> {
    let existing = load_message_draft_attachments(tx, group_id_hex)?;
    if existing == incoming {
        return Ok(());
    }

    let same_id_order = existing.len() == incoming.len()
        && existing
            .iter()
            .zip(incoming)
            .all(|(stored, replacement)| stored.id == replacement.id);
    if same_id_order {
        for (stored, replacement) in existing.iter().zip(incoming) {
            if stored != replacement {
                update_message_draft_attachment(tx, group_id_hex, None, replacement)?;
            }
        }
        return Ok(());
    }

    let existing_by_id = existing
        .iter()
        .map(|attachment| (attachment.id.as_str(), attachment))
        .collect::<HashMap<_, _>>();
    let incoming_ids = incoming
        .iter()
        .map(|attachment| attachment.id.as_str())
        .collect::<HashSet<_>>();
    let position_offset = existing
        .len()
        .checked_add(incoming.len())
        .and_then(|length| length.checked_add(1))
        .and_then(|length| i64::try_from(length).ok())
        .ok_or_else(|| StorageError::Backend("too many message draft attachments".to_owned()))?;

    if !existing.is_empty() {
        tx.execute(
            "UPDATE message_draft_attachments
             SET position = position + ?2
             WHERE group_id_hex = ?1",
            params![group_id_hex, position_offset],
        )
        .storage()?;
    }

    for (position, attachment) in incoming.iter().enumerate() {
        let position = i64::try_from(position)
            .map_err(|_| StorageError::Backend("too many message draft attachments".to_owned()))?;
        match existing_by_id.get(attachment.id.as_str()) {
            Some(stored) if *stored == attachment => {
                tx.execute(
                    "UPDATE message_draft_attachments
                     SET position = ?3
                     WHERE group_id_hex = ?1 AND attachment_id = ?2",
                    params![group_id_hex, attachment.id, position],
                )
                .storage()?;
            }
            Some(_) => {
                update_message_draft_attachment(tx, group_id_hex, Some(position), attachment)?;
            }
            None => {
                insert_message_draft_attachment(tx, group_id_hex, position, attachment)?;
            }
        }
    }

    for attachment in &existing {
        if !incoming_ids.contains(attachment.id.as_str()) {
            tx.execute(
                "DELETE FROM message_draft_attachments
                 WHERE group_id_hex = ?1 AND attachment_id = ?2",
                params![group_id_hex, attachment.id],
            )
            .storage()?;
        }
    }
    Ok(())
}

fn insert_message_draft_attachment(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    position: i64,
    attachment: &StoredMessageDraftAttachment,
) -> StorageResult<()> {
    let waveform_samples = encoded_waveform_samples(attachment)?;
    tx.execute(
        "INSERT INTO message_draft_attachments (
            group_id_hex, position, attachment_id, file_name, media_type,
            plaintext, dim, thumbhash, duration_seconds, waveform_samples_json
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            group_id_hex,
            position,
            attachment.id,
            attachment.file_name,
            attachment.media_type,
            attachment.plaintext,
            attachment.dim,
            attachment.thumbhash,
            attachment.duration_seconds,
            waveform_samples,
        ],
    )
    .storage()?;
    Ok(())
}

fn update_message_draft_attachment(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    position: Option<i64>,
    attachment: &StoredMessageDraftAttachment,
) -> StorageResult<()> {
    let waveform_samples = encoded_waveform_samples(attachment)?;
    if let Some(position) = position {
        tx.execute(
            "UPDATE message_draft_attachments
             SET position = ?3, file_name = ?4, media_type = ?5, plaintext = ?6,
                 dim = ?7, thumbhash = ?8, duration_seconds = ?9,
                 waveform_samples_json = ?10
             WHERE group_id_hex = ?1 AND attachment_id = ?2",
            params![
                group_id_hex,
                attachment.id,
                position,
                attachment.file_name,
                attachment.media_type,
                attachment.plaintext,
                attachment.dim,
                attachment.thumbhash,
                attachment.duration_seconds,
                waveform_samples,
            ],
        )
        .storage()?;
    } else {
        tx.execute(
            "UPDATE message_draft_attachments
             SET file_name = ?3, media_type = ?4, plaintext = ?5, dim = ?6,
                 thumbhash = ?7, duration_seconds = ?8, waveform_samples_json = ?9
             WHERE group_id_hex = ?1 AND attachment_id = ?2",
            params![
                group_id_hex,
                attachment.id,
                attachment.file_name,
                attachment.media_type,
                attachment.plaintext,
                attachment.dim,
                attachment.thumbhash,
                attachment.duration_seconds,
                waveform_samples,
            ],
        )
        .storage()?;
    }
    Ok(())
}

fn encoded_waveform_samples(attachment: &StoredMessageDraftAttachment) -> StorageResult<String> {
    serde_json::to_string(&attachment.waveform_samples).map_err(|_| {
        StorageError::Serialization("invalid message draft waveform samples".to_owned())
    })
}

fn load_message_draft_attachments(
    conn: &Connection,
    group_id_hex: &str,
) -> StorageResult<Vec<StoredMessageDraftAttachment>> {
    let mut statement = conn
        .prepare(
            "SELECT attachment_id, file_name, media_type, plaintext, dim, thumbhash,
                    duration_seconds, waveform_samples_json
             FROM message_draft_attachments
             WHERE group_id_hex = ?1
             ORDER BY position ASC",
        )
        .storage()?;
    let rows = statement
        .query_map(params![group_id_hex], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<f64>>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .storage()?;
    let mut attachments = Vec::new();
    for row in rows {
        let (id, file_name, media_type, plaintext, dim, thumbhash, duration_seconds, samples) =
            row.storage()?;
        let waveform_samples = serde_json::from_str(&samples).map_err(|_| {
            StorageError::Serialization("invalid message draft waveform samples".to_owned())
        })?;
        attachments.push(StoredMessageDraftAttachment {
            id,
            file_name,
            media_type,
            plaintext,
            dim,
            thumbhash,
            duration_seconds,
            waveform_samples,
        });
    }
    Ok(attachments)
}

fn load_message_draft(
    conn: &Connection,
    group_id_hex: &str,
) -> StorageResult<Option<StoredMessageDraft>> {
    let draft = conn
        .query_row(
            "SELECT content, reply_to_message_id_hex, created_at_ms, updated_at_ms
                 FROM message_drafts
                 WHERE group_id_hex = ?1",
            params![group_id_hex],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .storage()?;
    let Some((content, reply_to_message_id_hex, created_at_ms, updated_at_ms)) = draft else {
        return Ok(None);
    };

    let media_attachments = load_message_draft_attachments(conn, group_id_hex)?;

    Ok(Some(StoredMessageDraft {
        group_id_hex: group_id_hex.to_owned(),
        content,
        reply_to_message_id_hex,
        media_attachments,
        created_at_ms,
        updated_at_ms,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SelfMembership, StoredAccountGroup, StoredAccountState};

    const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;

    fn group(group_id_hex: &str) -> StoredAccountGroup {
        StoredAccountGroup {
            group_id_hex: group_id_hex.to_owned(),
            endpoint: "marmot:group:test".to_owned(),
            profile_name: "Test".to_owned(),
            profile_description: String::new(),
            image_hash_hex: String::new(),
            image_key_hex: String::new(),
            image_nonce_hex: String::new(),
            image_upload_key_hex: String::new(),
            image_media_type: None,
            admin_keys_hex: String::new(),
            archived: false,
            pending_confirmation: false,
            welcomer_account_id_hex: None,
            via_welcome_message_id_hex: None,
            self_membership: SelfMembership::Member,
            components: vec![],
        }
    }

    fn attachment_rowid(
        storage: &SqliteAccountStorage,
        group_id_hex: &str,
        attachment_id: &str,
    ) -> i64 {
        storage
            .lock()
            .unwrap()
            .query_row(
                "SELECT rowid FROM message_draft_attachments
                 WHERE group_id_hex = ?1 AND attachment_id = ?2",
                params![group_id_hex, attachment_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn message_draft_round_trips_and_deletes_with_group() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let group_id_hex = "11".repeat(16);
        storage
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".to_owned(),
                    seen_events: vec![],
                    last_transport_timestamp: None,
                    groups: vec![group(&group_id_hex)],
                },
                100,
                MAX_FUTURE_SKEW_SECS,
            )
            .unwrap();

        let attachment = StoredMessageDraftAttachment {
            id: "attachment-1".to_owned(),
            file_name: "voice.m4a".to_owned(),
            media_type: "audio/mp4".to_owned(),
            plaintext: vec![1, 2, 3],
            dim: None,
            thumbhash: None,
            duration_seconds: Some(1.5),
            waveform_samples: vec![0.25, 0.75],
        };
        let saved = storage
            .save_message_draft(
                &group_id_hex,
                "hello",
                Some(&"aa".repeat(32)),
                std::slice::from_ref(&attachment),
            )
            .unwrap();
        assert_eq!(saved.content, "hello");
        assert_eq!(saved.media_attachments, vec![attachment.clone()]);
        assert_eq!(
            storage.message_drafts().unwrap(),
            vec![StoredMessageDraftSummary {
                group_id_hex: group_id_hex.clone(),
                content: "hello".to_owned(),
                reply_to_message_id_hex: Some("aa".repeat(32)),
                media_attachments: vec![StoredMessageDraftAttachmentSummary {
                    id: attachment.id.clone(),
                    file_name: attachment.file_name.clone(),
                    media_type: attachment.media_type.clone(),
                    plaintext_size: 3,
                }],
                created_at_ms: saved.created_at_ms,
                updated_at_ms: saved.updated_at_ms,
            }]
        );

        let initial_attachment_rowid = attachment_rowid(&storage, &group_id_hex, &attachment.id);
        let text_only_update = storage
            .save_message_draft(
                &group_id_hex,
                "updated text",
                None,
                std::slice::from_ref(&attachment),
            )
            .unwrap();
        assert_eq!(text_only_update.created_at_ms, saved.created_at_ms);
        assert_eq!(text_only_update.media_attachments, vec![attachment.clone()]);
        assert_eq!(
            attachment_rowid(&storage, &group_id_hex, &attachment.id),
            initial_attachment_rowid,
            "text-only saves must not rewrite attachment blobs"
        );

        let updated = storage
            .save_message_draft(&group_id_hex, "updated", None, &[])
            .unwrap();
        assert_eq!(updated.created_at_ms, saved.created_at_ms);
        assert_eq!(updated.content, "updated");
        assert!(updated.media_attachments.is_empty());

        storage.delete_message_draft(&group_id_hex).unwrap();
        assert!(storage.message_draft(&group_id_hex).unwrap().is_none());

        storage
            .save_message_draft(&group_id_hex, "cascade", None, &[])
            .unwrap();
        storage
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".to_owned(),
                    seen_events: vec![],
                    last_transport_timestamp: None,
                    groups: vec![],
                },
                100,
                MAX_FUTURE_SKEW_SECS,
            )
            .unwrap();
        assert!(storage.message_draft(&group_id_hex).unwrap().is_none());
    }

    #[test]
    fn message_draft_attachment_reorder_preserves_existing_rows() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let group_id_hex = "22".repeat(16);
        storage
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".to_owned(),
                    seen_events: vec![],
                    last_transport_timestamp: None,
                    groups: vec![group(&group_id_hex)],
                },
                100,
                MAX_FUTURE_SKEW_SECS,
            )
            .unwrap();
        let first = StoredMessageDraftAttachment {
            id: "first".to_owned(),
            file_name: "first.txt".to_owned(),
            media_type: "text/plain".to_owned(),
            plaintext: vec![1],
            dim: None,
            thumbhash: None,
            duration_seconds: None,
            waveform_samples: vec![],
        };
        let second = StoredMessageDraftAttachment {
            id: "second".to_owned(),
            file_name: "second.txt".to_owned(),
            media_type: "text/plain".to_owned(),
            plaintext: vec![2],
            dim: None,
            thumbhash: None,
            duration_seconds: None,
            waveform_samples: vec![],
        };
        storage
            .save_message_draft(
                &group_id_hex,
                "draft",
                None,
                &[first.clone(), second.clone()],
            )
            .unwrap();
        let first_rowid = attachment_rowid(&storage, &group_id_hex, &first.id);
        let second_rowid = attachment_rowid(&storage, &group_id_hex, &second.id);

        storage
            .save_message_draft(
                &group_id_hex,
                "draft",
                None,
                &[second.clone(), first.clone()],
            )
            .unwrap();

        assert_eq!(
            attachment_rowid(&storage, &group_id_hex, &first.id),
            first_rowid
        );
        assert_eq!(
            attachment_rowid(&storage, &group_id_hex, &second.id),
            second_rowid
        );
        assert_eq!(
            storage
                .message_draft(&group_id_hex)
                .unwrap()
                .unwrap()
                .media_attachments,
            vec![second, first]
        );
    }

    #[test]
    fn saving_draft_for_unknown_group_is_typed_not_found() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        assert!(matches!(
            storage.save_message_draft(&"33".repeat(16), "draft", None, &[]),
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn saving_draft_retries_concurrent_writer_contention() {
        use crate::{SqlCipherKey, SqliteStorageOptions};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("draft-contention.sqlite");
        let key = SqlCipherKey::new("draft contention key").unwrap();
        let options = SqliteStorageOptions {
            busy_timeout_ms: 50,
            ..SqliteStorageOptions::default()
        };
        let storage =
            SqliteAccountStorage::open_encrypted_with_options(&path, &key, options.clone())
                .unwrap();
        let group_id_hex = "55".repeat(16);
        storage
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".to_owned(),
                    seen_events: vec![],
                    last_transport_timestamp: None,
                    groups: vec![group(&group_id_hex)],
                },
                100,
                MAX_FUTURE_SKEW_SECS,
            )
            .unwrap();

        let blocker_path = path.clone();
        let blocker_key = SqlCipherKey::new("draft contention key").unwrap();
        let (lock_acquired_tx, lock_acquired_rx) = std::sync::mpsc::channel();
        let blocker = std::thread::spawn(move || {
            let blocker = SqliteAccountStorage::open_encrypted_with_options(
                &blocker_path,
                &blocker_key,
                options,
            )
            .unwrap();
            let conn = blocker.lock().unwrap();
            conn.execute_batch("BEGIN IMMEDIATE").unwrap();
            lock_acquired_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
            conn.execute_batch("COMMIT").unwrap();
        });
        lock_acquired_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        let saved = storage
            .save_message_draft(&group_id_hex, "survives contention", None, &[])
            .expect("draft save retries after transient contention");
        blocker.join().unwrap();
        assert_eq!(saved.content, "survives contention");
    }

    #[test]
    fn saving_draft_rejects_non_finite_waveform_samples_before_writing() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let group_id_hex = "44".repeat(16);
        storage
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".to_owned(),
                    seen_events: vec![],
                    last_transport_timestamp: None,
                    groups: vec![group(&group_id_hex)],
                },
                100,
                MAX_FUTURE_SKEW_SECS,
            )
            .unwrap();
        let attachment = StoredMessageDraftAttachment {
            id: "voice".to_owned(),
            file_name: "voice.m4a".to_owned(),
            media_type: "audio/mp4".to_owned(),
            plaintext: vec![1, 2, 3],
            dim: None,
            thumbhash: None,
            duration_seconds: Some(1.0),
            waveform_samples: vec![0.25, f64::NAN],
        };

        let error = storage
            .save_message_draft(&group_id_hex, "draft", None, &[attachment])
            .unwrap_err();

        assert!(matches!(error, StorageError::Serialization(_)));
        assert!(storage.message_draft(&group_id_hex).unwrap().is_none());
    }
}
