use crate::{SqliteAccountStorage, SqliteResultExt, unix_now_ms};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, PartialEq)]
pub struct StoredMessageDraft {
    pub group_id_hex: String,
    pub content: String,
    pub reply_to_message_id_hex: Option<String>,
    pub media_attachments: Vec<StoredMessageDraftAttachment>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl SqliteAccountStorage {
    pub fn message_drafts(&self) -> StorageResult<Vec<StoredMessageDraft>> {
        let conn = self.lock()?;
        let group_ids = {
            let mut statement = conn
                .prepare("SELECT group_id_hex FROM message_drafts ORDER BY updated_at_ms DESC")
                .storage()?;
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?
        };

        group_ids
            .into_iter()
            .map(|group_id_hex| {
                load_message_draft(&conn, &group_id_hex)?.ok_or_else(|| {
                    StorageError::Backend("message draft disappeared while loading".to_owned())
                })
            })
            .collect()
    }

    pub fn message_draft(&self, group_id_hex: &str) -> StorageResult<Option<StoredMessageDraft>> {
        let conn = self.lock()?;
        load_message_draft(&conn, group_id_hex)
    }

    pub fn save_message_draft(
        &self,
        group_id_hex: &str,
        content: &str,
        reply_to_message_id_hex: Option<&str>,
        media_attachments: &[StoredMessageDraftAttachment],
    ) -> StorageResult<StoredMessageDraft> {
        let now_ms = unix_now_ms();
        {
            let mut conn = self.lock()?;
            let tx = conn.transaction().storage()?;
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
            tx.execute(
                "DELETE FROM message_draft_attachments WHERE group_id_hex = ?1",
                params![group_id_hex],
            )
            .storage()?;
            {
                let mut statement = tx
                    .prepare(
                        "INSERT INTO message_draft_attachments (
                            group_id_hex, position, attachment_id, file_name, media_type,
                            plaintext, dim, thumbhash, duration_seconds, waveform_samples_json
                         )
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    )
                    .storage()?;
                for (position, attachment) in media_attachments.iter().enumerate() {
                    let position = i64::try_from(position).map_err(|_| {
                        StorageError::Backend("too many message draft attachments".to_owned())
                    })?;
                    let waveform_samples = serde_json::to_string(&attachment.waveform_samples)
                        .map_err(|error| {
                            StorageError::Backend(format!(
                                "could not encode draft waveform samples: {error}"
                            ))
                        })?;
                    statement
                        .execute(params![
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
                        ])
                        .storage()?;
                }
            }
            tx.commit().storage()?;
        }

        self.message_draft(group_id_hex)?.ok_or_else(|| {
            StorageError::Backend("saved message draft could not be reloaded".to_owned())
        })
    }

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
    let mut media_attachments = Vec::new();
    for row in rows {
        let (id, file_name, media_type, plaintext, dim, thumbhash, duration_seconds, samples) =
            row.storage()?;
        let waveform_samples = serde_json::from_str(&samples).map_err(|error| {
            StorageError::Backend(format!("invalid draft waveform samples: {error}"))
        })?;
        media_attachments.push(StoredMessageDraftAttachment {
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
        assert_eq!(saved.media_attachments, vec![attachment]);
        assert_eq!(storage.message_drafts().unwrap(), vec![saved.clone()]);

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
            )
            .unwrap();
        assert!(storage.message_draft(&group_id_hex).unwrap().is_none());
    }
}
