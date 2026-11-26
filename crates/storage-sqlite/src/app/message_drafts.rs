pub(crate) mod files;
pub(crate) mod revisioned;
mod saved;
pub use files::{
    MessageDraftAttachmentFileMeta, MessageDraftAttachmentRead, MessageDraftAttachmentStage,
    MessageDraftStageRefusal, MessageDraftUploadBody, MessageDraftUploadSource,
};
pub use revisioned::{
    ChatListDraftVersion, MessageDraftRevision, MessageDraftRevisionError, SelectedMessageDraft,
    SelectedMessageDraftAttachment, SelectedMessageDraftContent,
};
pub use saved::{
    MessageDraftId, StoredIdentifiedMessageDraft, StoredIdentifiedMessageDraftSummary,
    StoredMessageDraftState,
};

#[cfg(test)]
use crate::SqliteAccountStorage;
use crate::base::connection::CachedSql;
use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::{SqliteAppStorage, SqliteResultExt, unix_now_ms};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};

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

/// One attachment of a draft being saved: new inline bytes, the id of an
/// attachment already in the draft, kept as stored without its bytes, or the
/// id of one to remove.
#[derive(Clone, PartialEq)]
pub enum StoredMessageDraftAttachmentInput {
    Inline(StoredMessageDraftAttachment),
    Retained(String),
    Removed(String),
}

impl fmt::Debug for StoredMessageDraftAttachmentInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline(attachment) => formatter.debug_tuple("Inline").field(attachment).finish(),
            Self::Retained(_) => formatter.debug_tuple("Retained").finish_non_exhaustive(),
            Self::Removed(_) => formatter.debug_tuple("Removed").finish_non_exhaustive(),
        }
    }
}

/// A borrowed attachment the draft holds after a save, so inline bytes are
/// never copied on their way into the database.
#[derive(Clone, Copy)]
pub(crate) enum DraftAttachmentInput<'a> {
    Inline(&'a StoredMessageDraftAttachment),
    Retained(&'a str),
}

impl<'a> DraftAttachmentInput<'a> {
    /// What `input` leaves in the draft: nothing for a removal.
    pub(crate) fn kept(input: &'a StoredMessageDraftAttachmentInput) -> Option<Self> {
        match input {
            StoredMessageDraftAttachmentInput::Inline(attachment) => Some(Self::Inline(attachment)),
            StoredMessageDraftAttachmentInput::Retained(id) => Some(Self::Retained(id)),
            StoredMessageDraftAttachmentInput::Removed(_) => None,
        }
    }

    fn id(&self) -> &'a str {
        match self {
            Self::Inline(attachment) => &attachment.id,
            Self::Retained(id) => id,
        }
    }

    pub(crate) fn inline(&self) -> Option<&'a StoredMessageDraftAttachment> {
        match self {
            Self::Inline(attachment) => Some(attachment),
            Self::Retained(_) => None,
        }
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

impl SqliteAppStorage {
    /// List draft preview metadata newest-first without loading attachment BLOBs.
    pub fn message_drafts(&self) -> StorageResult<Vec<StoredMessageDraftSummary>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let mut drafts = {
            let mut statement = tx
                .prepare_cached(
                    "SELECT group_id_hex, coalesce(content, ''), reply_to_message_id_hex,
                            created_at_ms, updated_at_ms, draft_id
                     FROM message_drafts LEFT JOIN message_draft_bodies USING (draft_rowid)
                     WHERE active = 1
                     ORDER BY updated_at_ms DESC, draft_id",
                )
                .storage()?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, [u8; 16]>(5)?,
                        StoredMessageDraftSummary {
                            group_id_hex: row.get(0)?,
                            content: row.get(1)?,
                            reply_to_message_id_hex: row.get(2)?,
                            media_attachments: Vec::new(),
                            created_at_ms: row.get(3)?,
                            updated_at_ms: row.get(4)?,
                        },
                    ))
                })
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?
        };

        for (id, draft) in &mut drafts {
            draft.media_attachments = load_message_draft_attachment_summaries(&tx, id)?;
        }
        tx.commit().storage()?;
        Ok(drafts.into_iter().map(|(_, draft)| draft).collect())
    }

    /// Load one fully hydrated draft for a group. A draft holding a
    /// file-backed attachment is refused: its bytes are never hydrated.
    pub fn message_draft(
        &self,
        group_id_hex: &str,
    ) -> Result<Option<StoredMessageDraft>, MessageDraftRevisionError> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let file_backed: bool = tx
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM message_draft_attachments
                 WHERE draft_id = (SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1 AND active = 1)
                   AND file_id IS NOT NULL)",
                params![group_id_hex],
                |row| row.get(0),
            )
            .storage()?;
        if file_backed {
            return Err(MessageDraftRevisionError::Invalid(
                "the draft holds a file-backed attachment",
            ));
        }
        let draft = load_message_draft(&tx, group_id_hex)?;
        tx.commit().storage()?;
        Ok(draft)
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
        let media_attachments = media_attachments
            .iter()
            .map(DraftAttachmentInput::Inline)
            .collect::<Vec<_>>();
        self.connection.with_transaction(|| {
            self.write_message_draft(
                group_id_hex,
                content,
                reply_to_message_id_hex,
                &media_attachments,
            )?;
            let conn = self.lock()?;
            load_message_draft(&conn, group_id_hex)?.ok_or_else(|| {
                StorageError::Backend("saved message draft could not be reloaded".to_owned())
            })
        })
    }

    /// Write only: revisioned callers need descriptor metadata, not a second
    /// hydrated copy of every attachment that the host just supplied. Callers
    /// validate waveform samples before entering their outer transaction.
    fn write_message_draft(
        &self,
        group_id_hex: &str,
        content: &str,
        reply_to_message_id_hex: Option<&str>,
        media_attachments: &[DraftAttachmentInput<'_>],
    ) -> StorageResult<()> {
        let now_ms = unix_now_ms();
        self.connection.with_transaction(|| {
            let mut conn = self.lock()?;
            let tx = conn.savepoint().storage()?;
            let group_exists = tx
                .query_row_cached(
                    "SELECT EXISTS(SELECT 1 FROM account_groups WHERE group_id_hex = ?1)",
                    params![group_id_hex],
                    |row| row.get::<_, bool>(0),
                )
                .storage()?;
            if !group_exists {
                return Err(StorageError::NotFound);
            }
            let before = saved::DraftQuotaUsage::read(&tx, group_id_hex)?;
            let (draft_id, rowid): ([u8; 16], i64) = tx
                .query_row_cached(
                    "INSERT INTO message_drafts (
                    group_id_hex, reply_to_message_id_hex, created_at_ms, updated_at_ms
                 )
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(group_id_hex) WHERE active = 1 DO UPDATE SET
                    reply_to_message_id_hex = excluded.reply_to_message_id_hex,
                    updated_at_ms = excluded.updated_at_ms
                 RETURNING draft_id, draft_rowid",
                    params![group_id_hex, reply_to_message_id_hex, now_ms],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .storage()?;
            tx.execute_cached(
                "INSERT INTO message_draft_bodies (draft_rowid, content) VALUES (?1, ?2)
                 ON CONFLICT(draft_rowid) DO UPDATE SET content = excluded.content",
                params![rowid, content],
            )
            .map_err(|error| {
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::TooBig) {
                    StorageError::MessageDraftQuotaExceeded
                } else {
                    crate::base::codec::map_sqlite_error(error)
                }
            })?;
            sync_message_draft_attachments(&tx, &draft_id, media_attachments)?;
            saved::DraftQuotaUsage::read(&tx, group_id_hex)?.check_growth_from(&before)?;
            tx.commit().storage()?;
            Ok(())
        })
    }

    /// Delete one draft and its cascading attachment rows.
    pub fn delete_message_draft(&self, group_id_hex: &str) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            revisioned::end_composition_tx(&conn, group_id_hex)
        })
    }

    /// Clear all composer drafts when a group disbands.
    pub fn delete_group_message_drafts(&self, group_id_hex: &str) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let mut conn = self.lock()?;
            let tx = conn.savepoint().storage()?;
            revisioned::end_composition_tx(&tx, group_id_hex)?;
            tx.execute_cached(
                "DELETE FROM message_drafts WHERE group_id_hex = ?1 AND active = 0",
                [group_id_hex],
            )
            .storage()?;
            tx.commit().storage()
        })
    }
}

fn validate_waveform_samples<'a>(
    attachments: impl IntoIterator<Item = &'a StoredMessageDraftAttachment>,
) -> StorageResult<()> {
    if attachments
        .into_iter()
        .flat_map(|attachment| &attachment.waveform_samples)
        .any(|sample| !sample.is_finite())
    {
        return Err(StorageError::Serialization(
            "message draft waveform samples must be finite".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) const ATTACHMENT_SUMMARIES_SQL: &str = "SELECT attachment_id, file_name, media_type,
             CASE WHEN file_id IS NULL THEN length(plaintext)
                 ELSE (SELECT m.byte_len FROM media_files m WHERE m.id = file_id) END
             FROM message_draft_attachments
             WHERE draft_id = ?1
             ORDER BY position ASC";

fn load_message_draft_attachment_summaries(
    conn: &Connection,
    draft_id: &[u8; 16],
) -> StorageResult<Vec<StoredMessageDraftAttachmentSummary>> {
    let mut statement = conn.prepare_cached(ATTACHMENT_SUMMARIES_SQL).storage()?;
    let rows = statement
        .query_map(params![draft_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<i64>>(3)?.unwrap_or_default(),
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

/// The ids of a draft's attachments in their stored order.
pub(crate) fn draft_attachment_ids_tx(
    conn: &Connection,
    group_id_hex: &str,
) -> StorageResult<Vec<String>> {
    let mut statement = conn
        .prepare_cached(
            "SELECT attachment_id FROM message_draft_attachments
             WHERE draft_id = (SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1 AND active = 1)
             ORDER BY position",
        )
        .storage()?;
    let ids = statement
        .query_map(params![group_id_hex], |row| row.get(0))
        .storage()?
        .collect::<Result<_, _>>()
        .storage()?;
    Ok(ids)
}

/// A stored attachment row. A file-backed one holds no inline bytes.
struct ExistingAttachment {
    attachment: StoredMessageDraftAttachment,
    file_backed: bool,
}

impl ExistingAttachment {
    /// Whether `input` leaves this row exactly as it is.
    fn kept_by(&self, input: &DraftAttachmentInput<'_>) -> bool {
        match input {
            DraftAttachmentInput::Retained(id) => self.attachment.id == *id,
            DraftAttachmentInput::Inline(attachment) => {
                !self.file_backed && self.attachment == **attachment
            }
        }
    }
}

fn sync_message_draft_attachments(
    tx: &Connection,
    draft_id: &[u8; 16],
    incoming: &[DraftAttachmentInput<'_>],
) -> StorageResult<()> {
    let existing = load_existing_attachments(tx, draft_id)?;
    if existing.len() == incoming.len()
        && existing
            .iter()
            .zip(incoming)
            .all(|(stored, replacement)| stored.kept_by(replacement))
    {
        return Ok(());
    }

    let same_id_order = existing.len() == incoming.len()
        && existing
            .iter()
            .zip(incoming)
            .all(|(stored, replacement)| stored.attachment.id == replacement.id());
    if same_id_order {
        for (stored, replacement) in existing.iter().zip(incoming) {
            if let Some(replacement) = replacement.inline()
                && !stored.kept_by(&DraftAttachmentInput::Inline(replacement))
            {
                update_message_draft_attachment(tx, draft_id, None, replacement)?;
            }
        }
        return Ok(());
    }

    let existing_by_id = existing
        .iter()
        .map(|stored| (stored.attachment.id.as_str(), stored))
        .collect::<HashMap<_, _>>();
    let incoming_ids = incoming
        .iter()
        .map(DraftAttachmentInput::id)
        .collect::<HashSet<_>>();
    let position_offset = existing
        .len()
        .checked_add(incoming.len())
        .and_then(|length| length.checked_add(1))
        .and_then(|length| i64::try_from(length).ok())
        .ok_or_else(|| StorageError::Backend("too many message draft attachments".to_owned()))?;

    if !existing.is_empty() {
        tx.execute_cached(
            "UPDATE message_draft_attachments
             SET position = position + ?2
             WHERE draft_id = ?1",
            params![draft_id, position_offset],
        )
        .storage()?;
    }

    for (position, attachment) in incoming.iter().enumerate() {
        let position = i64::try_from(position)
            .map_err(|_| StorageError::Backend("too many message draft attachments".to_owned()))?;
        match (existing_by_id.get(attachment.id()), attachment.inline()) {
            (Some(stored), _) if stored.kept_by(attachment) => {
                tx.execute_cached(
                    "UPDATE message_draft_attachments
                     SET position = ?3
                     WHERE draft_id = ?1 AND attachment_id = ?2",
                    params![draft_id, attachment.id(), position],
                )
                .storage()?;
            }
            (Some(_), Some(replacement)) => {
                update_message_draft_attachment(tx, draft_id, Some(position), replacement)?;
            }
            (None, Some(new)) => {
                insert_message_draft_attachment(tx, draft_id, position, new)?;
            }
            // Callers check retained ids against the draft first.
            (_, None) => {
                return Err(StorageError::Backend(
                    "retained message draft attachment is missing".to_owned(),
                ));
            }
        }
    }

    for stored in &existing {
        if !incoming_ids.contains(stored.attachment.id.as_str()) {
            tx.execute_cached(
                "DELETE FROM message_draft_attachments
                 WHERE draft_id = ?1 AND attachment_id = ?2",
                params![draft_id, stored.attachment.id],
            )
            .storage()?;
        }
    }
    Ok(())
}

fn insert_message_draft_attachment(
    tx: &Connection,
    draft_id: &[u8; 16],
    position: i64,
    attachment: &StoredMessageDraftAttachment,
) -> StorageResult<()> {
    let waveform_samples = encoded_waveform_samples(attachment)?;
    tx.execute_cached(
        "INSERT INTO message_draft_attachments (
            draft_id, position, attachment_id, file_name, media_type,
            plaintext, dim, thumbhash, duration_seconds, waveform_samples_json
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            draft_id,
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
    tx: &Connection,
    draft_id: &[u8; 16],
    position: Option<i64>,
    attachment: &StoredMessageDraftAttachment,
) -> StorageResult<()> {
    let waveform_samples = encoded_waveform_samples(attachment)?;
    if let Some(position) = position {
        tx.execute_cached(
            "UPDATE message_draft_attachments
             SET position = ?3, file_name = ?4, media_type = ?5, plaintext = ?6,
                 dim = ?7, thumbhash = ?8, duration_seconds = ?9,
                 waveform_samples_json = ?10, file_id = NULL
             WHERE draft_id = ?1 AND attachment_id = ?2",
            params![
                draft_id,
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
        tx.execute_cached(
            "UPDATE message_draft_attachments
             SET file_name = ?3, media_type = ?4, plaintext = ?5, dim = ?6,
                 thumbhash = ?7, duration_seconds = ?8, waveform_samples_json = ?9,
                 file_id = NULL
             WHERE draft_id = ?1 AND attachment_id = ?2",
            params![
                draft_id,
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
    draft_id: &[u8; 16],
) -> StorageResult<Vec<StoredMessageDraftAttachment>> {
    Ok(load_existing_attachments(conn, draft_id)?
        .into_iter()
        .map(|stored| stored.attachment)
        .collect())
}

fn load_existing_attachments(
    conn: &Connection,
    draft_id: &[u8; 16],
) -> StorageResult<Vec<ExistingAttachment>> {
    let mut statement = conn
        .prepare_cached(
            "SELECT attachment_id, file_name, media_type, plaintext, dim, thumbhash,
                    duration_seconds, waveform_samples_json, file_id IS NOT NULL
             FROM message_draft_attachments
             WHERE draft_id = ?1
             ORDER BY position ASC",
        )
        .storage()?;
    let rows = statement
        .query_map(params![draft_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<f64>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, bool>(8)?,
            ))
        })
        .storage()?;
    let mut attachments = Vec::new();
    for row in rows {
        let (
            id,
            file_name,
            media_type,
            plaintext,
            dim,
            thumbhash,
            duration_seconds,
            samples,
            file_backed,
        ) = row.storage()?;
        let waveform_samples = serde_json::from_str(&samples).map_err(|_| {
            StorageError::Serialization("invalid message draft waveform samples".to_owned())
        })?;
        attachments.push(ExistingAttachment {
            attachment: StoredMessageDraftAttachment {
                id,
                file_name,
                media_type,
                plaintext,
                dim,
                thumbhash,
                duration_seconds,
                waveform_samples,
            },
            file_backed,
        });
    }
    Ok(attachments)
}

fn load_message_draft(
    conn: &Connection,
    group_id_hex: &str,
) -> StorageResult<Option<StoredMessageDraft>> {
    let draft = conn
        .query_row_cached(
            "SELECT coalesce(content, ''), reply_to_message_id_hex, created_at_ms, updated_at_ms, draft_id
                 FROM message_drafts LEFT JOIN message_draft_bodies USING (draft_rowid)
                 WHERE group_id_hex = ?1 AND active = 1",
            params![group_id_hex],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, [u8; 16]>(4)?,
                ))
            },
        )
        .optional()
        .storage()?;
    let Some((content, reply_to_message_id_hex, created_at_ms, updated_at_ms, draft_id)) = draft
    else {
        return Ok(None);
    };

    let media_attachments = load_message_draft_attachments(conn, &draft_id)?;

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
            member_count: None,
            direct_member_ids_hex: None,
            presentation_member_ids_hex: None,
            welcomer_account_id_hex: None,
            via_welcome_message_id_hex: None,
            nostr_routing_last_epoch: 0,
            prior_nostr_routes: Vec::new(),
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
                 WHERE draft_id = (SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1 AND active = 1)
                   AND attachment_id = ?2",
                params![group_id_hex, attachment_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn message_draft_round_trips_and_survives_projection_pruning() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let group_id_hex = "11".repeat(16);
        app.save_account_projection_state(
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
        let saved = app
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
            app.message_drafts().unwrap(),
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
        let text_only_update = app
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

        let updated = app
            .save_message_draft(&group_id_hex, "updated", None, &[])
            .unwrap();
        assert_eq!(updated.created_at_ms, saved.created_at_ms);
        assert_eq!(updated.content, "updated");
        assert!(updated.media_attachments.is_empty());

        app.delete_message_draft(&group_id_hex).unwrap();
        assert!(app.message_draft(&group_id_hex).unwrap().is_none());

        app.save_message_draft(
            &group_id_hex,
            "protected",
            None,
            std::slice::from_ref(&attachment),
        )
        .unwrap();
        app.save_account_projection_state(
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
        let protected = app.message_draft(&group_id_hex).unwrap().unwrap();
        assert_eq!(protected.content, "protected");
        assert_eq!(protected.media_attachments, vec![attachment]);
        assert_eq!(
            app.load_account_projection_state("alice", 100)
                .unwrap()
                .groups
                .len(),
            1,
            "the draft-owning projection row must remain for the foreign key"
        );

        let selected = app.selected_message_draft(&group_id_hex).unwrap();
        let saved_id = app.archive_message_draft(&selected.revision).unwrap();
        let empty_projection = StoredAccountState {
            label: "alice".to_owned(),
            seen_events: vec![],
            last_transport_timestamp: None,
            groups: vec![],
        };
        app.save_account_projection_state(&empty_projection, 100, MAX_FUTURE_SKEW_SECS)
            .unwrap();
        assert_eq!(
            app.identified_message_draft(&group_id_hex, saved_id)
                .unwrap()
                .content
                .content,
            "protected"
        );
        app.delete_saved_message_draft(&group_id_hex, saved_id)
            .unwrap();
        app.save_account_projection_state(
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
        assert!(
            app.load_account_projection_state("alice", 100)
                .unwrap()
                .groups
                .is_empty(),
            "the formerly protected row must become stale after draft deletion"
        );
    }

    thread_local! {
        static AFTER_DRAFT_ROWS_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Runs `read` on `reader`; once its `message_drafts` statement finishes and
    /// before it reads attachments, `write` commits on another connection.
    fn read_with_concurrent_writer<T>(
        reader: &SqliteAccountStorage,
        write: impl FnOnce() + 'static,
        read: impl FnOnce() -> T,
    ) -> T {
        use rusqlite::trace::{TraceEvent, TraceEventCodes};
        AFTER_DRAFT_ROWS_READ.set(Some(Box::new(write)));
        reader.lock().unwrap().trace_v2(
            TraceEventCodes::SQLITE_TRACE_PROFILE,
            Some(|event| {
                if let TraceEvent::Profile(statement, _) = event
                    && statement.sql().contains("FROM message_drafts")
                    && let Some(write) = AFTER_DRAFT_ROWS_READ.take()
                {
                    write();
                }
            }),
        );
        let value = read();
        reader
            .lock()
            .unwrap()
            .trace_v2(TraceEventCodes::empty(), None);
        assert!(
            AFTER_DRAFT_ROWS_READ.with_borrow(Option::is_none),
            "the concurrent writer never ran"
        );
        value
    }

    #[test]
    fn message_draft_reads_take_rows_and_attachments_from_one_snapshot() {
        use crate::SqlCipherKey;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("drafts.sqlite");
        let key = SqlCipherKey::raw([0x5d; 32]);
        let reader = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let writer = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let app = reader.app_storage();
        let group_id_hex = "66".repeat(16);
        app.save_account_projection_state(
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
        let recording = |file_name: &str, plaintext: Vec<u8>| StoredMessageDraftAttachment {
            id: "voice".to_owned(),
            file_name: file_name.to_owned(),
            media_type: "audio/mp4".to_owned(),
            plaintext,
            dim: None,
            thumbhash: None,
            duration_seconds: Some(1.0),
            waveform_samples: vec![0.5],
        };
        let rerecord = |attachment: StoredMessageDraftAttachment| {
            let writer = writer.app_storage();
            let group_id_hex = group_id_hex.clone();
            move || {
                writer
                    .save_message_draft(&group_id_hex, "draft", None, &[attachment])
                    .unwrap();
            }
        };

        let saved = app
            .save_message_draft(
                &group_id_hex,
                "draft",
                None,
                &[recording("first.m4a", vec![1])],
            )
            .unwrap();
        let second = recording("second.m4a", vec![2, 2]);
        let during = read_with_concurrent_writer(&reader, rerecord(second.clone()), || {
            app.message_draft(&group_id_hex).unwrap().unwrap()
        });
        assert_eq!(
            during, saved,
            "the row and its attachments share one snapshot"
        );
        assert_eq!(
            app.message_draft(&group_id_hex)
                .unwrap()
                .unwrap()
                .media_attachments,
            vec![second]
        );

        let listed = app.message_drafts().unwrap();
        let during = read_with_concurrent_writer(
            &reader,
            rerecord(recording("third.m4a", vec![3, 3, 3])),
            || app.message_drafts().unwrap(),
        );
        assert_eq!(
            during, listed,
            "listed rows and summaries share one snapshot"
        );
        assert_eq!(
            app.message_drafts().unwrap()[0].media_attachments[0].file_name,
            "third.m4a"
        );
    }

    #[test]
    fn message_draft_attachment_reorder_preserves_existing_rows() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        let group_id_hex = "22".repeat(16);
        app.save_account_projection_state(
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
        app.save_message_draft(
            &group_id_hex,
            "draft",
            None,
            &[first.clone(), second.clone()],
        )
        .unwrap();
        let first_rowid = attachment_rowid(&storage, &group_id_hex, &first.id);
        let second_rowid = attachment_rowid(&storage, &group_id_hex, &second.id);

        app.save_message_draft(
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
            app.message_draft(&group_id_hex)
                .unwrap()
                .unwrap()
                .media_attachments,
            vec![second.clone(), first.clone()]
        );

        // A new recording under a kept id replaces the stored bytes and
        // metadata, in place and when the list is also reordered.
        let rerecorded_second = StoredMessageDraftAttachment {
            file_name: "second-take.m4a".to_owned(),
            plaintext: vec![2, 2],
            duration_seconds: Some(2.0),
            waveform_samples: vec![0.5],
            ..second
        };
        let rerecorded_first = StoredMessageDraftAttachment {
            plaintext: vec![3, 3, 3],
            waveform_samples: vec![0.25, 0.75],
            ..first.clone()
        };
        for attachments in [
            vec![rerecorded_second.clone(), first.clone()],
            vec![rerecorded_first, rerecorded_second],
        ] {
            let revision = app.selected_message_draft(&group_id_hex).unwrap().revision;
            app.save_message_draft(&group_id_hex, "draft", None, &attachments)
                .unwrap();
            assert_eq!(
                app.message_draft(&group_id_hex)
                    .unwrap()
                    .unwrap()
                    .media_attachments,
                attachments
            );
            assert_ne!(
                app.selected_message_draft(&group_id_hex).unwrap().revision,
                revision
            );
        }
    }

    #[test]
    fn saving_draft_for_unknown_group_is_typed_not_found() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        assert!(matches!(
            storage
                .app_storage()
                .save_message_draft(&"33".repeat(16), "draft", None, &[]),
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn message_draft_text_above_sqlite_limit_returns_quota_error() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let app = storage.app_storage();
        storage
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('chat','',0);",
            )
            .unwrap();
        app.save_message_draft("chat", "draft", None, &[]).unwrap();
        let before = app.selected_message_draft("chat").unwrap();
        app.lock()
            .unwrap()
            .set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 8_000)
            .unwrap();

        assert!(matches!(
            app.save_message_draft("chat", &"a".repeat(8_001), None, &[]),
            Err(StorageError::MessageDraftQuotaExceeded)
        ));
        let after = app.selected_message_draft("chat").unwrap();
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.draft, before.draft);
    }

    #[test]
    fn saving_draft_retries_concurrent_writer_contention() {
        use crate::protocol::storage::write_contention::{Release, SharedDatabase};

        let db = SharedDatabase::new();
        let storage = db.open().app_storage();
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

        let held = db.hold_write_lock(Release::AfterAFailedAttempt, |_| {});
        let saved = storage
            .save_message_draft(&group_id_hex, "survives contention", None, &[])
            .expect("draft save retries after transient contention");
        held.join();
        assert_eq!(saved.content, "survives contention");
        assert_eq!(
            storage
                .message_draft(&group_id_hex)
                .unwrap()
                .unwrap()
                .content,
            "survives contention"
        );
    }

    #[test]
    fn saving_draft_rejects_non_finite_waveform_samples_before_writing() {
        let storage = SqliteAccountStorage::in_memory().unwrap().app_storage();
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

        assert!(
            matches!(&error, StorageError::Serialization(message)
                if message == "message draft waveform samples must be finite"),
            "{error:?}"
        );
        assert!(storage.message_draft(&group_id_hex).unwrap().is_none());
    }
}
