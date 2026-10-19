//! Manage storage (mdk#2314 step 5): what retained attachments hold on this
//! device, and removing them in bulk. Works across both body layouts (media
//! store files and legacy database rows). Every removal is the explicit
//! `Remove` a host already exposes: the attachment is suppressed (shown as
//! removed, download-again allowed), and the media files it released are
//! unlinked at once, so file-backed space returns immediately. Legacy bodies
//! free database pages, which return to the filesystem at compaction.
use super::MarmotAppRuntime;
use crate::AppError;
use cgka_traits::GroupId;
pub use storage_sqlite::{
    AttachmentMigrationState, AttachmentStorageUsage, ChatAttachmentUsage, ChatUsageCursor,
    RetainedSizeCursor,
};

/// One retained attachment in a largest-first listing. `target` feeds
/// straight into `attachment_local_assets`, `open_attachment_handoff`, or a
/// removal.
#[derive(Clone)]
pub struct RetainedAttachmentSummary {
    pub group_id_hex: String,
    pub target: super::AttachmentLocalTarget,
    pub byte_count: u64,
    /// From the published descriptor; empty when it does not parse.
    pub media_type: String,
    pub file_name: String,
    pub received_at: u64,
    /// Resumes the listing after this entry.
    pub cursor: RetainedSizeCursor,
}

impl std::fmt::Debug for RetainedAttachmentSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedAttachmentSummary")
            .field("byte_count", &self.byte_count)
            .finish_non_exhaustive()
    }
}

impl MarmotAppRuntime {
    /// Account-wide attachment storage across both layouts. Reads no
    /// bodies; needs no account worker. `migration` says where moving
    /// legacy bodies into the media store stands, including a pause for
    /// free space, as this runtime's account worker last saw it.
    pub async fn attachment_storage_usage(
        &self,
        account_ref: &str,
    ) -> Result<AttachmentStorageUsage, AppError> {
        self.attachment_read_with(account_ref, |app, label, storage, _| {
            let mut usage = storage
                .app_storage()
                .attachment_storage_usage(crate::unix_now_seconds())?;
            usage.migration = app
                .legacy_media_migration(label)
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .state(usage.migration);
            Ok(usage)
        })
        .await
    }

    /// Chats by retained attachment bytes, largest first, `limit` (1..=256)
    /// per page. Pass the last row's `cursor()` to continue. Content shared
    /// between chats counts in each; the usage summary counts it once.
    pub async fn attachment_storage_by_chat(
        &self,
        account_ref: &str,
        after: Option<ChatUsageCursor>,
        limit: usize,
    ) -> Result<Vec<ChatAttachmentUsage>, AppError> {
        self.attachment_read(account_ref, move |storage, _| {
            Ok(storage.app_storage().attachment_storage_by_chat(
                crate::unix_now_seconds(),
                after.as_ref(),
                limit,
            )?)
        })
        .await
    }

    /// Retained attachments, largest first, `limit` (1..=256) per page,
    /// optionally within one chat. Pass the last entry's `cursor` to
    /// continue.
    pub async fn largest_retained_attachments(
        &self,
        account_ref: &str,
        group: Option<&GroupId>,
        after: Option<RetainedSizeCursor>,
        limit: usize,
    ) -> Result<Vec<RetainedAttachmentSummary>, AppError> {
        let group = group.map(|group| hex::encode(group.as_slice()));
        self.attachment_read(account_ref, move |storage, allow_loopback| {
            let entries = storage.app_storage().largest_retained_attachments(
                crate::unix_now_seconds(),
                group.as_deref(),
                after.as_ref(),
                limit,
            )?;
            Ok(entries
                .into_iter()
                .map(|entry| {
                    let descriptor = serde_json::from_str::<Vec<String>>(&entry.slot_json)
                        .ok()
                        .and_then(|tag| {
                            crate::media::parse_media_attachment(&tag, None, allow_loopback).ok()
                        });
                    let (media_type, file_name) = descriptor
                        .map(|reference| (reference.media_type, reference.file_name))
                        .unwrap_or_default();
                    RetainedAttachmentSummary {
                        cursor: entry.cursor(),
                        group_id_hex: entry.group_id_hex,
                        target: super::AttachmentLocalTarget {
                            message_id_hex: entry.message_id_hex,
                            source_message_id_hex: entry.source_message_id_hex,
                            attachment_index: entry.attachment_index,
                        },
                        byte_count: entry.byte_count,
                        media_type,
                        file_name,
                        received_at: entry.received_at,
                    }
                })
                .collect())
        })
        .await
    }

    /// Removes every retained attachment in one chat, as explicit `Remove`
    /// does, and returns how many it removed. Media-store space is freed
    /// before this returns.
    pub async fn remove_chat_attachments(
        &self,
        account_ref: &str,
        group: &GroupId,
    ) -> Result<u64, AppError> {
        self.remove_retained(account_ref, Some(hex::encode(group.as_slice())), None)
            .await
    }

    /// Removes retained attachments of messages received before
    /// `received_before` (Unix seconds), across the account or within one
    /// chat, as explicit `Remove` does. Returns how many it removed.
    pub async fn remove_attachments_older_than(
        &self,
        account_ref: &str,
        received_before: u64,
        group: Option<&GroupId>,
    ) -> Result<u64, AppError> {
        self.remove_retained(
            account_ref,
            group.map(|group| hex::encode(group.as_slice())),
            Some(received_before),
        )
        .await
    }

    /// Bounded batches on the blocking pool, each one transaction followed
    /// by the unlink of the media files it released.
    async fn remove_retained(
        &self,
        account_ref: &str,
        group: Option<String>,
        received_before: Option<u64>,
    ) -> Result<u64, AppError> {
        let removed = self
            .attachment_read_with(account_ref, move |app, label, storage, _| {
                let media = app.account_media_store(label, &storage)?;
                let mut removed = 0u64;
                loop {
                    let batch = storage.app_storage().remove_retained_attachments(
                        crate::unix_now_seconds(),
                        group.as_deref(),
                        received_before,
                    )?;
                    media.unlink_released(&batch.released_files);
                    removed += batch.removed as u64;
                    if !batch.more || batch.removed == 0 {
                        return Ok(removed);
                    }
                }
            })
            .await?;
        if removed > 0 {
            self.wake_attachment_work();
        }
        Ok(removed)
    }
}
