//! Manage storage (mdk#2314 step 5): usage, largest-first listings and
//! their opaque paging handles. Never persist or log the handles.
use super::AttachmentLocalTargetFfi;
use marmot_app as app;
use std::sync::Arc;

/// Account-wide attachment storage across both body layouts.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AttachmentStorageUsageFfi {
    /// Media-store files, each counted once however many attachments share
    /// it.
    pub media_bytes: u64,
    /// Bodies still in the account database (the legacy layout). They move
    /// to the media store in the background; their space returns to the
    /// filesystem only after the database is compacted.
    pub legacy_bytes: u64,
    /// Attachments that read locally now.
    pub attachment_count: u64,
    /// The account database file, and the part of it that is free pages.
    pub database_bytes: u64,
    pub database_free_bytes: u64,
    /// Moving legacy bodies into the media store.
    pub migration: AttachmentMigrationStateFfi,
    /// With `Running`, the legacy bytes still to move; with `Paused`, how
    /// many more bytes must be free before the move resumes. Otherwise 0.
    pub migration_bytes: u64,
    /// The avatar and group-image cache, each stored image once. Unlike
    /// attachments it can be cleared (`clear_avatar_cache`) and is fetched
    /// again on demand.
    pub cache_bytes: u64,
}
impl From<app::AttachmentStorageUsage> for AttachmentStorageUsageFfi {
    fn from(v: app::AttachmentStorageUsage) -> Self {
        let (migration, migration_bytes) = match v.migration {
            app::AttachmentMigrationState::NotNeeded => (AttachmentMigrationStateFfi::NotNeeded, 0),
            app::AttachmentMigrationState::Running { remaining_bytes } => {
                (AttachmentMigrationStateFfi::Running, remaining_bytes)
            }
            app::AttachmentMigrationState::Paused { needed_bytes } => {
                (AttachmentMigrationStateFfi::Paused, needed_bytes)
            }
            app::AttachmentMigrationState::Complete => (AttachmentMigrationStateFfi::Complete, 0),
            app::AttachmentMigrationState::Compacting => {
                (AttachmentMigrationStateFfi::Compacting, 0)
            }
        };
        Self {
            media_bytes: v.media_bytes,
            legacy_bytes: v.legacy_bytes,
            attachment_count: v.attachment_count,
            database_bytes: v.database_bytes,
            database_free_bytes: v.database_free_bytes,
            migration,
            migration_bytes,
            cache_bytes: v.cache_bytes,
        }
    }
}

/// Where moving legacy attachment bodies out of the account database into
/// the media store stands. It runs in the background; nothing is deleted to
/// make room for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentMigrationStateFfi {
    /// No legacy bodies remain, and this runtime moved none.
    NotNeeded,
    /// Legacy bodies are moving; `migration_bytes` remain.
    Running,
    /// The smallest remaining body does not fit: the move resumes once
    /// `migration_bytes` more are free. Removing attachments frees space
    /// (file-backed ones at once) or shrinks what is left to move.
    Paused,
    /// This runtime moved the last legacy body.
    Complete,
    /// The account database is being compacted to return its free pages to
    /// the filesystem; the other figures are from just before it started.
    /// Account reads and writes wait until it finishes.
    Compacting,
}

/// How long retained attachments are kept on this device, per account
/// ("Keep media"). Attachments of messages older than the window are
/// removed automatically and show as `CleanedBySetting`; download again
/// stays allowed and keeps that attachment for the whole window from the
/// request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentKeepMediaFfi {
    /// Nothing is removed automatically. The default.
    Forever,
    /// 365 days.
    OneYear,
    /// 183 days.
    SixMonths,
    /// 30 days.
    ThirtyDays,
}
impl From<app::AttachmentKeepMedia> for AttachmentKeepMediaFfi {
    fn from(v: app::AttachmentKeepMedia) -> Self {
        match v {
            app::AttachmentKeepMedia::Forever => Self::Forever,
            app::AttachmentKeepMedia::OneYear => Self::OneYear,
            app::AttachmentKeepMedia::SixMonths => Self::SixMonths,
            app::AttachmentKeepMedia::ThirtyDays => Self::ThirtyDays,
        }
    }
}
impl From<AttachmentKeepMediaFfi> for app::AttachmentKeepMedia {
    fn from(v: AttachmentKeepMediaFfi) -> Self {
        match v {
            AttachmentKeepMediaFfi::Forever => Self::Forever,
            AttachmentKeepMediaFfi::OneYear => Self::OneYear,
            AttachmentKeepMediaFfi::SixMonths => Self::SixMonths,
            AttachmentKeepMediaFfi::ThirtyDays => Self::ThirtyDays,
        }
    }
}

/// Where the next page of chats starts.
#[derive(Debug, uniffi::Object)]
pub struct ChatStorageCursor {
    pub(crate) inner: app::ChatUsageCursor,
}

/// One chat's retained attachment storage. A stored file counts once per
/// chat however many of its attachments share it; content shared with other
/// chats counts in each.
#[derive(Clone, uniffi::Record)]
pub struct ChatAttachmentUsageFfi {
    pub group_id_hex: String,
    pub bytes: u64,
    pub attachment_count: u64,
}
impl std::fmt::Debug for ChatAttachmentUsageFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatAttachmentUsageFfi")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

/// Chats by storage, largest first. Continue while `next_cursor` is present;
/// the last page may be empty.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatStoragePageFfi {
    pub chats: Vec<ChatAttachmentUsageFfi>,
    pub next_cursor: Option<Arc<ChatStorageCursor>>,
}
impl ChatStoragePageFfi {
    pub(crate) fn new(chats: Vec<app::ChatAttachmentUsage>, limit: usize) -> Self {
        let next_cursor = (chats.len() == limit)
            .then(|| {
                chats.last().map(|last| {
                    Arc::new(ChatStorageCursor {
                        inner: last.cursor(),
                    })
                })
            })
            .flatten();
        Self {
            chats: chats
                .into_iter()
                .map(|chat| ChatAttachmentUsageFfi {
                    group_id_hex: chat.group_id_hex,
                    bytes: chat.bytes,
                    attachment_count: chat.attachment_count,
                })
                .collect(),
            next_cursor,
        }
    }
}

/// Where the next page of attachments starts.
#[derive(Debug, uniffi::Object)]
pub struct RetainedAttachmentsCursor {
    pub(crate) inner: app::RetainedSizeCursor,
}

/// One retained attachment. `target` works with `attachment_local_assets`,
/// `open_attachment_handoff` and removal.
#[derive(Clone, uniffi::Record)]
pub struct RetainedAttachmentSummaryFfi {
    pub group_id_hex: String,
    pub target: AttachmentLocalTargetFfi,
    pub byte_count: u64,
    /// From the published descriptor; empty when it does not parse.
    pub media_type: String,
    pub file_name: String,
    /// When the message was received, Unix seconds.
    pub received_at: u64,
}
impl std::fmt::Debug for RetainedAttachmentSummaryFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedAttachmentSummaryFfi")
            .field("byte_count", &self.byte_count)
            .finish_non_exhaustive()
    }
}

/// Retained attachments, largest first. Continue while `next_cursor` is
/// present; the last page may be empty.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RetainedAttachmentsPageFfi {
    pub attachments: Vec<RetainedAttachmentSummaryFfi>,
    pub next_cursor: Option<Arc<RetainedAttachmentsCursor>>,
}
impl RetainedAttachmentsPageFfi {
    pub(crate) fn new(attachments: Vec<app::RetainedAttachmentSummary>, limit: usize) -> Self {
        let next_cursor = (attachments.len() == limit)
            .then(|| {
                attachments.last().map(|last| {
                    Arc::new(RetainedAttachmentsCursor {
                        inner: last.cursor.clone(),
                    })
                })
            })
            .flatten();
        Self {
            attachments: attachments
                .into_iter()
                .map(|entry| RetainedAttachmentSummaryFfi {
                    group_id_hex: entry.group_id_hex,
                    target: AttachmentLocalTargetFfi {
                        message_id_hex: entry.target.message_id_hex,
                        source_message_id_hex: entry.target.source_message_id_hex,
                        attachment_index: entry.target.attachment_index,
                    },
                    byte_count: entry.byte_count,
                    media_type: entry.media_type,
                    file_name: entry.file_name,
                    received_at: entry.received_at,
                })
                .collect(),
            next_cursor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chat(group: &str, bytes: u64) -> app::ChatAttachmentUsage {
        app::ChatAttachmentUsage {
            group_id_hex: group.into(),
            bytes,
            attachment_count: 1,
        }
    }

    /// A full page offers a cursor; a short page ends the listing.
    #[test]
    fn a_page_continues_only_when_full() {
        let full = ChatStoragePageFfi::new(vec![chat("aa", 9), chat("bb", 4)], 2);
        assert_eq!(full.chats.len(), 2);
        assert!(full.next_cursor.is_some());
        let short = ChatStoragePageFfi::new(vec![chat("cc", 1)], 2);
        assert!(short.next_cursor.is_none());
        let empty = RetainedAttachmentsPageFfi::new(Vec::new(), 2);
        assert!(empty.attachments.is_empty() && empty.next_cursor.is_none());
    }

    #[test]
    fn the_migration_state_carries_its_byte_count_only_where_it_means_one() {
        let usage = |migration| {
            AttachmentStorageUsageFfi::from(app::AttachmentStorageUsage {
                migration,
                ..Default::default()
            })
        };
        let cases = [
            (
                app::AttachmentMigrationState::NotNeeded,
                AttachmentMigrationStateFfi::NotNeeded,
                0,
            ),
            (
                app::AttachmentMigrationState::Running { remaining_bytes: 7 },
                AttachmentMigrationStateFfi::Running,
                7,
            ),
            (
                app::AttachmentMigrationState::Paused { needed_bytes: 9 },
                AttachmentMigrationStateFfi::Paused,
                9,
            ),
            (
                app::AttachmentMigrationState::Complete,
                AttachmentMigrationStateFfi::Complete,
                0,
            ),
            (
                app::AttachmentMigrationState::Compacting,
                AttachmentMigrationStateFfi::Compacting,
                0,
            ),
        ];
        for (state, expected, bytes) in cases {
            let usage = usage(state);
            assert_eq!((usage.migration, usage.migration_bytes), (expected, bytes));
        }
    }
}
