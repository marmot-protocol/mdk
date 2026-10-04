//! Opaque process-local paging handles; no client-owned index or serialized cursor.
use super::MediaAttachmentOutcomeFfi;
use marmot_app as app;
use std::sync::Arc;

#[derive(Debug, uniffi::Object)]
pub struct AttachmentHistoryCursor {
    pub(crate) inner: app::AttachmentHistoryCursor,
}
#[derive(Debug, uniffi::Object)]
pub struct AttachmentHistoryVersion {
    pub(crate) inner: app::AttachmentHistoryVersion,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentHistoryChangeFfi {
    Unchanged,
    Additions,
    RestartRequired,
}
#[uniffi::export]
impl AttachmentHistoryVersion {
    /// Compare current with an older version, including after the last page.
    /// RestartRequired means discard all loaded rows before restarting at the head.
    pub fn change_since(
        &self,
        previous: Arc<AttachmentHistoryVersion>,
    ) -> AttachmentHistoryChangeFfi {
        if self.inner.requires_restart_since(&previous.inner) {
            AttachmentHistoryChangeFfi::RestartRequired
        } else if self.inner == previous.inner {
            AttachmentHistoryChangeFfi::Unchanged
        } else {
            AttachmentHistoryChangeFfi::Additions
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentCategoryFfi {
    Image,
    Video,
    Audio,
    File,
    Rejected,
}
impl From<app::AttachmentCategory> for AttachmentCategoryFfi {
    /// Preserve native MIME categories without reclassifying rejected slots in bindings.
    fn from(value: app::AttachmentCategory) -> Self {
        match value {
            app::AttachmentCategory::Image => Self::Image,
            app::AttachmentCategory::Video => Self::Video,
            app::AttachmentCategory::Audio => Self::Audio,
            app::AttachmentCategory::File => Self::File,
            app::AttachmentCategory::Rejected => Self::Rejected,
        }
    }
}
/// Shared-library presentation eligibility; does not gate artwork acquisition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AttachmentRoleFfi {
    Shared,
    InlineEmoji,
}
impl From<app::AttachmentRole> for AttachmentRoleFfi {
    /// Preserve the native presentation role across the binding boundary.
    fn from(value: app::AttachmentRole) -> Self {
        match value {
            app::AttachmentRole::Shared => Self::Shared,
            app::AttachmentRole::InlineEmoji => Self::InlineEmoji,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct AttachmentEntryFfi {
    pub message_id_hex: String,
    pub source_message_id_hex: String,
    pub sender: String,
    pub timeline_at: u64,
    pub received_at: u64,
    pub source_epoch: Option<u64>,
    pub category: AttachmentCategoryFfi,
    /// Exclude InlineEmoji from shared galleries; keep original slots and acquisition intact.
    pub role: AttachmentRoleFfi,
    /// Accepted or rejected in original album order, with its original attachment index.
    pub attachment: MediaAttachmentOutcomeFfi,
}
impl std::fmt::Debug for AttachmentEntryFfi {
    /// Hide source identities and media locators from generated record diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentEntryFfi").finish_non_exhaustive()
    }
}
impl From<app::AttachmentEntry> for AttachmentEntryFfi {
    /// Copy the source slot, parser verdict and native role without host-side inference.
    fn from(value: app::AttachmentEntry) -> Self {
        Self {
            message_id_hex: value.message_id_hex,
            source_message_id_hex: value.source_message_id_hex,
            sender: value.sender,
            timeline_at: value.timeline_at,
            received_at: value.received_at,
            source_epoch: value.source_epoch,
            category: value.category.into(),
            role: value.role.into(),
            attachment: value.attachment.into(),
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct AttachmentPageFfi {
    pub entries: Vec<AttachmentEntryFfi>,
    pub version: Arc<AttachmentHistoryVersion>,
    pub next_cursor: Option<Arc<AttachmentHistoryCursor>>,
    pub has_more: bool,
}
#[derive(Clone, Debug, uniffi::Enum)]
pub enum AttachmentPageReadFfi {
    Page { page: AttachmentPageFfi },
    RestartRequired,
    CursorMismatch,
    InvalidLimit,
}
impl From<app::AttachmentPageRead> for AttachmentPageReadFfi {
    /// Preserve paging failures and wrap successful page handles without serializing cursors.
    fn from(value: app::AttachmentPageRead) -> Self {
        match value {
            app::AttachmentPageRead::Page(page) => Self::Page {
                page: AttachmentPageFfi {
                    entries: page.entries.into_iter().map(Into::into).collect(),
                    version: Arc::new(AttachmentHistoryVersion {
                        inner: page.version,
                    }),
                    has_more: page.next_cursor.is_some(),
                    next_cursor: page
                        .next_cursor
                        .map(|inner| Arc::new(AttachmentHistoryCursor { inner })),
                },
            },
            app::AttachmentPageRead::RestartRequired => Self::RestartRequired,
            app::AttachmentPageRead::CursorMismatch => Self::CursorMismatch,
            app::AttachmentPageRead::InvalidLimit => Self::InvalidLimit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both roles survive record conversion without renumbering a rejected slot.
    #[test]
    fn attachment_role_survives_binding_conversion() {
        for (role, expected) in [
            (app::AttachmentRole::Shared, AttachmentRoleFfi::Shared),
            (
                app::AttachmentRole::InlineEmoji,
                AttachmentRoleFfi::InlineEmoji,
            ),
        ] {
            let entry = AttachmentEntryFfi::from(app::AttachmentEntry {
                message_id_hex: "private-message".into(),
                source_message_id_hex: "private-source".into(),
                sender: "private-sender".into(),
                timeline_at: 1,
                received_at: 2,
                source_epoch: Some(3),
                category: app::AttachmentCategory::Rejected,
                role,
                attachment: app::MediaAttachmentOutcome::Rejected {
                    attachment_index: 7,
                    rejection: app::MediaAttachmentRejection {
                        kind: app::MediaAttachmentRejectionKind::UnsupportedFormat,
                        detail: "unsupported".into(),
                    },
                },
            });
            assert_eq!(entry.role, expected);
            assert!(matches!(
                entry.attachment,
                MediaAttachmentOutcomeFfi::Rejected {
                    attachment_index: 7,
                    ..
                }
            ));
            assert!(!format!("{entry:?}").contains("private"));
        }
    }
}
