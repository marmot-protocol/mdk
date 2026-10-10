//! Account/query-bound paging handles; never persist or log them.
use super::{AttachmentEntryFfi, AttachmentHistoryChangeFfi};
use marmot_app as app;
use std::sync::Arc;
#[derive(Clone, Default, uniffi::Record)]
pub struct AccountAttachmentQueryFfi {
    pub groups: Vec<String>,
    pub senders: Vec<String>,
    pub after: Option<u64>,
    pub before: Option<u64>,
}
impl From<AccountAttachmentQueryFfi> for app::AccountAttachmentQuery {
    fn from(v: AccountAttachmentQueryFfi) -> Self {
        Self {
            groups: v.groups,
            senders: v.senders,
            after: v.after,
            before: v.before,
        }
    }
}
#[derive(Debug, uniffi::Object)]
pub struct AccountAttachmentCursor {
    pub(crate) inner: app::AccountAttachmentCursor,
}
#[derive(Debug, uniffi::Object)]
pub struct AccountAttachmentVersion {
    pub(crate) inner: app::AccountAttachmentVersion,
}
#[uniffi::export]
impl AccountAttachmentVersion {
    /// RestartRequired invalidates loaded rows; Additions leaves older-page cursors valid and offers refresh.
    pub fn change_since(
        &self,
        previous: Arc<AccountAttachmentVersion>,
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
#[derive(Clone, uniffi::Record)]
pub struct AccountAttachmentEntryFfi {
    pub metadata_limited: bool,
    pub group_id_hex: String,
    pub entry: AttachmentEntryFfi,
}
impl std::fmt::Debug for AccountAttachmentEntryFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountAttachmentEntryFfi")
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountAttachmentPageFfi {
    pub entries: Vec<AccountAttachmentEntryFfi>,
    pub version: Arc<AccountAttachmentVersion>,
    pub next_cursor: Option<Arc<AccountAttachmentCursor>>,
    pub has_more: bool,
    pub next_expiry: Option<u64>,
}
#[derive(Clone, Debug, uniffi::Enum)]
pub enum AccountAttachmentPageReadFfi {
    Page { page: AccountAttachmentPageFfi },
    RestartRequired,
    CursorMismatch,
    InvalidQuery,
    InvalidLimit,
    ResponseTooLarge,
}
impl From<app::AccountAttachmentPageRead> for AccountAttachmentPageReadFfi {
    fn from(v: app::AccountAttachmentPageRead) -> Self {
        match v {
            app::AccountAttachmentPageRead::Page(p) => Self::Page {
                page: AccountAttachmentPageFfi {
                    next_expiry: p.version.next_expiry,
                    entries: p
                        .entries
                        .into_iter()
                        .map(|e| AccountAttachmentEntryFfi {
                            metadata_limited: e.metadata_limited,
                            group_id_hex: e.group_id_hex,
                            entry: e.entry.into(),
                        })
                        .collect(),
                    version: Arc::new(AccountAttachmentVersion { inner: p.version }),
                    has_more: p.next_cursor.is_some(),
                    next_cursor: p
                        .next_cursor
                        .map(|inner| Arc::new(AccountAttachmentCursor { inner })),
                },
            },
            app::AccountAttachmentPageRead::RestartRequired => Self::RestartRequired,
            app::AccountAttachmentPageRead::CursorMismatch => Self::CursorMismatch,
            app::AccountAttachmentPageRead::InvalidQuery => Self::InvalidQuery,
            app::AccountAttachmentPageRead::InvalidLimit => Self::InvalidLimit,
            app::AccountAttachmentPageRead::ResponseTooLarge => Self::ResponseTooLarge,
        }
    }
}
