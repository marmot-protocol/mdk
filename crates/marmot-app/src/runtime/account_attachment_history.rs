//! Account-wide attachment pages without group fan-out or host-owned indexes.
use super::{MarmotAppRuntime, attachment_history::present};
use crate::AppError;
pub use storage_sqlite::{
    AccountAttachmentCursor, AccountAttachmentQuery, AccountAttachmentVersion,
};

#[derive(Clone)]
pub struct AccountAttachmentEntry {
    pub metadata_limited: bool,
    pub group_id_hex: String,
    pub entry: super::AttachmentEntry,
}
impl std::fmt::Debug for AccountAttachmentEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountAttachmentEntry")
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug)]
pub struct AccountAttachmentPage {
    pub entries: Vec<AccountAttachmentEntry>,
    pub version: AccountAttachmentVersion,
    pub next_cursor: Option<AccountAttachmentCursor>,
}
#[derive(Clone, Debug)]
pub enum AccountAttachmentPageRead {
    Page(Box<AccountAttachmentPage>),
    RestartRequired,
    CursorMismatch,
    InvalidQuery,
    InvalidLimit,
    ResponseTooLarge,
}
impl MarmotAppRuntime {
    /// One bounded local indexed candidate page across the account, with typed shared-parser metadata.
    /// Empty filtered pages retain continuation. Refresh after any attachment-source/visibility change.
    /// No relay, engine, acquisition, decryption or read acknowledgement side effects.
    pub async fn account_attachment_history_page(
        &self,
        account_ref: &str,
        query: AccountAttachmentQuery,
        limit: usize,
        cursor: Option<AccountAttachmentCursor>,
    ) -> Result<AccountAttachmentPageRead, AppError> {
        self.attachment_read(account_ref, move |storage, loopback| {
            use storage_sqlite::AccountAttachmentHistoryError as E;
            Ok(
                match storage.account_attachment_history_page(&query, limit, cursor.as_ref()) {
                    Ok(page) => {
                        let parsed = AccountAttachmentPage {
                            entries: page
                                .entries
                                .into_iter()
                                .map(|e| {
                                    Ok(AccountAttachmentEntry {
                                        metadata_limited: e.metadata_limited,
                                        group_id_hex: e.group_id_hex,
                                        entry: present(e.attachment, loopback)?,
                                    })
                                })
                                .collect::<Result<_, AppError>>()?,
                            version: page.version,
                            next_cursor: page.next_cursor,
                        };
                        let current =
                            storage
                                .account_attachment_history_version()
                                .map_err(|error| match error {
                                    E::Storage(error) => AppError::from(error),
                                    _ => {
                                        AppError::from(cgka_traits::storage::StorageError::Backend(
                                            "account attachment version unavailable".into(),
                                        ))
                                    }
                                })?;
                        if current.requires_restart_since(&parsed.version) {
                            AccountAttachmentPageRead::RestartRequired
                        } else {
                            AccountAttachmentPageRead::Page(Box::new(parsed))
                        }
                    }
                    Err(E::RestartRequired) => AccountAttachmentPageRead::RestartRequired,
                    Err(E::CursorMismatch) => AccountAttachmentPageRead::CursorMismatch,
                    Err(E::InvalidQuery) => AccountAttachmentPageRead::InvalidQuery,
                    Err(E::InvalidLimit) => AccountAttachmentPageRead::InvalidLimit,
                    Err(E::ResponseTooLarge) => AccountAttachmentPageRead::ResponseTooLarge,
                    Err(E::Storage(error)) => return Err(error.into()),
                },
            )
        })
        .await
    }
    /// Local account incarnation/change token, including when no page remains.
    pub async fn account_attachment_history_version(
        &self,
        account_ref: &str,
    ) -> Result<AccountAttachmentVersion, AppError> {
        self.attachment_read(account_ref, move |storage, _| {
            storage
                .account_attachment_history_version()
                .map_err(|e| match e {
                    storage_sqlite::AccountAttachmentHistoryError::Storage(error) => error.into(),
                    _ => AppError::from(cgka_traits::storage::StorageError::Backend(
                        "account attachment version unavailable".into(),
                    )),
                })
        })
        .await
    }
}

#[cfg(test)]
mod tests;
