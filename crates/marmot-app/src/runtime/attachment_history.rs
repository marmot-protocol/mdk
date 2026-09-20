//! Bounded, local-only attachment discovery. No live engine or relay prerequisite.
use super::{MarmotAppRuntime, blocking_app_task, wait_for_runtime_shutdown};
use crate::{AppError, MediaAttachmentOutcome};
use cgka_traits::GroupId;
pub use storage_sqlite::{
    AttachmentHistoryCursor, AttachmentHistoryVersion, MAX_ATTACHMENT_HISTORY_PAGE,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentCategory {
    Image,
    Video,
    Audio,
    File,
    Rejected,
}

#[derive(Clone)]
pub struct AttachmentEntry {
    pub message_id_hex: String,
    pub source_message_id_hex: String,
    pub sender: String,
    pub timeline_at: u64,
    pub received_at: u64,
    /// None for retained legacy rows. Never treat the parser's epoch fallback as authoritative.
    pub source_epoch: Option<u64>,
    pub category: AttachmentCategory,
    pub attachment: MediaAttachmentOutcome,
}
impl std::fmt::Debug for AttachmentEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentEntry").finish_non_exhaustive()
    }
}
#[derive(Clone, Debug)]
pub struct AttachmentPage {
    pub entries: Vec<AttachmentEntry>,
    pub version: AttachmentHistoryVersion,
    pub next_cursor: Option<AttachmentHistoryCursor>,
}
#[derive(Clone, Debug)]
pub enum AttachmentPageRead {
    Page(Box<AttachmentPage>),
    RestartRequired,
    CursorMismatch,
    InvalidLimit,
}

pub(crate) fn category(media_type: &str) -> AttachmentCategory {
    match storage_sqlite::AttachmentPermissionCategory::from_media_type(media_type) {
        storage_sqlite::AttachmentPermissionCategory::Image => AttachmentCategory::Image,
        storage_sqlite::AttachmentPermissionCategory::Video => AttachmentCategory::Video,
        storage_sqlite::AttachmentPermissionCategory::Audio => AttachmentCategory::Audio,
        storage_sqlite::AttachmentPermissionCategory::File => AttachmentCategory::File,
    }
}

fn present(
    entry: storage_sqlite::AttachmentHistoryEntry,
    allow_loopback: bool,
) -> Result<AttachmentEntry, AppError> {
    let index = u32::try_from(entry.attachment_index).map_err(|_| {
        AppError::InvalidEncryptedMedia("attachment index exceeds native range".into())
    })?;
    // Run the same parser used by timeline rows, keeping even malformed slot verdicts.
    let media = serde_json::json!({"imeta": [entry.slot]});
    let outcomes = crate::media_attachment_outcomes_from_media_json(
        Some(&media),
        entry.source_epoch,
        allow_loopback,
    );
    let mut attachment = outcomes.into_iter().next().ok_or_else(|| {
        AppError::InvalidEncryptedMedia("attachment slot produced no outcome".into())
    })?;
    let category = match &mut attachment {
        MediaAttachmentOutcome::Accepted {
            attachment_index,
            reference,
        } => {
            *attachment_index = index;
            // Classification is presentation of an already-validated MIME, not another imeta parser.
            category(&reference.media_type)
        }
        MediaAttachmentOutcome::Rejected {
            attachment_index, ..
        } => {
            *attachment_index = index;
            AttachmentCategory::Rejected
        }
    };
    Ok(AttachmentEntry {
        message_id_hex: entry.message_id_hex,
        source_message_id_hex: entry.source_message_id_hex,
        sender: entry.sender,
        timeline_at: entry.timeline_at,
        received_at: entry.received_at,
        source_epoch: entry.source_epoch,
        category,
        attachment,
    })
}
impl MarmotAppRuntime {
    pub(super) async fn attachment_read<T: Send + 'static>(
        &self,
        account_ref: &str,
        read: impl FnOnce(storage_sqlite::SqliteAccountStorage, bool) -> Result<T, AppError>
        + Send
        + 'static,
    ) -> Result<T, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let app = self.accounts.app.clone();
        let account_ref = account_ref.to_owned();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let work = blocking_app_task(move || {
            // Account resolution, store opening, SQL and parser work all stay off the caller thread.
            let account = app.account_home().account(&account_ref)?;
            let storage = app.account_storage(&account.label)?;
            if app.account_home().account(&account.label)?.account_id_hex != account.account_id_hex
            {
                return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
            }
            read(storage, app.allow_loopback_blob_endpoints())
        });
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => Err(AppError::RuntimeStopping),
            result = work => result,
        }
    }
    /// Read bounded original slots in canonical order, including rejected attachments.
    /// Categories support client-side per-page filtering; continue while next_cursor
    /// exists even when a page contains no desired category. Never scan until full.
    /// No engine, relay, decryption-secret warming or acquisition is performed.
    pub async fn attachment_history_page(
        &self,
        account_ref: &str,
        group: &GroupId,
        limit: usize,
        cursor: Option<AttachmentHistoryCursor>,
    ) -> Result<AttachmentPageRead, AppError> {
        let group = hex::encode(group.as_slice());
        self.attachment_read(account_ref, move |storage, allow_loopback| {
            use storage_sqlite::AttachmentHistoryError as E;
            match storage.attachment_history_page(&group, limit, cursor.as_ref()) {
                Ok(page) => Ok(AttachmentPageRead::Page(Box::new(AttachmentPage {
                    entries: page
                        .entries
                        .into_iter()
                        .map(|e| present(e, allow_loopback))
                        .collect::<Result<_, _>>()?,
                    version: page.version,
                    next_cursor: page.next_cursor,
                }))),
                Err(E::StaleCursor) => Ok(AttachmentPageRead::RestartRequired),
                Err(E::CursorMismatch) => Ok(AttachmentPageRead::CursorMismatch),
                Err(E::InvalidLimit) => Ok(AttachmentPageRead::InvalidLimit),
                Err(E::Storage(error)) => Err(error.into()),
            }
        })
        .await
    }
    /// Compare against the baseline retained with loaded rows, even after exhaustion.
    /// Equality means unchanged; requires_restart_since distinguishes destructive
    /// changes from additions above/below an already passed paging boundary.
    pub async fn attachment_history_version(
        &self,
        account_ref: &str,
        group: &GroupId,
    ) -> Result<AttachmentHistoryVersion, AppError> {
        let group = hex::encode(group.as_slice());
        self.attachment_read(account_ref, move |storage, _| {
            storage
                .attachment_history_version(&group)
                .map_err(|error| match error {
                    storage_sqlite::AttachmentHistoryError::Storage(error) => error.into(),
                    _ => AppError::InvalidEncryptedMedia("attachment version read failed".into()),
                })
        })
        .await
    }
}
#[cfg(test)]
mod tests;
