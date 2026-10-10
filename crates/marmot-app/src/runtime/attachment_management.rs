//! Shared global/chat download management and independently observed recovery health.
use super::{MarmotAppRuntime, attachment_history::present, wait_for_runtime_shutdown};
use crate::{AppError, HistoryNotice};
use std::{sync::Arc, time::Duration};
pub use storage_sqlite::{
    AttachmentCancellationBatch, AttachmentCancellationCursor, AttachmentFailureCategory,
    AttachmentJobActionToken, AttachmentJobCounts, AttachmentJobCursor, AttachmentJobOrigin,
    AttachmentJobQuery, AttachmentJobView, AttachmentManagementVersion,
};
use tokio::sync::{Mutex, broadcast, watch};
#[derive(Clone)]
pub struct ManagedAttachmentEntry {
    pub group_id_hex: String,
    pub entry: super::AttachmentEntry,
    pub explicit: bool,
    pub origin_known: bool,
    pub status: super::AttachmentTransferStatus,
    pub failure: AttachmentFailureCategory,
    pub action: AttachmentJobActionToken,
}
impl std::fmt::Debug for ManagedAttachmentEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedAttachmentEntry")
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug)]
pub struct ManagedAttachmentPage {
    pub entries: Vec<ManagedAttachmentEntry>,
    pub next_cursor: Option<AttachmentJobCursor>,
    pub next_expiry: Option<u64>,
    pub observed_at: u64,
}
#[derive(Clone)]
pub struct AttachmentManagementSnapshot {
    pub available: bool,
    /// None for account scope or an unavailable group, never evidence of successful synchronization.
    pub automatic_recovery_failed: Option<bool>,
    pub notices: Vec<HistoryNotice>,
    pub notices_complete: bool,
    pub counts: AttachmentJobCounts,
    pub page: ManagedAttachmentPage,
    pub version: AttachmentManagementVersion,
}
impl std::fmt::Debug for AttachmentManagementSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentManagementSnapshot")
            .field("available", &self.available)
            .field("counts", &self.counts)
            .finish_non_exhaustive()
    }
}
impl AttachmentManagementSnapshot {
    /// Explicit, capped default diagnostic export. No source identities, names, URLs, timestamps or tokens.
    pub fn redacted_diagnostics(&self) -> String {
        serde_json::json!({"available":self.available,"automatic_recovery_failed":self.automatic_recovery_failed,"notices_complete":self.notices_complete,"notice_count":self.notices.len(),"counts_complete":self.counts.complete,"active":self.counts.active,"needs_attention":self.counts.needs_attention,"ready":self.counts.ready,"paused":self.counts.paused,"cancelled":self.counts.cancelled,"policy_blocked":self.counts.policy_blocked,"other":self.counts.other}).to_string()
    }
}
fn present_page(
    p: storage_sqlite::AttachmentJobPage,
    loopback: bool,
) -> Result<ManagedAttachmentPage, AppError> {
    Ok(ManagedAttachmentPage {
        entries: p
            .entries
            .into_iter()
            .map(|e| {
                Ok(ManagedAttachmentEntry {
                    group_id_hex: e.group_id_hex,
                    entry: present(e.source, loopback)?,
                    explicit: e.explicit,
                    origin_known: e.origin_known,
                    failure: AttachmentFailureCategory::from_state(e.status.state),
                    status: e.status,
                    action: e.action,
                })
            })
            .collect::<Result<_, AppError>>()?,
        next_cursor: p.next_cursor,
        next_expiry: p.next_expiry,
        observed_at: p.observed_at,
    })
}
fn recheck(
    s: &storage_sqlite::SqliteAccountStorage,
    before: &storage_sqlite::AccountAttachmentVersion,
) -> Result<(), AppError> {
    let current = s.account_attachment_history_version().map_err(|_| {
        AppError::from(cgka_traits::storage::StorageError::Backend(
            "attachment management unavailable".into(),
        ))
    })?;
    if current.requires_restart_since(before) {
        return Err(AppError::from(cgka_traits::storage::StorageError::Backend(
            "attachment management restart required".into(),
        )));
    }
    Ok(())
}
fn effective_permission(
    s: &storage_sqlite::SqliteAccountStorage,
    config: &crate::MarmotAppConfig,
    permissions: &super::attachment_permission::Permissions,
) -> Result<storage_sqlite::AttachmentManagementPermission, AppError> {
    Ok(storage_sqlite::AttachmentManagementPermission {
        automatic: s
            .attachment_download_policy(&super::attachment_controls::default_policy(config))?
            .automatic
            && config.cursor_persistence != crate::CursorPersistence::Frozen,
        categories: if config.attachment_acquisition_mode
            == crate::AttachmentAcquisitionMode::HostManaged
        {
            permissions.categories(&s.attachment_store_identity()?)
        } else {
            [true; 4]
        },
    })
}
impl MarmotAppRuntime {
    pub async fn managed_attachment_page(
        &self,
        account: &str,
        query: AttachmentJobQuery,
        limit: usize,
        cursor: Option<AttachmentJobCursor>,
    ) -> Result<ManagedAttachmentPage, AppError> {
        let config = self.accounts.app.config.clone();
        let permissions = self.shared.attachment_permissions.clone();
        self.attachment_read(account, move |s, loopback| {
            let automatic = effective_permission(&s, &config, &permissions)?;
            let p = s.attachment_jobs_page(
                &query,
                limit,
                cursor.as_ref(),
                crate::unix_now_seconds(),
                automatic,
            )?;
            let h = p.history_version.clone();
            let p = present_page(p, loopback)?;
            recheck(&s, &h)?;
            Ok(p)
        })
        .await
    }
    pub async fn attachment_management_snapshot(
        &self,
        account: &str,
        query: AttachmentJobQuery,
    ) -> Result<AttachmentManagementSnapshot, AppError> {
        let config = self.accounts.app.config.clone();
        let permissions = self.shared.attachment_permissions.clone();
        self.attachment_read(account, move |s, loopback| {
            let automatic = effective_permission(&s, &config, &permissions)?;
            let f = s.attachment_management_frame(&query, crate::unix_now_seconds(), automatic)?;
            let h = f.page.history_version.clone();
            let result = AttachmentManagementSnapshot {
                available: f.available,
                automatic_recovery_failed: f.automatic_recovery_failed,
                notices: f
                    .notices
                    .iter()
                    .map(crate::history_notices::history_notice)
                    .collect(),
                notices_complete: f.notices_complete,
                counts: f.counts,
                page: present_page(f.page, loopback)?,
                version: f.version,
            };
            recheck(&s, &h)?;
            Ok(result)
        })
        .await
    }
    pub async fn begin_attachment_cancellation(
        &self,
        account: &str,
        group: Option<String>,
        automatic_only: bool,
    ) -> Result<AttachmentCancellationCursor, AppError> {
        self.attachment_read(account, move |s, _| {
            Ok(s.begin_attachment_cancellation(group.as_deref(), automatic_only)?)
        })
        .await
    }
    pub async fn cancel_attachment_batch(
        &self,
        account: &str,
        cursor: AttachmentCancellationCursor,
    ) -> Result<AttachmentCancellationBatch, AppError> {
        let result = self
            .attachment_read(account, move |s, _| {
                Ok(s.cancel_attachment_batch(&cursor, crate::unix_now_seconds())?)
            })
            .await?;
        self.wake_attachment_work();
        Ok(result)
    }
    pub async fn control_managed_attachment(
        &self,
        account: &str,
        action: AttachmentJobActionToken,
        retry: bool,
    ) -> Result<bool, AppError> {
        let result = self
            .attachment_read(account, move |s, _| {
                Ok(s.control_managed_attachment(&action, retry, crate::unix_now_seconds())?)
            })
            .await?;
        self.wake_attachment_work();
        Ok(result)
    }
    /// Event-driven head replacements, at most4Hz. Explicit continuation pages remain pull-based.
    pub async fn subscribe_attachment_management(
        &self,
        account: &str,
        query: AttachmentJobQuery,
    ) -> Result<Arc<RuntimeAttachmentManagementSubscription>, AppError> {
        let updates = self.shared.attachment_updates.subscribe();
        let presentation = self.accounts.app.presentation_signals.updates.subscribe();
        let events = self.events.subscribe();
        let resets = self
            .accounts
            .app
            .presentation_signals
            .account_resets
            .subscribe();
        let snapshot = self
            .attachment_management_snapshot(account, query.clone())
            .await?;
        Ok(Arc::new(RuntimeAttachmentManagementSubscription {
            runtime: self.clone(),
            account: account.into(),
            query,
            closed: watch::channel(false).0,
            state: Mutex::new(ManagementSubscriptionState {
                updates,
                events,
                presentation,
                resets,
                version: snapshot.version,
                expiry: snapshot.page.next_expiry,
                initial: true,
                last: tokio::time::Instant::now(),
            }),
        }))
    }
}
struct ManagementSubscriptionState {
    events: broadcast::Receiver<super::MarmotAppEvent>,
    updates: watch::Receiver<()>,
    presentation: broadcast::Receiver<crate::chat_presentation::signals::PresentationInvalidation>,
    resets: broadcast::Receiver<String>,
    version: AttachmentManagementVersion,
    expiry: Option<u64>,
    initial: bool,
    last: tokio::time::Instant,
}
pub struct RuntimeAttachmentManagementSubscription {
    runtime: MarmotAppRuntime,
    account: String,
    query: AttachmentJobQuery,
    closed: watch::Sender<bool>,
    state: Mutex<ManagementSubscriptionState>,
}
impl RuntimeAttachmentManagementSubscription {
    pub fn close(&self) {
        self.closed.send_replace(true);
    }
    pub async fn next(&self) -> Result<Option<AttachmentManagementSnapshot>, AppError> {
        let mut closed = self.closed.subscribe();
        let mut stop = self.runtime.shared.lifecycle().subscribe_shutdown();
        let mut st = self.state.lock().await;
        loop {
            if *closed.borrow() || self.runtime.shared.lifecycle().ensure_running().is_err() {
                return Ok(None);
            }
            if !st.initial {
                let deadline = st.expiry;
                let expiry = async move {
                    if let Some(t) = deadline {
                        tokio::time::sleep(Duration::from_secs(
                            t.saturating_sub(crate::unix_now_seconds()),
                        ))
                        .await
                    } else {
                        std::future::pending::<()>().await
                    }
                };
                let ManagementSubscriptionState {
                    updates,
                    events,
                    presentation,
                    resets,
                    ..
                } = &mut *st;
                tokio::select! {biased;_=closed.changed()=>return Ok(None),_=wait_for_runtime_shutdown(&mut stop)=>return Ok(None),_=resets.recv()=>{self.close();return Ok(None)},_=updates.changed()=>{},_=events.recv()=>{},_=presentation.recv()=>{},_=expiry=>{}}
                tokio::select! {biased;_=closed.changed()=>return Ok(None),_=wait_for_runtime_shutdown(&mut stop)=>return Ok(None),_=tokio::time::sleep_until(st.last+Duration::from_millis(250))=>{}}
            }
            let result = self
                .runtime
                .attachment_management_snapshot(&self.account, self.query.clone())
                .await;
            let snap = match result {
                Ok(s) => s,
                Err(e) => {
                    self.close();
                    return Err(e);
                }
            };
            if *closed.borrow()
                || self.runtime.shared.lifecycle().ensure_running().is_err()
                || !snap.version.same_account(&st.version)
            {
                self.close();
                return Ok(None);
            }
            let changed = st.initial || !snap.version.same_as(&st.version);
            st.initial = false;
            st.last = tokio::time::Instant::now();
            st.expiry = snap.page.next_expiry;
            st.version = snap.version.clone();
            if changed {
                return Ok(Some(snap));
            }
        }
    }
}
#[cfg(test)]
mod tests;
