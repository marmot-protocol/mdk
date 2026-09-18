//! Bounded local transfer observation and durable controls over existing acquisition jobs.
use super::{
    AttachmentAssetRef, AttachmentLocalTarget, MarmotAppRuntime, wait_for_runtime_shutdown,
};
use crate::{AppError, CursorPersistence, MarmotAppConfig};
use cgka_traits::GroupId;
use std::{sync::Arc, time::Duration};
pub use storage_sqlite::{
    AttachmentDownloadPolicy, AttachmentTransferState, AttachmentTransferStatus,
};
use tokio::sync::{Mutex, watch};

#[derive(Clone, Copy, Debug)]
pub enum AttachmentControl {
    Cancel,
    Retry,
    Remove,
}

pub(super) fn default_policy(config: &MarmotAppConfig) -> AttachmentDownloadPolicy {
    let p = config.attachment_acquisition.clone().unwrap_or_default();
    AttachmentDownloadPolicy {
        automatic: config.attachment_acquisition.is_some(),
        retained_bytes: p.retained_bytes_per_account,
        disk_reserve: p.minimum_free_disk_bytes,
        transfer_limit: p.maximum_transfer_bytes,
    }
}
fn validate_policy(policy: &AttachmentDownloadPolicy) -> Result<(), AppError> {
    policy
        .validate()
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid attachment download policy".into()))
}

impl MarmotAppRuntime {
    pub async fn attachment_download_policy(
        &self,
        account_ref: &str,
    ) -> Result<AttachmentDownloadPolicy, AppError> {
        let fallback = default_policy(&self.accounts.app.config);
        validate_policy(&fallback)?;
        self.attachment_read(account_ref, move |s, _| {
            Ok(s.attachment_download_policy(&fallback)?)
        })
        .await
    }
    /// Durable, per-account override. Disable pauses automatic work, not explicit
    /// requests or local reads. Cached bytes and individual cancel/removal survive.
    pub async fn set_attachment_download_policy(
        &self,
        account_ref: &str,
        policy: AttachmentDownloadPolicy,
    ) -> Result<(), AppError> {
        validate_policy(&policy)?;
        self.attachment_read(account_ref, move |s, _| {
            Ok(s.set_attachment_download_policy(&policy, crate::unix_now_seconds())?)
        })
        .await?;
        self.wake_attachment_work();
        Ok(())
    }
    fn wake_attachment_work(&self) {
        self.shared.attachment_updates.send_modify(|_| {});
        self.shared.attachment_cancellations.send_modify(|_| {});
        self.accounts.app.presentation_signals.wake();
    }
    /// Opaque job references come from transfer snapshots (including non-ready jobs).
    /// Cancellation does not erase ready bytes; removal explicitly does.
    pub async fn control_attachment(
        &self,
        account_ref: &str,
        reference: AttachmentAssetRef,
        control: AttachmentControl,
    ) -> Result<bool, AppError> {
        let changed = self
            .attachment_read(account_ref, move |s, _| {
                Ok(match control {
                    AttachmentControl::Cancel => s.cancel_attachment_acquisition(&reference)?,
                    AttachmentControl::Retry => {
                        s.explicitly_retry_attachment(&reference, crate::unix_now_seconds())?
                    }
                    AttachmentControl::Remove => s.remove_attachment_reference(&reference)?,
                })
            })
            .await?;
        self.wake_attachment_work();
        Ok(changed)
    }
    /// Explicitly request the exact current source, clearing removal/cancellation.
    /// This persists demand; it does not wait for a worker or network readiness.
    pub async fn download_attachment_again(
        &self,
        account_ref: &str,
        group: &GroupId,
        mut target: AttachmentLocalTarget,
    ) -> Result<Option<AttachmentAssetRef>, AppError> {
        super::attachment_access::validate_targets(std::slice::from_mut(&mut target))?;
        let group = hex::encode(group.as_slice());
        let result = self
            .attachment_read(account_ref, move |s, loopback| {
                let now = crate::unix_now_seconds();
                let Some(entry) = s.attachment_control_entry(
                    &group,
                    &target.message_id_hex,
                    &target.source_message_id_hex,
                    target.attachment_index,
                    now,
                )?
                else {
                    return Ok(None);
                };
                let Some(epoch) = entry.source_epoch else {
                    return Ok(None);
                };
                let tag: Vec<String> =
                    serde_json::from_value(entry.slot.clone()).map_err(|_| {
                        AppError::InvalidEncryptedMedia("invalid attachment slot".into())
                    })?;
                let reference = crate::parse_media_attachment(&tag, Some(epoch), loopback)?;
                let digest = crate::media::media_hash_from_reference(&reference)?;
                match s.request_attachment_download_again(&group, &entry, digest, now)? {
                    storage_sqlite::AttachmentDemand::Requested(reference) => Ok(Some(reference)),
                    _ => Ok(None),
                }
            })
            .await?;
        self.wake_attachment_work();
        Ok(result)
    }
    async fn attachment_transfer_frame(
        &self,
        account_ref: &str,
        group: &GroupId,
        mut targets: Vec<AttachmentLocalTarget>,
    ) -> Result<(Vec<u8>, Vec<Option<AttachmentTransferStatus>>), AppError> {
        super::attachment_access::validate_targets(&mut targets)?;
        let group = hex::encode(group.as_slice());
        let fallback = default_policy(&self.accounts.app.config);
        let frozen = self.accounts.app.config.cursor_persistence == CursorPersistence::Frozen;
        self.attachment_read(account_ref, move |s, _| {
            let policy = s.attachment_download_policy(&fallback)?;
            let targets = targets
                .iter()
                .map(|t| {
                    (
                        t.message_id_hex.as_str(),
                        t.source_message_id_hex.as_str(),
                        t.attachment_index,
                    )
                })
                .collect::<Vec<_>>();
            Ok(s.attachment_transfer_snapshot(
                &group,
                &targets,
                crate::unix_now_seconds(),
                policy.automatic && !frozen,
            )?)
        })
        .await
    }
    /// Local metadata only, at most 64 original slots in input order. None means
    /// unavailable/obsolete source, not failure. Does not start acquisition.
    pub async fn attachment_transfer_snapshot(
        &self,
        account_ref: &str,
        group: &GroupId,
        targets: Vec<AttachmentLocalTarget>,
    ) -> Result<Vec<Option<AttachmentTransferStatus>>, AppError> {
        self.attachment_transfer_frame(account_ref, group, targets)
            .await
            .map(|(_, rows)| rows)
    }
    /// Initial snapshot followed by coalesced replacement snapshots, at most four
    /// per second. No unbounded event queue or per-byte FFI callback. Drop/close
    /// terminates observation; it does not cancel the underlying download.
    pub async fn subscribe_attachment_transfers(
        &self,
        account_ref: &str,
        group: &GroupId,
        targets: Vec<AttachmentLocalTarget>,
    ) -> Result<Arc<RuntimeAttachmentTransferSubscription>, AppError> {
        let updates = self.shared.attachment_updates.subscribe();
        let (identity, rows) = self
            .attachment_transfer_frame(account_ref, group, targets.clone())
            .await?;
        Ok(Arc::new(RuntimeAttachmentTransferSubscription {
            runtime: self.clone(),
            account: account_ref.into(),
            group: group.clone(),
            targets,
            identity,
            closed: watch::channel(false).0,
            state: Mutex::new(TransferSubscriptionState {
                updates,
                rows,
                initial: true,
                last: tokio::time::Instant::now(),
            }),
        }))
    }
}

struct TransferSubscriptionState {
    updates: watch::Receiver<()>,
    rows: Vec<Option<AttachmentTransferStatus>>,
    initial: bool,
    last: tokio::time::Instant,
}
pub struct RuntimeAttachmentTransferSubscription {
    runtime: MarmotAppRuntime,
    account: String,
    group: GroupId,
    targets: Vec<AttachmentLocalTarget>,
    identity: Vec<u8>,
    closed: watch::Sender<bool>,
    state: Mutex<TransferSubscriptionState>,
}
impl RuntimeAttachmentTransferSubscription {
    pub fn close(&self) {
        self.closed.send_replace(true);
    }
    pub async fn next(&self) -> Result<Option<Vec<Option<AttachmentTransferStatus>>>, AppError> {
        let mut closed = self.closed.subscribe();
        let mut stopping = self.runtime.shared.lifecycle().subscribe_shutdown();
        let mut state = self.state.lock().await;
        if *closed.borrow() || self.runtime.shared.lifecycle().ensure_running().is_err() {
            return Ok(None);
        }
        if state.initial {
            // A handle may sit unused across deletion or account reconstruction.
            // Revalidate before exposing its first metadata frame too.
            let (identity, rows) = self
                .runtime
                .attachment_transfer_frame(&self.account, &self.group, self.targets.clone())
                .await?;
            if identity != self.identity
                || *closed.borrow()
                || self.runtime.shared.lifecycle().ensure_running().is_err()
            {
                self.close();
                return Ok(None);
            }
            state.rows = rows;
            state.initial = false;
            state.last = tokio::time::Instant::now();
            return Ok(Some(state.rows.clone()));
        }
        loop {
            tokio::select! {
                biased;
                _ = closed.changed()=>return Ok(None),
                _ = wait_for_runtime_shutdown(&mut stopping)=>return Ok(None),
                _ = state.updates.changed()=>{},
                // Visibility/expiry and changes made by another writer need no HTTP event.
                _ = tokio::time::sleep(Duration::from_secs(1))=>{},
            }
            tokio::select! {
                biased;
                _ = closed.changed()=>return Ok(None),
                _ = wait_for_runtime_shutdown(&mut stopping)=>return Ok(None),
                _ = tokio::time::sleep_until(state.last+Duration::from_millis(250))=>{},
            }
            let (identity, rows) = self
                .runtime
                .attachment_transfer_frame(&self.account, &self.group, self.targets.clone())
                .await?;
            if identity != self.identity
                || *closed.borrow()
                || self.runtime.shared.lifecycle().ensure_running().is_err()
            {
                self.close();
                return Ok(None);
            }
            state.last = tokio::time::Instant::now();
            if rows != state.rows {
                state.rows = rows.clone();
                return Ok(Some(rows));
            }
        }
    }
}
