//! Historical slot access through the native acquisition and handoff pipeline.
use std::sync::Arc;

use agent_control::{
    AgentControlAttachment, AgentControlAttachmentHandoff, AgentControlAttachmentState,
    AgentControlResponse,
};
use cgka_traits::GroupId;
use marmot_app::{AttachmentLocalTarget, AttachmentTransferState, MediaFileTransferControl};

use crate::validation::normalize_hex;
use crate::{AgentConnector, ConnectorError};

impl AgentConnector {
    pub(crate) async fn attachment_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        message_id_hex: &str,
        attachment_index: u32,
        download: bool,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let unavailable = || AgentControlResponse::Attachment { attachment: None };
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let message_id_hex = normalize_hex(message_id_hex)?;
        let Some(row) =
            self.runtime
                .timeline_message(&account.label, &group_id_hex, &message_id_hex)?
        else {
            return Ok(unavailable());
        };
        if row.deleted || row.invalidation_status.is_some() {
            return Ok(unavailable());
        }
        let Some(source_message_id_hex) = row.source_message_id_hex else {
            return Ok(unavailable());
        };
        let target = AttachmentLocalTarget {
            message_id_hex,
            source_message_id_hex: source_message_id_hex.clone(),
            attachment_index,
        };
        let group = GroupId::new(hex::decode(&group_id_hex)?);
        // Native status revalidates source visibility, group membership, original
        // slot, source generation and expiry, even when a timeline row is retained.
        let Some(mut status) = self
            .runtime
            .attachment_transfer_snapshot(&account.label, &group, vec![target.clone()])
            .await?
            .remove(0)
        else {
            return Ok(unavailable());
        };
        let Some(tag) = row
            .tags
            .iter()
            .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
            .nth(attachment_index as usize)
        else {
            return Ok(unavailable());
        };
        let reference = marmot_app::parse_media_attachment(
            tag,
            row.source_epoch,
            self.app.allow_loopback_blob_endpoints(),
        )
        .map_err(ConnectorError::AttachmentRejected)?;
        row.source_epoch
            .ok_or(ConnectorError::AttachmentEpochUnavailable)?;
        if download {
            if self
                .runtime
                .request_explicit_attachment(&account.label, &group, target.clone())
                .await?
                .is_none()
            {
                return Ok(unavailable());
            }
            let Some(current) = self
                .runtime
                .attachment_transfer_snapshot(&account.label, &group, vec![target.clone()])
                .await?
                .remove(0)
            else {
                return Ok(unavailable());
            };
            status = current;
        }
        let locally_available = self
            .runtime
            .attachment_local_assets(&account.label, &group, vec![target.clone()])
            .await?
            .remove(0)
            .is_some();
        let handoff = if download && locally_available {
            let Some(copy) = self
                .runtime
                .open_attachment_handoff(
                    &account.label,
                    &group,
                    target,
                    Arc::new(MediaFileTransferControl::default()),
                )
                .await?
            else {
                return Ok(unavailable());
            };
            Some(AgentControlAttachmentHandoff {
                lease: copy.lease,
                path: copy.path.to_string_lossy().into_owned(),
                size_bytes: copy.byte_count,
            })
        } else {
            None
        };
        Ok(AgentControlResponse::Attachment {
            attachment: Some(AgentControlAttachment {
                source_message_id_hex,
                attachment_index,
                source_epoch: reference.source_epoch,
                plaintext_sha256: reference.plaintext_sha256,
                ciphertext_sha256: reference.ciphertext_sha256,
                state: transfer_state(status.state),
                locally_available,
                retry_at: status.retry_at,
                failure_hint: failure_hint(status.state).map(str::to_owned),
                handoff,
            }),
        })
    }
}

fn transfer_state(state: AttachmentTransferState) -> AgentControlAttachmentState {
    use AgentControlAttachmentState as Wire;
    use AttachmentTransferState as Native;
    match state {
        Native::NotRequested => Wire::NotRequested,
        Native::Queued => Wire::Queued,
        Native::Downloading => Wire::Downloading,
        Native::VerifyingCiphertext => Wire::VerifyingCiphertext,
        Native::Decrypting => Wire::Decrypting,
        Native::VerifyingPlaintext => Wire::VerifyingPlaintext,
        Native::Ready => Wire::Ready,
        Native::RetryScheduled => Wire::RetryScheduled,
        Native::Failed => Wire::Failed,
        Native::Cancelled => Wire::Cancelled,
        Native::Paused => Wire::Paused,
        Native::Removed => Wire::Removed,
        Native::PolicyBlocked => Wire::PolicyBlocked,
        Native::PreviouslyAcquiredUnavailable => Wire::PreviouslyAcquiredUnavailable,
        Native::CompletedUnretained => Wire::CompletedUnretained,
        Native::RetryExhausted => Wire::RetryExhausted,
        Native::StorageBlocked => Wire::StorageBlocked,
        Native::CleanedBySetting => Wire::CleanedBySetting,
    }
}

fn failure_hint(state: AttachmentTransferState) -> Option<&'static str> {
    use AttachmentTransferState::*;
    match state {
        Failed | RetryExhausted => Some(
            "Native acquisition failed. Check transport availability and the original epoch key in MDK; an unavailable old key cannot be reconstructed by this API. Repeated requests do not reset native retry limits.",
        ),
        PolicyBlocked | Paused => Some(
            "Native acquisition is blocked or paused. Review account media permissions and group policy in MDK.",
        ),
        Removed | CleanedBySetting | PreviouslyAcquiredUnavailable | CompletedUnretained => Some(
            "No retained body is available. Use MDK's explicit Download again control if recovery is wanted.",
        ),
        StorageBlocked => Some("Free disk space for native acquisition, then retry."),
        Cancelled => Some("Acquisition was cancelled. Use MDK's explicit Retry control to resume."),
        _ => None,
    }
}

/// Own a reply's lease until its complete frame has been written. A failed,
/// oversized or cancelled write must not strand an unreachable plaintext copy.
pub(crate) struct AttachmentReplyLease {
    runtime: marmot_app::MarmotAppRuntime,
    lease: Option<String>,
}

impl AttachmentReplyLease {
    pub(crate) fn new(
        runtime: marmot_app::MarmotAppRuntime,
        response: &AgentControlResponse,
    ) -> Self {
        let lease = match response {
            AgentControlResponse::Attachment {
                attachment: Some(attachment),
            } => attachment.handoff.as_ref().map(|copy| copy.lease.clone()),
            _ => None,
        };
        Self { runtime, lease }
    }

    pub(crate) fn delivered(&mut self) {
        self.lease = None;
    }
}

impl Drop for AttachmentReplyLease {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            let runtime = self.runtime.clone();
            tokio::spawn(async move {
                if runtime.release_attachment_handoff(&lease).await.is_err() {
                    tracing::warn!(target: "agent_connector", method = "discard_attachment_reply", "attachment handoff cleanup failed");
                }
            });
        }
    }
}
