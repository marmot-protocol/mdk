//! Durable attachment policy and bounded progress snapshots.
use marmot_app as app;
#[derive(Clone, Debug, uniffi::Record)]
pub struct AttachmentDownloadPolicyFfi {
    pub automatic: bool,
    pub retained_bytes: u64,
    pub disk_reserve: u64,
    pub transfer_limit: u64,
}
impl From<app::AttachmentDownloadPolicy> for AttachmentDownloadPolicyFfi {
    fn from(p: app::AttachmentDownloadPolicy) -> Self {
        Self {
            automatic: p.automatic,
            retained_bytes: p.retained_bytes,
            disk_reserve: p.disk_reserve,
            transfer_limit: p.transfer_limit,
        }
    }
}
impl From<AttachmentDownloadPolicyFfi> for app::AttachmentDownloadPolicy {
    fn from(p: AttachmentDownloadPolicyFfi) -> Self {
        Self {
            automatic: p.automatic,
            retained_bytes: p.retained_bytes,
            disk_reserve: p.disk_reserve,
            transfer_limit: p.transfer_limit,
        }
    }
}
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum AttachmentControlFfi {
    Cancel,
    Retry,
    Remove,
}
impl From<AttachmentControlFfi> for app::AttachmentControl {
    fn from(c: AttachmentControlFfi) -> Self {
        match c {
            AttachmentControlFfi::Cancel => Self::Cancel,
            AttachmentControlFfi::Retry => Self::Retry,
            AttachmentControlFfi::Remove => Self::Remove,
        }
    }
}
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum AttachmentTransferStateFfi {
    Unavailable,
    NotRequested,
    Queued,
    Downloading,
    VerifyingCiphertext,
    Decrypting,
    VerifyingPlaintext,
    Ready,
    RetryScheduled,
    Failed,
    Cancelled,
    Paused,
    Removed,
    PolicyBlocked,
}
#[derive(Clone, uniffi::Record)]
pub struct AttachmentTransferStatusFfi {
    /// Opaque job reference, usable before bytes are ready. Account/store/source-bound.
    pub reference: Option<String>,
    pub state: AttachmentTransferStateFfi,
    /// A new HTTP body advances this generation; byte counters may then reset.
    pub attempt: u64,
    pub received: u64,
    pub total: Option<u64>,
    pub retry_at: Option<u64>,
}
impl From<Option<app::AttachmentTransferStatus>> for AttachmentTransferStatusFfi {
    fn from(value: Option<app::AttachmentTransferStatus>) -> Self {
        match value {
            None => Self {
                reference: None,
                state: AttachmentTransferStateFfi::Unavailable,
                attempt: 0,
                received: 0,
                total: None,
                retry_at: None,
            },
            Some(v) => Self {
                reference: v.reference.map(|r| r.to_opaque()),
                state: match v.state {
                    app::AttachmentTransferState::NotRequested => {
                        AttachmentTransferStateFfi::NotRequested
                    }
                    app::AttachmentTransferState::Queued => AttachmentTransferStateFfi::Queued,
                    app::AttachmentTransferState::Downloading => {
                        AttachmentTransferStateFfi::Downloading
                    }
                    app::AttachmentTransferState::VerifyingCiphertext => {
                        AttachmentTransferStateFfi::VerifyingCiphertext
                    }
                    app::AttachmentTransferState::Decrypting => {
                        AttachmentTransferStateFfi::Decrypting
                    }
                    app::AttachmentTransferState::VerifyingPlaintext => {
                        AttachmentTransferStateFfi::VerifyingPlaintext
                    }
                    app::AttachmentTransferState::Ready => AttachmentTransferStateFfi::Ready,
                    app::AttachmentTransferState::RetryScheduled => {
                        AttachmentTransferStateFfi::RetryScheduled
                    }
                    app::AttachmentTransferState::Failed => AttachmentTransferStateFfi::Failed,
                    app::AttachmentTransferState::Cancelled => {
                        AttachmentTransferStateFfi::Cancelled
                    }
                    app::AttachmentTransferState::Paused => AttachmentTransferStateFfi::Paused,
                    app::AttachmentTransferState::Removed => AttachmentTransferStateFfi::Removed,
                    app::AttachmentTransferState::PolicyBlocked => {
                        AttachmentTransferStateFfi::PolicyBlocked
                    }
                },
                attempt: v.attempt,
                received: v.received,
                total: v.total,
                retry_at: v.retry_at,
            },
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct AttachmentTransferSnapshotFfi {
    /// Complete replacement in target order, including duplicates; at most 64 entries.
    pub items: Vec<AttachmentTransferStatusFfi>,
}
impl From<Vec<Option<app::AttachmentTransferStatus>>> for AttachmentTransferSnapshotFfi {
    fn from(rows: Vec<Option<app::AttachmentTransferStatus>>) -> Self {
        Self {
            items: rows.into_iter().map(Into::into).collect(),
        }
    }
}
redact!(AttachmentTransferStatusFfi);
redact!(AttachmentTransferSnapshotFfi);
