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
    PreviouslyAcquiredUnavailable,
    CompletedUnretained,
    RetryExhausted,
    /// Free disk cannot cover the publication reserve; checkpoints are kept and
    /// the job readmits once space frees or on explicit Retry.
    StorageBlocked,
    /// The account's "Keep media" setting removed the body because the
    /// message is older than its window. Download again is allowed, as for
    /// `Removed`.
    CleanedBySetting,
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
                    app::AttachmentTransferState::PreviouslyAcquiredUnavailable => {
                        AttachmentTransferStateFfi::PreviouslyAcquiredUnavailable
                    }
                    app::AttachmentTransferState::CompletedUnretained => {
                        AttachmentTransferStateFfi::CompletedUnretained
                    }
                    app::AttachmentTransferState::RetryExhausted => {
                        AttachmentTransferStateFfi::RetryExhausted
                    }
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
                    app::AttachmentTransferState::StorageBlocked => {
                        AttachmentTransferStateFfi::StorageBlocked
                    }
                    app::AttachmentTransferState::CleanedBySetting => {
                        AttachmentTransferStateFfi::CleanedBySetting
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

/// Select before runtime startup; HostManaged never discovers demand autonomously.
#[derive(Debug, Clone, Copy, Default, uniffi::Enum)]
pub enum AttachmentAcquisitionModeFfi {
    #[default]
    NativeAutomatic,
    HostManaged,
}
impl From<AttachmentAcquisitionModeFfi> for app::AttachmentAcquisitionMode {
    fn from(mode: AttachmentAcquisitionModeFfi) -> Self {
        match mode {
            AttachmentAcquisitionModeFfi::NativeAutomatic => Self::NativeAutomatic,
            AttachmentAcquisitionModeFfi::HostManaged => Self::HostManaged,
        }
    }
}
#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct AttachmentAutomaticPermissionFfi {
    pub images: bool,
    pub videos: bool,
    pub audio: bool,
    pub files: bool,
}
impl From<AttachmentAutomaticPermissionFfi> for app::AttachmentAutomaticPermission {
    fn from(p: AttachmentAutomaticPermissionFfi) -> Self {
        Self {
            images: p.images,
            videos: p.videos,
            audio: p.audio,
            files: p.files,
        }
    }
}
#[derive(Debug, Clone, uniffi::Record)]
pub struct AutomaticAttachmentRequestFfi {
    pub status: AttachmentTransferStatusFfi,
    pub newly_queued: bool,
}
impl From<app::AutomaticAttachmentRequest> for AutomaticAttachmentRequestFfi {
    fn from(r: app::AutomaticAttachmentRequest) -> Self {
        Self {
            status: r.status.into(),
            newly_queued: r.newly_queued,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCATOR: &str = "1:00112233445566778899aabbccddeeff:ffeeddccbbaa99887766554433221100";

    #[test]
    fn transfer_states_remain_distinct_from_an_unavailable_source() {
        type IsState = fn(AttachmentTransferStateFfi) -> bool;
        let missing = AttachmentTransferStatusFfi::from(None);
        assert!(matches!(
            missing.state,
            AttachmentTransferStateFfi::Unavailable
        ));
        assert!(missing.reference.is_none());
        assert_eq!(
            (
                missing.attempt,
                missing.received,
                missing.total,
                missing.retry_at
            ),
            (0, 0, None, None)
        );
        let cases: [(app::AttachmentTransferState, IsState); 18] = [
            (app::AttachmentTransferState::NotRequested, |v| {
                matches!(v, AttachmentTransferStateFfi::NotRequested)
            }),
            (app::AttachmentTransferState::Queued, |v| {
                matches!(v, AttachmentTransferStateFfi::Queued)
            }),
            (app::AttachmentTransferState::Downloading, |v| {
                matches!(v, AttachmentTransferStateFfi::Downloading)
            }),
            (app::AttachmentTransferState::VerifyingCiphertext, |v| {
                matches!(v, AttachmentTransferStateFfi::VerifyingCiphertext)
            }),
            (app::AttachmentTransferState::Decrypting, |v| {
                matches!(v, AttachmentTransferStateFfi::Decrypting)
            }),
            (app::AttachmentTransferState::VerifyingPlaintext, |v| {
                matches!(v, AttachmentTransferStateFfi::VerifyingPlaintext)
            }),
            (app::AttachmentTransferState::Ready, |v| {
                matches!(v, AttachmentTransferStateFfi::Ready)
            }),
            (app::AttachmentTransferState::RetryScheduled, |v| {
                matches!(v, AttachmentTransferStateFfi::RetryScheduled)
            }),
            (app::AttachmentTransferState::Failed, |v| {
                matches!(v, AttachmentTransferStateFfi::Failed)
            }),
            (app::AttachmentTransferState::Cancelled, |v| {
                matches!(v, AttachmentTransferStateFfi::Cancelled)
            }),
            (app::AttachmentTransferState::Paused, |v| {
                matches!(v, AttachmentTransferStateFfi::Paused)
            }),
            (app::AttachmentTransferState::Removed, |v| {
                matches!(v, AttachmentTransferStateFfi::Removed)
            }),
            (app::AttachmentTransferState::PolicyBlocked, |v| {
                matches!(v, AttachmentTransferStateFfi::PolicyBlocked)
            }),
            (
                app::AttachmentTransferState::PreviouslyAcquiredUnavailable,
                |v| matches!(v, AttachmentTransferStateFfi::PreviouslyAcquiredUnavailable),
            ),
            (app::AttachmentTransferState::CompletedUnretained, |v| {
                matches!(v, AttachmentTransferStateFfi::CompletedUnretained)
            }),
            (app::AttachmentTransferState::RetryExhausted, |v| {
                matches!(v, AttachmentTransferStateFfi::RetryExhausted)
            }),
            (app::AttachmentTransferState::StorageBlocked, |v| {
                matches!(v, AttachmentTransferStateFfi::StorageBlocked)
            }),
            (app::AttachmentTransferState::CleanedBySetting, |v| {
                matches!(v, AttachmentTransferStateFfi::CleanedBySetting)
            }),
        ];
        for (state, expected) in cases {
            // These three source-visible states have no acquisition row/locator.
            let no_job = matches!(
                state,
                app::AttachmentTransferState::NotRequested
                    | app::AttachmentTransferState::Removed
                    | app::AttachmentTransferState::CleanedBySetting
            );
            let value = AttachmentTransferStatusFfi::from(Some(app::AttachmentTransferStatus {
                reference: (!no_job)
                    .then(|| app::AttachmentAssetRef::from_opaque(LOCATOR).unwrap()),
                automatic_media_type: no_job.then(|| "image/png".into()),
                state,
                attempt: 0,
                received: 0,
                total: None,
                retry_at: None,
            }));
            assert!(expected(value.state), "wrong host state for {state:?}");
        }
    }

    #[test]
    fn retry_status_keeps_its_locator_and_progress_context() {
        let value = AttachmentTransferStatusFfi::from(Some(app::AttachmentTransferStatus {
            reference: Some(app::AttachmentAssetRef::from_opaque(LOCATOR).unwrap()),
            automatic_media_type: None,
            state: app::AttachmentTransferState::RetryScheduled,
            attempt: 3,
            received: 23,
            total: Some(47),
            retry_at: Some(71),
        }));
        assert_eq!(value.reference.as_deref(), Some(LOCATOR));
        assert!(matches!(
            value.state,
            AttachmentTransferStateFfi::RetryScheduled
        ));
        assert_eq!(
            (value.attempt, value.received, value.total, value.retry_at),
            (3, 23, Some(47), Some(71))
        );
    }

    #[test]
    fn transfer_controls_select_the_native_action() {
        assert!(matches!(
            app::AttachmentControl::from(AttachmentControlFfi::Cancel),
            app::AttachmentControl::Cancel
        ));
        assert!(matches!(
            app::AttachmentControl::from(AttachmentControlFfi::Retry),
            app::AttachmentControl::Retry
        ));
        assert!(matches!(
            app::AttachmentControl::from(AttachmentControlFfi::Remove),
            app::AttachmentControl::Remove
        ));
    }
}
