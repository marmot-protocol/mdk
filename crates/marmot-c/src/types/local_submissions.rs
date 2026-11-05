use super::{account::MarmotSendSummary, media::MarmotMediaUploadResult};
use crate::macros::c_mirror;
use marmot_uniffi::{LocalSendAcceptanceFfi, LocalSendStatusFfi, MediaUploadSubmissionFfi};

c_mirror! {
    /// Durable local acceptance, not a relay acknowledgment.
    MarmotLocalSendAcceptance from LocalSendAcceptanceFfi,
    free marmot_local_send_acceptance_free {
        str client_token,
        str message_id_hex,
    }
}

c_mirror! {
    /// Uploaded references and optional durable message acceptance.
    MarmotMediaUploadSubmission from MediaUploadSubmissionFfi,
    free marmot_media_upload_submission_free {
        rec upload: MarmotMediaUploadResult,
        opt_rec acceptance: MarmotLocalSendAcceptance,
    }
}

struct StatusFields {
    state: u32,
    summary: Option<marmot_uniffi::conversions::SendSummaryFfi>,
}
c_mirror! {
    /// Local submission status: 0 queued, 1 engine-owned, 2 completed, 3 rejected.
    /// Summary is present only for completed attempts; inspect its disposition.
    MarmotLocalSendStatus from StatusFields,
    free marmot_local_send_status_free {
        copy state: u32,
        opt_rec summary: MarmotSendSummary,
    }
}
impl From<LocalSendStatusFfi> for MarmotLocalSendStatus {
    fn from(value: LocalSendStatusFfi) -> Self {
        let (state, summary) = match value {
            LocalSendStatusFfi::Queued => (0, None),
            LocalSendStatusFfi::EngineOwned => (1, None),
            LocalSendStatusFfi::Completed { summary } => (2, Some(summary)),
            LocalSendStatusFfi::Rejected => (3, None),
        };
        StatusFields { state, summary }.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::CFree;

    #[test]
    fn local_submission_records_deep_free_owned_tokens() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        let mut result = MarmotMediaUploadSubmission::from(MediaUploadSubmissionFfi {
            upload: marmot_uniffi::conversions::MediaUploadResultFfi {
                attachments: vec![],
                sent: None,
            },
            acceptance: Some(LocalSendAcceptanceFfi {
                client_token: "opaque-token".into(),
                message_id_hex: "aa".repeat(32),
            }),
        });
        assert!(!result.acceptance.is_null());
        let acceptance = unsafe { &*result.acceptance };
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(acceptance.client_token) }.to_bytes(),
            b"opaque-token"
        );
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(acceptance.message_id_hex) }
                .to_str()
                .unwrap(),
            "aa".repeat(32)
        );
        unsafe { result.free_in_place() };
        for (expected, status) in [
            LocalSendStatusFfi::Queued,
            LocalSendStatusFfi::EngineOwned,
            LocalSendStatusFfi::Completed { summary: marmot_uniffi::conversions::SendSummaryFfi {
                published: 2,
                message_ids: vec!["bb".repeat(32)],
                accept_disposition: marmot_uniffi::conversions::SendAcceptDispositionFfi::AcceptedPending,
                maintenance_disposition: marmot_uniffi::conversions::SendMaintenanceDispositionFfi::PostJoinRotationPendingRetryable,
            } },
            LocalSendStatusFfi::Rejected,
        ].into_iter().enumerate() {
            let mut mirror = MarmotLocalSendStatus::from(status);
            assert_eq!(mirror.state, expected as u32);
            if expected == 2 {
                assert!(!mirror.summary.is_null());
                let summary = unsafe { &*mirror.summary };
                assert_eq!(summary.published, 2);
                assert_eq!(summary.message_ids_len, 1);
                assert_eq!(unsafe { std::ffi::CStr::from_ptr(*summary.message_ids) }.to_str().unwrap(), "bb".repeat(32));
                assert_eq!(summary.accept_disposition, crate::types::account::MarmotSendAcceptDisposition::AcceptedPending);
                assert_eq!(summary.maintenance_disposition, crate::types::account::MarmotSendMaintenanceDisposition::PostJoinRotationPendingRetryable);
            } else {
                assert!(mirror.summary.is_null());
            }
            unsafe { mirror.free_in_place() };
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }
}
