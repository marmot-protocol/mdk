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
        unsafe { result.free_in_place() };
        for status in [
            LocalSendStatusFfi::Queued,
            LocalSendStatusFfi::EngineOwned,
            LocalSendStatusFfi::Rejected,
        ] {
            let mut mirror = MarmotLocalSendStatus::from(status);
            assert!(mirror.summary.is_null());
            unsafe { mirror.free_in_place() };
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }
}
