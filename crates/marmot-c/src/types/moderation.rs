//! C mirrors for encrypted group reports and review outcomes.
use super::timeline::{MarmotTimelineMessageRecord, MarmotTimelineReplyPreview};
use crate::macros::{c_enum, c_mirror};
use marmot_uniffi::{
    ContentReportFfi, ContentReportPageFfi, MessageModerationSummaryFfi, ModerationStatusFfi,
    ReportReasonFfi, ReportedContentFfi, ReportedContentPageFfi,
};
c_enum! { MarmotReportReason from ReportReasonFfi { Nudity, Malware, Profanity, Illegal, Spam, Impersonation, Other } }
c_enum! { MarmotModerationStatus from ModerationStatusFfi { Unreported, Pending, Reviewed, Removed } }
c_mirror! { MarmotMessageModerationSummary from MessageModerationSummaryFfi {
    enum_val status: MarmotModerationStatus,
    copy total_reports: u64,
    copy pending_reports: u64,
} }
c_mirror! { MarmotReportedContent from ReportedContentFfi {
    str message_id_hex,
    str revision_id_hex,
    rec moderation: MarmotMessageModerationSummary,
} }
c_mirror! { MarmotReportedContentPage from ReportedContentPageFfi, free marmot_reported_content_page_free {
    vec items/items_len: MarmotReportedContent,
    opt_str next_cursor,
    copy pending_message_count: u64,
} }
c_mirror! { MarmotContentReport from ContentReportFfi {
    str report_id_hex,
    str message_id_hex,
    str revision_id_hex,
    str reporter,
    enum_val reason: MarmotReportReason,
    str explanation,
    copy reported_at: u64,
    opt_str dismissed_by_event_id,
    opt_str reviewing_admin,
    opt_str reported_text,
    opt_rec reported_revision: MarmotTimelineReplyPreview,
} }
c_mirror! { MarmotContentReportPage from ContentReportPageFfi, free marmot_content_report_page_free {
    opt_str removed_by_event_id,
    opt_str removing_account,
    opt_copy has_removed_at/removed_at: u64,
    opt_rec current_message: MarmotTimelineMessageRecord,
    vec reports/reports_len: MarmotContentReport,
    opt_str next_cursor,
} }

impl MarmotReportReason {
    pub(crate) fn to_ffi(self) -> ReportReasonFfi {
        match self {
            Self::Nudity => ReportReasonFfi::Nudity,
            Self::Malware => ReportReasonFfi::Malware,
            Self::Profanity => ReportReasonFfi::Profanity,
            Self::Illegal => ReportReasonFfi::Illegal,
            Self::Spam => ReportReasonFfi::Spam,
            Self::Impersonation => ReportReasonFfi::Impersonation,
            Self::Other => ReportReasonFfi::Other,
        }
    }
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};
    #[test]
    fn report_pages_deep_free_and_reason_validation() {
        let _guard = audit::test_lock();
        let before = audit::live_allocations();
        assert!(MarmotReportReason::from_c(u32::MAX).is_err());
        let reports = boxed(MarmotContentReportPage::from(ContentReportPageFfi {
            removed_by_event_id: Some("delete".into()),
            removing_account: Some("admin".into()),
            removed_at: Some(1),
            current_message: None,
            next_cursor: Some("cursor".into()),
            reports: vec![ContentReportFfi {
                report_id_hex: "report".into(),
                message_id_hex: "message".into(),
                revision_id_hex: "revision".into(),
                reporter: "member".into(),
                reason: ReportReasonFfi::Other,
                explanation: "explanation".into(),
                reported_at: 1,
                dismissed_by_event_id: Some("decision".into()),
                reviewing_admin: Some("admin".into()),
                reported_text: Some("text".into()),
                reported_revision: None,
            }],
        }));
        let queue = boxed(MarmotReportedContentPage::from(ReportedContentPageFfi {
            next_cursor: None,
            pending_message_count: 1,
            items: vec![ReportedContentFfi {
                message_id_hex: "message".into(),
                revision_id_hex: "edit".into(),
                moderation: MessageModerationSummaryFfi {
                    status: ModerationStatusFfi::Pending,
                    total_reports: 1,
                    pending_reports: 1,
                },
            }],
        }));
        unsafe {
            marmot_content_report_page_free(reports);
            marmot_reported_content_page_free(queue);
            marmot_content_report_page_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
