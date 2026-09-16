//! C mirrors for individual reports and admin dismissal labels.
use crate::macros::{c_enum, c_mirror};
use marmot_uniffi::{
    ContentReportFfi, ContentReportPageFfi, ReportDismissalFfi, ReportDismissalPageFfi,
    ReportReasonFfi,
};
c_enum! { MarmotReportReason from ReportReasonFfi { Nudity, Malware, Profanity, Illegal, Spam, Impersonation, Other } }
c_mirror! { MarmotContentReport from ContentReportFfi {
    str report_id_hex,
    str message_id_hex,
    str message_author,
    str reporter,
    enum_val reason: MarmotReportReason,
    str explanation,
    copy reported_at: u64,
    copy dismissed: bool,
} }
c_mirror! { MarmotContentReportPage from ContentReportPageFfi, free marmot_content_report_page_free {
    vec reports/reports_len: MarmotContentReport,
    opt_str next_cursor,
} }
c_mirror! { MarmotReportDismissal from ReportDismissalFfi {
    str event_id_hex,
    str admin,
    str explanation,
    copy created_at: u64,
} }
c_mirror! { MarmotReportDismissalPage from ReportDismissalPageFfi, free marmot_report_dismissal_page_free {
    vec labels/labels_len: MarmotReportDismissal,
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
    fn individual_report_and_label_pages_deep_free() {
        let _guard = audit::test_lock();
        let before = audit::live_allocations();
        assert!(MarmotReportReason::from_c(u32::MAX).is_err());
        let reports = boxed(MarmotContentReportPage::from(ContentReportPageFfi {
            next_cursor: Some("cursor".into()),
            reports: vec![ContentReportFfi {
                report_id_hex: "report".into(),
                message_id_hex: "message".into(),
                message_author: "author".into(),
                reporter: "reporter".into(),
                reason: ReportReasonFfi::Other,
                explanation: "details".into(),
                reported_at: 1,
                dismissed: true,
            }],
        }));
        let labels = boxed(MarmotReportDismissalPage::from(ReportDismissalPageFfi {
            next_cursor: Some("cursor".into()),
            labels: vec![ReportDismissalFfi {
                event_id_hex: "label".into(),
                admin: "admin".into(),
                explanation: "reviewed".into(),
                created_at: 2,
            }],
        }));
        unsafe {
            marmot_content_report_page_free(reports);
            marmot_report_dismissal_page_free(labels);
            marmot_content_report_page_free(std::ptr::null_mut());
            marmot_report_dismissal_page_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
