//! Typed individual reports and admin dismissal labels for hosts.
use crate::conversions::{SendSummaryFfi, TimelineMessageRecordFfi};
use crate::{Marmot, MarmotKitError, group_id_from_hex};
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ReportReasonFfi {
    Nudity,
    Malware,
    Profanity,
    Illegal,
    Spam,
    Impersonation,
    Other,
}
impl From<ReportReasonFfi> for marmot_app::ReportReason {
    fn from(v: ReportReasonFfi) -> Self {
        match v {
            ReportReasonFfi::Nudity => Self::Nudity,
            ReportReasonFfi::Malware => Self::Malware,
            ReportReasonFfi::Profanity => Self::Profanity,
            ReportReasonFfi::Illegal => Self::Illegal,
            ReportReasonFfi::Spam => Self::Spam,
            ReportReasonFfi::Impersonation => Self::Impersonation,
            ReportReasonFfi::Other => Self::Other,
        }
    }
}
impl From<marmot_app::ReportReason> for ReportReasonFfi {
    fn from(v: marmot_app::ReportReason) -> Self {
        match v {
            marmot_app::ReportReason::Nudity => Self::Nudity,
            marmot_app::ReportReason::Malware => Self::Malware,
            marmot_app::ReportReason::Profanity => Self::Profanity,
            marmot_app::ReportReason::Illegal => Self::Illegal,
            marmot_app::ReportReason::Spam => Self::Spam,
            marmot_app::ReportReason::Impersonation => Self::Impersonation,
            marmot_app::ReportReason::Other => Self::Other,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ContentReportFfi {
    pub report_id_hex: String,
    pub message_id_hex: String,
    pub message_author: String,
    pub reporter: String,
    pub reason: ReportReasonFfi,
    pub explanation: String,
    pub reported_at: u64,
    pub dismissed: bool,
}
impl From<marmot_app::ContentReport> for ContentReportFfi {
    fn from(v: marmot_app::ContentReport) -> Self {
        Self {
            report_id_hex: v.report_id_hex,
            message_id_hex: v.message_id_hex,
            message_author: v.message_author,
            reporter: v.reporter,
            reason: v.reason.into(),
            explanation: v.explanation,
            reported_at: v.reported_at,
            dismissed: v.dismissed,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ContentReportPageFfi {
    pub reports: Vec<ContentReportFfi>,
    pub next_cursor: Option<String>,
}
impl From<marmot_app::ContentReportPage> for ContentReportPageFfi {
    fn from(v: marmot_app::ContentReportPage) -> Self {
        Self {
            reports: v.reports.into_iter().map(Into::into).collect(),
            next_cursor: v.next_cursor,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ReportDismissalFfi {
    pub event_id_hex: String,
    pub admin: String,
    pub explanation: String,
    pub created_at: u64,
}
impl From<marmot_app::ReportDismissal> for ReportDismissalFfi {
    fn from(v: marmot_app::ReportDismissal) -> Self {
        Self {
            event_id_hex: v.event_id_hex,
            admin: v.admin,
            explanation: v.explanation,
            created_at: v.created_at,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ReportDismissalPageFfi {
    pub labels: Vec<ReportDismissalFfi>,
    pub next_cursor: Option<String>,
}
impl From<marmot_app::ReportDismissalPage> for ReportDismissalPageFfi {
    fn from(v: marmot_app::ReportDismissalPage) -> Self {
        Self {
            labels: v.labels.into_iter().map(Into::into).collect(),
            next_cursor: v.next_cursor,
        }
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    pub async fn report_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        message_id: String,
        reason: ReportReasonFfi,
        explanation: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        Ok(self
            .runtime
            .report_message(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                &message_id,
                reason.into(),
                &explanation,
            )
            .await?
            .into())
    }
    pub async fn dismiss_reports(
        &self,
        account_ref: String,
        group_id_hex: String,
        report_ids: Vec<String>,
        explanation: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        Ok(self
            .runtime
            .dismiss_reports(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                report_ids,
                &explanation,
            )
            .await?
            .into())
    }
    pub fn content_reports(
        &self,
        account_ref: String,
        group_id_hex: String,
        message_id: Option<String>,
        after: Option<String>,
        limit: u32,
    ) -> Result<ContentReportPageFfi, MarmotKitError> {
        Ok(self
            .runtime
            .content_reports(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                message_id.as_deref(),
                after.as_deref(),
                limit as usize,
            )?
            .into())
    }
    pub fn reported_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        message_id: String,
    ) -> Result<Option<TimelineMessageRecordFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .reported_message(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                &message_id,
            )?
            .map(Into::into))
    }
    pub fn report_dismissals(
        &self,
        account_ref: String,
        group_id_hex: String,
        report_id: String,
        after: Option<String>,
        limit: u32,
    ) -> Result<ReportDismissalPageFfi, MarmotKitError> {
        Ok(self
            .runtime
            .report_dismissals(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                &report_id,
                after.as_deref(),
                limit as usize,
            )?
            .into())
    }
}
