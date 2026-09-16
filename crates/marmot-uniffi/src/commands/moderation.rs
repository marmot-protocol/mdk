//! Typed reporting and shared review for Swift and Kotlin hosts.
use crate::conversions::SendSummaryFfi;
use crate::{Marmot, MarmotKitError, group_id_from_hex};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;

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
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ModerationStatusFfi {
    Unreported,
    Pending,
    Reviewed,
    Removed,
}
impl From<marmot_app::ModerationStatus> for ModerationStatusFfi {
    fn from(v: marmot_app::ModerationStatus) -> Self {
        match v {
            marmot_app::ModerationStatus::Unreported => Self::Unreported,
            marmot_app::ModerationStatus::Pending => Self::Pending,
            marmot_app::ModerationStatus::Reviewed => Self::Reviewed,
            marmot_app::ModerationStatus::Removed => Self::Removed,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct MessageModerationSummaryFfi {
    pub status: ModerationStatusFfi,
    pub total_reports: u64,
    pub pending_reports: u64,
}
impl From<marmot_app::MessageModerationSummary> for MessageModerationSummaryFfi {
    fn from(v: marmot_app::MessageModerationSummary) -> Self {
        Self {
            status: v.status.into(),
            total_reports: v.total_reports,
            pending_reports: v.pending_reports,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ReportedContentFfi {
    pub message_id_hex: String,
    pub revision_id_hex: String,
    pub moderation: MessageModerationSummaryFfi,
}
impl From<marmot_app::ReportedContent> for ReportedContentFfi {
    fn from(v: marmot_app::ReportedContent) -> Self {
        Self {
            message_id_hex: v.message_id_hex,
            revision_id_hex: v.revision_id_hex,
            moderation: v.moderation.into(),
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ReportedContentPageFfi {
    pub items: Vec<ReportedContentFfi>,
    pub next_cursor: Option<String>,
    pub pending_message_count: u64,
}
impl From<marmot_app::ReportedContentPage> for ReportedContentPageFfi {
    fn from(v: marmot_app::ReportedContentPage) -> Self {
        Self {
            items: v.items.into_iter().map(Into::into).collect(),
            next_cursor: v.next_cursor,
            pending_message_count: v.pending_message_count,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ContentReportFfi {
    pub report_id_hex: String,
    pub message_id_hex: String,
    pub revision_id_hex: String,
    pub reporter: String,
    pub reason: ReportReasonFfi,
    pub explanation: String,
    pub reported_at: u64,
    pub dismissed_by_event_id: Option<String>,
    pub reviewing_admin: Option<String>,
    pub reported_text: Option<String>,
    pub reported_revision: Option<crate::conversions::TimelineReplyPreviewFfi>,
}
impl From<marmot_app::ContentReport> for ContentReportFfi {
    fn from(v: marmot_app::ContentReport) -> Self {
        Self {
            report_id_hex: v.report_id_hex,
            message_id_hex: v.message_id_hex,
            revision_id_hex: v.revision_id_hex,
            reporter: v.reporter,
            reason: v.reason.into(),
            explanation: v.explanation,
            reported_at: v.reported_at,
            dismissed_by_event_id: v.dismissed_by_event_id,
            reviewing_admin: v.reviewing_admin,
            reported_text: v.reported_text,
            reported_revision: v.reported_revision.map(Into::into),
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ContentReportPageFfi {
    pub removed_by_event_id: Option<String>,
    pub removing_account: Option<String>,
    pub removed_at: Option<u64>,
    pub current_message: Option<crate::TimelineMessageRecordFfi>,
    pub reports: Vec<ContentReportFfi>,
    pub next_cursor: Option<String>,
}
impl From<marmot_app::ContentReportPage> for ContentReportPageFfi {
    fn from(v: marmot_app::ContentReportPage) -> Self {
        Self {
            removed_by_event_id: v.removed_by_event_id,
            removing_account: v.removing_account,
            removed_at: v.removed_at,
            current_message: v.current_message.map(Into::into),
            reports: v.reports.into_iter().map(Into::into).collect(),
            next_cursor: v.next_cursor,
        }
    }
}
#[derive(uniffi::Object)]
pub struct ReportedContentSubscription {
    snapshot: StdMutex<Option<ReportedContentPageFfi>>,
    inner: Mutex<marmot_app::RuntimeReportedContentSubscription>,
}
#[uniffi::export(async_runtime = "tokio")]
impl ReportedContentSubscription {
    pub fn snapshot(&self) -> Option<ReportedContentPageFfi> {
        self.snapshot.lock().ok()?.take()
    }
    pub async fn next(&self) -> Option<ReportedContentPageFfi> {
        self.inner.lock().await.recv().await.map(Into::into)
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    #[allow(clippy::too_many_arguments)]
    pub async fn report_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        message_id: String,
        revision_id: String,
        reason: ReportReasonFfi,
        explanation: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        Ok(self
            .runtime
            .report_message(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                &message_id,
                &revision_id,
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
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        Ok(self
            .runtime
            .dismiss_reports(&account_ref, &group_id_from_hex(&group_id_hex)?, report_ids)
            .await?
            .into())
    }
    pub fn reported_content(
        &self,
        account_ref: String,
        group_id_hex: String,
        pending_only: bool,
        after: Option<String>,
        limit: u32,
    ) -> Result<ReportedContentPageFfi, MarmotKitError> {
        Ok(self
            .runtime
            .reported_content(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                pending_only,
                after.as_deref(),
                limit as usize,
            )?
            .into())
    }
    pub fn message_reports(
        &self,
        account_ref: String,
        group_id_hex: String,
        message_id: String,
        after: Option<String>,
        limit: u32,
    ) -> Result<ContentReportPageFfi, MarmotKitError> {
        Ok(self
            .runtime
            .message_reports(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                &message_id,
                after.as_deref(),
                limit as usize,
            )?
            .into())
    }
    pub async fn subscribe_reported_content(
        &self,
        account_ref: String,
        group_id_hex: String,
        pending_only: bool,
        limit: u32,
    ) -> Result<Arc<ReportedContentSubscription>, MarmotKitError> {
        let inner = self
            .runtime
            .subscribe_reported_content(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                pending_only,
                limit as usize,
            )
            .await?;
        let snapshot = Some(inner.snapshot.clone().into());
        Ok(Arc::new(ReportedContentSubscription {
            snapshot: StdMutex::new(snapshot),
            inner: Mutex::new(inner),
        }))
    }
}
