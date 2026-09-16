//! Reports and admin labels carried through the ordinary group-message runtime.
use super::*;
use crate::{ContentReportPage, ReportDismissalPage, ReportReason};

impl MarmotAppRuntime {
    pub async fn report_message(
        &self,
        account_ref: &str,
        group: &GroupId,
        message_id: &str,
        reason: ReportReason,
        explanation: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group,
                AppMessageIntent::Report {
                    target_message_id: message_id.into(),
                    reason,
                    explanation: explanation.into(),
                    target_author: None,
                },
            )
            .await
    }
    pub async fn dismiss_reports(
        &self,
        account_ref: &str,
        group: &GroupId,
        report_ids: Vec<String>,
        explanation: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group,
                AppMessageIntent::DismissReports {
                    report_ids,
                    explanation: explanation.into(),
                },
            )
            .await
    }
    /// List individual reports, optionally restricted to one message. No grouping
    /// or shared queue policy is imposed on the client.
    pub fn content_reports(
        &self,
        account_ref: &str,
        group: &GroupId,
        message_id: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ContentReportPage, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        Ok(self
            .accounts
            .app
            .account_storage(&account.label)?
            .content_reports(&hex::encode(group.as_slice()), message_id, after, limit)?)
    }
    pub fn reported_message(
        &self,
        account_ref: &str,
        group: &GroupId,
        message_id: &str,
    ) -> Result<Option<crate::TimelineMessageRecord>, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        Ok(self
            .accounts
            .app
            .account_storage(&account.label)?
            .reported_message(&hex::encode(group.as_slice()), message_id)?)
    }
    /// Each authorized admin label is returned independently; no winner is chosen.
    pub fn report_dismissals(
        &self,
        account_ref: &str,
        group: &GroupId,
        report_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ReportDismissalPage, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        Ok(self
            .accounts
            .app
            .account_storage(&account.label)?
            .report_dismissals(&hex::encode(group.as_slice()), report_id, after, limit)?)
    }
}
