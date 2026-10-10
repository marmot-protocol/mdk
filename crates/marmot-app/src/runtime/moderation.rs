//! Reports and admin labels carried through the ordinary group-message runtime.
use super::*;
use crate::{
    ContentReportPage, ModerationReportOrigin, ModerationReportOutcome,
    ModerationReportRetrySummary, ReportDismissalPage, ReportReason,
};

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

    /// Privately report `reported_pubkey` to the configured moderation team, gift-wrapped
    /// per NIP-59. Additive to [`Self::report_message`], which stays the in-group path.
    /// The report carries no conversation identifiers; see `crate::moderation_reports`.
    pub async fn submit_moderation_report(
        &self,
        account_ref: &str,
        reported_pubkey: &str,
        reason: ReportReason,
        explanation: &str,
        origin: ModerationReportOrigin,
    ) -> Result<ModerationReportOutcome, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .submit_moderation_report(
                &account.label,
                reported_pubkey,
                reason,
                explanation,
                origin,
                Some(self.shared.lifecycle().subscribe_shutdown()),
            )
            .await
    }

    /// Whether a valid moderation-report destination is installed.
    pub fn moderation_reporting_available(&self) -> bool {
        self.accounts.app.moderation_reporting_available()
    }

    /// Retry one account's queued moderation reports now. Catch-up does this
    /// automatically in the background.
    pub async fn retry_pending_moderation_reports(
        &self,
        account_ref: &str,
    ) -> Result<ModerationReportRetrySummary, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        self.accounts
            .app
            .retry_pending_moderation_reports(
                &account.label,
                Some(self.shared.lifecycle().subscribe_shutdown()),
            )
            .await
    }

    /// Start a background retry for every signed-in account with queued reports.
    /// Each pass stops at runtime shutdown or when its account signs out.
    pub(crate) fn spawn_moderation_report_retries(&self) {
        if self.shared.lifecycle().ensure_running().is_err() {
            return;
        }
        let app = self.accounts.app.clone();
        let Ok(accounts) = app.account_home().accounts() else {
            return;
        };
        for account in accounts {
            if !account.can_sign()
                || account.signed_out
                || !app.has_pending_moderation_reports(&account.label)
            {
                continue;
            }
            let app = app.clone();
            let stopping = self.shared.lifecycle().subscribe_shutdown();
            tokio::spawn(async move {
                if let Err(error) = app
                    .retry_pending_moderation_reports(&account.label, Some(stopping))
                    .await
                {
                    tracing::warn!(
                        target: "marmot_app::runtime",
                        method = "spawn_moderation_report_retries",
                        error_kind = error.privacy_safe_kind(),
                        "moderation report retry pass failed"
                    );
                }
            });
        }
    }

    pub(crate) async fn purge_moderation_reports_best_effort(&self, label: &str, method: &str) {
        if let Err(error) = self.accounts.app.purge_moderation_reports(label).await {
            tracing::warn!(
                target: "marmot_app::runtime",
                method,
                error_kind = error.privacy_safe_kind(),
                "failed to purge queued moderation reports"
            );
        }
    }
}
