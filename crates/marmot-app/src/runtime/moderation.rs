//! Group reporting commands and bounded live review queues.
use super::*;
use crate::{ContentReportPage, ReportReason, ReportedContentPage};

pub struct RuntimeReportedContentSubscription {
    pub snapshot: ReportedContentPage,
    storage: storage_sqlite::SqliteAccountStorage,
    account_id: String,
    group: String,
    pending_only: bool,
    limit: usize,
    events: broadcast::Receiver<MarmotAppEvent>,
    stopping: watch::Receiver<bool>,
}
impl RuntimeReportedContentSubscription {
    pub async fn recv(&mut self) -> Option<ReportedContentPage> {
        loop {
            tokio::select! {
                _ = super::wait_for_runtime_shutdown(&mut self.stopping) => return None,
                event = self.events.recv() => {
                    match event {
                        Ok(MarmotAppEvent::ProjectionUpdated(update)) if update.account_id_hex == self.account_id && update.update.group_id_hex == self.group => {},
                        Err(broadcast::error::RecvError::Lagged(_)) => {},
                        Err(broadcast::error::RecvError::Closed) => return None,
                        _ => continue,
                    }
                    let storage=self.storage.clone(); let group=self.group.clone();
                    let pending=self.pending_only; let limit=self.limit;
                    return match blocking_app_task(move || Ok(storage.reported_content(&group,pending,None,limit)?)).await {
                        Ok(page)=>Some(page),
                        Err(_)=> {
                            tracing::warn!(target:"marmot_app::moderation",method="recv","report subscription read failed");
                            None
                        }
                    };
                }
            }
        }
    }
}
impl MarmotAppRuntime {
    #[allow(clippy::too_many_arguments)]
    pub async fn report_message(
        &self,
        account_ref: &str,
        group: &GroupId,
        message_id: &str,
        revision_id: &str,
        reason: ReportReason,
        explanation: &str,
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group,
                AppMessageIntent::Report {
                    target_message_id: message_id.into(),
                    revision_id: revision_id.into(),
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
    ) -> Result<SendSummary, AppError> {
        self.accounts
            .send_app_event(
                account_ref,
                group,
                AppMessageIntent::DismissReports { report_ids },
            )
            .await
    }
    pub fn reported_content(
        &self,
        account_ref: &str,
        group: &GroupId,
        pending_only: bool,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ReportedContentPage, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        Ok(self
            .accounts
            .app
            .account_storage(&account.label)?
            .reported_content(&hex::encode(group.as_slice()), pending_only, after, limit)?)
    }
    pub fn message_reports(
        &self,
        account_ref: &str,
        group: &GroupId,
        message_id: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ContentReportPage, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        Ok(self
            .accounts
            .app
            .account_storage(&account.label)?
            .message_reports(&hex::encode(group.as_slice()), message_id, after, limit)?)
    }
    pub async fn subscribe_reported_content(
        &self,
        account_ref: &str,
        group: &GroupId,
        pending_only: bool,
        limit: usize,
    ) -> Result<RuntimeReportedContentSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let events = self.events.subscribe();
        let storage = self.accounts.app.account_storage(&account.label)?;
        let group = hex::encode(group.as_slice());
        let snapshot_storage = storage.clone();
        let snapshot_group = group.clone();
        let snapshot = blocking_app_task(move || {
            Ok(snapshot_storage.reported_content(&snapshot_group, pending_only, None, limit)?)
        })
        .await?;
        Ok(RuntimeReportedContentSubscription {
            snapshot,
            storage,
            account_id: account.account_id_hex,
            group,
            pending_only,
            limit,
            events,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
        })
    }
}
