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
                    let storage = self.storage.clone();
                    let group = self.group.clone();
                    let pending = self.pending_only;
                    let limit = self.limit;
                    match blocking_app_task(move || {
                        Ok(storage.reported_content(&group, pending, None, limit)?)
                    }).await {
                        Ok(page) => return Some(page),
                        Err(_) => {
                            tracing::warn!(
                                target: "marmot_app::moderation",
                                method = "recv",
                                "report subscription read failed"
                            );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn report_subscription_survives_read_failure_and_stops_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reports.sqlite");
        let key = storage_sqlite::SqlCipherKey::new("subscription test key").unwrap();
        let storage = storage_sqlite::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &connection,
            &key,
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        let (events, receiver) = broadcast::channel(1);
        let (stopping, shutdown) = watch::channel(false);
        let mut subscription = RuntimeReportedContentSubscription {
            snapshot: storage.reported_content("aa", true, None, 10).unwrap(),
            storage,
            account_id: "alice".into(),
            group: "aa".into(),
            pending_only: true,
            limit: 10,
            events: receiver,
            stopping: shutdown,
        };
        let overflow = || {
            for _ in 0..2 {
                events
                    .send(MarmotAppEvent::GroupStateUpdated {
                        account_id_hex: "alice".into(),
                        account_label: "alice".into(),
                        group_id: GroupId::new(vec![0xaa]),
                    })
                    .unwrap();
            }
        };
        // Force an actual read error, then restore the table on the same store.
        connection
            .execute_batch("ALTER TABLE content_moderation RENAME TO unavailable_moderation")
            .unwrap();
        assert!(
            subscription
                .storage
                .reported_content("aa", true, None, 10)
                .is_err()
        );
        overflow();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), subscription.recv())
                .await
                .is_err()
        );
        assert!(
            subscription.events.is_empty(),
            "failed refresh was consumed"
        );
        connection
            .execute_batch("ALTER TABLE unavailable_moderation RENAME TO content_moderation")
            .unwrap();
        overflow();
        let page = tokio::time::timeout(Duration::from_secs(3), subscription.recv())
            .await
            .unwrap()
            .expect("read failure must not terminate the subscription");
        assert_eq!(page, subscription.snapshot);
        stopping.send(true).unwrap();
        assert!(subscription.recv().await.is_none());
    }
}
