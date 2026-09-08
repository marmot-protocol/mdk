//! Account-owner maintenance and commit-before-notification recovery for selected presentation.
use crate::{AppClient, AppError};
use storage_sqlite::ChatPresentationVersion;

#[derive(Default)]
pub(super) struct PresentationMaintenance {
    last_notified: Option<ChatPresentationVersion>,
}
impl PresentationMaintenance {
    pub(super) fn run(&mut self, client: &AppClient, account_id: &str) -> Result<bool, AppError> {
        let app = &client.app;
        let storage = app.account_storage(&client.state.label)?;
        let shared = app.shared_storage()?;
        let result = (|| {
            // Build a missing legacy chat row through its existing owner. This is first-row
            // construction only; profile updates and idle maintenance never revisit history.
            let missing = storage.pending_chat_presentation_rows()?;
            let classifier = crate::MarmotApp::chat_list_mention_classifier(account_id);
            for group in &missing {
                storage.refresh_chat_list_row(account_id, group, &classifier)?;
            }
            let more =
                crate::chat_presentation::maintenance::maintain(&storage, &shared, account_id)?;
            Ok(more || !missing.is_empty())
        })();
        // Inspect committed state even after a failed later step. A fresh worker always compares,
        // so interruption between a row commit and this send recovers without another message.
        let version = storage.chat_presentation_version()?;
        if self.last_notified.as_ref() != Some(&version) {
            let _ = app.presentation_signals.updates.send(
                crate::chat_presentation::signals::PresentationInvalidation {
                    account_label: client.state.label.clone(),
                    version: version.clone(),
                },
            );
            self.last_notified = Some(version);
        }
        result
    }
}
