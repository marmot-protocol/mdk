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
        let result =
            crate::chat_presentation::maintenance::prepare_batch(&storage, &shared, account_id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MarmotApp, tests::ScriptedPushRelayClient};
    use marmot_account::AccountHome;
    use std::sync::Arc;
    use storage_sqlite::{ChatPresentationRead, StoredAccountState};

    #[tokio::test]
    async fn composed_maintenance_drains_reinserted_groups_and_defers_rejected_rows() {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("Original", &[]).await.unwrap();
        let id = hex::encode(group.as_slice());
        let storage = app.account_storage("alice").unwrap();
        app.chat_list_row("alice", &id).unwrap().unwrap();
        let mut snapshot = storage.load_account_projection_state("alice", 100).unwrap();
        storage
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".into(),
                    ..Default::default()
                },
                100,
                120,
            )
            .unwrap();
        assert!(
            storage.chat_list_row(&id).unwrap().is_none(),
            "normal snapshot pruning cascades the chat row"
        );
        storage
            .save_account_projection_state(&snapshot, 100, 120)
            .unwrap();
        assert_eq!(
            storage.pending_chat_presentation_rows().unwrap(),
            std::slice::from_ref(&id)
        );
        let mut worker = PresentationMaintenance::default();
        let mut stopped = false;
        for _ in 0..4 {
            if !worker.run(&client, &account.account_id_hex).unwrap() {
                stopped = true;
                break;
            }
        }
        assert!(
            stopped,
            "the entire worker step must quiesce after initialization"
        );
        assert!(storage.pending_chat_presentation_rows().unwrap().is_empty());
        let before = storage.chat_list_row(&id).unwrap();
        let version = storage.chat_presentation_version().unwrap();
        assert!(!worker.run(&client, &account.account_id_hex).unwrap());
        assert_eq!(storage.chat_list_row(&id).unwrap(), before);
        assert_eq!(storage.chat_presentation_version().unwrap(), version);

        // A retained profile version newer than available evidence rejects every
        // attempt. The outer worker must honor the inner no-progress result too.
        let input = storage.chat_presentation_input(&id).unwrap().unwrap();
        let ChatPresentationRead::Ready(mut retained) = storage.chat_presentation(&id).unwrap()
        else {
            panic!("initialized presentation");
        };
        retained.profile_version.as_mut().unwrap().revision += 1;
        storage.store_chat_presentation(&input, &retained).unwrap();
        snapshot.groups[0].profile_name = "Changed".into();
        storage
            .save_account_projection_state(&snapshot, 100, 120)
            .unwrap();
        assert!(
            !worker.run(&client, &account.account_id_hex).unwrap(),
            "rejected work must defer instead of immediately rebuilding"
        );
        assert_eq!(storage.pending_chat_presentation_inputs().unwrap().len(), 1);
    }
}
