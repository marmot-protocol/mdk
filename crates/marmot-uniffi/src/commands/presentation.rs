//! Complete chat-list display reads and the snapshot/subscription handoff.
use crate::conversions::{PresentedChatListSnapshotFfi, PresentedChatRowFfi};
use crate::subscriptions::PresentedChatListSubscription;
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Local whole rows, including selected title/avatar. First use may await local preparation.
    pub async fn presented_chat_list(
        &self,
        account_ref: String,
        include_archived: bool,
    ) -> Result<PresentedChatListSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .presented_chat_list(&account_ref, include_archived)
            .await?
            .into())
    }
    /// One complete row for creation/rebind; missing local groups return None.
    pub async fn presented_chat_list_row(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Option<PresentedChatRowFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .presented_chat_list_row(&account_ref, &group_id_hex)
            .await?
            .map(Into::into))
    }
    /// Returns an attached handle containing the initial snapshot. Take its snapshot once,
    /// then consume whole replacement updates; dispose the old handle on account switch.
    pub async fn open_presented_chat_list(
        &self,
        account_ref: String,
        include_archived: bool,
    ) -> Result<Arc<PresentedChatListSubscription>, MarmotKitError> {
        Ok(PresentedChatListSubscription::new(
            self.runtime
                .open_presented_chat_list(&account_ref, include_archived)
                .await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversions::PresentationTextFfi;
    use cgka_traits::TransportEndpoint;
    use marmot_app::{AccountSetupRequest, MarmotApp};
    use nostr_relay_builder::MockRelay;

    #[tokio::test]
    async fn presented_contract_round_trips_snapshot_and_updates_to_native() {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relays(dir.path(), vec![relay_url.clone()]);
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        let endpoint = TransportEndpoint(relay_url);
        let account = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let label = account.account.account_id_hex;
        let group = kit
            .create_group(label.clone(), "Native name".into(), vec![], None)
            .await
            .unwrap();
        let sub = kit
            .open_presented_chat_list(label.clone(), false)
            .await
            .unwrap();
        let initial = sub.snapshot().unwrap();
        assert!(sub.snapshot().is_none());
        assert_eq!(initial.sequence, 0);
        assert_eq!(initial.snapshot.rows.len(), 1);
        assert!(
            matches!(&initial.snapshot.rows[0].presentation.title, PresentationTextFfi::Literal { text } if text == "Native name")
        );
        let one = kit
            .presented_chat_list_row(label.clone(), group.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            one.row.group_id_hex,
            initial.snapshot.rows[0].row.group_id_hex
        );
        kit.set_chat_manually_unread(label.clone(), group.clone(), true)
            .unwrap();
        let update = tokio::time::timeout(std::time::Duration::from_secs(5), sub.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            update.subscription_generation,
            initial.subscription_generation
        );
        assert_eq!(update.sequence, 1);
        assert!(update.snapshot.rows[0].row.manually_marked_unread);
        assert!(matches!(
            kit.presented_chat_list_row(label.clone(), "not hex".into())
                .await,
            Err(MarmotKitError::InvalidHex { .. })
        ));
        kit.set_group_archived(label.clone(), group.clone(), true)
            .await
            .unwrap();
        let removed = tokio::time::timeout(std::time::Duration::from_secs(5), sub.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(removed.snapshot.rows.is_empty());
        let archived = kit.presented_chat_list(label.clone(), true).await.unwrap();
        assert_eq!(archived.rows.len(), 1);
        assert!(archived.rows[0].row.archived);
        kit.set_group_archived(label, group, false).await.unwrap();
        let restored = tokio::time::timeout(std::time::Duration::from_secs(5), sub.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(restored.snapshot.rows.len(), 1);
        kit.runtime.shutdown().await;
        assert!(sub.next().await.unwrap().is_none());
    }
}
