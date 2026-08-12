//! Durable chat-list and chat read-state commands.

use crate::conversions::{
    ChatListRowFfi, ChatNotificationSettingsFfi, ChatPinStateFfi, group_id_from_hex,
};
use crate::errors::MarmotKitError;
use crate::{Marmot, optional_message_id_hex};

#[uniffi::export]
impl Marmot {
    /// Durable chat-list rows for fast app launch. Rows include the group
    /// title/avatar, last kind-9 preview, unread count, and read anchors.
    pub fn chat_list(
        &self,
        account_ref: String,
        include_archived: bool,
    ) -> Result<Vec<ChatListRowFfi>, MarmotKitError> {
        let rows = self.runtime.chat_list(&account_ref, include_archived)?;
        let _span = tracing::debug_span!(
            target: "marmot_uniffi::conversion",
            "chat_list_conversion",
            method = "chat_list"
        )
        .entered();
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Establish the unread baseline the first time a user opens a group.
    /// Existing kind-9 history remains read; later remote kind-9 messages count
    /// until marked visible via `mark_timeline_message_read`.
    pub fn initialize_chat_read_state(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Option<ChatListRowFfi>, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        Ok(self
            .runtime
            .initialize_chat_read_state(&account_ref, &group_id_hex)?
            .map(Into::into))
    }

    /// Mark a kind-9 timeline message visible/read. Own kind-9 messages can
    /// advance the marker too, which clears any earlier unread messages.
    pub fn mark_timeline_message_read(
        &self,
        account_ref: String,
        group_id_hex: String,
        message_id_hex: String,
    ) -> Result<Option<ChatListRowFfi>, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        let message_id_hex = optional_message_id_hex(Some(message_id_hex))?.ok_or_else(|| {
            MarmotKitError::InvalidHex {
                details: "message id is required".to_owned(),
            }
        })?;
        Ok(self
            .runtime
            .mark_timeline_message_read(&account_ref, &group_id_hex, &message_id_hex)?
            .map(Into::into))
    }

    /// Set or clear a manual unread reminder without moving the durable
    /// timeline read marker backwards.
    pub fn set_chat_manually_unread(
        &self,
        account_ref: String,
        group_id_hex: String,
        manually_unread: bool,
    ) -> Result<Option<ChatListRowFfi>, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        Ok(self
            .runtime
            .set_chat_manually_unread(&account_ref, &group_id_hex, manually_unread)?
            .map(Into::into))
    }

    /// Pin or unpin one local chat. Newly pinned chats enter at the top of the
    /// manually ordered pinned section.
    pub fn set_chat_pinned(
        &self,
        account_ref: String,
        group_id_hex: String,
        pinned: bool,
    ) -> Result<ChatPinStateFfi, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        Ok(self
            .runtime
            .set_chat_pinned(&account_ref, &group_id_hex, pinned)?
            .into())
    }

    /// Atomically replace the order of the current pinned set. The input must
    /// contain every currently pinned group exactly once.
    pub fn set_pinned_chat_order(
        &self,
        account_ref: String,
        ordered_group_ids: Vec<String>,
    ) -> Result<ChatPinStateFfi, MarmotKitError> {
        let ordered_group_ids = ordered_group_ids
            .into_iter()
            .map(|group_id_hex| {
                group_id_from_hex(&group_id_hex).map(|group_id| hex::encode(group_id.as_slice()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .runtime
            .set_pinned_chat_order(&account_ref, ordered_group_ids)?
            .into())
    }

    /// Read the current MDK timed/indefinite mute state for one chat.
    pub fn chat_notification_settings(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<ChatNotificationSettingsFfi, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        Ok(self
            .runtime
            .chat_notification_settings(&account_ref, &group_id_hex)?
            .into())
    }

    /// Mute one chat until an absolute Unix epoch millisecond timestamp, or
    /// indefinitely when `muted_until_ms` is `None`.
    pub fn set_chat_muted(
        &self,
        account_ref: String,
        group_id_hex: String,
        muted_until_ms: Option<i64>,
    ) -> Result<ChatNotificationSettingsFfi, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        Ok(self
            .runtime
            .set_chat_muted(&account_ref, &group_id_hex, muted_until_ms)?
            .into())
    }

    /// Clear either a finite or indefinite MDK chat mute.
    pub fn clear_chat_muted(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<ChatNotificationSettingsFfi, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        Ok(self
            .runtime
            .clear_chat_muted(&account_ref, &group_id_hex)?
            .into())
    }
}

#[cfg(test)]
mod tests {
    use cgka_traits::TransportEndpoint;
    use marmot_app::{AccountSetupRequest, MarmotApp};
    use nostr_relay_builder::MockRelay;

    use super::*;
    use crate::{ChatListSubscriptionUpdateFfi, ChatListUpdateTriggerFfi};

    #[test]
    fn chat_pins_round_trip_across_runtime_and_ffi() {
        let test_thread = std::thread::Builder::new()
            .name("ffi-chat-pin-runtime-round-trip".to_owned())
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                let test_runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                test_runtime.block_on(chat_pins_round_trip_body());
            })
            .unwrap();
        test_thread.join().unwrap();
    }

    async fn chat_pins_round_trip_body() {
        let relay = MockRelay::run().await.expect("start mock relay");
        let relay_url = relay.url().await.to_string();
        let root = tempfile::tempdir().expect("tempdir");
        let app = MarmotApp::with_relays(root.path(), vec![relay_url.clone()]);
        let runtime = app.runtime();
        let kit = Marmot { app, runtime };
        let endpoint = TransportEndpoint(relay_url.clone());
        let account = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
            .expect("create identity");
        let account_ref = account.account.account_id_hex;
        let first = kit
            .create_group(
                account_ref.clone(),
                "First pin".to_owned(),
                Vec::new(),
                None,
            )
            .await
            .expect("create first group");
        let second = kit
            .create_group(
                account_ref.clone(),
                "Second pin".to_owned(),
                Vec::new(),
                None,
            )
            .await
            .expect("create second group");

        let isolated_endpoint = TransportEndpoint(relay_url);
        let isolated_account = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![isolated_endpoint.clone()],
                bootstrap_relays: vec![isolated_endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
            .expect("create isolated identity");
        let isolated_account_ref = isolated_account.account.account_id_hex;
        let isolated_group = kit
            .create_group(
                isolated_account_ref.clone(),
                "Isolated pin".to_owned(),
                Vec::new(),
                None,
            )
            .await
            .expect("create isolated group");
        let isolated_state = kit
            .set_chat_pinned(isolated_account_ref.clone(), isolated_group.clone(), true)
            .expect("pin isolated group");
        assert_eq!(
            isolated_state.ordered_group_ids,
            vec![isolated_group.clone()]
        );

        let subscription = kit
            .subscribe_chat_list(account_ref.clone(), false)
            .await
            .expect("subscribe chat list");
        assert_eq!(subscription.snapshot().len(), 2);

        let state = kit
            .set_chat_pinned(account_ref.clone(), first.clone(), true)
            .expect("pin first");
        assert_eq!(state.ordered_group_ids, vec![first.clone()]);
        let update = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            subscription.next_update(),
        )
        .await
        .expect("pin snapshot timeout")
        .expect("pin snapshot");
        assert!(matches!(
            update,
            ChatListSubscriptionUpdateFfi::Snapshot {
                trigger: ChatListUpdateTriggerFfi::PinOrderChanged,
                rows,
            } if rows.first().is_some_and(|row| {
                row.group_id_hex == first
                    && row.pinned
                    && row.pinned_position == Some(0)
            })
        ));

        let state = kit
            .set_chat_pinned(account_ref.clone(), second.clone(), true)
            .expect("pin second");
        assert_eq!(state.ordered_group_ids, vec![second.clone(), first.clone()]);
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            subscription.next_update(),
        )
        .await
        .expect("second pin snapshot timeout")
        .expect("second pin snapshot");

        let state = kit
            .set_chat_pinned(account_ref.clone(), second.clone(), false)
            .expect("unpin second");
        assert_eq!(state.ordered_group_ids, vec![first.clone()]);
        let update = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            subscription.next_update(),
        )
        .await
        .expect("unpin snapshot timeout")
        .expect("unpin snapshot");
        assert!(matches!(
            update,
            ChatListSubscriptionUpdateFfi::Snapshot {
                trigger: ChatListUpdateTriggerFfi::PinOrderChanged,
                rows,
            } if rows.first().is_some_and(|row| {
                row.group_id_hex == first
                    && row.pinned
                    && row.pinned_position == Some(0)
            }) && rows.iter().any(|row| {
                row.group_id_hex == second
                    && !row.pinned
                    && row.pinned_position.is_none()
            })
        ));

        let state = kit
            .set_chat_pinned(account_ref.clone(), second.clone(), true)
            .expect("re-pin second");
        assert_eq!(state.ordered_group_ids, vec![second.clone(), first.clone()]);
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            subscription.next_update(),
        )
        .await
        .expect("re-pin snapshot timeout")
        .expect("re-pin snapshot");

        let state = kit
            .set_pinned_chat_order(account_ref.clone(), vec![first.clone(), second.clone()])
            .expect("reorder pins");
        assert_eq!(state.ordered_group_ids, vec![first.clone(), second.clone()]);
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            subscription.next_update(),
        )
        .await
        .expect("reorder snapshot timeout")
        .expect("reorder snapshot");

        let invalid = kit
            .set_pinned_chat_order(account_ref.clone(), vec![first.clone()])
            .expect_err("partial pinned order must be rejected");
        assert!(matches!(invalid, MarmotKitError::InvalidChatPin { .. }));

        kit.set_group_archived(account_ref.clone(), first.clone(), true)
            .await
            .expect("archive pinned chat");
        let update = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            subscription.next_update(),
        )
        .await
        .expect("archive snapshot timeout")
        .expect("archive snapshot");
        assert!(matches!(
            update,
            ChatListSubscriptionUpdateFfi::Snapshot {
                trigger: ChatListUpdateTriggerFfi::ArchiveChanged,
                rows,
            } if rows.iter().all(|row| row.group_id_hex != first)
                && rows.first().is_some_and(|row| {
                    row.group_id_hex == second
                        && row.pinned
                        && row.pinned_position == Some(0)
                })
        ));

        kit.runtime.shutdown().await;
    }
}
