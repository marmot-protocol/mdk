//! Durable chat-list and chat read-state commands.

use std::time::Instant;

use crate::conversions::{
    ChatListRowFfi, ChatNotificationSettingsFfi, ChatPinStateFfi, ExistingDirectConversationFfi,
    group_id_from_hex,
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

    /// Read one hydrated chat-list row for a known group.
    ///
    /// Delegates to the runtime's keyed `chat_list_row` read. A well-formed
    /// group id with no local projection — including a group that belongs to
    /// another account, a group that is not yet projected, or a quarantined
    /// group without a chat-list row — returns `None`. Unknown accounts,
    /// malformed group ids, and storage failures keep the same typed errors as
    /// the other chat-list commands.
    pub fn chat_list_row(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Option<ChatListRowFfi>, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        let started_at = Instant::now();
        let result = self
            .runtime
            .chat_list_row(&account_ref, &group_id_hex)
            .map(|row| row.map(Into::into))
            .map_err(MarmotKitError::from);
        self.runtime
            .record_chat_list_row_read(started_at.elapsed(), result.is_ok());
        result
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Look up the reusable existing direct conversation with `peer_account_id`.
    ///
    /// `peer_account_id` accepts hex or `npub`. The read is keyed by this
    /// account plus that peer and returns at most one typed result. It does
    /// not transfer the complete chat list or require the host to page
    /// membership.
    ///
    /// A match is reusable when it is a Direct conversation (empty name and
    /// roster size 2), the local account is still an active member, lifecycle
    /// is not terminal, the group is not disbanding or leaving, and the
    /// current roster is exactly this account and the peer. Pending invites
    /// and archived rows remain reusable so hosts do not create a duplicate.
    /// When several reusable matches exist, selection follows durable
    /// chat-list activity order.
    ///
    /// Well-formed unknown peers, self lookups, and non-reusable historical
    /// groups return `None`. Malformed peer ids and unknown accounts keep the
    /// same typed errors as the other identity commands. After an account
    /// upgrade that introduces the peer index, this read returns
    /// [`MarmotKitError::DirectConversationIndexNotReady`] until the one-time
    /// backfill finishes; that is retryable and must not be treated as a miss.
    pub async fn existing_direct_conversation(
        &self,
        account_ref: String,
        peer_account_id: String,
    ) -> Result<Option<ExistingDirectConversationFfi>, MarmotKitError> {
        let started_at = Instant::now();
        let result = self
            .runtime
            .existing_direct_conversation(&account_ref, &peer_account_id)
            .await
            .map(|found| found.map(Into::into))
            .map_err(MarmotKitError::from);
        // Telemetry is recorded before the result is returned. The proof lives
        // in `existing_direct_conversation_lookup_is_keyed_and_independent_of_unrelated_chats`
        // in this module, next to this wrapper — not in a separate commands suite.
        self.runtime
            .record_existing_direct_conversation_read(started_at.elapsed(), result.is_ok());
        result
    }
}

#[uniffi::export]
impl Marmot {
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

    fn reusable_direct_conversation_winner(
        left: &ChatListRowFfi,
        right: &ChatListRowFfi,
    ) -> String {
        if left.activity_sort_at > right.activity_sort_at
            || (left.activity_sort_at == right.activity_sort_at
                && left.group_id_hex < right.group_id_hex)
        {
            left.group_id_hex.clone()
        } else {
            right.group_id_hex.clone()
        }
    }

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

    #[test]
    fn chat_list_row_matches_full_list_and_stays_independent_of_chat_count() {
        let test_thread = std::thread::Builder::new()
            .name("ffi-chat-list-row-round-trip".to_owned())
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                let test_runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                test_runtime.block_on(chat_list_row_round_trip_body());
            })
            .unwrap();
        test_thread.join().unwrap();
    }

    async fn chat_list_row_round_trip_body() {
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
                "Isolated row".to_owned(),
                Vec::new(),
                None,
            )
            .await
            .expect("create isolated group");

        let mut group_ids = Vec::new();
        for title in ["Alpha", "Beta", "Gamma", "Delta"] {
            group_ids.push(
                kit.create_group(account_ref.clone(), title.to_owned(), Vec::new(), None)
                    .await
                    .expect("create group"),
            );
        }
        let target = group_ids[2].clone();

        kit.set_group_archived(account_ref.clone(), group_ids[0].clone(), true)
            .await
            .expect("archive first chat");

        let missing = kit
            .chat_list_row(account_ref.clone(), "00aa".into())
            .expect("well-formed unknown group is a missing row, not an error");
        assert!(missing.is_none());

        let isolated_from_other_account = kit
            .chat_list_row(account_ref.clone(), isolated_group.clone())
            .expect("foreign group is account-isolated");
        assert!(isolated_from_other_account.is_none());

        let archived = kit
            .chat_list_row(account_ref.clone(), group_ids[0].clone())
            .expect("archived row remains readable")
            .expect("archived projection exists");
        assert_eq!(archived.group_id_hex, group_ids[0]);
        assert!(archived.archived);
        let visible_list = kit
            .chat_list(account_ref.clone(), false)
            .expect("visible chat list");
        assert!(
            visible_list
                .iter()
                .all(|row| row.group_id_hex != group_ids[0])
        );

        let before = kit.app_performance_snapshot();
        let row = kit
            .chat_list_row(account_ref.clone(), target.clone())
            .expect("read target row")
            .expect("target projection exists");
        let after = kit.app_performance_snapshot();
        assert_eq!(
            after.chat_list_row_read.attempts,
            before.chat_list_row_read.attempts + 1
        );
        assert_eq!(
            after.chat_list_row_read.successes,
            before.chat_list_row_read.successes + 1
        );
        assert_eq!(
            after.chat_list_row_read.attempts - before.chat_list_row_read.attempts,
            1,
            "single-row read must record one sample regardless of chat count"
        );

        let full_list = kit
            .chat_list(account_ref.clone(), true)
            .expect("full chat list");
        let expected = full_list
            .iter()
            .find(|candidate| candidate.group_id_hex == target)
            .expect("target exists in full list");
        assert_eq!(row.group_id_hex, expected.group_id_hex);
        assert_eq!(row.title, expected.title);
        assert_eq!(row.archived, expected.archived);
        assert_eq!(row.unread_count, expected.unread_count);
        assert_eq!(row.has_unread, expected.has_unread);
        assert_eq!(row.pinned, expected.pinned);
        assert_eq!(
            format!("{:?}", row.self_membership),
            format!("{:?}", expected.self_membership)
        );
        assert_eq!(
            format!("{:?}", row.conversation_kind),
            format!("{:?}", expected.conversation_kind)
        );
        assert_eq!(row.lifecycle_state, expected.lifecycle_state);
        assert_eq!(row.activity_sort_at, expected.activity_sort_at);

        kit.shutdown_and_close()
            .await
            .expect("close store after row reads");
        let closed = kit
            .chat_list_row(account_ref, target)
            .expect_err("closed storage must fail deterministically");
        assert!(matches!(closed, MarmotKitError::StorageClosed { .. }));
    }

    #[test]
    fn existing_direct_conversation_lookup_is_keyed_and_independent_of_unrelated_chats() {
        let test_thread = std::thread::Builder::new()
            .name("ffi-existing-direct-conversation".to_owned())
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                let test_runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                test_runtime.block_on(existing_direct_conversation_lookup_body());
            })
            .unwrap();
        test_thread.join().unwrap();
    }

    async fn existing_direct_conversation_lookup_body() {
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
                bootstrap_relays: vec![endpoint.clone()],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
            .expect("create identity");
        let account_ref = account.account.account_id_hex.clone();
        let account_label = account.account.label.clone();
        let peer = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint.clone()],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
            .expect("create peer identity");
        let peer_ref = peer.account.account_id_hex;
        let isolated = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint.clone()],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
            .expect("create isolated identity");
        let isolated_ref = isolated.account.account_id_hex;

        for title in ["Alpha", "Beta", "Gamma"] {
            kit.create_group(account_ref.clone(), title.to_owned(), Vec::new(), None)
                .await
                .expect("create unrelated group");
        }

        let unknown_peer = "dd".repeat(32);
        let missing = kit
            .existing_direct_conversation(account_ref.clone(), unknown_peer)
            .await
            .expect("unknown peer is a miss, not an error");
        assert!(missing.is_none());

        let self_lookup = kit
            .existing_direct_conversation(account_ref.clone(), account_ref.clone())
            .await
            .expect("self lookup is a miss");
        assert!(self_lookup.is_none());

        let malformed = kit
            .existing_direct_conversation(account_ref.clone(), "not-a-key".into())
            .await
            .expect_err("malformed peer id is a typed identity error");
        assert!(matches!(malformed, MarmotKitError::InvalidIdentity { .. }));

        let unknown_account = kit
            .existing_direct_conversation("missing-account".into(), peer_ref.clone())
            .await
            .expect_err("unknown account is typed");
        assert!(matches!(
            unknown_account,
            MarmotKitError::UnknownAccount { .. }
        ));

        let first = kit
            .create_group(
                account_ref.clone(),
                String::new(),
                vec![peer_ref.clone()],
                None,
            )
            .await
            .expect("create first direct conversation");
        let second = kit
            .create_group(
                account_ref.clone(),
                String::new(),
                vec![peer_ref.clone()],
                None,
            )
            .await
            .expect("create duplicate historical direct conversation");
        kit.send_text(account_ref.clone(), second.clone(), "later".into())
            .await
            .expect("bump activity on the newer duplicate");
        kit.set_chat_pinned(account_ref.clone(), first.clone(), true)
            .expect("pin older duplicate; pin must not win reuse");
        let first_row = kit
            .chat_list_row(account_ref.clone(), first.clone())
            .expect("read first duplicate row")
            .expect("first projection exists");
        let second_row = kit
            .chat_list_row(account_ref.clone(), second.clone())
            .expect("read second duplicate row")
            .expect("second projection exists");
        let expected_group_id = reusable_direct_conversation_winner(&first_row, &second_row);

        for _ in 0..3 {
            let other_peer = kit
                .runtime
                .create_identity(AccountSetupRequest {
                    default_relays: vec![endpoint.clone()],
                    bootstrap_relays: vec![endpoint.clone()],
                    publish_missing_relay_lists: true,
                    publish_initial_key_package: true,
                    ..AccountSetupRequest::default()
                })
                .await
                .expect("create other-peer identity");
            kit.create_group(
                account_ref.clone(),
                String::new(),
                vec![other_peer.account.account_id_hex],
                None,
            )
            .await
            .expect("create other-peer direct conversation");
        }

        let candidates = kit
            .app
            .direct_conversation_candidates(&account_label, &peer_ref)
            .expect("peer-keyed candidates");
        assert_eq!(
            candidates.len(),
            2,
            "candidate work must stay bounded by this peer's DMs, not other-peer DMs"
        );

        let isolated_from_other_account = kit
            .existing_direct_conversation(isolated_ref, peer_ref.clone())
            .await
            .expect("foreign account is isolated");
        assert!(isolated_from_other_account.is_none());

        let peer_npub = kit
            .normalize_member_ref(peer_ref.clone())
            .expect("peer npub")
            .npub;
        let before = kit.app_performance_snapshot();
        let found = kit
            .existing_direct_conversation(account_ref.clone(), peer_npub)
            .await
            .expect("lookup existing direct")
            .expect("reusable direct exists");
        let after = kit.app_performance_snapshot();
        assert_eq!(
            after.existing_direct_conversation_read.attempts,
            before.existing_direct_conversation_read.attempts + 1
        );
        assert_eq!(
            after.existing_direct_conversation_read.successes,
            before.existing_direct_conversation_read.successes + 1
        );
        assert_eq!(
            after.existing_direct_conversation_read.attempts
                - before.existing_direct_conversation_read.attempts,
            1,
            "lookup must record one sample regardless of unrelated chat count"
        );
        assert!(found.reusable);
        assert_eq!(
            found.group_id_hex, expected_group_id,
            "reuse must follow stored activity_sort_at DESC, then group_id_hex ASC, not pin order"
        );
        assert!(matches!(
            found.self_membership,
            crate::conversions::SelfMembershipFfi::Member
        ));
        let row = kit
            .chat_list_row(account_ref.clone(), found.group_id_hex.clone())
            .expect("read selected row")
            .expect("selected projection exists");
        assert!(matches!(
            row.conversation_kind,
            crate::ChatConversationKindFfi::Direct
        ));
        assert_eq!(row.activity_sort_at, found.activity_sort_at);

        kit.shutdown_and_close()
            .await
            .expect("close store after lookup");
        let closed = kit
            .existing_direct_conversation(account_ref, peer_ref)
            .await
            .expect_err("closed storage must fail deterministically");
        assert!(matches!(closed, MarmotKitError::StorageClosed { .. }));
    }
}
