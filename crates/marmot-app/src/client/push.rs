use cgka_traits::{GroupId, TransportEndpoint};

use crate::AppError;
use crate::messages::AppMessageIntent;
use crate::notifications;

use super::AppClient;

impl AppClient {
    pub(crate) async fn share_push_registration(&mut self) -> Result<usize, AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let settings = self.app.notification_settings(&account.label)?;
        let Some(registration) = self.app.stored_push_registration(&account.label)? else {
            return Ok(0);
        };
        if !settings.native_push_enabled {
            return Ok(0);
        }
        let keys = self
            .app
            .account_home()
            .load_signing_keys(&self.state.label)?;
        let mut shared = 0_usize;
        for group in self.state.groups.clone() {
            let Ok(group_id_bytes) = hex::decode(&group.group_id_hex) else {
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            let Ok((member_id_hex, leaf_index)) = self.local_member_leaf(&group_id) else {
                continue;
            };
            let (payload, record) = notifications::local_token_gossip_payload(
                group.group_id_hex.clone(),
                member_id_hex,
                leaf_index,
                &registration,
                &keys,
            )?;
            self.app.upsert_group_push_token(&account.label, &record)?;
            let content = serde_json::to_string(&payload)?;
            match self
                .send_app_event(&group_id, AppMessageIntent::PushTokenUpdate { content })
                .await
            {
                Ok((_event, _summary)) => shared += 1,
                Err(err) => {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "share_push_registration",
                        "push token gossip publish failed: {err}",
                    );
                }
            }
        }
        if shared > 0 {
            self.app
                .mark_push_registration_shared(&account.label, notifications::unix_now_ms())?;
        }
        Ok(shared)
    }

    pub(crate) async fn remove_push_registration(
        &mut self,
        registration: crate::PushRegistration,
    ) -> Result<usize, AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let keys = self
            .app
            .account_home()
            .load_signing_keys(&self.state.label)?;
        let mut removed = 0_usize;
        for group in self.state.groups.clone() {
            let Ok(group_id_bytes) = hex::decode(&group.group_id_hex) else {
                continue;
            };
            let group_id = GroupId::new(group_id_bytes);
            let Ok((member_id_hex, leaf_index)) = self.local_member_leaf(&group_id) else {
                continue;
            };
            let (payload, removal_record) = notifications::local_token_removal_payload(
                &group.group_id_hex,
                member_id_hex,
                leaf_index,
                &registration,
                &keys,
            )?;
            let content = serde_json::to_string(&payload)?;
            match self
                .send_app_event(&group_id, AppMessageIntent::PushTokenRemoval { content })
                .await
            {
                Ok((_event, _summary)) => removed += 1,
                Err(err) => {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "remove_push_registration",
                        "push token removal gossip publish failed: {err}",
                    );
                }
            }
            // Tombstone our own record locally with the same owner-signed stamp, so
            // a later stale kind 448 relaying our pre-removal record cannot
            // resurrect it.
            self.app.apply_local_push_removal(
                &account.label,
                &group.group_id_hex,
                &removal_record,
            )?;
        }
        Ok(removed)
    }

    pub(crate) async fn publish_notification_trigger_best_effort(
        &self,
        group_id: &GroupId,
        trigger: notifications::NotificationTrigger,
    ) {
        if let Err(err) = self.publish_notification_trigger(group_id, trigger).await {
            tracing::warn!(
                target: "marmot_app::notifications",
                method = "publish_notification_trigger_best_effort",
                "notification trigger publish failed: {err}",
            );
        }
    }

    async fn publish_notification_trigger(
        &self,
        group_id: &GroupId,
        _trigger: notifications::NotificationTrigger,
    ) -> Result<(), AppError> {
        let account = self.app.account_home().account(&self.state.label)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let tokens = self.app.group_push_tokens(&account.label, &group_id_hex)?;
        let by_server = notifications::token_records_by_server(tokens, &account.account_id_hex);
        if by_server.is_empty() {
            return Ok(());
        }
        let keys = self
            .app
            .account_home()
            .load_signing_keys(&self.state.label)?;
        for (server_pubkey_hex, records) in by_server {
            let encrypted_tokens = records
                .iter()
                .map(|record| record.encrypted_token.clone())
                .collect::<Vec<_>>();
            let endpoints =
                self.notification_trigger_target_relays(&server_pubkey_hex, &records)?;
            if endpoints.is_empty() {
                // No relay hint and no published kind-10050 inbox list for this
                // server: it is unreachable, so skip it as the genuine last
                // resort.
                continue;
            }
            let event =
                notifications::build_notification_gift_wrap(&server_pubkey_hex, &encrypted_tokens)
                    .await?;
            self.app
                .relay_client_for_endpoints(&keys, &endpoints)
                .publish_event(&endpoints, &event, 1)
                .await
                .map_err(AppError::Transport)?;
        }
        Ok(())
    }

    /// Relays to publish the gift-wrapped trigger to for `server_pubkey_hex`.
    /// Prefers the relay hints carried in the stored token records; when none
    /// exist, falls back to the server account's published kind-10050 NIP-17
    /// inbox relays (cached in the user directory). Returns empty when neither
    /// is available, i.e. the server is unreachable.
    fn notification_trigger_target_relays(
        &self,
        server_pubkey_hex: &str,
        records: &[notifications::GroupPushTokenRecord],
    ) -> Result<Vec<TransportEndpoint>, AppError> {
        let record_relay_hints = records
            .iter()
            .filter_map(|record| record.relay_hint.clone())
            .collect::<Vec<_>>();
        let server_inbox_relays = if record_relay_hints.is_empty() {
            self.app
                .directory_entry_for_account_id(server_pubkey_hex)?
                .map(|entry| entry.relay_lists.inbox.relays)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(notifications::select_notification_trigger_relays(
            &record_relay_hints,
            &server_inbox_relays,
        )
        .into_iter()
        .map(TransportEndpoint)
        .collect())
    }

    fn local_member_leaf(&self, group_id: &GroupId) -> Result<(String, u32), AppError> {
        let local_account = self.app.account_home().account(&self.state.label)?;
        let leaf_index = self.runtime.own_leaf_index(group_id)?;
        self.runtime
            .members(group_id)?
            .into_iter()
            .find_map(|member| {
                let member_id_hex = hex::encode(member.id.as_slice());
                (member_id_hex == local_account.account_id_hex)
                    .then_some((member_id_hex, leaf_index))
            })
            .ok_or_else(|| AppError::UnknownGroup(hex::encode(group_id.as_slice())))
    }

    pub(crate) fn cleanup_stale_push_tokens_best_effort(&self, group_id: &GroupId) {
        let Ok(account) = self.app.account_home().account(&self.state.label) else {
            return;
        };
        let Ok(members) = self.runtime.members(group_id) else {
            return;
        };
        let active_members = members
            .into_iter()
            .map(|member| hex::encode(member.id.as_slice()))
            .collect::<Vec<_>>();
        let group_id_hex = hex::encode(group_id.as_slice());
        let _ =
            self.app
                .remove_stale_group_push_tokens(&account.label, &group_id_hex, &active_members);
    }
}

pub(crate) fn notification_trigger_for_intent(
    intent: &AppMessageIntent,
) -> Option<notifications::NotificationTrigger> {
    match intent {
        AppMessageIntent::Chat { .. }
        | AppMessageIntent::Reply { .. }
        | AppMessageIntent::Media { .. }
        | AppMessageIntent::StreamFinal { .. } => {
            Some(notifications::NotificationTrigger::NewMessage)
        }
        AppMessageIntent::Reaction { .. }
        | AppMessageIntent::Unreact { .. }
        | AppMessageIntent::Edit { .. }
        | AppMessageIntent::Delete { .. }
        | AppMessageIntent::StreamStart { .. }
        | AppMessageIntent::AgentActivity { .. }
        | AppMessageIntent::AgentOperation { .. }
        | AppMessageIntent::GroupSystem { .. }
        | AppMessageIntent::PushTokenUpdate { .. }
        | AppMessageIntent::PushTokenRemoval { .. } => None,
    }
}
