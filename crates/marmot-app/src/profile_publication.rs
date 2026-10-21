//! Publication of the account's own profile and follow list.
//!
//! These publish the account's own state, so they stay in `marmot-app` when
//! the directory moves to its own crate (step 3 of
//! `docs/marmot-architecture/review/brief-directory.md`). They call the
//! directory to remember what they published.

use cgka_traits::{MemberId, TransportEndpoint};
use transport_nostr_peeler::NostrTransportEvent;

use crate::directory::records::{FetchedFollowList, UserProfileMetadata, profile_content_json};
use crate::ids::normalize_account_ids;
use crate::key_package_records::publish_endpoints_from_bootstrap;
use crate::{
    AccountRelayListBootstrap, AccountRelayListStatus, AppError, KIND_NOSTR_CONTACT_LIST,
    KIND_NOSTR_METADATA, MarmotApp, blocking_app_task,
};

impl MarmotApp {
    pub async fn publish_user_profile(
        &self,
        label: &str,
        profile: UserProfileMetadata,
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(label)?;
        let endpoints = self.outbox_endpoints(
            &account.account_id_hex,
            publish_endpoints_from_bootstrap(&bootstrap),
        );
        self.publish_user_profile_to_endpoints_and_indexers(
            &account.label,
            profile,
            endpoints,
            bootstrap.indexer_relays,
            bootstrap
                .default_relays
                .into_iter()
                .chain(bootstrap.bootstrap_relays)
                .collect(),
        )
        .await
        .map(|_| ())
    }

    /// Publish kind-0 metadata to an already-selected, account-scoped route,
    /// returning the authored event's `created_at` for the local cache.
    ///
    /// This is the action boundary used when the runtime has captured one
    /// coherent relay-list snapshot and must not re-read it before publishing.
    pub(crate) async fn publish_user_profile_to_endpoints_and_indexers(
        &self,
        label: &str,
        profile: UserProfileMetadata,
        endpoints: Vec<TransportEndpoint>,
        indexer_relays: Vec<TransportEndpoint>,
        declared_relays: Vec<TransportEndpoint>,
    ) -> Result<u64, AppError> {
        let observation = self.product_analytics.begin(
            crate::ProductFamily::Directory,
            "publish",
            crate::ProductUnit::Attempt,
        );
        let result = self
            .publish_user_profile_to_endpoints_unobserved(
                label,
                profile,
                endpoints,
                indexer_relays,
                declared_relays,
            )
            .await;
        if let Some(observation) = observation {
            observation.finish(if result.is_ok() { "success" } else { "failure" });
        }
        result
    }

    async fn publish_user_profile_to_endpoints_unobserved(
        &self,
        label: &str,
        profile: UserProfileMetadata,
        endpoints: Vec<TransportEndpoint>,
        indexer_relays: Vec<TransportEndpoint>,
        declared_relays: Vec<TransportEndpoint>,
    ) -> Result<u64, AppError> {
        let account = self.account_home().account(label)?;
        let signer = self.account_signer_for_summary(&account)?;
        let content = serde_json::to_string(&profile_content_json(&profile))?;
        let mut event = NostrTransportEvent::new_unsigned(
            account.account_id_hex.clone(),
            KIND_NOSTR_METADATA,
            Vec::new(),
            content,
        );
        let indexers = self.public_indexer_publish_endpoints(
            &indexer_relays,
            &endpoints,
            &endpoints,
            &declared_relays,
        );
        let account_id = MemberId::new(hex::decode(&account.account_id_hex)?);
        let nostr_signer = signer.as_nostr_signer();
        // Sign before sending so indexer copies and quorum completion carry
        // the exact event the account relays acknowledged.
        event = self
            .sign_replaceable_identity_event(label, nostr_signer.clone(), &event)
            .await?;
        let relay_client = self.relay_client_for_account_id(&account.account_id_hex, nostr_signer);
        let outcome = relay_client
            .publish_event_for_account(&account_id, &endpoints, &event, 1)
            .await?;
        if outcome.accepted.is_empty() {
            return Err(AppError::Publish(
                "no account relay acknowledged profile metadata".into(),
            ));
        }
        let mut completion =
            crate::QuorumCancelledDelivery::new(relay_client.clone(), account_id.clone());
        completion.add(&event, &endpoints, &outcome);
        self.spawn_quorum_cancelled_delivery(completion);
        let created_at = event.created_at;
        if let Some(copy) =
            crate::PublicIndexerCopy::new(relay_client, account_id, vec![event], indexers)
        {
            self.spawn_public_indexer_copy(copy);
        }
        Ok(created_at)
    }

    /// Select profile publication endpoints from one account relay-list
    /// snapshot. Prefer the account's published NIP-65 write relays, then its
    /// remembered bootstrap relays. A missing bootstrap list falls back to the
    /// snapshot's compatibility default/publish list.
    ///
    /// Every tier is filtered through the discovered-endpoint safety policy.
    /// If a tier contains only invalid, unsafe, or retired endpoints, selection
    /// continues to the next tier; no unusable endpoint reaches the dialer.
    pub(crate) fn account_profile_publish_endpoints(
        &self,
        relay_lists: &AccountRelayListStatus,
    ) -> Result<Vec<TransportEndpoint>, AppError> {
        let published = self.retain_safe_discovered_endpoints(
            relay_lists
                .nip65
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
            "account-owned profile publish relays",
        );
        if !published.is_empty() {
            return Ok(published);
        }

        let bootstrap = if relay_lists.bootstrap_relays.is_empty() {
            &relay_lists.default_relays
        } else {
            &relay_lists.bootstrap_relays
        };
        let bootstrap = self.retain_safe_discovered_endpoints(
            bootstrap.iter().cloned().map(TransportEndpoint).collect(),
            "account-owned profile bootstrap relays",
        );
        if bootstrap.is_empty() {
            return Err(AppError::RelayDirectory(
                "account relay configuration has no usable profile publication endpoints".into(),
            ));
        }
        Ok(bootstrap)
    }

    pub async fn publish_account_follow_list(
        &self,
        label: &str,
        follows: &[&str],
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(label)?;
        let signer = self.account_signer_for_summary(&account)?;
        let endpoints = self.outbox_endpoints(
            &account.account_id_hex,
            publish_endpoints_from_bootstrap(&bootstrap),
        );
        let cached_follows =
            normalize_account_ids(follows.iter().map(|follow| (*follow).to_owned()).collect())?;
        let tags = cached_follows
            .iter()
            .map(|account_id| vec!["p".to_owned(), account_id.clone()])
            .collect();
        let nostr_signer = signer.as_nostr_signer();
        // Sign before sending so quorum completion resends the exact event.
        let event = self
            .sign_replaceable_identity_event(
                label,
                nostr_signer.clone(),
                &NostrTransportEvent::new_unsigned(
                    account.account_id_hex.clone(),
                    KIND_NOSTR_CONTACT_LIST,
                    tags,
                    String::new(),
                ),
            )
            .await?;
        let relay_client = self.relay_client_for_account_id(&account.account_id_hex, nostr_signer);
        let outcome = relay_client.publish_event(&endpoints, &event, 1).await?;
        let mut completion = crate::QuorumCancelledDelivery::new(
            relay_client,
            MemberId::new(hex::decode(&account.account_id_hex)?),
        );
        completion.add(&event, &endpoints, &outcome);
        self.spawn_quorum_cancelled_delivery(completion);
        // Publishing a local kind-3 list must make its own cached edge set
        // immediately available to the bindings, without admitting every
        // followed account as a watched directory entry.
        {
            let app = self.clone();
            let account_id = account.account_id_hex.clone();
            let follow_list = FetchedFollowList {
                follows: cached_follows,
                source_relays: endpoints
                    .iter()
                    .map(|endpoint| endpoint.0.clone())
                    .collect(),
            };
            if let Err(error) = blocking_app_task(move || {
                Ok(app.remember_directory_follow_edges_for_search(&account_id, &follow_list)?)
            })
            .await
            {
                tracing::warn!(
                    target: "marmot_app::directory",
                    method = "publish_account_follow_list",
                    error_kind = error.privacy_safe_kind(),
                    "follow list published but local cache update failed"
                );
            }
        }
        Ok(())
    }
}
