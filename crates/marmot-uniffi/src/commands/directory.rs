//! Directory, identity-resolution, profile, and Markdown-preview commands.

use std::sync::Arc;

use marmot_app::UserSearchParams;

use crate::conversions::{UserProfileMetadataFfi, normalize_member_ref_ffi};
use crate::errors::MarmotKitError;
use crate::markdown::{self, MarkdownDocumentFfi};
use crate::subscriptions::UserSearchSubscription;
use crate::{Marmot, endpoints};

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Best-effort cached display name for an account id. Returns the Nostr
    /// kind:0 display_name/name when the runtime has projected one, or the
    /// local account label if the id refers to one of our own accounts.
    /// `None` when nothing is known yet — call `refresh_directory` to fetch.
    pub fn display_name(&self, account_id_hex: String) -> Option<String> {
        self.runtime.display_name_for_account_id(&account_id_hex)
    }

    /// Convert a hex account id (Nostr public key) into its `npub…` bech32
    /// form for display. `None` if the hex isn't a valid public key.
    pub fn npub(&self, account_id_hex: String) -> Option<String> {
        marmot_app::npub_for_account_id(&account_id_hex).ok()
    }

    /// Normalize a public-key reference (npub or hex) to canonical hex.
    /// `None` if it isn't a valid public key. Used to resolve a scanned or
    /// deep-linked npub back to the account id the rest of the API expects.
    pub fn account_id_hex(&self, reference: String) -> Option<String> {
        normalize_member_ref_ffi(&reference)
            .ok()
            .map(|normalized| normalized.account_id_hex)
    }

    /// Parse plaintext message content into the same Markdown AST returned on
    /// message and timeline records. Useful for draft previews and host-side
    /// fallback rendering.
    pub fn parse_markdown(&self, text: String) -> MarkdownDocumentFfi {
        markdown::parse_markdown_document(&text)
    }

    /// Full cached Nostr kind:0 profile for an account id (name, display
    /// name, about, picture, nip05, lud16), if the runtime has one
    /// projected. The local account's own profile is cached immediately
    /// after `publish_user_profile`; other accounts' profiles populate via
    /// `refresh_directory`. Returns `None` when nothing is cached yet.
    pub fn user_profile(
        &self,
        account_id_hex: String,
    ) -> Result<Option<UserProfileMetadataFfi>, MarmotKitError> {
        let entry = self.app.directory_entry_for_account_id(&account_id_hex)?;
        Ok(entry.and_then(|record| record.profile).map(Into::into))
    }

    /// Cached Nostr kind:0 `website` metadata for an account id, when it is a
    /// string. The generic profile record intentionally exposes the fields the
    /// host can publish; this read-only accessor preserves arbitrary kind:0
    /// metadata while still making the standard website field available to
    /// profile presentation surfaces.
    pub fn user_profile_website(
        &self,
        account_id_hex: String,
    ) -> Result<Option<String>, MarmotKitError> {
        let entry = self.app.directory_entry_for_account_id(&account_id_hex)?;
        Ok(entry.and_then(|record| record.profile).and_then(|profile| {
            profile
                .extra
                .get("website")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        }))
    }

    /// Fetch and cache an account's own Nostr kind:0 profile from `relays`.
    /// After this resolves, `user_profile` / `display_name` return the
    /// freshly-fetched metadata (name, picture, etc.) for that account.
    pub async fn refresh_profile(
        &self,
        account_id_hex: String,
        relays: Vec<String>,
    ) -> Result<(), MarmotKitError> {
        self.app
            .refresh_profile_for_account_id(&account_id_hex, endpoints(&relays))
            .await?;
        Ok(())
    }

    /// Search the searcher's web of trust, streaming matches as each radius
    /// resolves.
    ///
    /// `radius_start`/`radius_end` are inclusive social distances: 0 is the
    /// searcher, 1 their direct follows. Lower radii are still traversed to
    /// reach the window, they just do not emit — which is what makes
    /// `radius_start` usable for paging further out without re-delivering
    /// results the host already has.
    ///
    /// Returns as soon as the traversal is spawned; drive
    /// [`UserSearchSubscription::next_update`] in a loop until it yields
    /// `None`. Dropping the subscription cancels the traversal, so a host that
    /// abandons a search should release it rather than draining it.
    ///
    /// Radius 1 covers more than the follow list: people sharing a group with
    /// the searcher are seeded into it, because sharing a group is social
    /// proximity even when neither has followed the other. That membership is
    /// gathered here, where both the app and the runtime are in scope, rather
    /// than inside the search — hosts pass nothing extra for it.
    ///
    /// People found this way are deliberately *not* added to the local
    /// directory: a search result is not a relationship. `user_profile` keeps
    /// answering only for accounts the user has actually interacted with.
    pub async fn search_users(
        &self,
        account_id_hex: String,
        query: String,
        radius_start: u8,
        radius_end: u8,
    ) -> Result<Arc<UserSearchSubscription>, MarmotKitError> {
        // Seeds are radius 1 by definition, so a window that stops at radius 0
        // cannot use them -- and gathering them costs a membership read per
        // group. Ask only when the answer can matter.
        let radius_one_seeds = if radius_end >= 1 {
            self.runtime.group_co_members(&account_id_hex).await?
        } else {
            Vec::new()
        };
        let inner = self
            .app
            .search_users(UserSearchParams {
                searcher_account_id_hex: account_id_hex,
                query,
                radius_start,
                radius_end,
                radius_one_seeds,
            })
            .await?;
        Ok(UserSearchSubscription::new(inner))
    }
}

#[cfg(test)]
mod tests {
    use cgka_traits::TransportEndpoint;
    use marmot_app::{AccountSetupRequest, MarmotApp};
    use nostr_relay_builder::MockRelay;

    use super::*;
    use crate::conversions::{
        MatchQualityFfi, MatchedFieldFfi, SearchUpdateTriggerFfi, UserSearchUpdateFfi,
    };

    #[test]
    fn user_search_streams_typed_results_through_the_ffi_subscription() {
        // Composes UniFFI, the app runtime, and the search traversal. Debug
        // builds need more than libtest's default 2 MiB stack for that chain,
        // matching `draft_round_trip_crosses_runtime_and_ffi_boundaries`.
        let test_thread = std::thread::Builder::new()
            .name("ffi-user-search-stream".to_owned())
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                let test_runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                test_runtime.block_on(user_search_stream_body());
            })
            .unwrap();
        test_thread.join().unwrap();
    }

    async fn user_search_stream_body() {
        let relay = MockRelay::run().await.expect("start mock relay");
        let relay_url = relay.url().await.to_string();
        let root = tempfile::tempdir().expect("tempdir");
        let app = MarmotApp::with_relays(root.path(), vec![relay_url.clone()]);
        let runtime = app.runtime();
        let kit = Marmot { app, runtime };
        let endpoint = TransportEndpoint(relay_url);
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
        let account_id_hex = account.account.account_id_hex;

        // Publishing the local account's own profile caches it, which puts a
        // findable record at radius 0 without reaching past the relay boundary.
        kit.publish_user_profile(
            account_id_hex.clone(),
            UserProfileMetadataFfi {
                name: Some("needle".to_owned()),
                ..Default::default()
            },
            Vec::new(),
            Vec::new(),
        )
        .await
        .expect("publish profile");

        let subscription = kit
            .search_users(account_id_hex.clone(), "needle".to_owned(), 0, 0)
            .await
            .expect("start search");

        let mut updates: Vec<UserSearchUpdateFfi> = Vec::new();
        while let Some(update) = subscription.next_update().await {
            updates.push(update);
        }

        let matched = updates
            .iter()
            .flat_map(|update| &update.new_results)
            .find(|result| result.account_id_hex == account_id_hex)
            .expect("the published profile is findable at radius 0");
        assert_eq!(matched.radius, 0);
        assert!(matches!(matched.matched_field, MatchedFieldFfi::Name));
        assert!(matches!(matched.match_quality, MatchQualityFfi::Exact));

        // The stream must terminate, and terminate exactly once, on the
        // terminal trigger — a host loops on `next_update` until it sees `None`.
        assert!(matches!(
            updates.last().expect("at least one update").trigger,
            SearchUpdateTriggerFfi::SearchCompleted
        ));
        assert!(subscription.next_update().await.is_none());
    }
}
