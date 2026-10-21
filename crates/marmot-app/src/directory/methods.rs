//! The directory's fetches and public API on [`Directory`]: relay-list and
//! profile/key-package/follow-list fetches and the `directory_*`/
//! `*_user_directory` methods. `MarmotApp`'s public versions are delegates in
//! `directory_delegates.rs`. Entry reads and writes, ingest and
//! record hydration are the store, in `directory/store.rs`. The stateless
//! record types and helpers these build on live in
//! [`crate::directory::records`]. The cache lifecycle is in
//! [`crate::directory_resources`], and publishing the account's own profile and
//! follow list is in [`crate::profile_publication`].

use crate::directory::error::{DirectoryError, blocking_directory_task};
use std::collections::{BTreeMap, HashMap, HashSet};

use cgka_traits::TransportEndpoint;
use nostr_sdk::prelude::PublicKey;
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
};

use super::Directory;
use super::observer::{DirectoryObservation, DirectoryObserver, ObservedFamily, ObservedUnit};
use super::resources::DirectoryResources;
#[cfg(test)]
use crate::MarmotApp;
use crate::directory::ids::parse_account_id_hex;
use crate::directory::published_records::{
    fresh_or_cached_key_package, fresh_relay_list_status_from_records,
    latest_fresh_key_package_from_records, merge_relay_list_status, relay_list_queries,
};
use crate::directory::records::{
    CachedIdentityProjection, FetchedFollowList, MAX_CACHED_IDENTITY_PAGE_SIZE,
    UserDirectoryRecord, UserDirectoryRefresh, UserDirectorySearch, UserDirectorySearchResult,
    UserProfileMetadata, cached_identity_projection, display_name_for_profile,
    latest_follow_list_from_records, latest_fresh_profiles_from_records,
    upsert_newer_directory_entry, user_directory_record_from_public, user_record_match,
};
use crate::directory::{
    DirectoryCache, hydrate_directory_record, plan_directory_sync, sort_user_search_results,
};
use crate::{
    AccountRelayListStatus, FetchedKeyPackage, KIND_NOSTR_CONTACT_LIST, KIND_NOSTR_METADATA,
    MissingRelayListKind, push_unique_strings,
};
use transport_nostr::DirectorySyncPlan;
use transport_nostr::{DirectoryEventQuery, DirectoryRelayEventRecord as RelayEventRecord};

pub(crate) const USER_DIRECTORY_SEARCH_MAX_VISITED: usize = 8192;
pub(crate) const USER_DIRECTORY_SEARCH_MAX_FRONTIER: usize = 4096;

impl<R: DirectoryResources + DirectoryObserver> Directory<R> {
    /// Resolve batched profile names with first-cache precedence, then local labels.
    /// Shared profiles replace cached profiles only when strictly newer.
    pub(crate) fn display_names_for_account_ids(
        &self,
        account_id_hexes: &[String],
    ) -> Result<HashMap<String, String>, DirectoryError> {
        let mut account_ids = account_id_hexes
            .iter()
            .map(|account_id| parse_account_id_hex(account_id))
            .collect::<Result<Vec<_>, _>>()?;
        account_ids.sort();
        account_ids.dedup();
        if account_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let caches = self.resources.current_caches()?;
        let shared_storage = self.resources.shared_storage()?;
        let local_accounts = self.local_accounts_by_id()?;
        let mut profiles = HashMap::<String, Option<UserProfileMetadata>>::new();
        let mut missing = account_ids.clone();
        for cache in caches {
            profiles.extend(cache.profiles_for_ids(&missing)?);
            // The first cache row wins even when it contains no profile.
            missing.retain(|id| !profiles.contains_key(id));
            if missing.is_empty() {
                break;
            }
        }
        for record in shared_storage.directory_profiles_for_ids(&account_ids)? {
            let Some(json) = record.profile_json else {
                continue;
            };
            let candidate: UserProfileMetadata = serde_json::from_str(&json)?;
            let profile = profiles.entry(record.account_id_hex).or_default();
            // Match select_newer_directory_entry: account-cache ties win.
            if profile
                .as_ref()
                .is_none_or(|current| candidate.created_at > current.created_at)
            {
                *profile = Some(candidate);
            }
        }
        let mut names = HashMap::new();

        for account_id in account_ids {
            if let Some(name) =
                display_name_for_profile(profiles.get(&account_id).and_then(Option::as_ref))
            {
                names.insert(account_id, name);
                continue;
            }
            if let Some(name) = local_accounts.get(&account_id) {
                names.insert(account_id, name.label.clone());
            }
        }

        Ok(names)
    }

    pub async fn fetch_account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, DirectoryError> {
        self.fetch_relay_list_status(account_id_hex, bootstrap_relays)
            .await
    }

    pub(crate) async fn fetch_relay_list_status(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, DirectoryError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| DirectoryError::InvalidPublicKey)?;
        let account_id_hex = public_key.to_hex();
        let bootstrap_relays = self.directory_source_relays(&bootstrap_relays);
        let freshness = self.directory_freshness();
        let records = self
            .relay_plane
            .fetch_directory_events(
                bootstrap_relays.clone(),
                relay_list_queries(account_id_hex.clone()),
            )
            .await
            .map_err(|e| DirectoryError::RelayDirectory(format!("fetch relay lists: {e}")))?;
        let selection = fresh_relay_list_status_from_records(&account_id_hex, records, freshness);
        let cached = {
            let directory = self.clone();
            let account_id = account_id_hex.clone();
            blocking_directory_task(move || directory.cached_relay_list_status(&account_id)).await?
        };
        // The one-hop diagnostic and target-aware resolver share the same
        // per-kind anti-clobber rule; observing an older record is not freshness.
        let mut status = merge_relay_list_status(cached, selection.value);
        if status.bootstrap_relays.is_empty() {
            status.bootstrap_relays = bootstrap_relays
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect();
        }
        {
            let directory = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = status.clone();
            blocking_directory_task(move || {
                directory.remember_directory_relay_lists(&account_id, &remembered)
            })
            .await?;
        }
        Ok(status)
    }

    /// Resolve an account's relay metadata through its advertised NIP-65
    /// write relays before treating a kind-10050 inbox list as absent.
    ///
    /// The explicit fetch API above intentionally remains a one-hop diagnostic
    /// primitive. Production account setup uses this target-aware wrapper so a
    /// discovery relay (`D`) can point at an outbox (`W`) that owns the current
    /// inbox declaration. If the second hop fails, already-observed positive
    /// inbox metadata remains usable; an empty first hop is not promoted into
    /// authoritative absence.
    pub(crate) async fn resolve_account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
        discovery_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, DirectoryError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| DirectoryError::InvalidPublicKey)?;
        let account_id_hex = public_key.to_hex();
        let discovery_relays = self.directory_source_relays(&discovery_relays);
        let freshness = self.directory_freshness();
        let cached = {
            let directory = self.clone();
            let account_id = account_id_hex.clone();
            blocking_directory_task(move || directory.cached_relay_list_status(&account_id)).await?
        };
        let first = self
            .relay_plane
            .fetch_directory_events_with_completion(
                discovery_relays.clone(),
                relay_list_queries(account_id_hex.clone()),
            )
            .await
            .map_err(|e| DirectoryError::RelayDirectory(format!("fetch relay lists: {e}")))?;
        let mut records = first.records;
        let first_observed =
            fresh_relay_list_status_from_records(&account_id_hex, records.clone(), freshness).value;
        let observed_outboxes = first_observed.nip65.created_at > 0;
        let first_hop = merge_relay_list_status(cached.clone(), first_observed);
        let outbox_relays = self.relay_plane.retain_safe_discovered_endpoints(
            first_hop
                .nip65
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
            "account inbox outbox discovery",
        );
        let mut complete = first.complete;
        if !outbox_relays.is_empty() {
            match self
                .relay_plane
                .fetch_directory_events_with_completion(
                    outbox_relays,
                    relay_list_queries(account_id_hex.clone()),
                )
                .await
            {
                Ok(second) => {
                    // Once freshly observed NIP-65 metadata identifies the
                    // account's outboxes, their completed read establishes inbox
                    // absence; an unavailable discovery indexer cannot veto it.
                    // Cached-only outboxes may be stale and prove nothing.
                    complete = second.complete && (complete || observed_outboxes);
                    records.extend(second.records);
                }
                Err(_) => complete = false,
            }
        }

        let observed = fresh_relay_list_status_from_records(&account_id_hex, records, freshness);
        // A rejected future-dated declaration is not evidence of absence.
        complete &= !observed.rejected_future;
        let mut status = merge_relay_list_status(cached, observed.value);
        // Persist signed observations (including explicit-empty lists) and
        // valid cached metadata even when discovery was incomplete. Do not
        // durably turn the caller's discovery fallback into claimed account
        // metadata merely because a lookup failed.
        if status.nip65.created_at > 0 || status.inbox.created_at > 0 {
            let directory = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = status.clone();
            blocking_directory_task(move || {
                directory.remember_directory_relay_lists(&account_id, &remembered)
            })
            .await?;
        }
        if status.bootstrap_relays.is_empty() {
            status.bootstrap_relays = discovery_relays
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect();
        }

        let explicit_empty = (status.nip65.created_at > 0 && status.nip65.relays.is_empty())
            || (status.inbox.created_at > 0 && status.inbox.relays.is_empty());
        let uncertain_absence =
            !complete && (status.nip65.relays.is_empty() || status.inbox.relays.is_empty());
        if uncertain_absence {
            return Err(DirectoryError::DirectoryLookupIncomplete(account_id_hex));
        }
        if explicit_empty {
            return Err(DirectoryError::MissingRelayLists(status.missing.clone()));
        }
        Ok(status)
    }

    pub async fn fetch_current_account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
        required_list_kind: Option<&str>,
    ) -> Result<Option<AccountRelayListStatus>, DirectoryError> {
        let observation = self.resources.begin(
            ObservedFamily::Directory,
            "relay_list",
            ObservedUnit::Attempt,
        );
        let result = self
            .fetch_current_account_relay_list_status_for_account_id_unobserved(
                account_id_hex,
                bootstrap_relays,
                required_list_kind,
            )
            .await;
        if let Some(observation) = observation {
            observation.directory_sample(
                match &result {
                    Ok((Some(_), _)) => "success",
                    Ok((None, _)) => "empty",
                    Err(_) => "failure",
                },
                // Failed fetches have no result provenance; classify the network attempt.
                result.as_ref().map_or("network", |(_, source)| *source),
                1,
            );
            observation.discard();
        }
        result.map(|(status, _)| status)
    }

    async fn fetch_current_account_relay_list_status_for_account_id_unobserved(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
        required_list_kind: Option<&str>,
    ) -> Result<(Option<AccountRelayListStatus>, &'static str), DirectoryError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| DirectoryError::InvalidPublicKey)?;
        let account_id_hex = public_key.to_hex();
        let required_list_kind = match required_list_kind {
            Some("nip65") => Some(KIND_NIP65_RELAY_LIST),
            Some("inbox") => Some(KIND_MARMOT_INBOX_RELAY_LIST),
            Some(other) => {
                return Err(DirectoryError::RelayDirectory(format!(
                    "unsupported relay list type: {other}"
                )));
            }
            None => None,
        };
        let bootstrap_relays = self.directory_source_relays(&bootstrap_relays);
        let freshness = self.directory_freshness();
        let records = self
            .relay_plane
            .fetch_directory_events(
                bootstrap_relays.clone(),
                relay_list_queries(account_id_hex.clone()),
            )
            .await
            .map_err(|e| DirectoryError::RelayDirectory(format!("fetch relay lists: {e}")))?;
        let observed_nip65 = records.iter().any(|record| {
            record.event.pubkey == account_id_hex
                && record.event.kind == KIND_NIP65_RELAY_LIST
                && freshness.accepts(record)
        });
        let observed_inbox = records.iter().any(|record| {
            record.event.pubkey == account_id_hex
                && record.event.kind == KIND_MARMOT_INBOX_RELAY_LIST
                && freshness.accepts(record)
        });
        let has_required_list = match required_list_kind {
            Some(KIND_NIP65_RELAY_LIST) => observed_nip65,
            Some(KIND_MARMOT_INBOX_RELAY_LIST) => observed_inbox,
            Some(_) => false,
            None => observed_nip65 || observed_inbox,
        };
        if !has_required_list {
            return Ok((None, "network"));
        }
        let selection = fresh_relay_list_status_from_records(&account_id_hex, records, freshness);
        let mut status = selection.value;
        let cached = {
            let directory = self.clone();
            let account_id = account_id_hex.clone();
            blocking_directory_task(move || directory.cached_relay_list_status(&account_id)).await?
        };
        let source = if (!observed_nip65 && cached.nip65.created_at > 0)
            || (!observed_inbox && cached.inbox.created_at > 0)
            || cached
                .bootstrap_relays
                .iter()
                .any(|relay| !status.bootstrap_relays.contains(relay))
        {
            "mixed"
        } else {
            "network"
        };
        if !observed_nip65 {
            status.nip65 = cached.nip65;
        }
        if !observed_inbox {
            status.inbox = cached.inbox;
        }
        push_unique_strings(&mut status.bootstrap_relays, cached.bootstrap_relays);
        if status.bootstrap_relays.is_empty() {
            status.bootstrap_relays = bootstrap_relays
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect();
        }
        status.refresh();
        {
            let directory = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = status.clone();
            blocking_directory_task(move || {
                directory.remember_directory_relay_lists(&account_id, &remembered)
            })
            .await?;
        }
        Ok((Some(status), source))
    }

    /// Fetch the account's own current published kind:0 profile metadata from
    /// the selected relays.
    ///
    /// kind:0 is a replaceable event, so a fresh publish overwrites the prior
    /// one entirely. Callers that perform partial updates (CLI `profile
    /// update`) must read the current value here and overlay only the fields
    /// they intend to change, otherwise unset fields are silently wiped. The
    /// shape mirrors [`Self::fetch_current_account_relay_list_status_for_account_id`]:
    /// returns `Ok(None)` when the selected relays hold no fresh profile event
    /// for the account so the caller can refuse to clobber an unconfirmed
    /// remote state instead of publishing a partial replacement. The fetched
    /// profile is cached in the local directory on success.
    pub async fn fetch_current_user_profile_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<Option<UserProfileMetadata>, DirectoryError> {
        let observation =
            self.resources
                .begin(ObservedFamily::Directory, "profile", ObservedUnit::Attempt);
        let result = self
            .fetch_current_user_profile_for_account_id_unobserved(account_id_hex, bootstrap_relays)
            .await;
        if let Some(observation) = observation {
            observation.directory_sample(
                match &result {
                    Ok(Some(_)) => "success",
                    Ok(None) => "empty",
                    Err(_) => "failure",
                },
                "network",
                1,
            );
            observation.discard();
        }
        result
    }

    async fn fetch_current_user_profile_for_account_id_unobserved(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<Option<UserProfileMetadata>, DirectoryError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| DirectoryError::InvalidPublicKey)?;
        let account_id_hex = public_key.to_hex();
        let source_relays = self.directory_source_relays(&bootstrap_relays);
        let records = self
            .fetch_events_for_account_ids(
                std::slice::from_ref(&account_id_hex),
                KIND_NOSTR_METADATA,
                &source_relays,
            )
            .await?;
        let profiles =
            latest_fresh_profiles_from_records(records, self.directory_freshness()).value;
        let Some(profile) = profiles.get(&account_id_hex).cloned() else {
            return Ok(None);
        };
        {
            let directory = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = profile.clone();
            blocking_directory_task(move || {
                directory.remember_directory_profile_if_newer(&account_id, &remembered)
            })
            .await?;
        }
        Ok(Some(profile))
    }

    pub async fn fetch_latest_key_package_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<FetchedKeyPackage, DirectoryError> {
        let observation = self.resources.begin(
            ObservedFamily::Directory,
            "key_package",
            ObservedUnit::Attempt,
        );
        let result = self
            .fetch_latest_key_package_for_account_id_unobserved(account_id_hex, bootstrap_relays)
            .await;
        if let Some(observation) = observation {
            observation.directory_sample(
                match &result {
                    Ok(_) => "success",
                    Err(DirectoryError::MissingKeyPackage { .. }) => "empty",
                    Err(DirectoryError::InvalidKeyPackageEvent(_)) => "invalid",
                    Err(_) => "failure",
                },
                // Failed fetches have no result provenance; classify the network attempt.
                result.as_ref().map_or("network", |(_, source)| *source),
                1,
            );
            observation.discard();
        }
        result.map(|(fetched, _)| fetched)
    }

    async fn fetch_latest_key_package_for_account_id_unobserved(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<(FetchedKeyPackage, &'static str), DirectoryError> {
        // The incomplete outcome names the canonical account, even for an npub.
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        tokio::time::timeout(
            std::time::Duration::from_secs(50),
            self.fetch_latest_key_package_for_account_id_bounded(&account_id_hex, bootstrap_relays),
        )
        .await
        .map_err(|_| DirectoryError::DirectoryLookupIncomplete(account_id_hex))?
    }

    async fn fetch_latest_key_package_for_account_id_bounded(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<(FetchedKeyPackage, &'static str), DirectoryError> {
        // Normalize the identifier to canonical hex up front. The relay *queries*
        // below re-parse internally, but the KeyPackage record filter compares
        // `event.pubkey` (always hex) against this string verbatim — so an npub
        // arg would resolve the relay list yet silently drop every KeyPackage
        // record (hex != npub), surfacing a bogus `MissingKeyPackage` for an
        // account that has one. Canonicalizing here makes the arg accept npub or
        // hex consistently across query and filter.
        let canonical = PublicKey::parse(account_id_hex)
            .map_err(|_| DirectoryError::InvalidPublicKey)?
            .to_hex();
        let account_id_hex = canonical.as_str();
        let discovery_relays = self.directory_source_relays(&bootstrap_relays);
        let has_explicit_bootstrap_relays = !bootstrap_relays.is_empty();
        let mut relay_lists = if has_explicit_bootstrap_relays {
            self.fetch_relay_list_status(account_id_hex, bootstrap_relays)
                .await?
        } else {
            let directory = self.clone();
            let account_id = account_id_hex.to_owned();
            blocking_directory_task(move || directory.cached_relay_list_status(&account_id)).await?
        };
        if !has_explicit_bootstrap_relays && relay_lists.nip65.relays.is_empty() {
            let source_relays = self.directory_source_relays(&[]);
            if !source_relays.is_empty() {
                relay_lists = self
                    .fetch_relay_list_status(account_id_hex, source_relays)
                    .await?;
            }
        }
        {
            let directory = self.clone();
            let account_id = account_id_hex.to_owned();
            let remembered = relay_lists.clone();
            blocking_directory_task(move || {
                directory.remember_directory_relay_lists(&account_id, &remembered)
            })
            .await?;
        }
        let mut source_relays = self.relay_plane.retain_safe_discovered_endpoints(
            relay_lists
                .nip65
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
            "key package directory fetch",
        );
        if source_relays.is_empty() {
            source_relays = self.directory_source_relays(&[]);
        }
        if source_relays.is_empty() {
            return Err(DirectoryError::MissingRelayLists(vec![
                MissingRelayListKind::Nip65,
            ]));
        }
        let outcome = self
            .relay_plane
            .fetch_directory_events_with_completion(
                source_relays.clone(),
                vec![DirectoryEventQuery::new(
                    KIND_MARMOT_KEY_PACKAGE,
                    vec![account_id_hex.to_owned()],
                    12,
                )],
            )
            .await
            .map_err(|error| {
                DirectoryError::RelayDirectory(format!("fetch key packages: {error}"))
            })?;
        let cached_entry = {
            let directory = self.clone();
            let account_id = account_id_hex.to_owned();
            blocking_directory_task(move || directory.directory_entry(&account_id)).await?
        };
        let cached_entry = cached_entry.map(|mut entry| {
            if let Some(metadata) = entry.key_package.as_mut() {
                metadata.key_package_event_id =
                    metadata.key_package_event_id.trim().to_ascii_lowercase();
                // A diagnostic cache without a usable public event id cannot
                // be checked for exact-event revocation and is ineligible.
                if nostr_sdk::prelude::EventId::from_hex(&metadata.key_package_event_id).is_err() {
                    entry.key_package = None;
                }
            }
            entry
        });
        let cached_target = cached_entry
            .as_ref()
            .and_then(|entry| entry.key_package.as_ref())
            .map(crate::directory::published_records::KeyPackageRecoveryTarget::from_cached);
        let records = self
            .recover_key_package_records(super::key_package_recovery::KeyPackageRecoveryRequest {
                account: account_id_hex,
                searched: &source_relays,
                observed: outcome.records,
                primary_complete: outcome.complete,
                discovery: &discovery_relays,
                requirements: None,
                cached_target,
            })
            .await?;
        let cached_entry = cached_entry.filter(|entry| {
            records.cache_evidence.as_ref().is_none_or(|evidence| {
                entry
                    .key_package
                    .as_ref()
                    .is_none_or(|cached| evidence.allows_cached(cached))
            })
        });
        let selection = latest_fresh_key_package_from_records(
            account_id_hex,
            records.records,
            records.freshness,
            &self.config.key_package_client_preference,
        )?;
        let from_cache = selection.value.is_none();
        let mut fetched = fresh_or_cached_key_package(account_id_hex, selection, cached_entry)?;
        // Without a fresh selection, only a successful cache fallback reaches this point.
        let source = if from_cache { "cache" } else { "network" };
        fetched.relay_lists = relay_lists;
        {
            let directory = self.clone();
            let remembered = fetched.clone();
            blocking_directory_task(move || directory.remember_directory_key_package(&remembered))
                .await?;
        }
        Ok((fetched, source))
    }

    pub async fn refresh_directory_entry_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRecord, DirectoryError> {
        let status = if bootstrap_relays.is_empty() {
            let directory = self.clone();
            let account_id = account_id_hex.to_owned();
            blocking_directory_task(move || directory.cached_relay_list_status(&account_id)).await?
        } else {
            self.fetch_relay_list_status(account_id_hex, bootstrap_relays)
                .await?
        };
        {
            let directory = self.clone();
            let account_id = account_id_hex.to_owned();
            let remembered = status.clone();
            blocking_directory_task(move || {
                directory.remember_directory_relay_lists(&account_id, &remembered)
            })
            .await?;
        }
        let directory = self.clone();
        let account_id = account_id_hex.to_owned();
        blocking_directory_task(move || {
            directory
                .directory_entry(&account_id)?
                .ok_or_else(|| DirectoryError::MissingDirectoryEntry(account_id))
        })
        .await
    }

    pub fn directory_entry_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
        self.directory_entry(account_id_hex)
    }

    /// Bounded local cached-identity page for many account IDs.
    ///
    /// Acquires directory caches and shared storage once, then projects each
    /// requested id in input order. Invalid IDs become rows rather than failing
    /// the page. This is a cache read, not a network refresh.
    pub fn cached_identity_projections_for_account_ids(
        &self,
        account_id_hexes: &[String],
    ) -> Result<Vec<CachedIdentityProjection>, DirectoryError> {
        if account_id_hexes.len() > MAX_CACHED_IDENTITY_PAGE_SIZE {
            return Err(DirectoryError::InvalidCachedIdentityPage(format!(
                "requested {} accounts; maximum page size is {MAX_CACHED_IDENTITY_PAGE_SIZE}",
                account_id_hexes.len()
            )));
        }
        if account_id_hexes.is_empty() {
            return Ok(Vec::new());
        }

        let caches = self.resources.current_caches()?;
        let shared_storage = self.resources.shared_storage()?;
        let local_accounts = self.local_accounts_by_id()?;
        let mut projections = Vec::with_capacity(account_id_hexes.len());

        for requested_id in account_id_hexes {
            let Ok(account_id_hex) = parse_account_id_hex(requested_id) else {
                projections.push(cached_identity_projection(
                    requested_id.clone(),
                    None,
                    None,
                    None,
                ));
                continue;
            };
            let profile = self
                .directory_entry_for_account_id_with_handles(
                    &account_id_hex,
                    &caches,
                    &shared_storage,
                    &local_accounts,
                )?
                .and_then(|entry| entry.profile);
            let local_label = local_accounts
                .get(&account_id_hex)
                .map(|account| account.label.clone());
            projections.push(cached_identity_projection(
                requested_id.clone(),
                Some(account_id_hex),
                profile,
                local_label,
            ));
        }

        Ok(projections)
    }

    pub async fn refresh_user_directory_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRefresh, DirectoryError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        {
            let directory = self.clone();
            let account_id = account_id_hex.clone();
            blocking_directory_task(move || directory.remember_directory_user(&account_id)).await?;
        }
        let follow_list = self
            .fetch_follow_list_for_account_id(&account_id_hex, &bootstrap_relays)
            .await?;
        {
            let directory = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = follow_list.clone();
            blocking_directory_task(move || {
                directory.remember_directory_follow_list(&account_id, &remembered)
            })
            .await?;
        }

        let profile_count = self
            .refresh_directory_profiles(&follow_list.follows, &bootstrap_relays)
            .await?;

        Ok(UserDirectoryRefresh {
            account_id_hex,
            follow_count: follow_list.follows.len(),
            profile_count,
        })
    }

    pub fn search_user_directory(
        &self,
        search: UserDirectorySearch,
    ) -> Result<Vec<UserDirectorySearchResult>, DirectoryError> {
        search.validate()?;
        let records =
            self.directory_search_records(&search.searcher_account_id_hex, search.radius_end)?;
        let query = search.query.trim().to_lowercase();
        if query.is_empty() {
            return Ok(Vec::new());
        }

        let follows =
            self.cached_search_follows(&parse_account_id_hex(&search.searcher_account_id_hex)?)?;
        let mut results = Vec::new();
        for (record, radius) in records {
            if radius < search.radius_start || radius > search.radius_end {
                continue;
            }
            let Some(search_match) = user_record_match(&record, &query) else {
                continue;
            };
            results.push(UserDirectorySearchResult {
                is_followed_by_searcher: follows.contains(&record.account_id_hex),
                account_id_hex: record.account_id_hex.clone(),
                npub: record.npub.clone(),
                radius,
                matched_field: search_match.field,
                match_quality: search_match.quality,
                provider_rank: None,
                profile: record.profile.clone(),
            });
        }
        sort_user_search_results(&mut results);
        if let Some(limit) = search.limit {
            results.truncate(limit);
        }
        Ok(results)
    }

    pub fn account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<AccountRelayListStatus, DirectoryError> {
        self.cached_relay_list_status(account_id_hex)
    }

    pub(crate) async fn fetch_key_package_events_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: &[TransportEndpoint],
    ) -> Result<Vec<RelayEventRecord>, DirectoryError> {
        self.fetch_key_package_events_for_account_id_with_limit(account_id_hex, source_relays, 12)
            .await
    }

    pub(crate) async fn fetch_key_package_events_for_account_id_with_limit(
        &self,
        account_id_hex: &str,
        source_relays: &[TransportEndpoint],
        limit: usize,
    ) -> Result<Vec<RelayEventRecord>, DirectoryError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| DirectoryError::InvalidPublicKey)?;
        let source_relays = self.directory_source_relays(source_relays);
        self.relay_plane
            .fetch_directory_events(
                source_relays,
                vec![DirectoryEventQuery::new(
                    KIND_MARMOT_KEY_PACKAGE,
                    vec![public_key.to_hex()],
                    limit,
                )],
            )
            .await
            .map_err(|e| DirectoryError::RelayDirectory(format!("fetch key packages: {e}")))
    }

    pub(crate) async fn fetch_follow_list_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: &[TransportEndpoint],
    ) -> Result<FetchedFollowList, DirectoryError> {
        let records = self
            .fetch_events_for_account_ids(
                &[account_id_hex.to_owned()],
                KIND_NOSTR_CONTACT_LIST,
                source_relays,
            )
            .await?;
        let selection =
            latest_follow_list_from_records(account_id_hex, records, self.directory_freshness());
        if let Some(follow_list) = selection.value {
            return Ok(follow_list);
        }
        // No event on this relay set means "unknown", not "the account
        // follows nobody". Preserve any cached edges whether the candidates
        // were absent or rejected as future-dated.
        let cached_entry = {
            let directory = self.clone();
            let account_id = account_id_hex.to_owned();
            blocking_directory_task(move || directory.directory_entry(&account_id)).await?
        };
        Ok(cached_or_unknown_follow_list(cached_entry, source_relays))
    }

    pub async fn fetch_current_follow_list_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: Vec<TransportEndpoint>,
    ) -> Result<Option<Vec<String>>, DirectoryError> {
        let observation =
            self.resources
                .begin(ObservedFamily::Directory, "follows", ObservedUnit::Attempt);
        let result = self
            .fetch_current_follow_list_for_account_id_unobserved(account_id_hex, source_relays)
            .await;
        if let Some(observation) = observation {
            observation.directory_sample(
                match &result {
                    Ok(Some(_)) => "success",
                    Ok(None) => "empty",
                    Err(_) => "failure",
                },
                "network",
                1,
            );
            observation.discard();
        }
        result
    }

    async fn fetch_current_follow_list_for_account_id_unobserved(
        &self,
        account_id_hex: &str,
        source_relays: Vec<TransportEndpoint>,
    ) -> Result<Option<Vec<String>>, DirectoryError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        let records = self
            .fetch_events_for_account_ids(
                std::slice::from_ref(&account_id_hex),
                KIND_NOSTR_CONTACT_LIST,
                &source_relays,
            )
            .await?;
        let Some(follow_list) =
            latest_follow_list_from_records(&account_id_hex, records, self.directory_freshness())
                .value
        else {
            return Ok(None);
        };
        {
            let directory = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = follow_list.clone();
            blocking_directory_task(move || {
                directory.remember_directory_follow_list(&account_id, &remembered)
            })
            .await?;
        }
        Ok(Some(follow_list.follows))
    }

    async fn refresh_directory_profiles(
        &self,
        account_ids: &[String],
        source_relays: &[TransportEndpoint],
    ) -> Result<usize, DirectoryError> {
        if account_ids.is_empty() {
            return Ok(0);
        }
        let records = self
            .fetch_events_for_account_ids(account_ids, KIND_NOSTR_METADATA, source_relays)
            .await?;
        let profiles =
            latest_fresh_profiles_from_records(records, self.directory_freshness()).value;
        {
            let directory = self.clone();
            let account_ids = account_ids.to_vec();
            let remembered = profiles.clone();
            blocking_directory_task(move || {
                for account_id in &account_ids {
                    directory.remember_directory_user(account_id)?;
                }
                for (account_id, profile) in &remembered {
                    directory.remember_directory_profile_if_newer(account_id, profile)?;
                }
                Ok(())
            })
            .await?;
        }
        Ok(profiles.len())
    }

    /// Fetch and cache a single account's own Nostr kind:0 profile from
    /// relays. Unlike `refresh_user_directory_for_account_id` (which refreshes
    /// the account's *follows'* profiles), this targets the account itself, so
    /// its display name / avatar become locally available right away.
    pub async fn refresh_profile_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: Vec<TransportEndpoint>,
    ) -> Result<(), DirectoryError> {
        self.refresh_directory_profiles(&[account_id_hex.to_owned()], &source_relays)
            .await?;
        Ok(())
    }

    pub(crate) fn directory_entries(&self) -> Result<Vec<UserDirectoryRecord>, DirectoryError> {
        let local_accounts = self.local_accounts_by_id()?;
        let mut entries_by_id = BTreeMap::new();
        for cache in self.resources.current_caches()? {
            for entry in cache.entries()? {
                upsert_newer_directory_entry(
                    &mut entries_by_id,
                    hydrate_directory_record(entry, &local_accounts)?,
                );
            }
        }
        for record in self.resources.shared_storage()?.public_directory_users()? {
            let entry = hydrate_directory_record(
                user_directory_record_from_public(record)?,
                &local_accounts,
            )?;
            upsert_newer_directory_entry(&mut entries_by_id, entry);
        }
        Ok(entries_by_id.into_values().collect())
    }

    pub(crate) fn directory_sync_plan(&self) -> Result<DirectorySyncPlan, DirectoryError> {
        let local_account_ids = self
            .resources
            .local_accounts()?
            .into_iter()
            .filter(|account| account.active_signing)
            .map(|account| account.account_id_hex)
            .collect::<Vec<_>>();
        let mut known_user_ids = self
            .directory_entries()?
            .into_iter()
            .map(|entry| entry.account_id_hex)
            .collect::<Vec<_>>();
        known_user_ids.extend(local_account_ids.iter().cloned());
        Ok(plan_directory_sync(
            self.config.default_relays.clone(),
            local_account_ids,
            known_user_ids,
            None,
        ))
    }

    fn directory_search_records(
        &self,
        searcher_account_id_hex: &str,
        radius_end: u8,
    ) -> Result<Vec<(UserDirectoryRecord, u8)>, DirectoryError> {
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let mut frontier = vec![parse_account_id_hex(searcher_account_id_hex)?];
        let caches = self.resources.current_caches()?;
        // One instant for the whole traversal: a layer must not disagree with
        // itself about whether a cached profile has expired.
        let now = crate::directory::unix_now_seconds() as i64;

        for radius in 0..=radius_end {
            let mut next = Vec::new();
            frontier.sort();
            frontier.dedup();

            for account_id in frontier {
                if seen.len() >= USER_DIRECTORY_SEARCH_MAX_VISITED {
                    return Ok(records);
                }
                if !seen.insert(account_id.clone()) {
                    continue;
                }

                let Some(mut record) =
                    Self::directory_search_record_from_caches(&caches, &account_id, now)?
                else {
                    continue;
                };
                if radius == 0 {
                    record.follows = self
                        .cached_search_follow_list(&account_id)?
                        .unwrap_or_default();
                }
                if radius < radius_end {
                    for follow in &record.follows {
                        if next.len() >= USER_DIRECTORY_SEARCH_MAX_FRONTIER {
                            break;
                        }
                        if !seen.contains(follow) {
                            next.push(follow.clone());
                        }
                    }
                }
                records.push((record, radius));
            }

            frontier = next;
        }

        Ok(records)
    }

    fn directory_search_record_from_caches(
        caches: &[DirectoryCache],
        account_id_hex: &str,
        now: i64,
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
        for cache in caches {
            if let Some(entry) = cache.search_record(account_id_hex, now)? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }
}

pub(crate) fn cached_or_unknown_follow_list(
    cached: Option<UserDirectoryRecord>,
    source_relays: &[TransportEndpoint],
) -> FetchedFollowList {
    if let Some(entry) = cached {
        return FetchedFollowList {
            follows: entry.follows,
            source_relays: entry.follow_source_relays,
        };
    }
    FetchedFollowList {
        follows: Vec::new(),
        source_relays: source_relays
            .iter()
            .map(|endpoint| endpoint.0.clone())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hydration_uses_one_catalog() {
        let root = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relays(root.path(), vec![]);
        let home = app.account_home();
        let alice = home.create_account("alice").unwrap();
        // Legacy homes can retain two labels for one identity.
        let mut alias = alice.clone();
        alias.label = "z-alias".into();
        let alias_dir = home.account_dir(&alias.label);
        fs_private::create_dir_all_private(&alias_dir).unwrap();
        fs_private::write_private(
            &alias_dir.join("account.json"),
            &serde_json::to_vec(&alias).unwrap(),
        )
        .unwrap();
        let local_accounts = app.local_accounts_by_id().unwrap();
        let local = &local_accounts[&alice.account_id_hex];
        assert_eq!(
            local.directory,
            app.local_account_for_id(&alice.account_id_hex).unwrap()
        );
        assert_eq!(local.label, home.accounts().unwrap().last().unwrap().label);
        assert_ne!(local.directory.label, local.label);
        // Notification's existing single-entry reader keeps the first alias.
        assert_eq!(
            app.display_name_from_directory_entry(&alice.account_id_hex, None)
                .unwrap()
                .as_deref(),
            Some(local.directory.label.as_str())
        );
        let entry = app.empty_directory_record(&alice.account_id_hex);
        for label in ["alice", "z-alias"] {
            fs_private::write_private(&home.account_dir(label).join("account.json"), b"broken")
                .unwrap();
        }
        for index in 0..1000 {
            let mut row = entry.clone();
            if index != 0 {
                row.account_id_hex = format!("{index:064x}");
            }
            let hydrated = hydrate_directory_record(row, &local_accounts).unwrap();
            if index == 0 {
                assert_eq!(hydrated.local_account.unwrap(), local.directory);
            } else {
                assert!(hydrated.local_account.is_none());
            }
        }
        assert!(app.local_accounts_by_id().unwrap().is_empty());
    }
}
