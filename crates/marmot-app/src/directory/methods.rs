//! User-directory domain methods for [`MarmotApp`].
//!
//! Split `impl MarmotApp` block covering the user-directory cache/sync surface:
//! relay-list and profile/key-package/follow-list fetches, the public
//! `directory_*`/`*_user_directory` API, directory-cache lifecycle, and
//! in-memory directory-record hydration. The stateless record types and helpers
//! these build on live in [`crate::directory::records`].

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;

use cgka_traits::TransportEndpoint;
use marmot_account::AccountSummary;
use nostr_sdk::prelude::PublicKey;
use storage_sqlite::{PublicDirectoryUserRecord, SqliteSharedStorage};
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
};
use transport_nostr_peeler::NostrTransportEvent;

use crate::directory::records::{
    DirectoryKeyPackage, FetchedFollowList, UserDirectoryLocalAccount, UserDirectoryRecord,
    UserDirectoryRefresh, UserDirectorySearch, UserDirectorySearchResult, UserProfileMetadata,
    field_rank, follow_list_from_record, latest_follow_list_from_records,
    latest_fresh_profiles_from_records, match_quality_rank, profile_content_json,
    profile_from_record, public_directory_user_record, select_newer_directory_entry,
    source_relays_from_record, upsert_newer_directory_entry, user_directory_record_from_public,
    user_record_match,
};
use crate::directory::{DirectoryCache, DirectorySyncHandle, DirectorySyncPlan};
use crate::ids::{
    normalize_account_ids, npub_for_account_id, npub_for_account_id_lossy, parse_account_id_hex,
};
use crate::key_package_records::{
    fill_missing_relay_lists_from_cached, fresh_or_cached_key_package,
    fresh_relay_list_status_from_records, key_package_from_record,
    latest_fresh_key_package_from_records, publish_endpoints_from_bootstrap, relay_list_queries,
    relay_lists_have_any_relays,
};
use crate::relay_plane::{DirectoryEventQuery, DirectoryRelayEventRecord as RelayEventRecord};
use crate::{
    APP_CACHE_DB_FILE, AccountRelayListBootstrap, AccountRelayListStatus, AppError,
    DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER, DirectoryFreshness, FetchedKeyPackage,
    KIND_NOSTR_CONTACT_LIST, KIND_NOSTR_METADATA, MarmotApp, MissingRelayListKind, ReceivedMessage,
    SqlcipherDatabaseKind, USER_DIRECTORY_SEARCH_MAX_FRONTIER, USER_DIRECTORY_SEARCH_MAX_VISITED,
    push_unique_strings, relays_from_relay_list_event, remove_sqlite_file_set,
};

impl MarmotApp {
    pub fn warm_directory_storage(&self) -> Result<(), AppError> {
        let _span = tracing::debug_span!(
            target: "marmot_app::directory",
            "directory_storage_warm",
            method = "warm_directory_storage"
        )
        .entered();
        let _shared = self.shared_storage()?;
        let _caches = self.directory_caches()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn directory_cache_open_count_for_test(&self) -> usize {
        self.directory_cache_open_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn directory_cache_cached_for_test(&self, label: &str) -> bool {
        self.directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(label)
    }

    pub async fn fetch_account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| AppError::InvalidPublicKey)?;
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
            .map_err(|e| AppError::RelayDirectory(format!("fetch relay lists: {e}")))?;
        let selection = fresh_relay_list_status_from_records(&account_id_hex, records, freshness);
        let mut status = selection.value;
        if selection.rejected_future || !relay_lists_have_any_relays(&status) {
            let cached = self.account_relay_list_status_for_account_id(&account_id_hex)?;
            if relay_lists_have_any_relays(&cached) {
                if !relay_lists_have_any_relays(&status) {
                    return Ok(cached);
                }
                if selection.rejected_future {
                    fill_missing_relay_lists_from_cached(&mut status, &cached);
                }
            }
        }
        if status.bootstrap_relays.is_empty() {
            status.bootstrap_relays = bootstrap_relays
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect();
        }
        self.remember_directory_relay_lists(&account_id_hex, &status)?;
        Ok(status)
    }

    pub async fn fetch_current_account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
        required_list_kind: Option<&str>,
    ) -> Result<Option<AccountRelayListStatus>, AppError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| AppError::InvalidPublicKey)?;
        let account_id_hex = public_key.to_hex();
        let required_list_kind = match required_list_kind {
            Some("nip65") => Some(KIND_NIP65_RELAY_LIST),
            Some("inbox") => Some(KIND_MARMOT_INBOX_RELAY_LIST),
            Some(other) => {
                return Err(AppError::RelayDirectory(format!(
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
            .map_err(|e| AppError::RelayDirectory(format!("fetch relay lists: {e}")))?;
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
            return Ok(None);
        }
        let selection = fresh_relay_list_status_from_records(&account_id_hex, records, freshness);
        let mut status = selection.value;
        let cached = self.account_relay_list_status_for_account_id(&account_id_hex)?;
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
        self.remember_directory_relay_lists(&account_id_hex, &status)?;
        Ok(Some(status))
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
    ) -> Result<Option<UserProfileMetadata>, AppError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| AppError::InvalidPublicKey)?;
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
        self.remember_directory_profile(&account_id_hex, &profile)?;
        Ok(Some(profile))
    }

    pub async fn fetch_latest_key_package_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<FetchedKeyPackage, AppError> {
        // Normalize the identifier to canonical hex up front. The relay *queries*
        // below re-parse internally, but the KeyPackage record filter compares
        // `event.pubkey` (always hex) against this string verbatim — so an npub
        // arg would resolve the relay list yet silently drop every KeyPackage
        // record (hex != npub), surfacing a bogus `MissingKeyPackage` for an
        // account that has one. Canonicalizing here makes the arg accept npub or
        // hex consistently across query and filter.
        let canonical = PublicKey::parse(account_id_hex)
            .map_err(|_| AppError::InvalidPublicKey)?
            .to_hex();
        let account_id_hex = canonical.as_str();
        let has_explicit_bootstrap_relays = !bootstrap_relays.is_empty();
        let mut relay_lists = if has_explicit_bootstrap_relays {
            self.fetch_account_relay_list_status_for_account_id(account_id_hex, bootstrap_relays)
                .await?
        } else {
            self.account_relay_list_status_for_account_id(account_id_hex)?
        };
        if !has_explicit_bootstrap_relays && relay_lists.nip65.relays.is_empty() {
            let source_relays = self.directory_source_relays(&[]);
            if !source_relays.is_empty() {
                relay_lists = self
                    .fetch_account_relay_list_status_for_account_id(account_id_hex, source_relays)
                    .await?;
            }
        }
        self.remember_directory_relay_lists(account_id_hex, &relay_lists)?;
        if relay_lists.nip65.relays.is_empty() {
            return Err(AppError::MissingRelayLists(vec![
                MissingRelayListKind::Nip65,
            ]));
        }

        let source_relays = relay_lists
            .nip65
            .relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        let records = self
            .fetch_key_package_events_for_account_id(account_id_hex, &source_relays)
            .await?;
        let cached_entry = self.directory_entry_for_account_id(account_id_hex)?;
        let mut fetched = fresh_or_cached_key_package(
            account_id_hex,
            latest_fresh_key_package_from_records(
                account_id_hex,
                records,
                self.directory_freshness(),
            )?,
            cached_entry,
        )?;
        fetched.relay_lists = relay_lists;
        self.remember_directory_key_package(&fetched)?;
        Ok(fetched)
    }

    pub async fn refresh_directory_entry_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRecord, AppError> {
        let status = if bootstrap_relays.is_empty() {
            self.account_relay_list_status_for_account_id(account_id_hex)?
        } else {
            self.fetch_account_relay_list_status_for_account_id(account_id_hex, bootstrap_relays)
                .await?
        };
        self.remember_directory_relay_lists(account_id_hex, &status)?;
        self.directory_entry_for_account_id(account_id_hex)?
            .ok_or_else(|| AppError::MissingDirectoryEntry(account_id_hex.to_owned()))
    }

    pub fn directory_entry_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        let caches = self.directory_caches()?;
        let shared_storage = self.shared_storage()?;
        self.directory_entry_for_account_id_with_handles(&account_id_hex, &caches, &shared_storage)
    }

    pub async fn refresh_user_directory_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRefresh, AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        self.remember_directory_user(&account_id_hex)?;
        let follow_list = self
            .fetch_follow_list_for_account_id(&account_id_hex, &bootstrap_relays)
            .await?;
        self.remember_directory_follow_list(&account_id_hex, &follow_list)?;

        let profile_count = self
            .refresh_directory_profiles(&follow_list.follows, &bootstrap_relays)
            .await?;

        Ok(UserDirectoryRefresh {
            account_id_hex,
            follow_count: follow_list.follows.len(),
            profile_count,
        })
    }

    pub async fn publish_user_profile(
        &self,
        label: &str,
        profile: UserProfileMetadata,
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        let keys = self.account_home().load_signing_keys(label)?;
        let endpoints = self.outbox_endpoints(
            &keys.public_key().to_hex(),
            publish_endpoints_from_bootstrap(&bootstrap),
        );
        let content = serde_json::to_string(&profile_content_json(&profile))?;
        let event = NostrTransportEvent::new_unsigned(
            keys.public_key().to_hex(),
            KIND_NOSTR_METADATA,
            Vec::new(),
            content,
        );
        self.relay_client_for_endpoints(&keys, &endpoints)
            .publish_event(&endpoints, &event, 1)
            .await?;
        Ok(())
    }

    pub async fn publish_account_follow_list(
        &self,
        label: &str,
        follows: &[&str],
        bootstrap: AccountRelayListBootstrap,
    ) -> Result<(), AppError> {
        let keys = self.account_home().load_signing_keys(label)?;
        let endpoints = self.outbox_endpoints(
            &keys.public_key().to_hex(),
            publish_endpoints_from_bootstrap(&bootstrap),
        );
        let tags = follows
            .iter()
            .map(|follow| {
                parse_account_id_hex(follow).map(|account_id| vec!["p".to_owned(), account_id])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let event = NostrTransportEvent::new_unsigned(
            keys.public_key().to_hex(),
            KIND_NOSTR_CONTACT_LIST,
            tags,
            String::new(),
        );
        self.relay_client_for_endpoints(&keys, &endpoints)
            .publish_event(&endpoints, &event, 1)
            .await?;
        Ok(())
    }

    pub fn search_user_directory(
        &self,
        search: UserDirectorySearch,
    ) -> Result<Vec<UserDirectorySearchResult>, AppError> {
        search.validate()?;
        let records =
            self.directory_search_records(&search.searcher_account_id_hex, search.radius_end)?;
        let query = search.query.trim().to_lowercase();
        if query.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        for (record, radius) in records {
            if radius < search.radius_start || radius > search.radius_end {
                continue;
            }
            let Some(search_match) = user_record_match(&record, &query) else {
                continue;
            };
            results.push(UserDirectorySearchResult {
                account_id_hex: record.account_id_hex.clone(),
                npub: record.npub.clone(),
                radius,
                matched_field: search_match.field,
                match_quality: search_match.quality,
                profile: record.profile.clone(),
            });
        }
        results.sort_by(|a, b| {
            a.radius
                .cmp(&b.radius)
                .then_with(|| {
                    match_quality_rank(&a.match_quality).cmp(&match_quality_rank(&b.match_quality))
                })
                .then_with(|| field_rank(&a.matched_field).cmp(&field_rank(&b.matched_field)))
                .then_with(|| a.account_id_hex.cmp(&b.account_id_hex))
        });
        if let Some(limit) = search.limit {
            results.truncate(limit);
        }
        Ok(results)
    }

    pub fn account_relay_list_status(
        &self,
        label: &str,
    ) -> Result<AccountRelayListStatus, AppError> {
        let account = self.account_home().account(label)?;
        self.account_relay_list_status_for_account_id(&account.account_id_hex)
    }

    pub fn account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<AccountRelayListStatus, AppError> {
        Ok(self
            .directory_entry_for_account_id(account_id_hex)?
            .map(|entry| entry.relay_lists)
            .unwrap_or_else(AccountRelayListStatus::empty))
    }

    pub(crate) async fn fetch_key_package_events_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: &[TransportEndpoint],
    ) -> Result<Vec<RelayEventRecord>, AppError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| AppError::InvalidPublicKey)?;
        let source_relays = self.directory_source_relays(source_relays);
        self.relay_plane
            .fetch_directory_events(
                source_relays,
                vec![DirectoryEventQuery::new(
                    KIND_MARMOT_KEY_PACKAGE,
                    vec![public_key.to_hex()],
                    12,
                )],
            )
            .await
            .map_err(|e| AppError::RelayDirectory(format!("fetch key packages: {e}")))
    }

    async fn fetch_follow_list_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: &[TransportEndpoint],
    ) -> Result<FetchedFollowList, AppError> {
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
        if selection.rejected_future
            && let Some(entry) = self.directory_entry_for_account_id(account_id_hex)?
        {
            return Ok(FetchedFollowList {
                follows: entry.follows,
                source_relays: entry.follow_source_relays,
            });
        }
        Ok(FetchedFollowList {
            follows: Vec::new(),
            source_relays: source_relays
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect(),
        })
    }

    pub async fn fetch_current_follow_list_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: Vec<TransportEndpoint>,
    ) -> Result<Option<Vec<String>>, AppError> {
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
        self.remember_directory_follow_list(&account_id_hex, &follow_list)?;
        Ok(Some(follow_list.follows))
    }

    async fn refresh_directory_profiles(
        &self,
        account_ids: &[String],
        source_relays: &[TransportEndpoint],
    ) -> Result<usize, AppError> {
        if account_ids.is_empty() {
            return Ok(0);
        }
        let records = self
            .fetch_events_for_account_ids(account_ids, KIND_NOSTR_METADATA, source_relays)
            .await?;
        let profiles =
            latest_fresh_profiles_from_records(records, self.directory_freshness()).value;
        for account_id in account_ids {
            self.remember_directory_user(account_id)?;
        }
        for (account_id, profile) in &profiles {
            self.remember_directory_profile(account_id, profile)?;
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
    ) -> Result<(), AppError> {
        self.refresh_directory_profiles(&[account_id_hex.to_owned()], &source_relays)
            .await?;
        Ok(())
    }

    async fn fetch_events_for_account_ids(
        &self,
        account_ids: &[String],
        kind: u64,
        source_relays: &[TransportEndpoint],
    ) -> Result<Vec<RelayEventRecord>, AppError> {
        let source_relays = self.directory_source_relays(source_relays);
        let account_ids = account_ids
            .iter()
            .map(|account_id| parse_account_id_hex(account_id))
            .collect::<Result<Vec<_>, _>>()?;
        let limit = (account_ids.len() * 4).max(1);
        self.relay_plane
            .fetch_directory_events(
                source_relays,
                vec![DirectoryEventQuery::new(kind, account_ids, limit)],
            )
            .await
            .map_err(|e| AppError::RelayDirectory(format!("fetch user directory events: {e}")))
    }

    pub(crate) fn directory_freshness(&self) -> DirectoryFreshness {
        DirectoryFreshness::from_now(self.config.directory_max_future_skew)
    }

    pub(crate) fn directory_source_relays(
        &self,
        source_relays: &[TransportEndpoint],
    ) -> Vec<TransportEndpoint> {
        if !source_relays.is_empty() {
            return source_relays.to_vec();
        }
        self.relay_endpoints()
    }

    pub(crate) fn directory_entries(&self) -> Result<Vec<UserDirectoryRecord>, AppError> {
        let mut entries_by_id = BTreeMap::new();
        for cache in self.directory_caches()? {
            for entry in cache.entries()? {
                upsert_newer_directory_entry(
                    &mut entries_by_id,
                    self.hydrate_directory_record(entry)?,
                );
            }
        }
        for record in self.shared_storage()?.public_directory_users()? {
            let entry = self.hydrate_public_directory_record(record)?;
            upsert_newer_directory_entry(&mut entries_by_id, entry);
        }
        Ok(entries_by_id.into_values().collect())
    }

    pub(crate) fn directory_sync_plan(&self) -> Result<DirectorySyncPlan, AppError> {
        let local_account_ids = self
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.is_active_local_signing())
            .map(|account| account.account_id_hex)
            .collect::<Vec<_>>();
        let mut known_user_ids = self
            .directory_entries()?
            .into_iter()
            .map(|entry| entry.account_id_hex)
            .collect::<Vec<_>>();
        known_user_ids.extend(local_account_ids.iter().cloned());
        Ok(DirectorySyncPlan::from_known_users(
            self.relay_endpoints(),
            local_account_ids,
            known_user_ids,
            None,
        ))
    }

    fn directory_search_records(
        &self,
        searcher_account_id_hex: &str,
        radius_end: u8,
    ) -> Result<Vec<(UserDirectoryRecord, u8)>, AppError> {
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let mut frontier = vec![parse_account_id_hex(searcher_account_id_hex)?];
        let caches = self.directory_caches()?;

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

                let Some(record) = Self::directory_search_record_from_caches(&caches, &account_id)?
                else {
                    continue;
                };
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

    pub(crate) fn directory_entry_for_account_id_with_handles(
        &self,
        account_id_hex: &str,
        caches: &[DirectoryCache],
        shared_storage: &SqliteSharedStorage,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        let cached_entry = Self::directory_entry_from_caches(caches, account_id_hex)?
            .map(|entry| self.hydrate_directory_record(entry))
            .transpose()?;
        let shared_entry = shared_storage
            .public_directory_user(account_id_hex)?
            .map(|record| self.hydrate_public_directory_record(record))
            .transpose()?;
        Ok(select_newer_directory_entry(cached_entry, shared_entry))
    }

    fn directory_entry_from_caches(
        caches: &[DirectoryCache],
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        for cache in caches {
            if let Some(entry) = cache.entry(account_id_hex)? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    fn directory_search_record_from_caches(
        caches: &[DirectoryCache],
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        for cache in caches {
            if let Some(entry) = cache.search_record(account_id_hex)? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    fn remember_directory_relay_lists(
        &self,
        account_id_hex: &str,
        relay_lists: &AccountRelayListStatus,
    ) -> Result<(), AppError> {
        let mut entry = self
            .directory_entry_for_account_id(account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(account_id_hex));
        entry.account_id_hex = account_id_hex.to_owned();
        entry.relay_lists = relay_lists.clone();
        self.save_directory_entry(&entry)
    }

    pub(crate) fn remember_directory_key_package(
        &self,
        fetched: &FetchedKeyPackage,
    ) -> Result<(), AppError> {
        let mut entry = self
            .directory_entry_for_account_id(&fetched.account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(&fetched.account_id_hex));
        entry.account_id_hex = fetched.account_id_hex.clone();
        entry.relay_lists = fetched.relay_lists.clone();
        entry.key_package = Some(DirectoryKeyPackage {
            key_package_id: fetched.key_package_id.clone(),
            key_package_ref_hex: fetched.key_package_ref_hex.clone(),
            key_package_event_id: fetched.key_package_event_id.clone(),
            key_package_hex: hex::encode(fetched.key_package.bytes()),
            created_at: fetched.created_at,
            source_relays: fetched.source_relays.clone(),
        });
        self.save_directory_entry(&entry)
    }

    fn remember_directory_user(&self, account_id_hex: &str) -> Result<(), AppError> {
        self.remember_directory_user_with_reason(account_id_hex, "directory")
    }

    pub(crate) fn remember_directory_user_with_reason(
        &self,
        account_id_hex: &str,
        reason: &str,
    ) -> Result<(), AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        let entry = self
            .directory_entry_for_account_id(&account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(&account_id_hex));
        self.save_directory_entry_with_reason(&entry, reason)
    }

    pub(crate) fn remember_directory_message_sender(
        &self,
        message: &ReceivedMessage,
    ) -> Result<(), AppError> {
        self.remember_directory_user_with_reason(&message.sender, "message")
    }

    fn remember_directory_follow_list(
        &self,
        account_id_hex: &str,
        follow_list: &FetchedFollowList,
    ) -> Result<(), AppError> {
        let mut entry = self
            .directory_entry_for_account_id(account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(account_id_hex));
        entry.follows = follow_list.follows.clone();
        entry.follow_source_relays = follow_list.source_relays.clone();
        self.save_directory_entry(&entry)?;
        for follow in &follow_list.follows {
            self.remember_directory_user(follow)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn remember_directory_follow_list_for_test(
        &self,
        account_id_hex: &str,
        follow_list: &FetchedFollowList,
    ) -> Result<(), AppError> {
        self.remember_directory_follow_list(account_id_hex, follow_list)
    }

    /// Persist the follow edges from an ingested remote contact list for
    /// bounded directory search, without promoting the author's follows into
    /// known directory entries.
    ///
    /// Promoting every followed pubkey via [`Self::remember_directory_user`]
    /// would schedule a directory-sync rebuild that watches the new pubkeys,
    /// whose own contact lists would in turn be ingested — an unbounded
    /// transitive social-graph crawl (darkmatter#687). Instead the edges are
    /// recorded in the per-account search graph, which directory search reads
    /// but [`Self::directory_sync_plan`] does not. When the author is already a
    /// known directory entry (e.g. a local account whose contact list we sync),
    /// its own cached follow edges are refreshed too, but its follows are still
    /// not promoted.
    fn remember_directory_follow_edges_for_search(
        &self,
        account_id_hex: &str,
        follow_list: &FetchedFollowList,
    ) -> Result<(), AppError> {
        let npub = npub_for_account_id_lossy(account_id_hex);
        for cache in self.directory_caches()? {
            cache.remember_search_graph_follows(account_id_hex, &npub, &follow_list.follows)?;
        }
        if let Some(mut entry) = self.directory_entry_for_account_id(account_id_hex)? {
            entry.follows = follow_list.follows.clone();
            entry.follow_source_relays = follow_list.source_relays.clone();
            self.save_directory_entry(&entry)?;
        }
        Ok(())
    }

    pub(crate) fn remember_directory_profile(
        &self,
        account_id_hex: &str,
        profile: &UserProfileMetadata,
    ) -> Result<(), AppError> {
        let mut entry = self
            .directory_entry_for_account_id(account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(account_id_hex));
        entry.profile = Some(profile.clone());
        self.save_directory_entry(&entry)
    }

    pub(crate) fn remember_directory_profile_if_newer(
        &self,
        account_id_hex: &str,
        profile: &UserProfileMetadata,
    ) -> Result<(), AppError> {
        // Retain the cached profile when it is at least as recent as the
        // fetched copy. Nostr `created_at` is second-resolution, so a rapid
        // profile republish can carry the same timestamp as the previous
        // pre-edit kind-0. A strict `>` guard would treat an equal-second stale
        // relay copy as "newer or equal -> replace" and revert the just-published
        // local edit (darkmatter#206). Keeping the cache on equality protects
        // the local edit; an equal-timestamp event re-fetched from a relay is
        // either the user's own echoed publish (identical content) or a stale
        // copy that must not win.
        if let Some(entry) = self.directory_entry_for_account_id(account_id_hex)?
            && entry
                .profile
                .as_ref()
                .is_some_and(|cached| cached.created_at >= profile.created_at)
        {
            return Ok(());
        }
        self.remember_directory_profile(account_id_hex, profile)
    }

    fn remember_directory_relay_list_event(
        &self,
        account_id_hex: &str,
        record: &RelayEventRecord,
    ) -> Result<(), AppError> {
        let relays = relays_from_relay_list_event(&record.event);
        if relays.is_empty() {
            return Ok(());
        }
        let mut entry = self
            .directory_entry_for_account_id(account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(account_id_hex));
        match record.event.kind {
            KIND_NIP65_RELAY_LIST => entry.relay_lists.nip65.relays = relays,
            KIND_MARMOT_INBOX_RELAY_LIST => entry.relay_lists.inbox.relays = relays,
            _ => return Ok(()),
        }
        push_unique_strings(
            &mut entry.relay_lists.bootstrap_relays,
            source_relays_from_record(record),
        );
        entry.relay_lists.refresh();
        self.save_directory_entry(&entry)
    }

    pub(crate) fn ingest_directory_relay_event(
        &self,
        record: RelayEventRecord,
    ) -> Result<(), AppError> {
        if !self.directory_freshness().accepts(&record) {
            return Ok(());
        }
        let account_id_hex = parse_account_id_hex(&record.event.pubkey)?;
        match record.event.kind {
            KIND_NOSTR_METADATA => {
                if let Some((profile_account_id, profile)) = profile_from_record(record) {
                    self.remember_directory_profile_if_newer(&profile_account_id, &profile)?;
                }
            }
            KIND_NOSTR_CONTACT_LIST => {
                let follow_list = follow_list_from_record(record);
                self.remember_directory_follow_edges_for_search(&account_id_hex, &follow_list)?;
            }
            KIND_NIP65_RELAY_LIST | KIND_MARMOT_INBOX_RELAY_LIST => {
                self.remember_directory_relay_list_event(&account_id_hex, &record)?;
            }
            KIND_MARMOT_KEY_PACKAGE => {
                let mut fetched = key_package_from_record(record)?;
                fetched.relay_lists = self
                    .account_relay_list_status_for_account_id(&account_id_hex)
                    .unwrap_or_else(|_| AccountRelayListStatus::empty());
                self.remember_directory_key_package(&fetched)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn save_directory_entry(&self, entry: &UserDirectoryRecord) -> Result<(), AppError> {
        self.save_directory_entry_with_reason(entry, "directory")
    }

    pub(crate) fn save_directory_entry_with_reason(
        &self,
        entry: &UserDirectoryRecord,
        reason: &str,
    ) -> Result<(), AppError> {
        let proposed_entry = self.hydrate_directory_record(entry.clone())?;
        let shared_storage = self.shared_storage()?;
        let shared_record = shared_storage.public_directory_user(&proposed_entry.account_id_hex)?;
        let shared_entry = shared_record
            .clone()
            .map(|record| self.hydrate_public_directory_record(record))
            .transpose()?;
        let entry = select_newer_directory_entry(Some(proposed_entry), shared_entry.clone())
            .expect("proposed directory entry should be present");
        let caches = self.directory_caches()?;
        let public_entry = public_directory_user_record(&entry)?;
        let shared_entry_matches = shared_record.as_ref() == Some(&public_entry);
        let mut caches_match = true;
        for cache in &caches {
            let cached_entry = cache
                .entry(&entry.account_id_hex)?
                .map(|record| self.hydrate_directory_record(record))
                .transpose()?;
            if cached_entry.as_ref() != Some(&entry) {
                caches_match = false;
                break;
            }
        }
        if shared_entry_matches && caches_match {
            // Do not call `put_with_reason` just to refresh
            // `directory_known_user_reasons.last_seen_at`: this is the receive
            // hot path for duplicate senders, and a write-per-message would
            // recreate the amplification this guard prevents. Today the reason
            // table is provenance for persisted directory entries, not an
            // activity log.
            return Ok(());
        }
        shared_storage.put_public_directory_user(&public_entry)?;
        for cache in caches {
            cache.put_with_reason(&entry, reason)?;
        }
        self.request_directory_sync_rebuild();
        Ok(())
    }

    pub(crate) fn set_directory_sync_handle(&self, handle: Option<DirectorySyncHandle>) {
        *self
            .directory_sync
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = handle;
    }

    fn request_directory_sync_rebuild(&self) {
        let handle = self
            .directory_sync
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(handle) = handle {
            handle.request_rebuild();
        }
    }

    pub(crate) fn directory_cache_path(&self, label: &str) -> PathBuf {
        self.account_dir(label).join(APP_CACHE_DB_FILE)
    }

    fn legacy_directory_cache_path(&self) -> PathBuf {
        self.root.join(APP_CACHE_DB_FILE)
    }

    pub(crate) fn directory_cache_for_account(
        &self,
        account: &AccountSummary,
    ) -> Result<DirectoryCache, AppError> {
        self.clean_future_dated_directory_caches_for_all_accounts_once()?;
        if let Some(cache) = self
            .directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&account.label)
            .cloned()
        {
            return Ok(cache);
        }
        let _span = tracing::debug_span!(
            target: "marmot_app::directory",
            "directory_cache_handle_open",
            method = "directory_cache_for_account"
        )
        .entered();
        let keys = self.account_home().load_signing_keys(&account.label)?;
        let path = self.directory_cache_path(&account.label);
        let key = self.sqlcipher_key(
            &account.label,
            &keys,
            &path,
            SqlcipherDatabaseKind::DirectoryCache,
        )?;
        let cache = DirectoryCache::open(path, &key)?;
        #[cfg(test)]
        self.directory_cache_open_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut caches = self
            .directory_caches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(caches
            .entry(account.label.clone())
            .or_insert_with(|| cache.clone())
            .clone())
    }

    pub(crate) fn directory_caches(&self) -> Result<Vec<DirectoryCache>, AppError> {
        let accounts = self
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.is_active_local_signing())
            .collect::<Vec<_>>();
        self.clean_future_dated_directory_caches_once(&accounts)?;

        let mut caches = Vec::with_capacity(accounts.len());
        for account in accounts {
            caches.push(self.directory_cache_for_account(&account)?);
        }

        self.migrate_legacy_directory_cache_once(&caches)?;
        Ok(caches)
    }

    pub(crate) fn migrate_legacy_directory_cache_once(
        &self,
        caches: &[DirectoryCache],
    ) -> Result<(), AppError> {
        let mut checked = self
            .legacy_directory_cache_checked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *checked {
            return Ok(());
        }
        let legacy_path = self.legacy_directory_cache_path();
        let legacy_entries = DirectoryCache::open_legacy_plaintext(legacy_path.clone())?
            .map(|cache| cache.entries())
            .transpose()?;

        let Some(entries) = legacy_entries else {
            *checked = true;
            return Ok(());
        };

        let entries = entries
            .into_iter()
            .map(|entry| self.hydrate_directory_record(entry))
            .collect::<Result<Vec<_>, _>>()?;
        let shared_storage = self.shared_storage()?;
        for entry in &entries {
            shared_storage.put_public_directory_user(&public_directory_user_record(entry)?)?;
        }
        for cache in caches {
            for entry in &entries {
                cache.put(entry)?;
            }
        }
        for entry in &entries {
            if shared_storage
                .public_directory_user(&entry.account_id_hex)?
                .is_none()
            {
                return Err(AppError::MissingDirectoryEntry(
                    entry.account_id_hex.clone(),
                ));
            }
            for cache in caches {
                if cache.entry(&entry.account_id_hex)?.is_none() {
                    return Err(AppError::MissingDirectoryEntry(
                        entry.account_id_hex.clone(),
                    ));
                }
            }
        }
        remove_sqlite_file_set(&legacy_path)?;
        *checked = true;
        Ok(())
    }

    fn clean_future_dated_directory_caches_once(
        &self,
        accounts: &[AccountSummary],
    ) -> Result<(), AppError> {
        let marker_path = self.root.join(DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER);
        if marker_path.exists() {
            return Ok(());
        }
        fs::create_dir_all(&self.root)?;
        remove_sqlite_file_set(&self.legacy_directory_cache_path())?;
        for account in accounts {
            remove_sqlite_file_set(&self.directory_cache_path(&account.label))?;
        }
        fs::write(marker_path, b"done\n")?;
        Ok(())
    }

    fn clean_future_dated_directory_caches_for_all_accounts_once(&self) -> Result<(), AppError> {
        let accounts = self
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.is_active_local_signing())
            .collect::<Vec<_>>();
        self.clean_future_dated_directory_caches_once(&accounts)
    }

    fn empty_directory_record(&self, account_id_hex: &str) -> UserDirectoryRecord {
        UserDirectoryRecord {
            account_id_hex: account_id_hex.to_owned(),
            npub: npub_for_account_id_lossy(account_id_hex),
            local_account: self.local_account_for_id(account_id_hex),
            profile: None,
            follows: Vec::new(),
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        }
    }

    fn hydrate_directory_record(
        &self,
        mut entry: UserDirectoryRecord,
    ) -> Result<UserDirectoryRecord, AppError> {
        entry.account_id_hex = parse_account_id_hex(&entry.account_id_hex)?;
        entry.npub = npub_for_account_id(&entry.account_id_hex)?;
        entry.local_account = self.local_account_for_id(&entry.account_id_hex);
        entry.follows = normalize_account_ids(entry.follows)?;
        entry.follow_source_relays.sort();
        entry.follow_source_relays.dedup();
        Ok(entry)
    }

    pub(crate) fn hydrate_public_directory_record(
        &self,
        record: PublicDirectoryUserRecord,
    ) -> Result<UserDirectoryRecord, AppError> {
        self.hydrate_directory_record(user_directory_record_from_public(record)?)
    }

    fn local_account_for_id(&self, account_id_hex: &str) -> Option<UserDirectoryLocalAccount> {
        self.account_home()
            .accounts()
            .ok()?
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex)
            .map(|account| UserDirectoryLocalAccount {
                label: account.label,
                local_signing: account.local_signing,
            })
    }
}
