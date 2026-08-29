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

use cgka_traits::{MaintenanceStorage, TransportEndpoint};
use marmot_account::AccountSummary;
use nostr_sdk::prelude::PublicKey;
use storage_sqlite::{PublicDirectoryUserRecord, SqliteSharedStorage};
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
};
use transport_nostr_peeler::NostrTransportEvent;

use crate::directory::records::{
    CachedIdentityProjection, DirectoryKeyPackage, FetchedFollowList,
    MAX_CACHED_IDENTITY_PAGE_SIZE, UserDirectoryLocalAccount, UserDirectoryRecord,
    UserDirectoryRefresh, UserDirectorySearch, UserDirectorySearchResult, UserProfileMetadata,
    cached_identity_projection, follow_list_from_record, latest_follow_list_from_records,
    latest_fresh_profiles_from_records, profile_content_json, profile_from_record,
    public_directory_user_record, select_newer_directory_entry, source_relays_from_record,
    upsert_newer_directory_entry, user_directory_record_from_public, user_record_match,
};
use crate::directory::{
    DirectoryCache, DirectorySyncHandle, DirectorySyncPlan, sort_user_search_results,
};
use crate::ids::{
    normalize_account_ids, npub_for_account_id, npub_for_account_id_lossy, parse_account_id_hex,
};
use crate::key_package_records::{
    fresh_or_cached_key_package, fresh_relay_list_status_from_records, key_package_from_record,
    latest_fresh_key_package_from_records, publish_endpoints_from_bootstrap, relay_list_queries,
};
use crate::relay_plane::{DirectoryEventQuery, DirectoryRelayEventRecord as RelayEventRecord};
use crate::{
    APP_CACHE_DB_FILE, AccountRelayListBootstrap, AccountRelayListStatus, AppError,
    DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER, DirectoryFreshness, FetchedKeyPackage,
    KIND_NOSTR_CONTACT_LIST, KIND_NOSTR_METADATA, MarmotApp, MissingRelayListKind, ReceivedMessage,
    SqlcipherDatabaseKind, USER_DIRECTORY_SEARCH_MAX_FRONTIER, USER_DIRECTORY_SEARCH_MAX_VISITED,
    blocking_app_task, push_unique_strings, relay_list_state_from_event, remove_sqlite_file_set,
};

/// Per-relay bound for setup-time kind-10002 history. A conforming relay has
/// one replaceable winner; reaching this bound is therefore ambiguous and must
/// not establish local route authority.
const SETUP_NIP65_STRICT_HISTORY_LIMIT: usize = 12;

#[derive(Clone, Copy)]
enum RemovedSlotAdmission<'a> {
    InspectSessionGate,
    AlreadyAdmitted(Option<&'a AccountSummary>),
}

fn merge_newer_live_key_package(
    current: &mut Option<DirectoryKeyPackage>,
    candidate: Option<&DirectoryKeyPackage>,
) {
    let Some(candidate) = candidate else {
        return;
    };
    let replace = current.as_ref().is_none_or(|current| {
        crate::nostr_replaceable_coordinate_is_newer(
            candidate.created_at,
            &candidate.key_package_event_id,
            current.created_at,
            &current.key_package_event_id,
        )
    });
    if replace {
        *current = Some(candidate.clone());
    }
}

impl MarmotApp {
    pub fn warm_directory_storage(&self) -> Result<(), AppError> {
        let _span = tracing::debug_span!(
            target: "marmot_app::directory",
            "directory_storage_warm",
            method = "warm_directory_storage"
        )
        .entered();
        let shared = self.shared_storage()?;
        let caches = self.directory_caches()?;
        self.reconcile_removed_local_key_package_projections(&caches, &shared)?;
        Ok(())
    }

    /// Retry the non-authoritative projection scrub after a crash between the
    /// immutable tombstone commit and cache cleanup. Only active account
    /// caches are opened here; a signed-out cache is reconciled when an
    /// explicit sign-in makes it active and warms directory storage again.
    fn reconcile_removed_local_key_package_projections(
        &self,
        caches: &[DirectoryCache],
        shared: &SqliteSharedStorage,
    ) -> Result<(), AppError> {
        // Tombstones are immutable and both projection clears are CAS-style.
        // Do not hold the projection-mutation mutex while the marker check
        // consults account-session admission: live ingestion orders those
        // locks admission -> mutation, so the inverse order would deadlock.
        let mut changed = false;
        for record in shared.public_directory_users()? {
            let Some(key_package_json) = record.key_package_json.as_deref() else {
                continue;
            };
            let key_package: DirectoryKeyPackage = serde_json::from_str(key_package_json)?;
            if self.removed_local_key_package_slot_is_retired(
                &record.account_id_hex,
                &key_package.key_package_id,
            )? {
                changed |= shared.clear_public_directory_key_package_if_matches(
                    &record.account_id_hex,
                    key_package_json,
                )?;
            }
        }
        for cache in caches {
            for entry in cache.entries()? {
                let Some(key_package) = entry.key_package else {
                    continue;
                };
                if self.removed_local_key_package_slot_is_retired(
                    &entry.account_id_hex,
                    &key_package.key_package_id,
                )? {
                    changed |= cache.clear_key_package_if_slot(
                        &entry.account_id_hex,
                        Some(&key_package.key_package_id),
                    )?;
                }
            }
        }
        if changed {
            self.request_directory_sync_rebuild();
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn directory_cache_open_count_for_test(&self) -> usize {
        self.directory_cache_open_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn directory_handle_acquire_count_for_test(&self) -> usize {
        self.directory_handle_acquire_count
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
        let selection = fresh_relay_list_status_from_records(&account_id_hex, records, freshness);
        let mut status = selection.value;
        if !observed_nip65 || !observed_inbox {
            let app = self.clone();
            let account_id = account_id_hex.clone();
            let cached = blocking_app_task(move || {
                app.account_relay_list_status_for_account_id(&account_id)
            })
            .await?;
            if !observed_nip65 {
                status.nip65 = cached.nip65;
            }
            if !observed_inbox {
                status.inbox = cached.inbox;
            }
            push_unique_strings(&mut status.bootstrap_relays, cached.bootstrap_relays);
            status.refresh();
        }
        if status.bootstrap_relays.is_empty() {
            status.bootstrap_relays = bootstrap_relays
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect();
        }
        {
            let app = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = status.clone();
            blocking_app_task(move || {
                app.remember_observed_directory_relay_lists(&account_id, &remembered)
            })
            .await?;
        }
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
        let cached = {
            let app = self.clone();
            let account_id = account_id_hex.clone();
            blocking_app_task(move || app.account_relay_list_status_for_account_id(&account_id))
                .await?
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
            let app = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = status.clone();
            blocking_app_task(move || {
                app.remember_observed_directory_relay_lists(&account_id, &remembered)
            })
            .await?;
        }
        Ok(Some(status))
    }

    /// Fetch the exact signed kind-10002 winner used to establish a local
    /// signing account's durable route authority during import/login.
    ///
    /// Unlike ordinary directory projection reads, every requested relay must
    /// explicitly complete its stored-event page. A future-dated event or a
    /// page that fills the bounded history capacity is inconclusive rather
    /// than permission to adopt an older visible revision.
    pub(crate) async fn fetch_exact_self_nip65_event_strict(
        &self,
        account_id_hex: &str,
        discovery_relays: &[TransportEndpoint],
    ) -> Result<Option<RelayEventRecord>, AppError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| AppError::InvalidPublicKey)?;
        let account_id_hex = public_key.to_hex();
        let source_relays = self.directory_source_relays(discovery_relays);
        let records = self
            .relay_plane
            .fetch_directory_events_strict(
                source_relays,
                vec![DirectoryEventQuery::new(
                    KIND_NIP65_RELAY_LIST,
                    vec![account_id_hex.clone()],
                    SETUP_NIP65_STRICT_HISTORY_LIMIT,
                )],
            )
            .await
            .map_err(|error| {
                AppError::RelayDirectory(format!(
                    "strict setup NIP-65 discovery did not complete: {error}"
                ))
            })?;

        let freshness = self.directory_freshness();
        let mut endpoint_event_ids = BTreeMap::<String, HashSet<String>>::new();
        let mut candidates = Vec::new();
        for record in records {
            if record.event.pubkey != account_id_hex || record.event.kind != KIND_NIP65_RELAY_LIST {
                return Err(AppError::RelayDirectory(
                    "strict setup NIP-65 discovery returned an unrelated event".into(),
                ));
            }
            record.event.to_verified_nostr_event().map_err(|_| {
                AppError::RelayDirectory(
                    "strict setup NIP-65 discovery returned an invalid signature".into(),
                )
            })?;
            if !freshness.accepts(&record) {
                return Err(AppError::RelayDirectory(
                    "strict setup NIP-65 discovery observed a future-dated event".into(),
                ));
            }
            if record.endpoints.is_empty() {
                return Err(AppError::RelayDirectory(
                    "strict setup NIP-65 discovery returned an unscoped event".into(),
                ));
            }
            if relay_list_state_from_event(&record.event).is_none() {
                return Err(AppError::RelayDirectory(
                    "strict setup NIP-65 discovery returned a malformed relay list".into(),
                ));
            }
            for endpoint in &record.endpoints {
                endpoint_event_ids
                    .entry(endpoint.0.clone())
                    .or_default()
                    .insert(record.event.id.clone());
            }
            candidates.push(record);
        }
        if endpoint_event_ids
            .values()
            .any(|event_ids| event_ids.len() >= SETUP_NIP65_STRICT_HISTORY_LIMIT)
        {
            return Err(AppError::RelayDirectory(
                "strict setup NIP-65 discovery reached its bounded history capacity".into(),
            ));
        }

        let Some(mut winner_index) = (!candidates.is_empty()).then_some(0usize) else {
            return Ok(None);
        };
        for candidate_index in 1..candidates.len() {
            let candidate = &candidates[candidate_index].event;
            let winner = &candidates[winner_index].event;
            if crate::nostr_replaceable_coordinate_is_newer(
                candidate.created_at,
                &candidate.id,
                winner.created_at,
                &winner.id,
            ) {
                winner_index = candidate_index;
            }
        }
        let winner_event = candidates[winner_index].event.clone();
        let winner_state = relay_list_state_from_event(&winner_event).ok_or_else(|| {
            AppError::RelayDirectory("strict setup NIP-65 winner has no relay-list state".into())
        })?;
        let safe_write_relays = self.sanitize_key_package_deletion_endpoints(
            winner_state
                .relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
        )?;
        if safe_write_relays.is_empty() {
            return Err(AppError::MissingRelayLists(vec![
                MissingRelayListKind::Nip65,
            ]));
        }
        let mut endpoints = candidates
            .iter()
            .filter(|candidate| candidate.event.id == winner_event.id)
            .flat_map(|candidate| candidate.endpoints.iter().cloned())
            .collect::<Vec<_>>();
        endpoints.sort();
        endpoints.dedup();
        Ok(Some(RelayEventRecord {
            endpoints,
            event: winner_event,
        }))
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
        {
            let app = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = profile.clone();
            blocking_app_task(move || {
                app.remember_directory_profile_if_newer(&account_id, &remembered)
            })
            .await?;
        }
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
            let app = self.clone();
            let account_id = account_id_hex.to_owned();
            blocking_app_task(move || app.account_relay_list_status_for_account_id(&account_id))
                .await?
        };
        if !has_explicit_bootstrap_relays && relay_lists.nip65.relays.is_empty() {
            let source_relays = self.directory_source_relays(&[]);
            if !source_relays.is_empty() {
                relay_lists = self
                    .fetch_account_relay_list_status_for_account_id(account_id_hex, source_relays)
                    .await?;
            }
        }
        {
            let app = self.clone();
            let account_id = account_id_hex.to_owned();
            let remembered = relay_lists.clone();
            blocking_app_task(move || {
                app.remember_observed_directory_relay_lists(&account_id, &remembered)
            })
            .await?;
        }
        let mut source_relays = self.retain_safe_discovered_endpoints(
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
            return Err(AppError::MissingRelayLists(vec![
                MissingRelayListKind::Nip65,
            ]));
        }
        let records = self
            .fetch_key_package_events_for_account_id(account_id_hex, &source_relays)
            .await?;
        let cached_entry = {
            let app = self.clone();
            let account_id = account_id_hex.to_owned();
            blocking_app_task(move || app.directory_entry_for_account_id(&account_id)).await?
        };
        let mut fetched = fresh_or_cached_key_package(
            account_id_hex,
            self.latest_fresh_non_retired_key_package_from_records(account_id_hex, records)?,
            cached_entry,
        )?;
        fetched.relay_lists = relay_lists;
        let remembered = {
            let app = self.clone();
            let remembered = fetched.clone();
            blocking_app_task(move || app.remember_directory_key_package_if_live(&remembered))
                .await?
        };
        if !remembered {
            return Err(AppError::MissingKeyPackage(account_id_hex.to_owned()));
        }
        Ok(fetched)
    }

    /// Filter immutable removed-local slots before selecting the newest NIP-33
    /// coordinate. This preserves a valid sibling-device slot even when a
    /// newer relay echo exists for the removed device's retired `d` tag.
    pub(crate) fn latest_fresh_non_retired_key_package_from_records(
        &self,
        account_id_hex: &str,
        records: Vec<RelayEventRecord>,
    ) -> Result<crate::DirectorySelection<Option<FetchedKeyPackage>>, AppError> {
        let mut admitted = Vec::with_capacity(records.len());
        for record in records {
            let retired = record.event.kind == KIND_MARMOT_KEY_PACKAGE
                && record.event.pubkey == account_id_hex
                && self.removed_local_key_package_slot_is_retired(
                    account_id_hex,
                    record.event.tag_value("d").unwrap_or_default(),
                )?;
            if !retired {
                admitted.push(record);
            }
        }
        latest_fresh_key_package_from_records(account_id_hex, admitted, self.directory_freshness())
    }

    pub async fn refresh_directory_entry_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRecord, AppError> {
        let status = if bootstrap_relays.is_empty() {
            let app = self.clone();
            let account_id = account_id_hex.to_owned();
            blocking_app_task(move || app.account_relay_list_status_for_account_id(&account_id))
                .await?
        } else {
            self.fetch_account_relay_list_status_for_account_id(account_id_hex, bootstrap_relays)
                .await?
        };
        {
            let app = self.clone();
            let account_id = account_id_hex.to_owned();
            let remembered = status.clone();
            blocking_app_task(move || {
                app.remember_observed_directory_relay_lists(&account_id, &remembered)
            })
            .await?;
        }
        let app = self.clone();
        let account_id = account_id_hex.to_owned();
        blocking_app_task(move || {
            app.directory_entry_for_account_id(&account_id)?
                .ok_or_else(|| AppError::MissingDirectoryEntry(account_id))
        })
        .await
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

    /// Admission-aware cache read for a caller already holding
    /// `account_session_admissions`. The ordinary hydration path may inspect
    /// that same non-reentrant mutex when an account-wide legacy tombstone is
    /// present, so admitted callers must carry their proof through instead.
    pub(crate) fn directory_entry_for_account_id_with_admitted_account(
        &self,
        account_id_hex: &str,
        local_signing_account: Option<&AccountSummary>,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        let caches = self.directory_caches()?;
        let shared_storage = self.shared_storage()?;
        self.directory_entry_for_account_id_with_handles_and_admission(
            &account_id_hex,
            &caches,
            &shared_storage,
            RemovedSlotAdmission::AlreadyAdmitted(local_signing_account),
        )
    }

    /// Bounded local cached-identity page for many account IDs.
    ///
    /// Acquires directory caches and shared storage once, then projects each
    /// requested id in input order. Invalid IDs become rows rather than failing
    /// the page. This is a cache read, not a network refresh.
    pub fn cached_identity_projections_for_account_ids(
        &self,
        account_id_hexes: &[String],
    ) -> Result<Vec<CachedIdentityProjection>, AppError> {
        if account_id_hexes.len() > MAX_CACHED_IDENTITY_PAGE_SIZE {
            return Err(AppError::InvalidCachedIdentityPage(format!(
                "requested {} accounts; maximum page size is {MAX_CACHED_IDENTITY_PAGE_SIZE}",
                account_id_hexes.len()
            )));
        }
        if account_id_hexes.is_empty() {
            return Ok(Vec::new());
        }

        let caches = self.directory_caches()?;
        let shared_storage = self.shared_storage()?;
        let local_labels = self.local_account_labels_by_id()?;
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
                )?
                .and_then(|entry| entry.profile);
            let local_label = local_labels.get(&account_id_hex).cloned();
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
    ) -> Result<UserDirectoryRefresh, AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        {
            let app = self.clone();
            let account_id = account_id_hex.clone();
            blocking_app_task(move || app.remember_directory_user(&account_id)).await?;
        }
        let follow_list = self
            .fetch_follow_list_for_account_id(&account_id_hex, &bootstrap_relays)
            .await?;
        {
            let app = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = follow_list.clone();
            blocking_app_task(move || app.remember_directory_follow_list(&account_id, &remembered))
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
        self.publish_user_profile_to_endpoints(&account.label, profile, endpoints)
            .await
    }

    /// Publish kind-0 metadata to an already-selected, account-scoped route.
    ///
    /// This is the action boundary used when the runtime has captured one
    /// coherent relay-list snapshot and must not re-read it before publishing.
    pub(crate) async fn publish_user_profile_to_endpoints(
        &self,
        label: &str,
        profile: UserProfileMetadata,
        endpoints: Vec<TransportEndpoint>,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(label)?;
        let signer = self.account_signer_for_summary(&account)?;
        let content = serde_json::to_string(&profile_content_json(&profile))?;
        let event = NostrTransportEvent::new_unsigned(
            account.account_id_hex.clone(),
            KIND_NOSTR_METADATA,
            Vec::new(),
            content,
        );
        self.relay_client_for_account_id(&account.account_id_hex, signer.as_nostr_signer())
            .publish_event(&endpoints, &event, 1)
            .await?;
        Ok(())
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
        let event = NostrTransportEvent::new_unsigned(
            account.account_id_hex.clone(),
            KIND_NOSTR_CONTACT_LIST,
            tags,
            String::new(),
        );
        self.relay_client_for_account_id(&account.account_id_hex, signer.as_nostr_signer())
            .publish_event(&endpoints, &event, 1)
            .await?;
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
                app.remember_directory_follow_edges_for_search(&account_id, &follow_list)
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
        self.fetch_key_package_events_for_account_id_with_limit(account_id_hex, source_relays, 12)
            .await
    }

    pub(crate) async fn fetch_key_package_events_for_account_id_with_limit(
        &self,
        account_id_hex: &str,
        source_relays: &[TransportEndpoint],
        limit: usize,
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
                    limit,
                )],
            )
            .await
            .map_err(|e| AppError::RelayDirectory(format!("fetch key packages: {e}")))
    }

    pub(crate) async fn fetch_key_package_events_for_account_id_with_limit_strict(
        &self,
        account_id_hex: &str,
        source_relays: &[TransportEndpoint],
        limit: usize,
    ) -> Result<Vec<RelayEventRecord>, AppError> {
        let public_key =
            PublicKey::parse(account_id_hex).map_err(|_| AppError::InvalidPublicKey)?;
        let source_relays = self.directory_source_relays(source_relays);
        self.relay_plane
            .fetch_directory_events_strict(
                source_relays,
                vec![DirectoryEventQuery::new(
                    KIND_MARMOT_KEY_PACKAGE,
                    vec![public_key.to_hex()],
                    limit,
                )],
            )
            .await
            .map_err(|e| AppError::RelayDirectory(format!("strict key package fetch: {e}")))
    }

    pub(crate) async fn fetch_follow_list_for_account_id(
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
        // No event on this relay set means "unknown", not "the account
        // follows nobody". Preserve any cached edges whether the candidates
        // were absent or rejected as future-dated.
        let cached_entry = {
            let app = self.clone();
            let account_id = account_id_hex.to_owned();
            blocking_app_task(move || app.directory_entry_for_account_id(&account_id)).await?
        };
        Ok(cached_or_unknown_follow_list(cached_entry, source_relays))
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
        {
            let app = self.clone();
            let account_id = account_id_hex.clone();
            let remembered = follow_list.clone();
            blocking_app_task(move || app.remember_directory_follow_list(&account_id, &remembered))
                .await?;
        }
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
        {
            let app = self.clone();
            let account_ids = account_ids.to_vec();
            let remembered = profiles.clone();
            blocking_app_task(move || {
                for account_id in &account_ids {
                    app.remember_directory_user(account_id)?;
                }
                for (account_id, profile) in &remembered {
                    app.remember_directory_profile_if_newer(account_id, profile)?;
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
    ) -> Result<(), AppError> {
        self.refresh_directory_profiles(&[account_id_hex.to_owned()], &source_relays)
            .await?;
        Ok(())
    }

    pub(crate) async fn fetch_events_for_account_ids(
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

    /// Accounts to fall back to when a searcher's own web of trust is empty.
    /// See [`MarmotAppConfig::directory_search_fallback_seeds`].
    pub(crate) fn directory_search_fallback_seeds(&self) -> &[String] {
        &self.config.directory_search_fallback_seeds
    }

    /// Narrow network-sourced relay-list endpoints to the ones this device is
    /// willing to dial, whether the list belongs to this device's local account
    /// or to another account. Published data remains untrusted in both cases;
    /// filtering affects only the operation's route and never rewrites the list.
    ///
    /// Routes to the same host-safety rule configured endpoints face; see
    /// [`RelaySafetyPolicy::retain_safe_endpoints`] for why a published list
    /// filters rather than fails.
    pub(crate) fn retain_safe_discovered_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Vec<TransportEndpoint> {
        self.relay_plane
            .retain_safe_discovered_endpoints(endpoints, context)
    }

    pub(crate) fn directory_source_relays(
        &self,
        source_relays: &[TransportEndpoint],
    ) -> Vec<TransportEndpoint> {
        if !source_relays.is_empty() {
            return source_relays.to_vec();
        }
        if !self.config.directory_relay_urls.is_empty() {
            return self
                .config
                .directory_relay_urls
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect();
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
            .filter(|account| account.is_active_signing())
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
        // One instant for the whole traversal: a layer must not disagree with
        // itself about whether a cached profile has expired.
        let now = crate::unix_now_seconds() as i64;

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

                let Some(record) =
                    Self::directory_search_record_from_caches(&caches, &account_id, now)?
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
        self.directory_entry_for_account_id_with_handles_and_admission(
            account_id_hex,
            caches,
            shared_storage,
            RemovedSlotAdmission::InspectSessionGate,
        )
    }

    fn directory_entry_for_account_id_with_handles_and_admission(
        &self,
        account_id_hex: &str,
        caches: &[DirectoryCache],
        shared_storage: &SqliteSharedStorage,
        admission: RemovedSlotAdmission<'_>,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        let cached_entry = Self::directory_entry_from_caches(caches, account_id_hex)?
            .map(|entry| self.hydrate_directory_record_with_admission(entry, admission))
            .transpose()?;
        let shared_entry = shared_storage
            .public_directory_user(account_id_hex)?
            .map(|record| {
                self.hydrate_directory_record_with_admission(
                    user_directory_record_from_public(record)?,
                    admission,
                )
            })
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
        now: i64,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        for cache in caches {
            if let Some(entry) = cache.search_record(account_id_hex, now)? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    pub(crate) fn remember_directory_relay_lists(
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

    /// Cache relay-list observations without allowing a generic directory read
    /// to replace the locally managed NIP-65 route. The account-manager path is
    /// the sole authority for a local identity's kind-10002 projection; inbox
    /// and bootstrap observations remain safe to refresh here.
    fn remember_observed_directory_relay_lists(
        &self,
        account_id_hex: &str,
        relay_lists: &AccountRelayListStatus,
    ) -> Result<(), AppError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        if self.local_account_label_for_id(&account_id_hex).is_none() {
            return self.remember_directory_relay_lists(&account_id_hex, relay_lists);
        }
        let mut entry = self
            .directory_entry_for_account_id(&account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(&account_id_hex));
        let local_nip65 = entry.relay_lists.nip65.clone();
        entry.account_id_hex = account_id_hex;
        entry.relay_lists = relay_lists.clone();
        entry.relay_lists.nip65 = local_nip65;
        entry.relay_lists.refresh();
        self.save_directory_entry(&entry)
    }

    pub(crate) fn remember_directory_key_package(
        &self,
        fetched: &FetchedKeyPackage,
    ) -> Result<(), AppError> {
        let _ = self.remember_directory_key_package_if_live(fetched)?;
        Ok(())
    }

    /// Admit one exact KeyPackage observation into the durable directory.
    ///
    /// For identities this app can sign as, the account-private lifecycle is
    /// authoritative. Signed-out accounts are rejected before their SQLCipher
    /// storage is opened, and active accounts accept only the exact current or
    /// pending signed revision. Public/tracked account records intentionally
    /// remain ordinary remote identities and do not acquire local lifecycle
    /// semantics merely because they are present in `AccountHome`.
    pub(crate) fn remember_directory_key_package_if_live(
        &self,
        fetched: &FetchedKeyPackage,
    ) -> Result<bool, AppError> {
        Ok(self
            .with_local_key_package_admission(&fetched.account_id_hex, |local_signing_account| {
                self.remember_directory_key_package_if_live_admitted(fetched, local_signing_account)
            })?
            .unwrap_or(false))
    }

    /// Run one bounded local KeyPackage cache operation under the same
    /// admission mutex teardown closes synchronously before its first await.
    /// An operation admitted first finishes before teardown can proceed to its
    /// final eviction; an operation arriving second observes the closed gate
    /// and returns before opening any account-private directory/session store.
    pub(crate) fn with_local_key_package_admission<T>(
        &self,
        account_id_hex: &str,
        operation: impl FnOnce(Option<&AccountSummary>) -> Result<T, AppError>,
    ) -> Result<Option<T>, AppError> {
        let local_signing_account = self.local_signing_account_for_id(account_id_hex)?;
        let _session_admission = if let Some(account) = local_signing_account.as_ref() {
            let admission = self
                .account_session_admissions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let admission_open = admission
                .get(&account.label)
                .is_none_or(|state| state.account_id_hex != account.account_id_hex || state.open);
            if account.signed_out || !admission_open {
                return Ok(None);
            }
            Some(admission)
        } else {
            None
        };
        operation(local_signing_account.as_ref()).map(Some)
    }

    /// Cache an exact revision after the caller has serialized local signing
    /// state with teardown's session-admission gate.
    fn remember_directory_key_package_if_live_admitted(
        &self,
        fetched: &FetchedKeyPackage,
        local_signing_account: Option<&AccountSummary>,
    ) -> Result<bool, AppError> {
        if self.removed_local_key_package_slot_is_retired_for_admitted_account(
            &fetched.account_id_hex,
            &fetched.key_package_id,
            local_signing_account,
        )? {
            return Ok(false);
        }
        if let Some(account) = local_signing_account
            && !self.local_key_package_revision_is_live_for_account(
                account,
                &fetched.key_package_ref_hex,
                &fetched.key_package_event_id,
            )?
        {
            // The account lifecycle is the private-material authority for our
            // own identity. A delayed relay echo must never make a consumed,
            // deleted, signed-out, or otherwise non-live revision available
            // to local invite resolution again.
            return Ok(false);
        }
        let mut entry = self
            .directory_entry_for_account_id_with_admitted_account(
                &fetched.account_id_hex,
                local_signing_account,
            )?
            .unwrap_or_else(|| self.empty_directory_record(&fetched.account_id_hex));
        if entry.key_package.as_ref().is_some_and(|cached| {
            !crate::nostr_replaceable_coordinate_is_newer(
                fetched.created_at,
                &fetched.key_package_event_id,
                cached.created_at,
                &cached.key_package_event_id,
            )
        }) {
            let already_remembered = entry.key_package.as_ref().is_some_and(|cached| {
                cached.key_package_id == fetched.key_package_id
                    && cached.key_package_ref_hex == fetched.key_package_ref_hex
                    && cached.key_package_event_id == fetched.key_package_event_id
                    && cached.key_package_hex == hex::encode(fetched.key_package.bytes())
                    && cached.created_at == fetched.created_at
            });
            // Live subscriptions deliver one relay record at a time and may
            // echo an older parameterized-replaceable revision after a newer
            // one was already projected. Keep the NIP-33 coordinate winner so
            // arrival order cannot resurrect a consumed/stale KeyPackage.
            return Ok(already_remembered);
        }
        let local_nip65 = local_signing_account.map(|_| entry.relay_lists.nip65.clone());
        entry.account_id_hex = fetched.account_id_hex.clone();
        entry.relay_lists = fetched.relay_lists.clone();
        if let Some(local_nip65) = local_nip65 {
            entry.relay_lists.nip65 = local_nip65;
            entry.relay_lists.refresh();
        }
        entry.key_package = Some(DirectoryKeyPackage {
            key_package_id: fetched.key_package_id.clone(),
            key_package_ref_hex: fetched.key_package_ref_hex.clone(),
            key_package_event_id: fetched.key_package_event_id.clone(),
            key_package_hex: hex::encode(fetched.key_package.bytes()),
            created_at: fetched.created_at,
            source_relays: fetched.source_relays.clone(),
        });
        self.save_directory_entry_with_reason_under_admission(
            &entry,
            "directory",
            local_signing_account,
        )?;

        // `save_directory_entry` reconciles the account-private and shared
        // projections. Re-read the winner so a concurrent newer coordinate is
        // a rejection at a composition commit boundary rather than permission
        // to return the older prefetched bytes.
        Ok(self
            .directory_entry_for_account_id_with_admitted_account(
                &fetched.account_id_hex,
                local_signing_account,
            )?
            .and_then(|entry| entry.key_package)
            .is_some_and(|cached| {
                cached.key_package_id == fetched.key_package_id
                    && cached.key_package_ref_hex == fetched.key_package_ref_hex
                    && cached.key_package_event_id == fetched.key_package_event_id
                    && cached.key_package_hex == hex::encode(fetched.key_package.bytes())
                    && cached.created_at == fetched.created_at
            }))
    }

    pub(crate) fn local_signing_account_for_id(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<AccountSummary>, AppError> {
        Ok(self
            .account_home()
            .accounts()?
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex && account.can_sign()))
    }

    /// Whether an observed exact revision is still authorized by local
    /// private-material state. Remote and tracked-only identities return true;
    /// signed-out signing identities return false before account storage is
    /// consulted.
    pub(crate) fn local_key_package_revision_is_live(
        &self,
        account_id_hex: &str,
        key_package_ref_hex: &str,
        key_package_event_id: &str,
    ) -> Result<bool, AppError> {
        let Some(account) = self.local_signing_account_for_id(account_id_hex)? else {
            return Ok(true);
        };
        let admission = self
            .account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let admission_open = admission
            .get(&account.label)
            .is_none_or(|state| state.account_id_hex != account.account_id_hex || state.open);
        if account.signed_out || !admission_open {
            return Ok(false);
        }
        self.local_key_package_revision_is_live_for_account(
            &account,
            key_package_ref_hex,
            key_package_event_id,
        )
    }

    /// Inner lifecycle authority check for callers already holding the account
    /// session-admission mutex.
    pub(crate) fn local_key_package_revision_is_live_for_account(
        &self,
        account: &AccountSummary,
        key_package_ref_hex: &str,
        key_package_event_id: &str,
    ) -> Result<bool, AppError> {
        let key_package_ref = hex::decode(key_package_ref_hex)?;
        let event_id_bytes = hex::decode(key_package_event_id)?;
        if event_id_bytes.len() != 32 {
            return Ok(false);
        }
        let event_id = cgka_traits::MessageId::new(event_id_bytes);
        let Some(lifecycle) = self
            .account_storage(&account.label)?
            .key_package_lifecycle()?
        else {
            return Ok(false);
        };
        if lifecycle.key_package_ref_is_consumed(&key_package_ref)
            || lifecycle
                .deleted_live_revision_event_ids
                .contains(&event_id)
        {
            return Ok(false);
        }
        let live_current = lifecycle.current_key_package_ref.as_ref() == Some(&key_package_ref)
            && lifecycle.authored_event_id.as_ref() == Some(&event_id)
            && lifecycle
                .authored_signed_event
                .as_ref()
                .is_none_or(|artifact| artifact.id == event_id);
        let live_pending = lifecycle
            .pending_replacement
            .as_ref()
            .is_some_and(|pending| {
                pending.key_package_ref == key_package_ref
                    && pending
                        .signed_event
                        .as_ref()
                        .is_some_and(|artifact| artifact.id == event_id)
            });
        Ok(live_current || live_pending)
    }

    /// Validate locally stored current private material against the exact live
    /// lifecycle revision. The event id is lifecycle-owned, so callers only
    /// supply the KeyPackageRef derived from the candidate bytes.
    pub(crate) fn local_current_key_package_ref_is_live(
        &self,
        account_id_hex: &str,
        key_package_ref_hex: &str,
    ) -> Result<bool, AppError> {
        let Some(account) = self.local_signing_account_for_id(account_id_hex)? else {
            return Ok(true);
        };
        let admission = self
            .account_session_admissions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let admission_open = admission
            .get(&account.label)
            .is_none_or(|state| state.account_id_hex != account.account_id_hex || state.open);
        if account.signed_out || !admission_open {
            return Ok(false);
        }
        let key_package_ref = hex::decode(key_package_ref_hex)?;
        let Some(lifecycle) = self
            .account_storage(&account.label)?
            .key_package_lifecycle()?
        else {
            return Ok(false);
        };
        let Some(event_id) = lifecycle.authored_event_id.as_ref() else {
            return Ok(false);
        };
        Ok(
            lifecycle.current_key_package_ref.as_ref() == Some(&key_package_ref)
                && !lifecycle.key_package_ref_is_consumed(&key_package_ref)
                && !lifecycle.deleted_live_revision_event_ids.contains(event_id)
                && lifecycle
                    .authored_signed_event
                    .as_ref()
                    .is_none_or(|artifact| &artifact.id == event_id),
        )
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
    /// transitive social-graph crawl (mdk#687). Instead the edges are
    /// recorded in the per-account search graph, which directory search reads
    /// but [`Self::directory_sync_plan`] does not. When the author is already a
    /// known directory entry (e.g. a local account whose contact list we sync),
    /// its own cached follow edges are refreshed too, but its follows are still
    /// not promoted.
    pub(crate) fn remember_directory_follow_edges_for_search(
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
        // local edit (mdk#206). Keeping the cache on equality protects
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
        if record.event.kind == KIND_NIP65_RELAY_LIST
            && self.local_account_label_for_id(account_id_hex).is_some()
        {
            return Ok(());
        }
        let Some(state) = relay_list_state_from_event(&record.event) else {
            return Ok(());
        };
        let mut entry = self
            .directory_entry_for_account_id(account_id_hex)?
            .unwrap_or_else(|| self.empty_directory_record(account_id_hex));
        match record.event.kind {
            KIND_NIP65_RELAY_LIST => entry.relay_lists.nip65 = state,
            KIND_MARMOT_INBOX_RELAY_LIST => entry.relay_lists.inbox = state,
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
        if record.event.kind == KIND_NIP65_RELAY_LIST
            && self.local_account_label_for_id(&account_id_hex).is_some()
        {
            return Ok(());
        }
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
                let _ = self.with_local_key_package_admission(
                    &account_id_hex,
                    |local_signing_account| {
                        fetched.relay_lists = self
                            .directory_entry_for_account_id_with_admitted_account(
                                &account_id_hex,
                                local_signing_account,
                            )
                            .map(|entry| {
                                entry
                                    .map(|entry| entry.relay_lists)
                                    .unwrap_or_else(AccountRelayListStatus::empty)
                            })
                            .unwrap_or_else(|_| AccountRelayListStatus::empty());
                        self.remember_directory_key_package_if_live_admitted(
                            &fetched,
                            local_signing_account,
                        )
                    },
                )?;
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
        let local_signing_account = self.local_signing_account_for_id(&entry.account_id_hex)?;
        let session_admission = local_signing_account.as_ref().map(|_| {
            self.account_session_admissions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        });
        let admitted_local_signing_account = local_signing_account.as_ref().filter(|account| {
            account.is_active_signing()
                && session_admission.as_ref().is_some_and(|admissions| {
                    admissions.get(&account.label).is_none_or(|state| {
                        state.account_id_hex != account.account_id_hex || state.open
                    })
                })
        });
        self.save_directory_entry_with_reason_under_admission(
            entry,
            reason,
            admitted_local_signing_account,
        )
    }

    /// Persist a projection while carrying the caller's already-held session
    /// admission proof. Lock ordering is always session admission -> removed
    /// slot mutation; hydration must use that proof rather than recursively
    /// inspecting the non-reentrant admission mutex.
    fn save_directory_entry_with_reason_under_admission(
        &self,
        entry: &UserDirectoryRecord,
        reason: &str,
        local_signing_account: Option<&AccountSummary>,
    ) -> Result<(), AppError> {
        // Acquire handles first: one-time legacy migration takes the mutation
        // mutex internally and must finish before this write transaction takes
        // the same mutex.
        let caches = self.directory_caches()?;
        let shared_storage = self.shared_storage()?;
        let _removed_local_key_package_mutation = self
            .removed_local_key_package_mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let admission = RemovedSlotAdmission::AlreadyAdmitted(local_signing_account);
        let proposed_entry =
            self.hydrate_directory_record_with_admission(entry.clone(), admission)?;
        let shared_record = shared_storage.public_directory_user(&proposed_entry.account_id_hex)?;
        let shared_entry = shared_record
            .clone()
            .map(|record| {
                self.hydrate_directory_record_with_admission(
                    user_directory_record_from_public(record)?,
                    admission,
                )
            })
            .transpose()?;
        // Profile/follow changes and KeyPackage revisions have independent
        // Nostr coordinates. In particular, filtering a retired local slot
        // turns one stale whole-record candidate into `key_package = None`;
        // that must not let a newer profile timestamp erase a live sibling
        // device's KeyPackage from another projection.
        let mut live_key_package = proposed_entry.key_package.clone();
        merge_newer_live_key_package(
            &mut live_key_package,
            shared_entry
                .as_ref()
                .and_then(|entry| entry.key_package.as_ref()),
        );
        let mut cached_entries = Vec::with_capacity(caches.len());
        for cache in &caches {
            let cached_entry = cache
                .entry(&proposed_entry.account_id_hex)?
                .map(|record| self.hydrate_directory_record_with_admission(record, admission))
                .transpose()?;
            merge_newer_live_key_package(
                &mut live_key_package,
                cached_entry
                    .as_ref()
                    .and_then(|entry| entry.key_package.as_ref()),
            );
            cached_entries.push(cached_entry);
        }
        let mut entry = select_newer_directory_entry(Some(proposed_entry), shared_entry.clone())
            .expect("proposed directory entry should be present");
        entry.key_package = live_key_package;
        let public_entry = public_directory_user_record(&entry)?;
        let shared_entry_matches = shared_record.as_ref() == Some(&public_entry);
        let mut caches_match = true;
        for cached_entry in cached_entries {
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

    pub(crate) fn request_directory_sync_rebuild(&self) {
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
        self.ensure_storage_open("directory cache")?;
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
        let _lifecycle = self.begin_storage_open("directory cache")?;
        let _span = tracing::debug_span!(
            target: "marmot_app::directory",
            "directory_cache_handle_open",
            method = "directory_cache_for_account"
        )
        .entered();
        let path = self.directory_cache_path(&account.label);
        let key = if account.local_signing {
            let keys = self.account_home().load_signing_keys(&account.label)?;
            self.sqlcipher_key(
                &account.label,
                &keys,
                &path,
                SqlcipherDatabaseKind::DirectoryCache,
            )?
        } else {
            self.external_sqlcipher_key(
                &account.label,
                &account.account_id_hex,
                &path,
                SqlcipherDatabaseKind::DirectoryCache,
            )?
        };
        let cache = DirectoryCache::open(path, &key)?;
        #[cfg(test)]
        self.directory_cache_open_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Publishing under `_lifecycle` is what keeps this cache reachable by a
        // later `close_storage`; see `MarmotApp::begin_storage_open`.
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
        #[cfg(test)]
        self.directory_handle_acquire_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let accounts = self
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.is_active_signing())
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
        let _removed_local_key_package_mutation = self
            .removed_local_key_package_mutation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
            // A plaintext legacy cache can contain only pre-migration state,
            // so an account-wide removal marker rejects every slot it carries.
            // Do not consult account-session admission while holding the
            // marker mutation mutex; that would invert live ingestion's
            // admission -> mutation lock order.
            .map(|entry| {
                self.hydrate_directory_record_with_admission(
                    entry,
                    RemovedSlotAdmission::AlreadyAdmitted(None),
                )
            })
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
        fs_private::write_private(&marker_path, b"done\n")?;
        Ok(())
    }

    fn clean_future_dated_directory_caches_for_all_accounts_once(&self) -> Result<(), AppError> {
        let accounts = self
            .account_home()
            .accounts()?
            .into_iter()
            .filter(|account| account.is_active_signing())
            .collect::<Vec<_>>();
        self.clean_future_dated_directory_caches_once(&accounts)
    }

    pub(crate) fn empty_directory_record(&self, account_id_hex: &str) -> UserDirectoryRecord {
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
        entry: UserDirectoryRecord,
    ) -> Result<UserDirectoryRecord, AppError> {
        self.hydrate_directory_record_with_admission(
            entry,
            RemovedSlotAdmission::InspectSessionGate,
        )
    }

    fn hydrate_directory_record_with_admission(
        &self,
        mut entry: UserDirectoryRecord,
        admission: RemovedSlotAdmission<'_>,
    ) -> Result<UserDirectoryRecord, AppError> {
        entry.account_id_hex = parse_account_id_hex(&entry.account_id_hex)?;
        entry.npub = npub_for_account_id(&entry.account_id_hex)?;
        let key_package_is_retired = entry
            .key_package
            .as_ref()
            .map(|key_package| match admission {
                RemovedSlotAdmission::InspectSessionGate => self
                    .removed_local_key_package_slot_is_retired(
                        &entry.account_id_hex,
                        &key_package.key_package_id,
                    ),
                RemovedSlotAdmission::AlreadyAdmitted(local_signing_account) => self
                    .removed_local_key_package_slot_is_retired_for_admitted_account(
                        &entry.account_id_hex,
                        &key_package.key_package_id,
                        local_signing_account,
                    ),
            })
            .transpose()?
            .unwrap_or(false);
        if key_package_is_retired {
            entry.key_package = None;
        }
        entry.local_account = self.local_account_for_id(&entry.account_id_hex);
        if let Some(local) = entry.local_account.as_ref()
            && let Some(generation) =
                self.read_nip65_route_generation_for_authoring(&local.label)?
        {
            // Profiles and KeyPackages may make a shared/cache record newer as
            // a whole, but they do not carry route authority. Overlay the exact
            // state bound to the verified local kind-10002 generation so cache
            // selection can never roll the account back to stale relays.
            entry.relay_lists.nip65 = generation.nip65;
            entry.relay_lists.refresh();
        }
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
