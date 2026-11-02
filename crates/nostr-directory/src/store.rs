//! The directory store: reading and writing directory entries across the
//! per-account caches and the shared public tier, ingesting relay events,
//! and the freshness bound they share. Writes ask the resources for caches
//! at the moment they write.

use std::collections::HashMap;

#[cfg(any(test, feature = "test-support"))]
use storage_sqlite::PublicDirectoryUserRecord;
use storage_sqlite::SqliteSharedStorage;
use transport_nostr::DirectoryRelayEventRecord as RelayEventRecord;
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
};

use super::error::DirectoryError;
use super::ids::{
    normalize_account_ids, npub_for_account_id, npub_for_account_id_lossy, parse_account_id_hex,
};
use super::published_records::{
    AccountRelayListStatus, DirectoryFreshness, FetchedKeyPackage, key_package_from_record,
    merge_relay_list_status, push_unique_strings, relay_list_state_from_event,
};
use super::records::{
    DirectoryKeyPackage, FetchedFollowList, KIND_NOSTR_CONTACT_LIST, KIND_NOSTR_METADATA,
    LocalAccountNames, UserDirectoryLocalAccount, UserDirectoryRecord, UserProfileMetadata,
    follow_list_from_record, profile_from_record, public_directory_user_record,
    select_newer_directory_entry, source_relays_from_record, user_directory_record_from_public,
};
use super::resources::DirectoryResources;
use super::{Directory, DirectoryCache};

impl<R: DirectoryResources> Directory<R> {
    pub fn local_accounts_by_id(
        &self,
    ) -> Result<HashMap<String, LocalAccountNames>, DirectoryError> {
        let mut local = HashMap::new();
        for account in self.resources.local_accounts()? {
            // Preserve first-record directory links and last-label display fallback for aliases.
            local
                .entry(account.account_id_hex)
                .and_modify(|names: &mut LocalAccountNames| names.label = account.label.clone())
                .or_insert_with(|| LocalAccountNames {
                    directory: UserDirectoryLocalAccount {
                        label: account.label.clone(),
                        local_signing: account.local_signing,
                    },
                    label: account.label,
                });
        }
        Ok(local)
    }

    pub(crate) fn directory_entry(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        let caches = self.resources.current_caches()?;
        let shared_storage = self.resources.shared_storage()?;
        let local_accounts = self.local_accounts_by_id()?;
        self.directory_entry_for_account_id_with_handles(
            &account_id_hex,
            &caches,
            &shared_storage,
            &local_accounts,
        )
    }

    pub(crate) fn cached_relay_list_status(
        &self,
        account_id_hex: &str,
    ) -> Result<AccountRelayListStatus, DirectoryError> {
        Ok(self
            .directory_entry(account_id_hex)?
            .map(|entry| entry.relay_lists)
            .unwrap_or_else(AccountRelayListStatus::empty))
    }

    pub(crate) fn directory_freshness(&self) -> DirectoryFreshness {
        if let Some(clock) = &self.config.test_clock {
            return DirectoryFreshness::at(
                clock.load(std::sync::atomic::Ordering::SeqCst),
                self.config.max_future_skew,
            );
        }
        DirectoryFreshness::from_now(self.config.max_future_skew)
    }

    pub fn directory_entry_for_account_id_with_handles(
        &self,
        account_id_hex: &str,
        caches: &[DirectoryCache],
        shared_storage: &SqliteSharedStorage,
        local_accounts: &HashMap<String, LocalAccountNames>,
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
        let cached_entry = directory_entry_from_caches(caches, account_id_hex)?
            .map(|entry| hydrate_directory_record(entry, local_accounts))
            .transpose()?;
        let shared_entry = shared_storage
            .public_directory_user(account_id_hex)?
            .map(|record| {
                hydrate_directory_record(user_directory_record_from_public(record)?, local_accounts)
            })
            .transpose()?;
        Ok(select_newer_directory_entry(cached_entry, shared_entry))
    }

    pub fn remember_directory_relay_lists(
        &self,
        account_id_hex: &str,
        relay_lists: &AccountRelayListStatus,
    ) -> Result<(), DirectoryError> {
        self.update_directory_entry(account_id_hex, |entry| {
            entry.relay_lists =
                merge_relay_list_status(entry.relay_lists.clone(), relay_lists.clone());
            true
        })
    }

    pub fn remember_directory_key_package(
        &self,
        fetched: &FetchedKeyPackage,
    ) -> Result<(), DirectoryError> {
        self.update_directory_entry(&fetched.account_id_hex, |entry| {
            entry.relay_lists =
                merge_relay_list_status(entry.relay_lists.clone(), fetched.relay_lists.clone());
            entry.key_package = Some(DirectoryKeyPackage {
                key_package_id: fetched.key_package_id.clone(),
                key_package_ref_hex: fetched.key_package_ref_hex.clone(),
                key_package_event_id: fetched.key_package_event_id.clone(),
                key_package_hex: hex::encode(fetched.key_package.bytes()),
                created_at: fetched.created_at,
                source_relays: fetched.source_relays.clone(),
            });
            true
        })
    }

    pub(crate) fn remember_directory_user(
        &self,
        account_id_hex: &str,
    ) -> Result<(), DirectoryError> {
        self.remember_directory_user_with_reason(account_id_hex, "directory")
    }

    pub(crate) fn remember_directory_user_with_reason(
        &self,
        account_id_hex: &str,
        reason: &str,
    ) -> Result<(), DirectoryError> {
        self.update_directory_entry_with_reason(account_id_hex, reason, true, |_| true)
    }

    pub fn remember_directory_message_sender(
        &self,
        sender_account_id_hex: &str,
    ) -> Result<(), DirectoryError> {
        self.remember_directory_user_with_reason(sender_account_id_hex, "message")
    }

    pub(crate) fn remember_directory_follow_list(
        &self,
        account_id_hex: &str,
        follow_list: &FetchedFollowList,
    ) -> Result<(), DirectoryError> {
        self.update_directory_entry(account_id_hex, |entry| {
            entry.follows = follow_list.follows.clone();
            entry.follow_source_relays = follow_list.source_relays.clone();
            true
        })?;
        // Finish graph maintenance and user promotion after releasing the
        // record lane: those paths may perform their own directory updates.
        // A fetched empty kind-3 remains authoritative.
        self.remember_directory_follow_edges_for_search(account_id_hex, follow_list)?;
        for follow in &follow_list.follows {
            self.remember_directory_user(follow)?;
        }
        Ok(())
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
    /// but `MarmotApp::directory_sync_plan` does not. When the author is already a
    /// known directory entry (e.g. a local account whose contact list we sync),
    /// its own cached follow edges are refreshed too, but its follows are still
    /// not promoted.
    pub fn remember_directory_follow_edges_for_search(
        &self,
        account_id_hex: &str,
        follow_list: &FetchedFollowList,
    ) -> Result<(), DirectoryError> {
        let npub = npub_for_account_id_lossy(account_id_hex);
        for cache in self.resources.current_caches()? {
            cache.remember_search_graph_follows(account_id_hex, &npub, &follow_list.follows)?;
        }
        // Graph-only ingestion must not promote an unknown author.
        self.update_directory_entry_with_reason(account_id_hex, "directory", false, |entry| {
            entry.follows = follow_list.follows.clone();
            entry.follow_source_relays = follow_list.source_relays.clone();
            true
        })
    }

    pub fn remember_directory_profile(
        &self,
        account_id_hex: &str,
        profile: &UserProfileMetadata,
    ) -> Result<(), DirectoryError> {
        self.update_directory_entry(account_id_hex, |entry| {
            entry.profile = Some(profile.clone());
            true
        })
    }

    pub(crate) fn remember_directory_profile_if_newer(
        &self,
        account_id_hex: &str,
        profile: &UserProfileMetadata,
    ) -> Result<(), DirectoryError> {
        self.update_directory_entry(account_id_hex, |entry| {
            // Check and mutate in the same lane. Equal-second relay echoes
            // still cannot undo the just-published local value (mdk#206).
            if entry
                .profile
                .as_ref()
                .is_some_and(|cached| cached.created_at >= profile.created_at)
            {
                return false;
            }
            entry.profile = Some(profile.clone());
            true
        })
    }

    fn remember_directory_relay_list_event(
        &self,
        account_id_hex: &str,
        record: &RelayEventRecord,
    ) -> Result<(), DirectoryError> {
        let Some(state) = relay_list_state_from_event(&record.event) else {
            return Ok(());
        };
        self.update_directory_entry(account_id_hex, |entry| {
            // Keep the existing cached-on-equality policy (mdk#920).
            match record.event.kind {
                KIND_NIP65_RELAY_LIST
                    if entry.relay_lists.nip65.created_at != 0
                        && entry.relay_lists.nip65.created_at >= record.event.created_at =>
                {
                    return false;
                }
                KIND_MARMOT_INBOX_RELAY_LIST
                    if entry.relay_lists.inbox.created_at != 0
                        && entry.relay_lists.inbox.created_at >= record.event.created_at =>
                {
                    return false;
                }
                KIND_NIP65_RELAY_LIST => entry.relay_lists.nip65 = state,
                KIND_MARMOT_INBOX_RELAY_LIST => entry.relay_lists.inbox = state,
                _ => return false,
            }
            push_unique_strings(
                &mut entry.relay_lists.bootstrap_relays,
                source_relays_from_record(record),
            );
            entry.relay_lists.refresh();
            true
        })
    }

    pub fn ingest_directory_relay_event(
        &self,
        record: RelayEventRecord,
    ) -> Result<(), DirectoryError> {
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
                    .cached_relay_list_status(&account_id_hex)
                    .unwrap_or_else(|_| AccountRelayListStatus::empty());
                self.remember_directory_key_package(&fetched)?;
            }
            _ => {}
        }
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn save_directory_entry(
        &self,
        entry: &UserDirectoryRecord,
    ) -> Result<(), DirectoryError> {
        self.save_directory_entry_with_reason(entry, "directory")
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn save_directory_entry_with_reason(
        &self,
        entry: &UserDirectoryRecord,
        reason: &str,
    ) -> Result<(), DirectoryError> {
        self.update_directory_entry_with_reason(&entry.account_id_hex, reason, true, |current| {
            *current = entry.clone();
            true
        })
    }

    fn update_directory_entry(
        &self,
        account_id_hex: &str,
        update: impl FnOnce(&mut UserDirectoryRecord) -> bool,
    ) -> Result<(), DirectoryError> {
        self.update_directory_entry_with_reason(account_id_hex, "directory", true, update)
    }

    fn update_directory_entry_with_reason(
        &self,
        account_id_hex: &str,
        reason: &str,
        create_missing: bool,
        update: impl FnOnce(&mut UserDirectoryRecord) -> bool,
    ) -> Result<(), DirectoryError> {
        let account_id_hex = parse_account_id_hex(account_id_hex)?;
        // The host owns cache opening/eviction. Acquire its handles before the
        // lane so account lifecycle locks cannot invert the directory lock.
        let local_accounts = self.local_accounts_by_id()?;
        let shared_storage = self.resources.shared_storage()?;
        let caches = self.resources.current_caches()?;
        let empty = UserDirectoryRecord {
            account_id_hex: account_id_hex.clone(),
            npub: npub_for_account_id(&account_id_hex)?,
            local_account: local_accounts
                .get(&account_id_hex)
                .map(|names| names.directory.clone()),
            profile: None,
            follows: Vec::new(),
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        };
        let mut changed = false;
        let result: Result<(), DirectoryError> = (|| {
            let _lane = self
                .state
                .entry_updates
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let cached_entry = directory_entry_from_caches(&caches, &account_id_hex)?
                .map(|entry| hydrate_directory_record(entry, &local_accounts))
                .transpose()?;
            let shared_record = shared_storage.public_directory_user(&account_id_hex)?;
            let shared_entry = shared_record
                .clone()
                .map(|record| {
                    hydrate_directory_record(
                        user_directory_record_from_public(record)?,
                        &local_accounts,
                    )
                })
                .transpose()?;
            let current = select_newer_directory_entry(cached_entry, shared_entry);
            if current.is_none() && !create_missing {
                return Ok(());
            }
            let mut proposed = current.clone().unwrap_or(empty);
            if !update(&mut proposed) {
                return Ok(());
            }
            let proposed = hydrate_directory_record(proposed, &local_accounts)?;
            // Preserve the existing component-wise recency merge: an explicit
            // local candidate wins equality, but cannot drag older siblings
            // across cache boundaries. Ingest guards above retain cached ties.
            let entry = select_newer_directory_entry(Some(proposed), current)
                .expect("proposed directory entry should be present");
            let public_entry = public_directory_user_record(&entry)?;
            let shared_matches = shared_record.as_ref() == Some(&public_entry);
            let mut caches_match = true;
            for cache in &caches {
                let cached = cache
                    .entry(&account_id_hex)?
                    .map(|record| hydrate_directory_record(record, &local_accounts))
                    .transpose()?;
                if cached.as_ref() != Some(&entry) {
                    caches_match = false;
                    break;
                }
            }
            if shared_matches && caches_match {
                // Duplicate receive traffic must not amplify writes merely to
                // refresh a provenance reason's last_seen_at.
                return Ok(());
            }
            shared_storage.put_public_directory_user(&public_entry)?;
            changed = true;
            for cache in &caches {
                cache.put_with_reason(&entry, reason)?;
            }
            Ok(())
        })();
        // Host callbacks may read or write directory state. Also notify when
        // the shared row changed but a later account-cache write failed.
        if changed {
            self.resources.directory_entry_changed(&account_id_hex);
            if result.is_ok() {
                self.request_directory_sync_rebuild();
            }
        }
        result
    }

    fn request_directory_sync_rebuild(&self) {
        let handle = self
            .state
            .sync_handle
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(handle) = handle {
            handle.request_rebuild();
        }
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

    #[cfg(any(test, feature = "test-support"))]
    pub fn hydrate_public_directory_record(
        &self,
        record: PublicDirectoryUserRecord,
    ) -> Result<UserDirectoryRecord, DirectoryError> {
        hydrate_directory_record(
            user_directory_record_from_public(record)?,
            &self.local_accounts_by_id()?,
        )
    }

    pub(crate) fn local_account_for_id(
        &self,
        account_id_hex: &str,
    ) -> Option<UserDirectoryLocalAccount> {
        self.resources
            .local_accounts()
            .ok()?
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex)
            .map(|account| UserDirectoryLocalAccount {
                label: account.label,
                local_signing: account.local_signing,
            })
    }
}

fn directory_entry_from_caches(
    caches: &[DirectoryCache],
    account_id_hex: &str,
) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
    for cache in caches {
        if let Some(entry) = cache.entry(account_id_hex)? {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

pub fn hydrate_directory_record(
    mut entry: UserDirectoryRecord,
    local_accounts: &HashMap<String, LocalAccountNames>,
) -> Result<UserDirectoryRecord, DirectoryError> {
    entry.account_id_hex = parse_account_id_hex(&entry.account_id_hex)?;
    entry.npub = npub_for_account_id(&entry.account_id_hex)?;
    entry.local_account = local_accounts
        .get(&entry.account_id_hex)
        .map(|names| names.directory.clone());
    entry.follows = normalize_account_ids(entry.follows)?;
    entry.follow_source_relays.sort();
    entry.follow_source_relays.dedup();
    Ok(entry)
}

#[cfg(test)]
mod tests;
