//! `MarmotApp`'s public directory methods, as one-line delegates to
//! [`Directory`](crate::directory::Directory). They keep returning `AppError`
//! until callers move to `app.directory()` and these go (PR 7 of
//! `docs/marmot-architecture/review/brief-directory.md`).

use std::collections::HashMap;

use cgka_traits::TransportEndpoint;
use cgka_traits::engine::KeyPackage;
#[cfg(test)]
use storage_sqlite::PublicDirectoryUserRecord;
use storage_sqlite::SqliteSharedStorage;
use transport_nostr::DirectoryRelayEventRecord as RelayEventRecord;

use crate::directory::DirectoryCache;
use crate::directory::error::DirectoryError;
use crate::directory::records::{FetchedFollowList, LocalAccountNames};
use crate::{
    AccountRelayListStatus, AppError, CachedIdentityProjection, FetchedKeyPackage, MarmotApp,
    MemberKeyPackagePrewarmSummary, UserDirectoryRecord, UserDirectoryRefresh, UserDirectorySearch,
    UserDirectorySearchResult, UserProfileMetadata, UserSearchParams, UserSearchSubscription,
};
#[cfg(test)]
use crate::{DirectoryFreshness, UserDirectoryLocalAccount};

impl MarmotApp {
    /// Search all cached public identities, independent of social-graph reachability.
    /// This does no relay work or group-membership reads. Follow attribution is
    /// relative to `searcher_account_id_hex`; local labels and private nicknames
    /// never participate. A zero limit returns no results. Call off the UI thread.
    pub fn search_cached_users(
        &self,
        searcher_account_id_hex: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<UserDirectorySearchResult>, AppError> {
        Ok(self
            .directory()
            .search_cached_users(searcher_account_id_hex, query, limit)?)
    }

    /// Start a streaming search across the searcher's web of trust.
    ///
    /// Returns as soon as the traversal is spawned; matches arrive through
    /// [`UserSearchSubscription::next_update`]. Dropping the subscription stops
    /// the traversal at its next checkpoint.
    pub async fn search_users(
        &self,
        params: UserSearchParams,
    ) -> Result<UserSearchSubscription, AppError> {
        Ok(self.directory().search_users(params).await?)
    }

    /// Resolve a roster as one deterministic set.
    ///
    /// Account aliases are canonicalized and duplicate account ids collapse to
    /// their first input position. Every package is fetched from relays; cached
    /// packages are never a fallback if that lookup fails. On error, the error
    /// belonging to the first unresolved canonical member is returned even if
    /// later relay work completed earlier.
    pub async fn resolve_member_key_packages(
        &self,
        member_refs: &[&str],
    ) -> Result<Vec<KeyPackage>, AppError> {
        Ok(self
            .directory()
            .resolve_member_key_packages(member_refs)
            .await?)
    }

    /// Prewarm group composition without reserving or consuming any package.
    /// Success reports relay/metadata readiness only; final Create/Invite
    /// re-fetches packages and enforces the engine's membership policy.
    ///
    /// The roster must also resolve a safe Marmot inbox route for every member;
    /// missing routes return [`AppError::MissingMemberInboxRoute`]. Successfully
    /// discovered routes remain cached even when another member fails readiness.
    /// A malformed current slot publication suppresses older packages here too;
    /// return an error rather than report readiness from superseded material.
    /// Every call fetches packages for a fresh readiness signal; hosts should
    /// debounce composition changes. A later create call can reuse discovery routes,
    /// but fetches KeyPackages again because prewarmed material may have been
    /// consumed in the meantime.
    pub async fn prewarm_group_member_key_packages(
        &self,
        member_refs: &[&str],
    ) -> Result<MemberKeyPackagePrewarmSummary, AppError> {
        Ok(self
            .directory()
            .prewarm_group_member_key_packages(member_refs)
            .await?)
    }

    pub async fn fetch_account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountRelayListStatus, AppError> {
        Ok(self
            .directory()
            .fetch_account_relay_list_status_for_account_id(account_id_hex, bootstrap_relays)
            .await?)
    }

    pub async fn fetch_current_account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
        required_list_kind: Option<&str>,
    ) -> Result<Option<AccountRelayListStatus>, AppError> {
        Ok(self
            .directory()
            .fetch_current_account_relay_list_status_for_account_id(
                account_id_hex,
                bootstrap_relays,
                required_list_kind,
            )
            .await?)
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
        Ok(self
            .directory()
            .fetch_current_user_profile_for_account_id(account_id_hex, bootstrap_relays)
            .await?)
    }

    pub async fn fetch_latest_key_package_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<FetchedKeyPackage, AppError> {
        Ok(self
            .directory()
            .fetch_latest_key_package_for_account_id(account_id_hex, bootstrap_relays)
            .await?)
    }

    pub async fn refresh_directory_entry_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRecord, AppError> {
        Ok(self
            .directory()
            .refresh_directory_entry_for_account_id(account_id_hex, bootstrap_relays)
            .await?)
    }

    pub fn directory_entry_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, AppError> {
        Ok(self
            .directory()
            .directory_entry_for_account_id(account_id_hex)?)
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
        Ok(self
            .directory()
            .cached_identity_projections_for_account_ids(account_id_hexes)?)
    }

    pub async fn refresh_user_directory_for_account_id(
        &self,
        account_id_hex: &str,
        bootstrap_relays: Vec<TransportEndpoint>,
    ) -> Result<UserDirectoryRefresh, AppError> {
        Ok(self
            .directory()
            .refresh_user_directory_for_account_id(account_id_hex, bootstrap_relays)
            .await?)
    }

    pub fn search_user_directory(
        &self,
        search: UserDirectorySearch,
    ) -> Result<Vec<UserDirectorySearchResult>, AppError> {
        Ok(self.directory().search_user_directory(search)?)
    }

    pub fn account_relay_list_status_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<AccountRelayListStatus, AppError> {
        Ok(self
            .directory()
            .account_relay_list_status_for_account_id(account_id_hex)?)
    }

    pub async fn fetch_current_follow_list_for_account_id(
        &self,
        account_id_hex: &str,
        source_relays: Vec<TransportEndpoint>,
    ) -> Result<Option<Vec<String>>, AppError> {
        Ok(self
            .directory()
            .fetch_current_follow_list_for_account_id(account_id_hex, source_relays)
            .await?)
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
        Ok(self
            .directory()
            .refresh_profile_for_account_id(account_id_hex, source_relays)
            .await?)
    }
}

// Crate-internal delegates to the directory for app code and tests; each goes
// when its last caller moves to `directory()` (PR 7).
impl MarmotApp {
    #[cfg(test)]
    pub(crate) fn directory_entry(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
        self.directory().directory_entry(account_id_hex)
    }

    pub(crate) fn directory_entry_for_account_id_with_handles(
        &self,
        account_id_hex: &str,
        caches: &[DirectoryCache],
        shared_storage: &SqliteSharedStorage,
        local_accounts: &HashMap<String, LocalAccountNames>,
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
        self.directory()
            .directory_entry_for_account_id_with_handles(
                account_id_hex,
                caches,
                shared_storage,
                local_accounts,
            )
    }

    #[cfg(test)]
    pub(crate) fn directory_freshness(&self) -> DirectoryFreshness {
        self.directory().directory_freshness()
    }

    #[cfg(test)]
    pub(crate) fn empty_directory_record(&self, account_id_hex: &str) -> UserDirectoryRecord {
        self.directory().empty_directory_record(account_id_hex)
    }

    #[cfg(test)]
    pub(crate) fn hydrate_public_directory_record(
        &self,
        record: PublicDirectoryUserRecord,
    ) -> Result<UserDirectoryRecord, DirectoryError> {
        self.directory().hydrate_public_directory_record(record)
    }

    pub(crate) fn ingest_directory_relay_event(
        &self,
        record: RelayEventRecord,
    ) -> Result<(), DirectoryError> {
        self.directory().ingest_directory_relay_event(record)
    }

    #[cfg(test)]
    pub(crate) fn local_account_for_id(
        &self,
        account_id_hex: &str,
    ) -> Option<UserDirectoryLocalAccount> {
        self.directory().local_account_for_id(account_id_hex)
    }

    pub(crate) fn local_accounts_by_id(
        &self,
    ) -> Result<HashMap<String, LocalAccountNames>, DirectoryError> {
        self.directory().local_accounts_by_id()
    }

    pub(crate) fn remember_directory_follow_edges_for_search(
        &self,
        account_id_hex: &str,
        follow_list: &FetchedFollowList,
    ) -> Result<(), DirectoryError> {
        self.directory()
            .remember_directory_follow_edges_for_search(account_id_hex, follow_list)
    }

    #[cfg(test)]
    pub(crate) fn remember_directory_follow_list_for_test(
        &self,
        account_id_hex: &str,
        follow_list: &FetchedFollowList,
    ) -> Result<(), DirectoryError> {
        self.directory()
            .remember_directory_follow_list(account_id_hex, follow_list)
    }

    pub(crate) fn remember_directory_key_package(
        &self,
        fetched: &FetchedKeyPackage,
    ) -> Result<(), DirectoryError> {
        self.directory().remember_directory_key_package(fetched)
    }

    pub(crate) fn remember_directory_message_sender(
        &self,
        sender_account_id_hex: &str,
    ) -> Result<(), DirectoryError> {
        self.directory()
            .remember_directory_message_sender(sender_account_id_hex)
    }

    pub(crate) fn remember_directory_profile(
        &self,
        account_id_hex: &str,
        profile: &UserProfileMetadata,
    ) -> Result<(), DirectoryError> {
        self.directory()
            .remember_directory_profile(account_id_hex, profile)
    }

    #[cfg(test)]
    pub(crate) fn remember_directory_profile_if_newer(
        &self,
        account_id_hex: &str,
        profile: &UserProfileMetadata,
    ) -> Result<(), DirectoryError> {
        self.directory()
            .remember_directory_profile_if_newer(account_id_hex, profile)
    }

    pub(crate) fn remember_directory_relay_lists(
        &self,
        account_id_hex: &str,
        relay_lists: &AccountRelayListStatus,
    ) -> Result<(), DirectoryError> {
        self.directory()
            .remember_directory_relay_lists(account_id_hex, relay_lists)
    }

    #[cfg(test)]
    pub(crate) fn remember_directory_user_with_reason(
        &self,
        account_id_hex: &str,
        reason: &str,
    ) -> Result<(), DirectoryError> {
        self.directory()
            .remember_directory_user_with_reason(account_id_hex, reason)
    }

    #[cfg(test)]
    pub(crate) fn save_directory_entry(
        &self,
        entry: &UserDirectoryRecord,
    ) -> Result<(), DirectoryError> {
        self.directory().save_directory_entry(entry)
    }

    #[cfg(test)]
    pub(crate) fn save_directory_entry_with_reason(
        &self,
        entry: &UserDirectoryRecord,
        reason: &str,
    ) -> Result<(), DirectoryError> {
        self.directory()
            .save_directory_entry_with_reason(entry, reason)
    }
}

#[allow(dead_code)]
fn member_resolution_future_is_send(app: &MarmotApp) {
    fn assert_send<T: Send>(_: T) {}
    assert_send(app.resolve_member_key_packages(&[]));
}
