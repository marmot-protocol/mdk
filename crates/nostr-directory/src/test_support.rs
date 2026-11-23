//! Test hooks for `marmot-app`'s directory tests, built only with the
//! `test-support` feature. Each wraps a crate-private method so production
//! callers cannot reach it; the free items those tests need are re-exported
//! from the crate root under the same gate.

use std::sync::{Arc, Mutex};

use cgka_traits::TransportEndpoint;
use rusqlite::OptionalExtension;
use transport_nostr::{DirectoryRelayEventRecord, DirectorySyncPlan, MarmotRelayPlane};

use crate::FetchedKeyPackage;
use crate::cache::{DirectoryCache, DirectorySearchGraphRecord};
use crate::error::DirectoryError;
use crate::key_package_recovery::KeyPackageRecoveryRequest;
use crate::member_key_packages::{
    MemberKeyPackagePrewarmCache, MemberResolutionPurpose, ResolvedMemberKeyPackages,
};
use crate::observer::DirectoryObserver;
use crate::published_records::{DirectoryFreshness, MAX_KEY_PACKAGES_PER_ACCOUNT};
use crate::records::{
    FetchedFollowList, LocalAccountNames, UserDirectoryLocalAccount, UserDirectoryRecord,
    UserProfileMetadata,
};
use crate::resources::DirectoryAccount;
use crate::resources::{BlockListSink, DirectoryResources};
use crate::service::{Directory, DirectoryState};
use crate::sync::DirectorySyncHandle;

impl DirectoryCache {
    pub fn availability_evidence_revision_for_test(
        &self,
        follow_account_id_hex: &str,
    ) -> Result<i64, DirectoryError> {
        self.lock()?
            .query_row(
                "SELECT evidence_revision FROM follow_availability
                 WHERE follow_account_id_hex = ?1",
                [follow_account_id_hex],
                |row| row.get(0),
            )
            .optional()
            .map(|revision| revision.unwrap_or(0))
            .map_err(Into::into)
    }

    pub fn search_record_for_test(
        &self,
        account_id_hex: &str,
        now: i64,
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
        self.search_record(account_id_hex, now)
    }

    pub fn search_graph_follows_for_test(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<Vec<String>>, DirectoryError> {
        self.search_graph_follows(account_id_hex)
    }

    pub fn put_search_graph_record_for_test(
        &self,
        record: &DirectorySearchGraphRecord,
        now: i64,
    ) -> Result<(), DirectoryError> {
        self.put_search_graph_record(record, now)
    }

    pub fn remember_search_graph_follows_for_test(
        &self,
        account_id_hex: &str,
        npub: &str,
        follows: &[String],
    ) -> Result<(), DirectoryError> {
        self.remember_search_graph_follows(account_id_hex, npub, follows)
    }
}

impl DirectoryFreshness {
    /// The bound a directory with this clock and skew applies.
    pub fn at_for_test(now: u64, max_future_skew: std::time::Duration) -> Self {
        Self::at(now, max_future_skew)
    }
}

impl LocalAccountNames {
    pub fn directory_for_test(&self) -> &UserDirectoryLocalAccount {
        &self.directory
    }
}

impl DirectoryState {
    pub fn member_key_package_prewarm_cache_for_test(
        &self,
    ) -> &Arc<Mutex<MemberKeyPackagePrewarmCache>> {
        &self.member_key_package_prewarm_cache
    }
}

impl DirectorySyncHandle {
    pub fn spawn_for_test<R: DirectoryResources + DirectoryObserver + BlockListSink>(
        directory: Directory<R>,
        relay_plane: MarmotRelayPlane,
    ) -> Self {
        Self::spawn(directory, relay_plane)
    }

    pub fn request_rebuild_for_test(&self) {
        self.request_rebuild()
    }
}

impl<R: DirectoryResources + DirectoryObserver> Directory<R> {
    pub async fn resolve_member_key_packages_for_purpose_for_test(
        &self,
        member_refs: Vec<String>,
        purpose: MemberResolutionPurpose,
        requirements: Option<&cgka_engine::key_package::KeyPackageRequirements>,
    ) -> Result<ResolvedMemberKeyPackages, DirectoryError> {
        self.resolve_member_key_packages_for_purpose(member_refs, purpose, requirements)
            .await
    }

    pub fn directory_sync_plan_for_test(&self) -> Result<DirectorySyncPlan, DirectoryError> {
        self.directory_sync_plan()
    }
}

impl<R: DirectoryResources> Directory<R> {
    pub fn public_event_query_relays_for_test(
        &self,
        hints: Vec<TransportEndpoint>,
    ) -> Vec<TransportEndpoint> {
        self.public_event_query_relays(hints)
    }

    pub fn public_event_supplementary_relays_for_test(
        &self,
        queried: &[TransportEndpoint],
        discovery_indexers: &[TransportEndpoint],
        author_relays: Vec<TransportEndpoint>,
    ) -> Vec<TransportEndpoint> {
        self.public_event_supplementary_relays(queried, discovery_indexers, author_relays)
    }

    pub fn public_event_refresh_cooling_down_for_test(&self, key: &str) -> bool {
        self.public_event_refresh_cooling_down(key)
    }

    pub fn start_public_event_refresh_cooldown_for_test(&self, key: String) {
        self.start_public_event_refresh_cooldown(key)
    }

    pub fn directory_entry_for_test(
        &self,
        account_id_hex: &str,
    ) -> Result<Option<UserDirectoryRecord>, DirectoryError> {
        self.directory_entry(account_id_hex)
    }

    pub fn directory_freshness_for_test(&self) -> DirectoryFreshness {
        self.directory_freshness()
    }

    pub fn reset_availability_for_test(&self, account_id_hex: &str) {
        Directory::reset_availability_cadence(self, account_id_hex);
    }

    pub fn notify_availability_admission_for_test(&self) -> Arc<tokio::sync::Notify> {
        let notify = Arc::new(tokio::sync::Notify::new());
        *self
            .state
            .availability_admission
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(notify.clone());
        notify
    }

    pub fn availability_evidence_revision_for_test(
        &self,
        account: &DirectoryAccount,
        follow_account_id_hex: &str,
    ) -> Result<i64, DirectoryError> {
        self.resources
            .cache_for_account(account)?
            .availability_evidence_revision_for_test(follow_account_id_hex)
    }

    pub fn remember_directory_user_with_reason_for_test(
        &self,
        account_id_hex: &str,
        reason: &str,
    ) -> Result<(), DirectoryError> {
        self.remember_directory_user_with_reason(account_id_hex, reason)
    }

    pub fn remember_directory_follow_list_for_test(
        &self,
        account_id_hex: &str,
        follow_list: &FetchedFollowList,
    ) -> Result<(), DirectoryError> {
        self.remember_directory_follow_list(account_id_hex, follow_list)
    }

    pub fn remember_directory_profile_if_newer_for_test(
        &self,
        account_id_hex: &str,
        profile: &UserProfileMetadata,
    ) -> Result<(), DirectoryError> {
        self.remember_directory_profile_if_newer(account_id_hex, profile)
    }

    pub fn save_directory_entry_for_test(
        &self,
        entry: &UserDirectoryRecord,
    ) -> Result<(), DirectoryError> {
        self.save_directory_entry(entry)
    }

    pub fn save_directory_entry_with_reason_for_test(
        &self,
        entry: &UserDirectoryRecord,
        reason: &str,
    ) -> Result<(), DirectoryError> {
        self.save_directory_entry_with_reason(entry, reason)
    }

    pub fn local_account_for_id_for_test(
        &self,
        account_id_hex: &str,
    ) -> Option<UserDirectoryLocalAccount> {
        self.local_account_for_id(account_id_hex)
    }

    pub fn empty_directory_record_for_test(&self, account_id_hex: &str) -> UserDirectoryRecord {
        self.empty_directory_record(account_id_hex)
    }

    /// Runs recovery over `observed` with `discovery` as its supplementary
    /// relays, then final selection after losing the packages recovery
    /// selected, as wall-clock revalidation can.
    pub async fn recover_then_lose_selection_for_test(
        &self,
        account_id_hex: &str,
        observed: Vec<DirectoryRelayEventRecord>,
        primary_complete: bool,
        discovery: Vec<TransportEndpoint>,
        requirements: &cgka_engine::key_package::KeyPackageRequirements,
    ) -> Result<Vec<FetchedKeyPackage>, DirectoryError> {
        let mut recovered = self
            .recover_key_package_records(KeyPackageRecoveryRequest {
                account: account_id_hex,
                searched: &[],
                observed,
                hints: Vec::new(),
                primary_complete,
                discovery: &discovery,
                requirements: Some(requirements),
                fence: None,
                cached_target: None,
                wanted: MAX_KEY_PACKAGES_PER_ACCOUNT,
            })
            .await?;
        let lost = recovered
            .select(account_id_hex, Some(requirements), None)?
            .into_iter()
            .map(|fetched| fetched.key_package_event_id)
            .collect::<Vec<_>>();
        recovered
            .records
            .retain(|record| !lost.contains(&record.event.id));
        recovered.select(account_id_hex, Some(requirements), None)
    }
}
