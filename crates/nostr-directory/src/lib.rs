mod cache;
mod cached_search;
pub mod config;
pub mod error;
mod ids;
mod key_package_recovery;
mod member_key_packages;
mod methods;
mod observer;
mod open_ranking;
mod previews;
mod published_records;
mod records;
mod resources;
mod search;
mod service;
mod store;
mod sync;
#[cfg(any(test, feature = "test-support"))]
mod test_support;

pub use cache::DirectoryCache;
pub use config::DirectoryConfig;
pub use ids::{
    account_id_hex_from_ref, normalize_account_ids, nprofile_for_account_id, npub_for_account_id,
    parse_account_id_hex, validate_relay_urls,
};
pub use member_key_packages::{
    MemberKeyPackagePrewarmSummary, MemberKeyPackageResolutionStats, MemberResolutionPurpose,
    ResolvedMemberKeyPackages,
};
pub use observer::{DirectoryObservation, DirectoryObserver, ObservedFamily, ObservedUnit};
pub use previews::{MAX_PUBLIC_EVENT_REFERENCES, PublicEventPreview, PublicEventPreviewRead};
pub use published_records::{
    AccountRelayListState, AccountRelayListStatus, FetchedKeyPackage, MissingRelayListKind,
    key_package_from_hex_with_optional_source, key_package_from_record, push_unique_strings,
    relay_list_state_from_event, sort_directory_records,
};
pub use records::{
    CachedIdentityProjection, CurrentFollowList, DirectoryKeyPackage, FetchedFollowList,
    KIND_NOSTR_CONTACT_LIST, KIND_NOSTR_METADATA, LocalAccountNames, MAX_CACHED_IDENTITY_PAGE_SIZE,
    MUTE_LIST_KIND, MatchQuality, MatchedField, UserDirectoryLocalAccount, UserDirectoryRecord,
    UserDirectoryRefresh, UserDirectorySearch, UserDirectorySearchResult, UserProfileMetadata,
    display_name_for_profile, followed_account_id, follows_from_tags, profile_content_json,
    public_directory_user_record,
};
pub use resources::{BlockListSink, DirectoryAccount, DirectoryResources};
pub use search::{
    OFF_GRAPH_SEARCH_RADIUS, SearchUpdateTrigger, UserSearchParams, UserSearchSubscription,
    UserSearchUpdate, sort_user_search_results,
};
pub use service::{Directory, DirectoryState};
pub use store::hydrate_directory_record;
pub use sync::{DirectorySyncHandle, DirectorySyncRunSummary};

// Root paths the directory's own modules use.
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) use published_records::DirectoryFreshness;
pub(crate) use published_records::DirectorySelection;
pub(crate) use sync::plan_directory_sync;

// What only `marmot-app`'s directory tests reach, including every type their
// signatures name.
#[cfg(any(test, feature = "test-support"))]
pub use cache::{DirectorySearchGraphRecord, SEARCH_GRAPH_PROFILE_TTL_SECONDS};
#[cfg(any(test, feature = "test-support"))]
pub use ids::npub_for_account_id_lossy;
#[cfg(any(test, feature = "test-support"))]
pub use member_key_packages::{MEMBER_PREWARM_CACHE_TTL, MemberKeyPackagePrewarmCache};
#[cfg(any(test, feature = "test-support"))]
pub use methods::{USER_DIRECTORY_SEARCH_MAX_FRONTIER, cached_or_unknown_follow_list};
#[cfg(any(test, feature = "test-support"))]
pub use previews::EVENT_DELETION_QUERY_LIMIT;
#[cfg(any(test, feature = "test-support"))]
pub use published_records::{
    DirectoryFreshness, KeyPackageSelection, PreferredKeyPackage, fresh_or_cached_key_package,
    latest_fresh_key_package_from_records, preferred_fresh_key_package_from_records,
    relay_list_queries, relay_list_status_from_records, relays_from_relay_list_event,
    require_key_package_tag, require_multi_value_key_package_tag_matches,
    validated_cached_key_package,
};
#[cfg(any(test, feature = "test-support"))]
pub use records::MAX_FOLLOW_LIST_ENTRIES;
#[cfg(any(test, feature = "test-support"))]
pub use search::MAX_SUPPORTED_SEARCH_RADIUS;
#[cfg(any(test, feature = "test-support"))]
pub use sync::{DirectorySyncCommand, run_directory_sync_worker};

/// The directory's wall clock, in Unix seconds.
pub(crate) fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
