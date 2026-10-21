pub mod cache;
pub mod cached_search;
pub mod config;
pub mod error;
pub mod ids;
pub mod key_package_recovery;
pub mod member_key_packages;
pub mod methods;
pub mod observer;
pub mod open_ranking;
pub mod previews;
pub mod published_records;
pub mod records;
pub mod resources;
pub mod search;
pub mod service;
pub mod store;
pub mod sync;

pub use cache::DirectoryCache;
#[cfg(any(test, feature = "test-support"))]
pub use cache::{DirectorySearchGraphRecord, SEARCH_GRAPH_PROFILE_TTL_SECONDS};
pub use config::DirectoryConfig;
pub use member_key_packages::MemberKeyPackagePrewarmSummary;
pub use member_key_packages::MemberResolutionPurpose;
#[cfg(any(test, feature = "test-support"))]
pub use methods::USER_DIRECTORY_SEARCH_MAX_FRONTIER;
#[cfg(any(test, feature = "test-support"))]
pub use methods::cached_or_unknown_follow_list;
pub use observer::{DirectoryObservation, DirectoryObserver, ObservedFamily, ObservedUnit};
pub use published_records::{
    AccountRelayListState, AccountRelayListStatus, DirectoryFreshness, DirectorySelection,
    FetchedKeyPackage, MissingRelayListKind, push_unique_strings, relay_list_state_from_event,
    sort_directory_records,
};
pub use records::FetchedFollowList;
pub use records::{
    CachedIdentityProjection, DirectoryKeyPackage, KIND_NOSTR_CONTACT_LIST, KIND_NOSTR_METADATA,
    MAX_CACHED_IDENTITY_PAGE_SIZE, MatchQuality, MatchedField, UserDirectoryLocalAccount,
    UserDirectoryRecord, UserDirectoryRefresh, UserDirectorySearch, UserDirectorySearchResult,
    UserProfileMetadata,
};
pub use resources::{BlockListSink, DirectoryAccount, DirectoryResources};
pub use search::{
    OFF_GRAPH_SEARCH_RADIUS, SearchUpdateTrigger, UserSearchParams, UserSearchSubscription,
    UserSearchUpdate, sort_user_search_results,
};
pub use service::{Directory, DirectoryState};
pub use store::hydrate_directory_record;
pub use sync::{DirectorySyncHandle, plan_directory_sync};

/// The directory's wall clock, in Unix seconds.
pub fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
