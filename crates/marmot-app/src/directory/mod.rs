mod cache;
mod cached_search;
pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod ids;
mod key_package_recovery;
pub(crate) mod member_key_packages;
mod methods;
pub(crate) mod observer;
mod open_ranking;
pub(crate) mod previews;
pub(crate) mod published_records;
pub(crate) mod records;
pub(crate) mod resources;
pub(crate) mod search;
mod service;
mod store;
pub(crate) mod sync;

pub(crate) use cache::DirectoryCache;
#[cfg(test)]
pub(crate) use cache::{DirectorySearchGraphRecord, SEARCH_GRAPH_PROFILE_TTL_SECONDS};
pub(crate) use config::DirectoryConfig;
pub use member_key_packages::MemberKeyPackagePrewarmSummary;
pub(crate) use member_key_packages::MemberResolutionPurpose;
#[cfg(test)]
pub(crate) use methods::USER_DIRECTORY_SEARCH_MAX_FRONTIER;
#[cfg(test)]
pub(crate) use methods::cached_or_unknown_follow_list;
pub(crate) use observer::{DirectoryObservation, DirectoryObserver, ObservedFamily, ObservedUnit};
pub use published_records::{
    AccountRelayListState, AccountRelayListStatus, FetchedKeyPackage, MissingRelayListKind,
};
pub(crate) use records::FetchedFollowList;
pub use records::{
    CachedIdentityProjection, DirectoryKeyPackage, MAX_CACHED_IDENTITY_PAGE_SIZE, MatchQuality,
    MatchedField, UserDirectoryLocalAccount, UserDirectoryRecord, UserDirectoryRefresh,
    UserDirectorySearch, UserDirectorySearchResult, UserProfileMetadata,
};
pub(crate) use resources::{BlockListSink, DirectoryAccount, DirectoryResources};
pub use search::{
    OFF_GRAPH_SEARCH_RADIUS, SearchUpdateTrigger, UserSearchParams, UserSearchSubscription,
    UserSearchUpdate, sort_user_search_results,
};
pub(crate) use service::{Directory, DirectoryState};
pub(crate) use store::hydrate_directory_record;
pub(crate) use sync::{DirectorySyncHandle, plan_directory_sync};

/// The directory's wall clock, in Unix seconds.
pub(crate) fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
