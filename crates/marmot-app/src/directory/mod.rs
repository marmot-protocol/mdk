mod cache;
mod cached_search;
pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod ids;
mod key_package_recovery;
mod member_key_packages;
mod methods;
mod open_ranking;
pub(crate) mod previews;
pub(crate) mod published_records;
pub(crate) mod records;
pub(crate) mod resources;
mod search;
mod service;
mod sync;

pub(crate) use cache::DirectoryCache;
#[cfg(test)]
pub(crate) use cache::DirectorySearchGraphRecord;
pub use member_key_packages::MemberKeyPackagePrewarmSummary;
pub(crate) use member_key_packages::{MemberKeyPackagePrewarmCache, MemberResolutionPurpose};
#[cfg(test)]
pub(crate) use methods::USER_DIRECTORY_SEARCH_MAX_FRONTIER;
#[cfg(test)]
pub(crate) use methods::cached_or_unknown_follow_list;
pub use published_records::{
    AccountRelayListState, AccountRelayListStatus, FetchedKeyPackage, MissingRelayListKind,
};
pub(crate) use records::FetchedFollowList;
pub use records::{
    CachedIdentityProjection, DirectoryKeyPackage, MAX_CACHED_IDENTITY_PAGE_SIZE, MatchQuality,
    MatchedField, UserDirectoryLocalAccount, UserDirectoryRecord, UserDirectoryRefresh,
    UserDirectorySearch, UserDirectorySearchResult, UserProfileMetadata,
};
pub(crate) use resources::{DirectoryAccount, DirectoryResources};
pub use search::{
    OFF_GRAPH_SEARCH_RADIUS, SearchUpdateTrigger, UserSearchParams, UserSearchSubscription,
    UserSearchUpdate, sort_user_search_results,
};
pub(crate) use service::Directory;
pub(crate) use sync::{DirectorySyncHandle, plan_directory_sync};

/// The directory's wall clock, in Unix seconds.
pub(crate) fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
