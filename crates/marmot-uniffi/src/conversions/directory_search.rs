//! Streaming user-search FFI conversions.
//!
//! Mirrors marmot-app's search DTOs one-for-one. The match attribution stays
//! a closed enum on both sides of the boundary, so a host branches on cases
//! the compiler checks instead of comparing strings.

use marmot_app::{
    MatchQuality, MatchedField, SearchUpdateTrigger, UserDirectorySearchResult, UserSearchUpdate,
};

use super::account::UserProfileMetadataFfi;
use super::saturating_u32;

/// How closely the record matched, best first.
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum MatchQualityFfi {
    Exact,
    Prefix,
    Contains,
}

impl From<MatchQuality> for MatchQualityFfi {
    fn from(value: MatchQuality) -> Self {
        match value {
            MatchQuality::Exact => Self::Exact,
            MatchQuality::Prefix => Self::Prefix,
            MatchQuality::Contains => Self::Contains,
        }
    }
}

/// Which field matched, most identifying first.
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum MatchedFieldFfi {
    Name,
    Nip05,
    DisplayName,
    About,
    Npub,
    Pubkey,
}

impl From<MatchedField> for MatchedFieldFfi {
    fn from(value: MatchedField) -> Self {
        match value {
            MatchedField::Name => Self::Name,
            MatchedField::Nip05 => Self::Nip05,
            MatchedField::DisplayName => Self::DisplayName,
            MatchedField::About => Self::About,
            MatchedField::Npub => Self::Npub,
            MatchedField::Pubkey => Self::Pubkey,
        }
    }
}

/// One person the search found.
///
/// `is_followed_by_searcher` is the direct-follow label for the selected account.
/// Radius 1 can also mean a shared group; it must not be used as a follow flag.
/// Radius 255 means no relationship has been established for this result yet;
/// a later update may supply a graph radius. Cached public profiles can come
/// from any connected account without inheriting that account's relationships.
#[derive(Clone, Debug, uniffi::Record)]
pub struct UserDirectorySearchResultFfi {
    pub account_id_hex: String,
    pub npub: String,
    pub radius: u8,
    /// Direct follow of the selected searcher; radius 1 alone is insufficient.
    pub is_followed_by_searcher: bool,
    pub matched_field: MatchedFieldFfi,
    pub match_quality: MatchQualityFfi,
    /// Rank supplied by an off-graph discovery provider.
    pub provider_rank: Option<f64>,
    pub profile: Option<UserProfileMetadataFfi>,
}

impl From<UserDirectorySearchResult> for UserDirectorySearchResultFfi {
    fn from(value: UserDirectorySearchResult) -> Self {
        Self {
            account_id_hex: value.account_id_hex,
            npub: value.npub,
            radius: value.radius,
            is_followed_by_searcher: value.is_followed_by_searcher,
            matched_field: value.matched_field.into(),
            match_quality: value.match_quality.into(),
            provider_rank: value.provider_rank,
            profile: value.profile.map(Into::into),
        }
    }
}

/// Why an update was emitted, so a host can show traversal progress without
/// tracking the search itself.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum SearchUpdateTriggerFfi {
    RadiusStarted {
        radius: u8,
    },
    ResultsFound {
        radius: u8,
    },
    /// Results from the optional off-graph discovery tier. Each result still
    /// carries its own graph or discovery provenance.
    DiscoveryResultsFound,
    CachedResultsFound,
    RadiusCompleted {
        radius: u8,
    },
    /// This radius ran out of time; traversal stops here. Results already
    /// delivered stay valid — present them as partial, not failed.
    RadiusTimeout {
        radius: u8,
    },
    /// Expanding this radius hit the per-radius candidate cap, so deeper
    /// results are incomplete. Like a timeout, this is partial rather than
    /// failed: everything already delivered is still correct.
    RadiusTruncated {
        radius: u8,
    },
    /// Terminal: no further updates follow.
    SearchCompleted,
    /// Traversal failed. Always followed by [`Self::SearchCompleted`].
    Error {
        message: String,
    },
}

impl From<SearchUpdateTrigger> for SearchUpdateTriggerFfi {
    fn from(value: SearchUpdateTrigger) -> Self {
        match value {
            SearchUpdateTrigger::RadiusStarted { radius } => Self::RadiusStarted { radius },
            SearchUpdateTrigger::ResultsFound { radius } => Self::ResultsFound { radius },
            SearchUpdateTrigger::DiscoveryResultsFound => Self::DiscoveryResultsFound,
            SearchUpdateTrigger::CachedResultsFound => Self::CachedResultsFound,
            SearchUpdateTrigger::RadiusCompleted { radius } => Self::RadiusCompleted { radius },
            SearchUpdateTrigger::RadiusTimeout { radius } => Self::RadiusTimeout { radius },
            SearchUpdateTrigger::RadiusTruncated { radius } => Self::RadiusTruncated { radius },
            SearchUpdateTrigger::SearchCompleted => Self::SearchCompleted,
            SearchUpdateTrigger::Error { message } => Self::Error { message },
        }
    }
}

/// One incremental step of a running search.
#[derive(Clone, Debug, uniffi::Record)]
pub struct UserSearchUpdateFfi {
    pub trigger: SearchUpdateTriggerFfi,
    /// New identities, sorted within this batch. Cache, provider, and graph
    /// sources arrive independently. Merge by account id and re-sort after
    /// applying `updated_results` as replacements.
    pub new_results: Vec<UserDirectorySearchResultFfi>,
    /// Replace existing rows with these values, matching by account id.
    pub updated_results: Vec<UserDirectorySearchResultFfi>,
    /// Unique person count; replacements do not increment it.
    pub total_result_count: u32,
}

impl From<UserSearchUpdate> for UserSearchUpdateFfi {
    fn from(value: UserSearchUpdate) -> Self {
        Self {
            trigger: value.trigger.into(),
            new_results: value.new_results.into_iter().map(Into::into).collect(),
            updated_results: value.updated_results.into_iter().map(Into::into).collect(),
            total_result_count: saturating_u32(value.total_result_count),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::discriminant;

    #[test]
    fn match_quality_and_field_attribution_keep_their_typed_choices() {
        for (native, expected) in [
            (MatchQuality::Exact, MatchQualityFfi::Exact),
            (MatchQuality::Prefix, MatchQualityFfi::Prefix),
            (MatchQuality::Contains, MatchQualityFfi::Contains),
        ] {
            let actual: MatchQualityFfi = native.into();
            assert_eq!(discriminant(&actual), discriminant(&expected));
        }
        for (native, expected) in [
            (MatchedField::Name, MatchedFieldFfi::Name),
            (MatchedField::Nip05, MatchedFieldFfi::Nip05),
            (MatchedField::DisplayName, MatchedFieldFfi::DisplayName),
            (MatchedField::About, MatchedFieldFfi::About),
            (MatchedField::Npub, MatchedFieldFfi::Npub),
            (MatchedField::Pubkey, MatchedFieldFfi::Pubkey),
        ] {
            let actual: MatchedFieldFfi = native.into();
            assert_eq!(discriminant(&actual), discriminant(&expected));
        }
    }

    #[test]
    fn search_progress_preserves_trigger_and_its_radius_or_error() {
        type TriggerCheck = fn(SearchUpdateTriggerFfi) -> bool;
        // Fallback seeds report an unknown social distance (255), even though
        // their traversal hop remains bounded by MAX_SUPPORTED_SEARCH_RADIUS.
        let cases: [(SearchUpdateTrigger, TriggerCheck); 14] = [
            (SearchUpdateTrigger::RadiusStarted { radius: 0 }, |v| {
                matches!(v, SearchUpdateTriggerFfi::RadiusStarted { radius: 0 })
            }),
            (SearchUpdateTrigger::ResultsFound { radius: 2 }, |v| {
                matches!(v, SearchUpdateTriggerFfi::ResultsFound { radius: 2 })
            }),
            (SearchUpdateTrigger::DiscoveryResultsFound, |v| {
                matches!(v, SearchUpdateTriggerFfi::DiscoveryResultsFound)
            }),
            (SearchUpdateTrigger::CachedResultsFound, |v| {
                matches!(v, SearchUpdateTriggerFfi::CachedResultsFound)
            }),
            (SearchUpdateTrigger::RadiusCompleted { radius: 1 }, |v| {
                matches!(v, SearchUpdateTriggerFfi::RadiusCompleted { radius: 1 })
            }),
            (SearchUpdateTrigger::RadiusTimeout { radius: 2 }, |v| {
                matches!(v, SearchUpdateTriggerFfi::RadiusTimeout { radius: 2 })
            }),
            (SearchUpdateTrigger::RadiusTruncated { radius: 1 }, |v| {
                matches!(v, SearchUpdateTriggerFfi::RadiusTruncated { radius: 1 })
            }),
            (SearchUpdateTrigger::RadiusStarted { radius: 255 }, |v| {
                matches!(v, SearchUpdateTriggerFfi::RadiusStarted { radius: 255 })
            }),
            (SearchUpdateTrigger::ResultsFound { radius: 255 }, |v| {
                matches!(v, SearchUpdateTriggerFfi::ResultsFound { radius: 255 })
            }),
            (SearchUpdateTrigger::RadiusCompleted { radius: 255 }, |v| {
                matches!(v, SearchUpdateTriggerFfi::RadiusCompleted { radius: 255 })
            }),
            (SearchUpdateTrigger::RadiusTimeout { radius: 255 }, |v| {
                matches!(v, SearchUpdateTriggerFfi::RadiusTimeout { radius: 255 })
            }),
            (SearchUpdateTrigger::RadiusTruncated { radius: 255 }, |v| {
                matches!(v, SearchUpdateTriggerFfi::RadiusTruncated { radius: 255 })
            }),
            (SearchUpdateTrigger::SearchCompleted, |v| {
                matches!(v, SearchUpdateTriggerFfi::SearchCompleted)
            }),
            (
                SearchUpdateTrigger::Error {
                    message: "relay directory fetch failed: fixture fetch failure".into(),
                },
                |v| matches!(v, SearchUpdateTriggerFfi::Error { message } if message == "relay directory fetch failed: fixture fetch failure"),
            ),
        ];
        for (index, (native, accepts)) in cases.into_iter().enumerate() {
            assert!(accepts(native.into()), "search progress case {index}");
        }
    }
}
