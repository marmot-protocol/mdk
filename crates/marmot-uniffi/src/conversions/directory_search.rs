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
/// `radius` is social distance from the searcher: 0 is the searcher, 1 a
/// direct follow. Render it as provenance ("via someone you follow").
///
/// `255` is the exception and means *off-graph*: this person came from a
/// configured fallback or a discovery provider rather than through anyone the user
/// knows. Present those as discovery, never as a connection -- they are not a
/// distance from the user at all.
#[derive(Clone, Debug, uniffi::Record)]
pub struct UserDirectorySearchResultFfi {
    pub account_id_hex: String,
    pub npub: String,
    pub radius: u8,
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
    /// Matches found by this step, pre-sorted within the batch. Ordering
    /// *across* graph updates is radius order; an optional discovery batch
    /// follows graph traversal and may contain results retaining graph
    /// provenance. A host rendering one flat list should re-sort the aggregate.
    pub new_results: Vec<UserDirectorySearchResultFfi>,
    /// Running total this search has emitted so far, including `new_results`.
    pub total_result_count: u32,
}

impl From<UserSearchUpdate> for UserSearchUpdateFfi {
    fn from(value: UserSearchUpdate) -> Self {
        Self {
            trigger: value.trigger.into(),
            new_results: value.new_results.into_iter().map(Into::into).collect(),
            total_result_count: saturating_u32(value.total_result_count),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_app::{
        MatchQuality, MatchedField, SearchUpdateTrigger, UserDirectorySearchResult,
        UserSearchUpdate,
    };

    #[test]
    fn a_results_update_carries_its_matches_and_typed_attribution() {
        let update = UserSearchUpdate {
            trigger: SearchUpdateTrigger::ResultsFound { radius: 1 },
            new_results: vec![UserDirectorySearchResult {
                account_id_hex: "aa".repeat(32),
                npub: "npub1example".to_owned(),
                radius: 1,
                matched_field: MatchedField::DisplayName,
                match_quality: MatchQuality::Prefix,
                provider_rank: Some(0.75),
                profile: None,
            }],
            total_result_count: 1,
        };

        let ffi = UserSearchUpdateFfi::from(update);

        assert!(matches!(
            ffi.trigger,
            SearchUpdateTriggerFfi::ResultsFound { radius: 1 }
        ));
        assert_eq!(ffi.total_result_count, 1);
        assert_eq!(ffi.new_results.len(), 1);
        assert_eq!(ffi.new_results[0].provider_rank, Some(0.75));
        assert!(matches!(
            ffi.new_results[0].matched_field,
            MatchedFieldFfi::DisplayName
        ));
        assert!(matches!(
            ffi.new_results[0].match_quality,
            MatchQualityFfi::Prefix
        ));
    }

    #[test]
    fn the_terminal_trigger_survives_conversion() {
        let ffi = UserSearchUpdateFfi::from(UserSearchUpdate {
            trigger: SearchUpdateTrigger::SearchCompleted,
            new_results: Vec::new(),
            total_result_count: 3,
        });

        assert!(matches!(
            ffi.trigger,
            SearchUpdateTriggerFfi::SearchCompleted
        ));
        assert_eq!(ffi.total_result_count, 3);
    }

    #[test]
    fn discovery_results_keep_a_distinct_trigger() {
        assert!(matches!(
            SearchUpdateTriggerFfi::from(SearchUpdateTrigger::DiscoveryResultsFound),
            SearchUpdateTriggerFfi::DiscoveryResultsFound
        ));
    }
}
