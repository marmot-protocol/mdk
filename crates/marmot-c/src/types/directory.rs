//! C mirrors of the identity-directory conversions.

use marmot_uniffi::conversions::{
    CachedIdentityProjectionFfi, MatchQualityFfi, MatchedFieldFfi, SearchUpdateTriggerFfi,
    UserDirectorySearchResultFfi, UserSearchUpdateFfi,
};

use super::account::MarmotUserProfileMetadata;
use crate::macros::{c_enum, c_mirror};
use crate::memory::CFree;

c_mirror! {
    /// What the local directory cache knows about one requested id.
    /// Every field but `requested_id` is nullable: an id the cache has
    /// never seen still gets a row, so results line up with the request.
    MarmotCachedIdentityProjection from CachedIdentityProjectionFfi,
    free marmot_cached_identity_projection_free,
    list(MarmotCachedIdentityProjectionList, marmot_cached_identity_projection_list_free) {
        /// The id as the caller wrote it (`npub` or hex).
        str requested_id,
        opt_str account_id_hex,
        opt_rec profile: MarmotUserProfileMetadata,
        opt_str local_label,
        opt_str resolved_name,
    }
}

c_enum! {
    /// How closely a result matched the query.
    MarmotMatchQuality from MatchQualityFfi {
        Exact,
        Prefix,
        Contains,
    }
}

c_enum! {
    /// Which profile field the query matched.
    MarmotMatchedField from MatchedFieldFfi {
        Name,
        Nip05,
        DisplayName,
        About,
        Npub,
        Pubkey,
    }
}

c_mirror! {
    /// One search hit, with typed attribution for why it matched.
    MarmotUserDirectorySearchResult from UserDirectorySearchResultFfi,
    list(MarmotUserDirectorySearchResultList, marmot_user_directory_search_result_list_free) {
        str account_id_hex,
        str npub,
        /// Social distance from the searching account.
        copy radius: u8,
        copy is_followed_by_searcher: bool,
        copy matched_field: MarmotMatchedField,
        copy match_quality: MarmotMatchQuality,
        opt_copy has_provider_rank/provider_rank: f64,
        opt_rec profile: MarmotUserProfileMetadata,
    }
}

/// Why a search update fired.
#[repr(C)]
pub enum MarmotSearchUpdateTrigger {
    RadiusStarted {
        radius: u8,
    },
    ResultsFound {
        radius: u8,
    },
    DiscoveryResultsFound,
    RadiusCompleted {
        radius: u8,
    },
    RadiusTimeout {
        radius: u8,
    },
    RadiusTruncated {
        radius: u8,
    },
    /// Terminal: the traversal is finished and the stream will close.
    SearchCompleted,
    Error {
        message: *mut ::std::ffi::c_char,
    },
    CachedResultsFound,
}

impl From<SearchUpdateTriggerFfi> for MarmotSearchUpdateTrigger {
    fn from(value: SearchUpdateTriggerFfi) -> Self {
        match value {
            SearchUpdateTriggerFfi::RadiusStarted { radius } => Self::RadiusStarted { radius },
            SearchUpdateTriggerFfi::ResultsFound { radius } => Self::ResultsFound { radius },
            SearchUpdateTriggerFfi::DiscoveryResultsFound => Self::DiscoveryResultsFound,
            SearchUpdateTriggerFfi::CachedResultsFound => Self::CachedResultsFound,
            SearchUpdateTriggerFfi::RadiusCompleted { radius } => Self::RadiusCompleted { radius },
            SearchUpdateTriggerFfi::RadiusTimeout { radius } => Self::RadiusTimeout { radius },
            SearchUpdateTriggerFfi::RadiusTruncated { radius } => Self::RadiusTruncated { radius },
            SearchUpdateTriggerFfi::SearchCompleted => Self::SearchCompleted,
            SearchUpdateTriggerFfi::Error { message } => Self::Error {
                message: crate::memory::owned_c_string(message),
            },
        }
    }
}

impl CFree for MarmotSearchUpdateTrigger {
    unsafe fn free_in_place(&mut self) {
        if let Self::Error { message } = self {
            unsafe { crate::memory::free_c_string(*message) };
        }
    }
}

c_mirror! {
    /// One step of a running user search. Free with
    /// `marmot_user_search_update_free`.
    MarmotUserSearchUpdate from UserSearchUpdateFfi,
    free marmot_user_search_update_free {
        rec trigger: MarmotSearchUpdateTrigger,
        /// Hits discovered since the previous update, not the full set.
        vec new_results/new_results_len: MarmotUserDirectorySearchResult,
        vec updated_results/updated_results_len: MarmotUserDirectorySearchResult,
        copy total_result_count: u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_replacements_preserve_follow_attribution_and_free_all_rows() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        let result = UserDirectorySearchResultFfi {
            account_id_hex: "11".repeat(32),
            npub: "npub1test".into(),
            radius: 1,
            is_followed_by_searcher: true,
            matched_field: MatchedFieldFfi::Name,
            match_quality: MatchQualityFfi::Exact,
            provider_rank: None,
            profile: Some(marmot_uniffi::conversions::UserProfileMetadataFfi {
                name: Some("needle".into()),
                ..Default::default()
            }),
        };
        let mut update = MarmotUserSearchUpdate::from(UserSearchUpdateFfi {
            trigger: SearchUpdateTriggerFfi::CachedResultsFound,
            new_results: vec![result.clone()],
            updated_results: vec![result],
            total_result_count: 1,
        });
        assert_eq!(update.new_results_len, 1);
        assert_eq!(update.updated_results_len, 1);
        unsafe {
            assert!((*update.updated_results).is_followed_by_searcher);
            update.free_in_place();
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }
}
