//! C ownership mirrors for verified public event cache reads.
use super::account::MarmotUserProfileMetadata;
use crate::macros::{c_enum, c_mirror};
use marmot_uniffi::{
    PublicEventCacheKeyFfi, PublicEventCacheKeyTypeFfi, PublicEventCacheReadFfi,
    PublicEventCacheStateFfi, PublicEventDeletionFfi, PublicEventPreviewFfi,
};

c_enum! {
    /// Which canonical identity a `MarmotPublicEventCacheKey` carries.
    MarmotPublicEventCacheKeyType from PublicEventCacheKeyTypeFfi {
        /// `event_id_hex` is non-NULL; the coordinate fields are NULL/unset.
        EventId,
        /// `author_pubkey_hex`, `kind` and `identifier` are set; `event_id_hex` is NULL.
        Coordinate,
    }
}

c_enum! {
    /// Local state of one public event reference.
    MarmotPublicEventCacheState from PublicEventCacheStateFfi {
        /// `preview` is non-NULL.
        Present,
        /// `deletion` is non-NULL: authenticated NIP-09 evidence.
        AuthoritativeDeleted,
        /// Nothing is known locally; not durable negative truth.
        Missing,
        /// Account lifecycle work is in progress; retry. Never a miss.
        Busy,
    }
}

c_mirror! {
    /// Canonical cache identity; relay hints never take part in it.
    MarmotPublicEventCacheKey from PublicEventCacheKeyFfi {
        copy key_type: MarmotPublicEventCacheKeyType,
        opt_str event_id_hex,
        opt_str author_pubkey_hex,
        opt_copy has_kind/kind: u32,
        opt_str identifier,
    }
}

c_mirror! {
    /// Signed event JSON plus freshness and optional account-scoped cached author metadata.
    MarmotPublicEventPreview from PublicEventPreviewFfi {
        str event_json,
        copy received_at: u64,
        copy refresh_recommended: bool,
        opt_rec author_profile: MarmotUserProfileMetadata,
        copy projection_version: u32,
    }
}

c_mirror! {
    /// The author's signed NIP-09 deletion request for the referenced event.
    MarmotPublicEventDeletion from PublicEventDeletionFfi {
        str deletion_event_json,
        copy received_at: u64,
        copy projection_version: u32,
    }
}

c_mirror! {
    /// One result per requested reference. `preview` is non-NULL exactly for
    /// `Present` and `deletion` exactly for `AuthoritativeDeleted`.
    MarmotPublicEventCacheRead from PublicEventCacheReadFfi,
    free marmot_public_event_cache_read_free,
    list(MarmotPublicEventCacheReadList, marmot_public_event_cache_read_list_free) {
        rec key: MarmotPublicEventCacheKey,
        copy state: MarmotPublicEventCacheState,
        opt_rec preview: MarmotPublicEventPreview,
        opt_rec deletion: MarmotPublicEventDeletion,
    }
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};
    use marmot_uniffi::conversions::UserProfileMetadataFfi;

    fn key(event_id: Option<&str>) -> PublicEventCacheKeyFfi {
        match event_id {
            Some(id) => PublicEventCacheKeyFfi {
                key_type: PublicEventCacheKeyTypeFfi::EventId,
                event_id_hex: Some(id.to_owned()),
                author_pubkey_hex: None,
                kind: None,
                identifier: None,
            },
            None => PublicEventCacheKeyFfi {
                key_type: PublicEventCacheKeyTypeFfi::Coordinate,
                event_id_hex: None,
                author_pubkey_hex: Some("ab".repeat(32)),
                kind: Some(30023),
                identifier: Some("entry".to_owned()),
            },
        }
    }

    #[test]
    fn public_event_cache_reads_deep_free() {
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let reads = vec![
            PublicEventCacheReadFfi {
                key: key(Some(&"cd".repeat(32))),
                state: PublicEventCacheStateFfi::Present,
                preview: Some(PublicEventPreviewFfi {
                    event_json: "{}".to_owned(),
                    received_at: 7,
                    refresh_recommended: true,
                    author_profile: Some(UserProfileMetadataFfi {
                        name: Some("alice".to_owned()),
                        ..UserProfileMetadataFfi::default()
                    }),
                    projection_version: 1,
                }),
                deletion: None,
            },
            PublicEventCacheReadFfi {
                key: key(None),
                state: PublicEventCacheStateFfi::AuthoritativeDeleted,
                preview: None,
                deletion: Some(PublicEventDeletionFfi {
                    deletion_event_json: "{}".to_owned(),
                    received_at: 8,
                    projection_version: 1,
                }),
            },
            PublicEventCacheReadFfi {
                key: key(None),
                state: PublicEventCacheStateFfi::Busy,
                preview: None,
                deletion: None,
            },
        ];
        let list = boxed(MarmotPublicEventCacheReadList::from(reads.clone()));
        let single = boxed(MarmotPublicEventCacheRead::from(reads[1].clone()));
        unsafe {
            assert_eq!((*list).len, 3);
            let first = &*(*list).items;
            assert_eq!(first.state, MarmotPublicEventCacheState::Present);
            assert_eq!(first.key.key_type, MarmotPublicEventCacheKeyType::EventId);
            assert!(!first.key.has_kind);
            assert!(!first.preview.is_null() && first.deletion.is_null());
            assert_eq!((*first.preview).projection_version, 1);
            assert!(!(*first.preview).author_profile.is_null());
            let second = &*(*list).items.add(1);
            assert!(second.key.has_kind && second.key.kind == 30023);
            assert!(second.preview.is_null() && !second.deletion.is_null());
            let third = &*(*list).items.add(2);
            assert_eq!(third.state, MarmotPublicEventCacheState::Busy);
            assert!(third.preview.is_null() && third.deletion.is_null());
            assert_eq!(
                (*single).state,
                MarmotPublicEventCacheState::AuthoritativeDeleted
            );
            marmot_public_event_cache_read_list_free(list);
            marmot_public_event_cache_read_free(single);
            marmot_public_event_cache_read_list_free(std::ptr::null_mut());
            marmot_public_event_cache_read_free(std::ptr::null_mut());
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
