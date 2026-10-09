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
        #[doc = "NULL or a JSON string literal; decode once preserving embedded NULs."]
        json_opt_str identifier,
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

    #[derive(Default)]
    struct TestSecrets(std::sync::Mutex<std::collections::HashMap<String, String>>);

    impl marmot_uniffi::SecretStore for TestSecrets {
        fn has_secret_for_label(
            &self,
            label: String,
        ) -> Result<bool, marmot_uniffi::MarmotKitError> {
            Ok(self.0.lock().unwrap().contains_key(&label))
        }
        fn has_secret_for_account_id(
            &self,
            _: String,
        ) -> Result<bool, marmot_uniffi::MarmotKitError> {
            Ok(false)
        }
        fn write_secret(
            &self,
            label: String,
            _: String,
            secret: String,
        ) -> Result<(), marmot_uniffi::MarmotKitError> {
            self.0.lock().unwrap().insert(label, secret);
            Ok(())
        }
        fn load_secret(
            &self,
            label: String,
            _: String,
        ) -> Result<String, marmot_uniffi::MarmotKitError> {
            self.0.lock().unwrap().get(&label).cloned().ok_or_else(|| {
                marmot_uniffi::MarmotKitError::SecretNotFound {
                    details: "test credential missing".into(),
                }
            })
        }
        fn remove_secret(
            &self,
            label: String,
            _: String,
        ) -> Result<(), marmot_uniffi::MarmotKitError> {
            self.0.lock().unwrap().remove(&label);
            Ok(())
        }
    }

    #[test]
    fn public_event_naddr_identifiers_preserve_nuls_through_c_reads() {
        use nostr::nips::nip19::{Nip19Coordinate, ToBech32};
        use nostr::prelude::{Coordinate, Keys, Kind};
        use std::ffi::{CStr, CString};
        use std::sync::Arc;

        let root = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let kit = {
            let _enter = runtime.enter();
            marmot_uniffi::Marmot::new_with_secret_store(
                root.path().to_str().unwrap().to_owned(),
                vec!["wss://relay.example.org".into()],
                Arc::new(TestSecrets::default()),
            )
            .unwrap()
        };
        let keys = Keys::generate();
        let account = runtime
            .block_on(kit.begin_onboarding(
                keys.secret_key().to_bech32().unwrap(),
                marmot_uniffi::conversions::OnboardingOptionsFfi {
                    default_relays: vec!["wss://relay.example.org".into()],
                    discovery_relays: vec!["wss://index.example.org".into()],
                    inbox_relays: vec![],
                },
            ))
            .unwrap();
        let identifiers = ["a\0b", "ab"];
        let references: Vec<CString> = identifiers
            .iter()
            .map(|identifier| {
                CString::new(
                    Nip19Coordinate::new(
                        Coordinate::new(Kind::from(30023), keys.public_key())
                            .identifier(*identifier),
                        [],
                    )
                    .to_bech32()
                    .unwrap(),
                )
                .unwrap()
            })
            .collect();
        assert_ne!(references[0], references[1]);
        let borrowed: Vec<_> = references
            .iter()
            .map(|reference| reference.as_ptr())
            .collect();
        let account_ref = CString::new(account.account_id_hex).unwrap();
        let client = crate::MarmotClient {
            runtime,
            marmot: kit,
        };
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let mut reads = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                crate::commands::marmot_cached_public_event_previews(
                    &raw const client,
                    account_ref.as_ptr(),
                    borrowed.as_ptr(),
                    borrowed.len(),
                    &raw mut reads,
                )
            },
            crate::MarmotStatus::Ok
        );
        unsafe {
            assert_eq!((*reads).len, 2);
            for (index, identifier) in identifiers.iter().enumerate() {
                let read = &*(*reads).items.add(index);
                assert_eq!(read.state, MarmotPublicEventCacheState::Missing);
                assert_eq!(read.key.key_type, MarmotPublicEventCacheKeyType::Coordinate);
                let encoded = CStr::from_ptr(read.key.identifier).to_str().unwrap();
                assert_eq!(
                    serde_json::from_str::<String>(encoded).unwrap(),
                    *identifier
                );
            }
            marmot_public_event_cache_read_list_free(reads);
        }
        assert_eq!(audit::live_allocations(), before);
        client.block_on(client.marmot.shutdown_and_close()).unwrap();
    }

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
