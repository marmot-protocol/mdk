//! Additive selected-presentation mirrors. Existing chat-row layouts remain stable.
use super::chat_list::{MarmotChatListAvatar, MarmotChatListRow};
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, free_c_string, owned_c_string};
use marmot_uniffi::conversions::*;
use std::ffi::c_char;

c_enum! { MarmotPresentationSource from PresentationSourceFfi { Group, PeerProfile, PeerFallback, GroupFallback, UnknownFallback, } }
c_enum! { MarmotPresentationResolution from PresentationResolutionFfi { Cached, LastKnown, Fallback, } }
/// Typed text; hosts localize the fallback cases.
#[repr(C)]
pub enum MarmotPresentationText {
    Literal {
        text: *mut c_char,
    },
    UnnamedGroup {
        has_member_count: bool,
        member_count: u64,
    },
    UnavailableConversation,
}
impl From<PresentationTextFfi> for MarmotPresentationText {
    fn from(v: PresentationTextFfi) -> Self {
        match v {
            PresentationTextFfi::Literal { text } => Self::Literal {
                text: owned_c_string(text),
            },
            PresentationTextFfi::UnnamedGroup { member_count } => Self::UnnamedGroup {
                has_member_count: member_count.is_some(),
                member_count: member_count.unwrap_or_default(),
            },
            PresentationTextFfi::UnavailableConversation => Self::UnavailableConversation,
        }
    }
}
impl CFree for MarmotPresentationText {
    unsafe fn free_in_place(&mut self) {
        if let Self::Literal { text } = self {
            unsafe { free_c_string(*text) };
        }
    }
}
/// Descriptor only. Group image material remains owned by the containing result.
#[repr(C)]
pub enum MarmotSelectedAvatar {
    RemoteImage {
        url: *mut c_char,
        cache_key: *mut c_char,
    },
    EncryptedGroupImage {
        image: MarmotChatListAvatar,
        cache_key: *mut c_char,
    },
    Placeholder {
        stable_seed: *mut c_char,
        source: MarmotPresentationSource,
    },
}
impl From<SelectedAvatarFfi> for MarmotSelectedAvatar {
    fn from(v: SelectedAvatarFfi) -> Self {
        match v {
            SelectedAvatarFfi::RemoteImage { url, cache_key } => Self::RemoteImage {
                url: owned_c_string(url),
                cache_key: owned_c_string(cache_key),
            },
            SelectedAvatarFfi::EncryptedGroupImage { image, cache_key } => {
                Self::EncryptedGroupImage {
                    image: image.into(),
                    cache_key: owned_c_string(cache_key),
                }
            }
            SelectedAvatarFfi::Placeholder {
                stable_seed,
                source,
            } => Self::Placeholder {
                stable_seed: owned_c_string(stable_seed),
                source: source.into(),
            },
        }
    }
}
impl CFree for MarmotSelectedAvatar {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            match self {
                Self::RemoteImage { url, cache_key } => {
                    free_c_string(*url);
                    free_c_string(*cache_key);
                }
                Self::EncryptedGroupImage { image, cache_key } => {
                    image.free_in_place();
                    free_c_string(*cache_key);
                }
                Self::Placeholder { stable_seed, .. } => free_c_string(*stable_seed),
            }
        }
    }
}
c_mirror! { MarmotConversationPresentation from ConversationPresentationFfi {
    rec title: MarmotPresentationText,
    rec avatar: MarmotSelectedAvatar,
    copy title_source: MarmotPresentationSource,
    copy avatar_source: MarmotPresentationSource,
    opt_str peer_id,
    copy resolution: MarmotPresentationResolution,
} }
c_mirror! { MarmotPresentationVersion from PresentationVersionFfi {
    bytes account_store_epoch/account_store_epoch_len,
    copy revision: u64,
} }
c_mirror! { MarmotPresentedChatRow from PresentedChatRowFfi, free marmot_presented_chat_row_free {
    rec row: MarmotChatListRow,
    rec presentation: MarmotConversationPresentation,
} }
c_mirror! { MarmotPresentedChatListSnapshot from PresentedChatListSnapshotFfi, free marmot_presented_chat_list_snapshot_free {
    vec rows/rows_len: MarmotPresentedChatRow,
    rec presentation_version: MarmotPresentationVersion,
} }
c_mirror! { MarmotPresentedChatListUpdate from PresentedChatListUpdateFfi, free marmot_presented_chat_list_update_free {
    str subscription_generation,
    copy sequence: u64,
    rec snapshot: MarmotPresentedChatListSnapshot,
} }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};
    fn image() -> ChatListAvatarFfi {
        ChatListAvatarFfi {
            image_hash_hex: "hash".into(),
            image_key_hex: "secret".into(),
            image_nonce_hex: "nonce".into(),
            image_upload_key_hex: "upload-secret".into(),
            media_type: Some("image/png".into()),
        }
    }
    #[test]
    fn presented_results_deep_free_every_selected_variant() {
        let _guard = audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = audit::live_allocations();
        let variants = [
            (
                PresentationTextFfi::Literal {
                    text: "Name".into(),
                },
                SelectedAvatarFfi::EncryptedGroupImage {
                    image: image(),
                    cache_key: "encrypted-cache".into(),
                },
            ),
            (
                PresentationTextFfi::UnnamedGroup {
                    member_count: Some(3),
                },
                SelectedAvatarFfi::RemoteImage {
                    url: "https://example.org/avatar".into(),
                    cache_key: "remote-cache".into(),
                },
            ),
            (
                PresentationTextFfi::UnavailableConversation,
                SelectedAvatarFfi::Placeholder {
                    stable_seed: "seed".into(),
                    source: PresentationSourceFfi::UnknownFallback,
                },
            ),
        ];
        for (title, avatar) in variants {
            let presentation = ConversationPresentationFfi {
                title,
                avatar,
                title_source: PresentationSourceFfi::Group,
                avatar_source: PresentationSourceFfi::Group,
                peer_id: Some("peer".into()),
                resolution: PresentationResolutionFfi::LastKnown,
            };
            let row = row();
            let update = PresentedChatListUpdateFfi {
                subscription_generation: "generation".into(),
                sequence: 3,
                snapshot: PresentedChatListSnapshotFfi {
                    rows: vec![PresentedChatRowFfi { row, presentation }],
                    presentation_version: PresentationVersionFfi {
                        account_store_epoch: vec![1; 16],
                        revision: 2,
                    },
                },
            };
            let mirror: MarmotPresentedChatListUpdate = update.into();
            assert_eq!(mirror.sequence, 3);
            assert_eq!(mirror.snapshot.rows_len, 1);
            assert_eq!(
                mirror.snapshot.presentation_version.account_store_epoch_len,
                16
            );
            unsafe {
                marmot_presented_chat_list_update_free(boxed(mirror));
            }
        }
        unsafe {
            marmot_presented_chat_list_update_free(std::ptr::null_mut());
            marmot_presented_chat_row_free(std::ptr::null_mut());
            marmot_presented_chat_list_snapshot_free(std::ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(audit::live_allocations(), before);
    }
    fn row() -> ChatListRowFfi {
        ChatListRowFfi {
            group_id_hex: "fixture".into(),
            pinned: false,
            pinned_position: None,
            archived: false,
            pending_confirmation: false,
            lifecycle_state: GroupLifecycleStateFfi::Stable,
            disbanding: false,
            disband_request: None,
            title: "fixture".into(),
            group_name: "fixture".into(),
            avatar_url: None,
            avatar: Some(image()),
            last_message: None,
            unread_count: 0,
            has_unread: false,
            manually_marked_unread: false,
            unread_mention_count: 0,
            unread_mention: false,
            first_unread_message_id_hex: None,
            last_read_message_id_hex: None,
            last_read_timeline_at: None,
            conversation_created_at: 0,
            activity_sort_at: 0,
            updated_at: 0,
            self_membership: SelfMembershipFfi::Member,
            conversation_kind: ChatConversationKindFfi::Group,
            muted: false,
            muted_until_ms: None,
            leave_request_pending: false,
            leave_requested_at_ms: None,
        }
    }
}
