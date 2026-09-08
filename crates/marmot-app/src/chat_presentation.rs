//! Shared selected chat presentation policy; no network access or client-specific formatting.
pub(crate) mod maintenance;
pub(crate) mod signals;
use crate::UserProfileMetadata;
use sha2::{Digest, Sha256};
use storage_sqlite::{
    ChatPresentationInput, ConversationPresentation, PresentationResolution, PresentationSource,
    PresentationText, SelectedAvatar,
};

/// Resolve already-cached evidence. Profile subjects must match the current peer.
/// Remote descriptors do not authorize a download; the media layer still owns dial safety,
/// including `reject_unsafe_group_avatar_contact_url` and validated-address pinning.
pub(crate) fn select_chat_presentation(
    input: &ChatPresentationInput,
    local_id: &str,
    profile: Option<(&str, &UserProfileMetadata)>,
) -> ConversationPresentation {
    let local_id = canonical_identity(local_id);
    let members: Option<Vec<_>> = input
        .members
        .iter()
        .map(|s| canonical_identity(s))
        .collect();
    let peer = match (&local_id, &members) {
        (Some(local), Some(members))
            if input.member_count == Some(2)
                && input.self_membership == storage_sqlite::SelfMembership::Member
                && members.len() == 2
                && members[0] != members[1]
                && members.contains(local) =>
        {
            members.iter().find(|id| *id != local).cloned()
        }
        _ => None,
    };
    let profile = profile
        .filter(|(id, _)| {
            canonical_identity(id)
                .as_ref()
                .is_some_and(|id| Some(id) == peer.as_ref())
        })
        .map(|(_, profile)| profile);
    let known_roster = input.member_count.is_some()
        && (input.member_count != Some(2)
            || members
                .as_ref()
                .is_some_and(|members| members.len() == 2 && members[0] != members[1]));
    let group_name = safe_name(&input.group_name);
    let fallback_source = if peer.is_some() {
        PresentationSource::PeerFallback
    } else if known_roster || group_name.is_some() {
        PresentationSource::GroupFallback
    } else {
        PresentationSource::UnknownFallback
    };
    let (title, title_source) = if let Some(name) = group_name {
        (PresentationText::Literal(name), PresentationSource::Group)
    } else if let Some(peer) = &peer {
        match profile.and_then(|p| {
            p.display_name
                .as_deref()
                .and_then(safe_name)
                .or_else(|| p.name.as_deref().and_then(safe_name))
        }) {
            Some(name) => (
                PresentationText::Literal(name),
                PresentationSource::PeerProfile,
            ),
            None => (
                PresentationText::Literal(crate::default_profile_pseudonym(peer)),
                PresentationSource::PeerFallback,
            ),
        }
    } else if known_roster {
        (
            PresentationText::UnnamedGroup {
                member_count: input.member_count,
            },
            PresentationSource::GroupFallback,
        )
    } else {
        (
            PresentationText::UnavailableConversation,
            PresentationSource::UnknownFallback,
        )
    };
    // Resetting an account store deliberately changes its cache namespace. Refetching is the
    // accepted cost of preventing old-store avatar reuse after identity/storage replacement.
    let key = |subject: &str, kind: &str, parts: &[&str]| {
        let mut digest = Sha256::new();
        for part in [
            b"mdk-chat-presentation-v1".as_slice(),
            input.source_version.store_epoch.as_slice(),
            local_id.as_deref().unwrap_or("").as_bytes(),
            input.group_id_hex.as_bytes(),
            subject.as_bytes(),
            kind.as_bytes(),
        ]
        .into_iter()
        .chain(parts.iter().map(|s| s.as_bytes()))
        {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        hex::encode(digest.finalize())
    };
    let (avatar, avatar_source) =
        if let Some(url) = input.avatar_url.as_deref().and_then(safe_image_url) {
            (
                SelectedAvatar::RemoteImage {
                    cache_key: key(&input.group_id_hex, "group-url", &[&url]),
                    url,
                },
                PresentationSource::Group,
            )
        } else if let Some(image) = input.avatar.as_ref().filter(|image| {
            valid_hex(&image.image_hash_hex, 32)
                && valid_hex(&image.image_key_hex, 32)
                && valid_hex(&image.image_nonce_hex, 12)
                && valid_hex(&image.image_upload_key_hex, 32)
        }) {
            (
                SelectedAvatar::EncryptedGroupImage {
                    image: image.clone(),
                    cache_key: key(
                        &input.group_id_hex,
                        "group-image",
                        &[
                            &image.image_hash_hex,
                            &image.image_key_hex,
                            &image.image_nonce_hex,
                            &image.image_upload_key_hex,
                            image.media_type.as_deref().unwrap_or(""),
                        ],
                    ),
                },
                PresentationSource::Group,
            )
        } else if let Some((peer, url)) = peer.as_deref().zip(
            profile
                .and_then(|p| p.picture.as_deref())
                .and_then(safe_image_url),
        ) {
            (
                SelectedAvatar::RemoteImage {
                    cache_key: key(peer, "peer-url", &[&url]),
                    url,
                },
                PresentationSource::PeerProfile,
            )
        } else {
            (
                SelectedAvatar::Placeholder {
                    stable_seed: key(
                        peer.as_deref().unwrap_or(&input.group_id_hex),
                        match fallback_source {
                            PresentationSource::PeerFallback => "person",
                            PresentationSource::GroupFallback => "group",
                            _ => "unknown",
                        },
                        &[],
                    ),
                    source: fallback_source,
                },
                fallback_source,
            )
        };
    let resolution = if matches!(
        title_source,
        PresentationSource::Group | PresentationSource::PeerProfile
    ) || matches!(
        avatar_source,
        PresentationSource::Group | PresentationSource::PeerProfile
    ) {
        PresentationResolution::Cached
    } else {
        PresentationResolution::Fallback
    };
    ConversationPresentation {
        title,
        avatar,
        title_source,
        avatar_source,
        peer_id: peer,
        resolution,
    }
}

fn canonical_identity(raw: &str) -> Option<String> {
    let raw = raw.trim();
    valid_hex(raw, 32).then(|| raw.to_ascii_lowercase())
}
fn valid_hex(raw: &str, bytes: usize) -> bool {
    raw.len() == bytes * 2 && raw.bytes().all(|b| b.is_ascii_hexdigit())
}
fn safe_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(4096)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}
fn safe_image_url(raw: &str) -> Option<String> {
    let normalized =
        cgka_traits::app_components::validate_and_normalize_group_avatar_url(raw).ok()?;
    // Both remote-image sources match the existing loader's contact/port policy, without DNS or I/O.
    crate::media::parse_profile_image_fetch_url(&normalized)
        .ok()
        .map(|url| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage_sqlite::{ChatListAvatar, ChatPresentationVersion};
    #[test]
    fn remote_images_use_the_same_usable_https_policy_for_group_and_peer() {
        for picture in [
            "http://example.com/avatar".to_owned(),
            "https://example.com/avatar#fragment".to_owned(),
            "https://example.com:8443/avatar".to_owned(),
            "https://user:pass@example.com/avatar".to_owned(),
            "https://10.0.0.5/avatar".to_owned(),
            "https://127.0.0.1/avatar".to_owned(),
            format!("https://example.com/{}", "a".repeat(2048)),
        ] {
            let profile = UserProfileMetadata {
                picture: Some(picture.clone()),
                ..Default::default()
            };
            assert!(matches!(
                select_chat_presentation(
                    &input(""),
                    &"aa".repeat(32),
                    Some((&"bb".repeat(32), &profile))
                )
                .avatar,
                SelectedAvatar::Placeholder { .. }
            ));
            let mut group_input = input("");
            group_input.avatar_url = Some(picture);
            assert!(matches!(
                select_chat_presentation(&group_input, &"aa".repeat(32), None).avatar,
                SelectedAvatar::Placeholder { .. }
            ));
        }
    }
    fn input(name: &str) -> ChatPresentationInput {
        ChatPresentationInput {
            group_id_hex: "11".repeat(16),
            row_epoch: vec![1; 16],
            source_version: ChatPresentationVersion {
                store_epoch: vec![0; 16],
                revision: 0,
            },
            group_name: name.into(),
            member_count: Some(2),
            self_membership: storage_sqlite::SelfMembership::Member,
            members: vec!["aa".repeat(32), "bb".repeat(32)],
            avatar_url: None,
            avatar: None,
        }
    }
    #[test]
    fn named_pair_uses_group_title_and_peer_avatar_independently() {
        let input = input("Our custom name");
        let profile = UserProfileMetadata {
            display_name: Some("Peer".into()),
            picture: Some("https://example.com/avatar.png".into()),
            ..Default::default()
        };
        let p =
            select_chat_presentation(&input, &"aa".repeat(32), Some((&"bb".repeat(32), &profile)));
        assert!(p.title == PresentationText::Literal("Our custom name".into()));
        assert_eq!(p.title_source, PresentationSource::Group);
        assert_eq!(p.avatar_source, PresentationSource::PeerProfile);
        assert!(matches!(p.avatar, SelectedAvatar::RemoteImage { .. }));
    }
    #[test]
    fn empty_profile_name_falls_through_and_wrong_identity_is_ignored() {
        let input = input("");
        let profile = UserProfileMetadata {
            display_name: Some(" \u{202e}\n".into()),
            name: Some(" Useful name ".into()),
            ..Default::default()
        };
        let p =
            select_chat_presentation(&input, &"aa".repeat(32), Some((&"bb".repeat(32), &profile)));
        assert!(p.title == PresentationText::Literal("Useful name".into()));
        let wrong =
            select_chat_presentation(&input, &"aa".repeat(32), Some((&"cc".repeat(32), &profile)));
        assert_eq!(wrong.title_source, PresentationSource::PeerFallback);
        assert!(
            wrong.title
                == PresentationText::Literal(crate::default_profile_pseudonym(&"bb".repeat(32)))
        );
    }
    #[test]
    fn roster_transition_clears_peer_and_keys_are_account_scoped() {
        let mut input = input("");
        let old = select_chat_presentation(&input, &"aa".repeat(32), None);
        input.members = vec!["aa".repeat(32), "cc".repeat(32)];
        let next = select_chat_presentation(&input, &"aa".repeat(32), None);
        assert!(old.avatar != next.avatar);
        input.member_count = Some(3);
        let group = select_chat_presentation(&input, &"aa".repeat(32), None);
        assert_eq!(group.peer_id, None);
        assert!(
            group.title
                == PresentationText::UnnamedGroup {
                    member_count: Some(3)
                }
        );
        input.member_count = None;
        assert!(
            select_chat_presentation(&input, &"aa".repeat(32), None).title
                == PresentationText::UnavailableConversation
        );
    }
    #[test]
    fn explicit_image_wins_and_profile_removal_returns_fallback() {
        let mut input = input("");
        input.avatar = Some(ChatListAvatar {
            image_hash_hex: "01".repeat(32),
            image_key_hex: "02".repeat(32),
            image_nonce_hex: "03".repeat(12),
            image_upload_key_hex: "04".repeat(32),
            media_type: Some("image/png".into()),
        });
        let profile = UserProfileMetadata {
            display_name: Some("Peer".into()),
            picture: Some("file:///private/image".into()),
            ..Default::default()
        };
        let p =
            select_chat_presentation(&input, &"aa".repeat(32), Some((&"bb".repeat(32), &profile)));
        assert_eq!(p.avatar_source, PresentationSource::Group);
        assert!(matches!(
            p.avatar,
            SelectedAvatar::EncryptedGroupImage { .. }
        ));
        input.avatar_url = Some("https://example.com/group.png".into());
        assert!(matches!(
            select_chat_presentation(&input, &"aa".repeat(32), None).avatar,
            SelectedAvatar::RemoteImage { .. }
        ));
        input.avatar_url = None;
        input.members = vec!["aa".repeat(32), "cc".repeat(32)];
        assert!(select_chat_presentation(&input, &"aa".repeat(32), None).avatar == p.avatar);
        input.members = vec!["aa".repeat(32), "bb".repeat(32)];
        input.avatar = None;
        let p = select_chat_presentation(
            &input,
            &"aa".repeat(32),
            Some((&"bb".repeat(32), &UserProfileMetadata::default())),
        );
        assert_eq!(p.title_source, PresentationSource::PeerFallback);
        assert!(matches!(p.avatar, SelectedAvatar::Placeholder { .. }));
        assert!(!format!("{p:?}").contains(&"bb".repeat(32)));
    }
    #[test]
    fn missing_roster_self_only_and_invalid_images_have_structured_fallbacks() {
        let mut input = input("");
        input.members.clear();
        assert!(
            select_chat_presentation(&input, &"aa".repeat(32), None).title
                == PresentationText::UnavailableConversation
        );
        input.member_count = Some(1);
        assert!(
            select_chat_presentation(&input, &"aa".repeat(32), None).title
                == PresentationText::UnnamedGroup {
                    member_count: Some(1)
                }
        );
        input.group_name = "Explicit".into();
        input.member_count = None;
        input.avatar_url = Some("file:///private/image".into());
        let selected = select_chat_presentation(&input, &"aa".repeat(32), None);
        assert_eq!(selected.title_source, PresentationSource::Group);
        assert!(matches!(
            selected.avatar,
            SelectedAvatar::Placeholder { .. }
        ));
    }
    #[test]
    fn avatar_cache_identity_is_isolated_and_stable_across_profile_versions() {
        let mut input = input("");
        let profile = UserProfileMetadata {
            picture: Some("https://example.com/avatar".into()),
            ..Default::default()
        };
        let select = |input: &ChatPresentationInput| {
            select_chat_presentation(input, &"aa".repeat(32), Some((&"bb".repeat(32), &profile)))
        };
        let first = select(&input);
        input.source_version.revision += 1;
        assert!(select(&input).avatar == first.avatar);
        input.source_version.store_epoch = vec![2; 16];
        assert!(select(&input).avatar != first.avatar);
        assert!(
            select(&input).avatar
                != select_chat_presentation(&input, &"bb".repeat(32), None).avatar
        );
    }
}
