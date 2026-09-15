use super::{ConversationAuthority, ConversationCapabilities};
use crate::chat_presentation::{canonical_identity, safe_image_url, safe_name};
use crate::{
    AppError, AppGroupLifecycleState, ConversationPresentation, MarmotApp, SelectedAvatar,
};
use std::collections::{BTreeMap, BTreeSet};
pub use storage_sqlite::ConversationPresentationPage;
use storage_sqlite::{ChatPresentationInput, TimelineMessageRecord};

pub const MAX_CONVERSATION_TAG_SCAN: usize = 256;
pub const MAX_CONVERSATION_MENTIONS: usize = 8;
pub const MAX_CONVERSATION_REACTION_KINDS: usize = 8;
pub const MAX_CONVERSATION_REACTOR_PREVIEWS: usize = 2;
pub const MAX_CONVERSATION_IDENTITIES: usize = crate::MAX_TIMELINE_LIMIT
    * (4 + 2 * MAX_CONVERSATION_MENTIONS
        + MAX_CONVERSATION_REACTION_KINDS * MAX_CONVERSATION_REACTOR_PREVIEWS)
    + 1;
/// Conservative serialized upper bound implied by field/collection limits;
/// verified in tests, without encoding the screen on every read/refresh.
pub const MAX_CONVERSATION_PRESENTATION_BYTES: usize = 64 * 1024 * 1024;
const MAX_IMAGE_MEDIA_TYPE_BYTES: usize = 128;
const MAX_REFERENCE_BYTES: usize = 1024;
const MAX_NAME_BYTES: usize = 256;

/// Scalars from the same worker capture as the selected account/group input.
/// M4 owns capture and revisions. Neither header construction nor identity
/// hydration loads a roster or decides command authority from cached profiles.
#[derive(Clone, Copy, Debug)]
pub struct ConversationHeaderState {
    pub authority: ConversationAuthority,
    pub archived: bool,
    pub epoch: Option<u64>,
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ConversationHeader {
    pub selected: ConversationPresentation,
    pub member_count: Option<u64>,
    pub archived: bool,
    pub epoch: Option<u64>,
    pub lifecycle: AppGroupLifecycleState,
    pub disbanding: bool,
    pub unrecoverable: bool,
    pub capabilities: ConversationCapabilities,
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ConversationIdentity {
    pub account_id_hex: String,
    pub display_name: String,
    pub avatar: SelectedAvatar,
    pub has_cached_profile: bool,
}

/// `None` means unavailable/malformed identity, not an invitation to look it up.
/// Every `Some` reference in this projection has an entry in `identities`.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ConversationMessageReferences {
    pub message_id_hex: String,
    pub sender: Option<String>,
    pub reply_author: Option<String>,
    pub mentions: Vec<String>,
    pub mentions_truncated: bool,
    pub reply_mentions: Vec<String>,
    pub reply_mentions_truncated: bool,
    /// Only backed by the stored synthesized-event origin, never arbitrary
    /// kind-1210 JSON. Invalidation remains on the accompanying timeline row.
    pub system: Option<ConversationSystemReferences>,
    pub reactions: ConversationReactions,
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ConversationSystemReferences {
    pub system_type: String,
    pub actor: Option<String>,
    pub subject: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ConversationReaction {
    pub emoji: String,
    pub count: usize,
    pub reactors: Vec<String>,
}

#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ConversationReactions {
    pub total_count: usize,
    pub total_kinds: usize,
    pub items: Vec<ConversationReaction>,
    pub omitted_kinds: usize,
}

/// Presentation sidecar to the retained timeline, not a second transcript.
/// Only these explicit references request resolved identity rendering. Raw
/// tags/content remain available through the existing narrow timeline API.
/// Ancillary lists report truncation; aggregate reaction counts stay exact.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ConversationWindowPresentation {
    pub header: ConversationHeader,
    pub messages: Vec<ConversationMessageReferences>,
    pub identities: BTreeMap<String, ConversationIdentity>,
}

impl std::fmt::Debug for ConversationWindowPresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationWindowPresentation")
            .field("messages", &self.messages.len())
            .field("identities", &self.identities.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConversationPresentationError {
    #[error("conversation presentation exceeds its bounded input or output budget")]
    LimitExceeded,
    #[error("conversation presentation inputs belong to different groups")]
    GroupMismatch,
    #[error("conversation input belongs to a different account store")]
    StoreMismatch,
    #[error("conversation header membership inputs disagree")]
    MembershipMismatch,
    #[error(transparent)]
    App(#[from] AppError),
}

impl ConversationWindowPresentation {
    /// Reuse the existing profile-commit signal. Lag means refresh all; M4
    /// owns subscription-before-read coordination and retry obligations.
    pub fn depends_on_profile(&self, account_id_hex: &str) -> bool {
        canonical_identity(account_id_hex).is_some_and(|id| self.identities.contains_key(&id))
    }
}

impl MarmotApp {
    /// Build shared presentation from a captured header input and bounded
    /// timeline page using local caches only. The account worker must capture
    /// `input`, `state`, `page` and provenance in its account read boundary;
    /// shared directory enrichment is a separate consistency domain.
    ///
    /// This foundation does not open a live window. M4 supplies the combined
    /// snapshot/stream contract. A refresh calls this again, so former members
    /// and profile-only changes resolve without roster membership or a network
    /// request. Narrow APIs remain available for expanded reactions/details.
    pub fn conversation_window_presentation(
        &self,
        label: &str,
        input: &ChatPresentationInput,
        state: ConversationHeaderState,
        prepared: &ConversationPresentationPage,
    ) -> Result<ConversationWindowPresentation, ConversationPresentationError> {
        let page = prepared.page();
        if page.messages.len() > crate::MAX_TIMELINE_LIMIT
            || input
                .avatar
                .as_ref()
                .and_then(|a| a.media_type.as_ref())
                .is_some_and(|value| value.len() > MAX_IMAGE_MEDIA_TYPE_BYTES)
        {
            return Err(ConversationPresentationError::LimitExceeded);
        }
        if input.self_membership != state.authority.self_membership {
            return Err(ConversationPresentationError::MembershipMismatch);
        }
        let account = self.account_home().account(label).map_err(AppError::from)?;
        let storage = self.account_storage(label)?;
        if prepared.store_epoch() != input.source_version.store_epoch {
            return Err(ConversationPresentationError::StoreMismatch);
        }
        if storage
            .chat_presentation_version()
            .map_err(AppError::from)?
            .store_epoch
            != input.source_version.store_epoch
        {
            return Err(ConversationPresentationError::StoreMismatch);
        }
        let mut ids = BTreeSet::new();
        let peer = crate::chat_presentation::presentation_peer(input, &account.account_id_hex);
        if let Some(peer) = &peer {
            ids.insert(peer.clone());
        }
        let mut messages = Vec::with_capacity(page.messages.len());
        for (index, message) in page.messages.iter().enumerate() {
            if message.group_id_hex != input.group_id_hex {
                return Err(ConversationPresentationError::GroupMismatch);
            }
            if message.message_id_hex.len() > MAX_REFERENCE_BYTES {
                return Err(ConversationPresentationError::LimitExceeded);
            }
            let references = message_references(
                message,
                prepared.authenticated_system_content(index),
                &mut ids,
            );
            messages.push(references);
        }
        if ids.len() > MAX_CONVERSATION_IDENTITIES {
            return Err(ConversationPresentationError::LimitExceeded);
        }
        let requested: Vec<_> = ids.into_iter().collect();
        let mut identities = BTreeMap::new();
        let mut peer_profile = None;
        for chunk in requested.chunks(crate::MAX_CACHED_IDENTITY_PAGE_SIZE) {
            for cached in self.cached_identity_projections_for_account_ids(chunk)? {
                let Some(id) = cached.account_id_hex else {
                    continue;
                };
                if peer.as_ref() == Some(&id) {
                    peer_profile = cached.profile.clone();
                }
                identities.insert(
                    id.clone(),
                    identity(
                        &id,
                        cached.profile.as_ref(),
                        cached.local_label.as_deref(),
                        input,
                        &account.account_id_hex,
                    ),
                );
            }
        }
        // Valid canonical identifiers always have a stable fallback, even if a
        // cache adapter cannot represent one. Dictionary completeness is total.
        for id in requested {
            identities
                .entry(id.clone())
                .or_insert_with(|| identity(&id, None, None, input, &account.account_id_hex));
        }
        let selected = crate::chat_presentation::select_chat_presentation(
            input,
            &account.account_id_hex,
            peer.as_deref().zip(peer_profile.as_ref()),
        );
        let result = ConversationWindowPresentation {
            header: ConversationHeader {
                selected,
                member_count: input.member_count,
                archived: state.archived,
                epoch: state.epoch,
                lifecycle: state.authority.lifecycle,
                disbanding: state.authority.disbanding,
                unrecoverable: state.authority.unrecoverable
                    || state.authority.lifecycle == AppGroupLifecycleState::Unrecoverable,
                capabilities: state.authority.capabilities(),
            },
            messages,
            identities,
        };
        Ok(result)
    }
}

fn bounded_text(text: &str, limit: usize) -> String {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn identity(
    id: &str,
    profile: Option<&crate::UserProfileMetadata>,
    local_label: Option<&str>,
    input: &ChatPresentationInput,
    local_id: &str,
) -> ConversationIdentity {
    let name = profile.and_then(|p| {
        p.display_name
            .as_deref()
            .and_then(safe_name)
            .or_else(|| p.name.as_deref().and_then(safe_name))
    });
    let display_name = name
        .or_else(|| local_label.and_then(safe_name))
        .unwrap_or_else(|| crate::profile_pseudonyms::default_profile_pseudonym(id));
    let avatar = profile
        .and_then(|p| p.picture.as_deref())
        .and_then(safe_image_url)
        .map(|url| SelectedAvatar::RemoteImage {
            cache_key: crate::chat_presentation::presentation_cache_key(
                input,
                local_id,
                id,
                "peer-url",
                &[&url],
            ),
            url,
        })
        .unwrap_or_else(|| SelectedAvatar::Placeholder {
            stable_seed: crate::chat_presentation::presentation_cache_key(
                input,
                local_id,
                id,
                "person",
                &[],
            ),
            source: crate::PresentationSource::PeerFallback,
        });
    ConversationIdentity {
        account_id_hex: id.to_owned(),
        display_name: bounded_text(&display_name, MAX_NAME_BYTES),
        avatar,
        has_cached_profile: profile.is_some(),
    }
}

fn reference(raw: &str, ids: &mut BTreeSet<String>) -> Option<String> {
    let id = canonical_identity(raw)?;
    ids.insert(id.clone());
    Some(id)
}

fn mentions(
    kind: u64,
    plaintext: &str,
    tags: &[Vec<String>],
    ids: &mut BTreeSet<String>,
) -> (Vec<String>, bool) {
    if kind != cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT {
        return (Vec::new(), false);
    }
    let mut found = BTreeSet::new();
    // Inline parsing reuses the same bounded Markdown/NIP-27 parser as sends
    // and unread classification. Never interpret a raw hex substring as a mention.
    for id in crate::messages::inline_mention_pubkey_hexes(plaintext)
        .into_iter()
        .chain(
            tags.iter()
                .take(MAX_CONVERSATION_TAG_SCAN)
                .filter(|t| t.first().is_some_and(|v| v == "p"))
                .filter_map(|t| t.get(1))
                .filter(|v| v.len() <= MAX_REFERENCE_BYTES)
                .filter_map(|v| crate::messages::mention_pubkey_hex(v)),
        )
    {
        found.insert(id);
        if found.len() > MAX_CONVERSATION_MENTIONS {
            break;
        }
    }
    let truncated = found.len() > MAX_CONVERSATION_MENTIONS
        || plaintext.len() > crate::messages::MAX_MARKDOWN_MENTION_SCAN_BYTES
        || tags.len() > MAX_CONVERSATION_TAG_SCAN;
    let found: Vec<_> = found.into_iter().take(MAX_CONVERSATION_MENTIONS).collect();
    ids.extend(found.iter().cloned());
    (found, truncated)
}

fn message_references(
    message: &TimelineMessageRecord,
    trusted: Option<&str>,
    ids: &mut BTreeSet<String>,
) -> ConversationMessageReferences {
    let sender = reference(&message.sender, ids);
    let reply_author = message
        .reply_preview
        .as_ref()
        .and_then(|p| reference(&p.sender, ids));
    let (mentions, mentions_truncated) =
        mentions(message.kind, &message.plaintext, &message.tags, ids);
    let (reply_mentions, reply_mentions_truncated) = message
        .reply_preview
        .as_ref()
        .map(|p| self::mentions(p.kind, &p.plaintext, &[], ids))
        .unwrap_or_default();
    let system = trusted
        .and_then(|text| crate::group_system_event_from_message(message.kind, text))
        .map(|event| ConversationSystemReferences {
            system_type: bounded_text(&event.system_type, MAX_NAME_BYTES),
            actor: event
                .actor_account_id_hex
                .as_deref()
                .and_then(|id| reference(id, ids)),
            subject: event
                .subject_account_id_hex
                .as_deref()
                .and_then(|id| reference(id, ids)),
        });
    let mut reactions = ConversationReactions {
        total_kinds: message.reactions.by_emoji.len(),
        ..Default::default()
    };
    // Match the existing native order: most-used first, then emoji. Keep only
    // a fixed-size selection of borrowed entries, not a roster-sized sort.
    let mut visible: Vec<(&String, &Vec<String>)> = Vec::new();
    for (emoji, reactors) in &message.reactions.by_emoji {
        reactions.total_count = reactions.total_count.saturating_add(reactors.len());
        if emoji.len() > MAX_NAME_BYTES {
            continue;
        }
        let position = visible.partition_point(|(key, values)| {
            values.len() > reactors.len() || (values.len() == reactors.len() && *key < emoji)
        });
        if position < MAX_CONVERSATION_REACTION_KINDS {
            visible.insert(position, (emoji, reactors));
            visible.truncate(MAX_CONVERSATION_REACTION_KINDS);
        }
    }
    for (emoji, reactors) in visible {
        let previews = reactors
            .iter()
            .take(MAX_CONVERSATION_REACTOR_PREVIEWS)
            .filter_map(|id| reference(id, ids))
            .collect();
        reactions.items.push(ConversationReaction {
            emoji: emoji.clone(),
            count: reactors.len(),
            reactors: previews,
        });
    }
    reactions.omitted_kinds = reactions.total_kinds - reactions.items.len();
    ConversationMessageReferences {
        message_id_hex: message.message_id_hex.clone(),
        sender,
        reply_author,
        mentions,
        mentions_truncated,
        reply_mentions,
        reply_mentions_truncated,
        system,
        reactions,
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn conversation_field_limits_bound_escaped_output_without_runtime_encoding() {
        let id = "a".repeat(64);
        // Quotes maximize JSON expansion for sanitized names and normalized
        // URLs (neither contains ASCII controls). This synthetic URL is a
        // conservative byte bound, not a valid contact descriptor.
        let avatar = SelectedAvatar::RemoteImage {
            url: "\"".repeat(cgka_traits::app_components::GROUP_AVATAR_URL_MAX_LEN),
            cache_key: id.clone(),
        };
        let identity = ConversationIdentity {
            account_id_hex: id.clone(),
            display_name: "\"".repeat(MAX_NAME_BYTES),
            avatar: avatar.clone(),
            has_cached_profile: false,
        };
        let row = ConversationMessageReferences {
            message_id_hex: "\u{0000}".repeat(MAX_REFERENCE_BYTES),
            sender: Some(id.clone()),
            reply_author: Some(id.clone()),
            mentions: vec![id.clone(); MAX_CONVERSATION_MENTIONS],
            mentions_truncated: false,
            reply_mentions: vec![id.clone(); MAX_CONVERSATION_MENTIONS],
            reply_mentions_truncated: false,
            system: Some(ConversationSystemReferences {
                system_type: "\u{0000}".repeat(MAX_NAME_BYTES),
                actor: Some(id.clone()),
                subject: Some(id.clone()),
            }),
            reactions: ConversationReactions {
                total_count: usize::MAX,
                total_kinds: usize::MAX,
                omitted_kinds: usize::MAX,
                items: vec![
                    ConversationReaction {
                        emoji: "\u{0000}".repeat(MAX_NAME_BYTES),
                        count: usize::MAX,
                        reactors: vec![id.clone(); MAX_CONVERSATION_REACTOR_PREVIEWS],
                    };
                    MAX_CONVERSATION_REACTION_KINDS
                ],
            },
        };
        let authority = ConversationAuthority {
            is_member: true,
            self_membership: crate::SelfMembership::Member,
            is_admin: true,
            admin_count: 1,
            pending_confirmation: true,
            leave_request_pending: false,
            lifecycle: AppGroupLifecycleState::Stable,
            unrecoverable: false,
            disbanding: false,
            disbanding_enabled: false,
            has_disbanding_blockers: false,
        };
        let header = ConversationHeader {
            selected: ConversationPresentation {
                // safe_name takes <=4096 Unicode scalars (<=16384 UTF-8
                // bytes), with <=2x escaping after stripping controls.
                title: crate::PresentationText::Literal("\"".repeat(4096 * 4)),
                avatar,
                title_source: crate::PresentationSource::UnknownFallback,
                avatar_source: crate::PresentationSource::UnknownFallback,
                peer_id: Some(id.clone()),
                resolution: crate::PresentationResolution::Fallback,
            },
            member_count: Some(u64::MAX),
            archived: false,
            epoch: Some(u64::MAX),
            lifecycle: AppGroupLifecycleState::Unrecoverable,
            disbanding: false,
            unrecoverable: false,
            capabilities: authority.capabilities(),
        };
        let identity_bytes = serde_json::to_vec(&identity).unwrap().len() + id.len() + 4;
        let row_bytes = serde_json::to_vec(&row).unwrap().len() + 1;
        // Fixed slack covers outer field names and enum spelling differences.
        let bound = identity_bytes * MAX_CONVERSATION_IDENTITIES
            + row_bytes * crate::MAX_TIMELINE_LIMIT
            + serde_json::to_vec(&header).unwrap().len()
            + 1024;
        assert!(bound < MAX_CONVERSATION_PRESENTATION_BYTES, "{bound}");
        // The other header avatar variant is smaller, even with max escaping
        // in its separately capped media type.
        let encrypted = SelectedAvatar::EncryptedGroupImage {
            cache_key: id.clone(),
            image: storage_sqlite::ChatListAvatar {
                image_hash_hex: id.clone(),
                image_key_hex: id.clone(),
                image_nonce_hex: "a".repeat(24),
                image_upload_key_hex: id,
                media_type: Some("\u{0000}".repeat(MAX_IMAGE_MEDIA_TYPE_BYTES)),
            },
        };
        assert!(
            serde_json::to_vec(&encrypted).unwrap().len()
                < serde_json::to_vec(&identity.avatar).unwrap().len()
        );
        let name = safe_name(&format!("\u{0000}\u{202e}{}", "🦫".repeat(300))).unwrap();
        let bounded = bounded_text(&name, MAX_NAME_BYTES);
        assert_eq!(bounded.len(), MAX_NAME_BYTES);
        assert!(bounded.chars().all(|c| c == '🦫'));
    }

    #[test]
    fn conversation_mentions_report_bounded_parser_prefix() {
        let mut ids = BTreeSet::new();
        let text = "x".repeat(crate::messages::MAX_MARKDOWN_MENTION_SCAN_BYTES + 1);
        let (references, truncated) = mentions(9, &text, &[], &mut ids);
        assert!(references.is_empty() && truncated);
        let (references, _) = mentions(9, &"aa".repeat(32), &[], &mut ids);
        assert!(references.is_empty());
        let mut tags = vec![vec!["p".into(), "aa".repeat(32)]; MAX_CONVERSATION_TAG_SCAN];
        tags.push(vec!["p".into(), "bb".repeat(32)]);
        let (references, truncated) = mentions(9, "", &tags, &mut ids);
        assert!(truncated);
        assert_eq!(references, vec!["aa".repeat(32)]);
    }
}
