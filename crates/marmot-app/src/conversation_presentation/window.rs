use super::{ConversationAuthority, ConversationCapabilities};
use crate::chat_presentation::{canonical_identity, safe_image_url, safe_name};
use crate::{
    AppError, AppGroupLifecycleState, ConversationPresentation, MarmotApp, SelectedAvatar,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use storage_sqlite::{ChatPresentationInput, TimelineMessageRecord, TimelinePage};

pub const MAX_CONVERSATION_TAG_SCAN: usize = 256;
pub const MAX_CONVERSATION_MENTIONS: usize = 8;
pub const MAX_CONVERSATION_REACTION_KINDS: usize = 8;
pub const MAX_CONVERSATION_REACTOR_PREVIEWS: usize = 2;
pub const MAX_CONVERSATION_IDENTITIES: usize = crate::MAX_TIMELINE_LIMIT
    * (4 + 2 * MAX_CONVERSATION_MENTIONS
        + MAX_CONVERSATION_REACTION_KINDS * MAX_CONVERSATION_REACTOR_PREVIEWS)
    + 1;
pub const MAX_CONVERSATION_PRESENTATION_BYTES: usize = 32 * 1024 * 1024;
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

#[derive(Clone, PartialEq, Eq, Serialize)]
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

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ConversationIdentity {
    pub account_id_hex: String,
    pub display_name: String,
    pub avatar: SelectedAvatar,
    pub has_cached_profile: bool,
}

/// `None` means unavailable/malformed identity, not an invitation to look it up.
/// Every `Some` reference in this projection has an entry in `identities`.
#[derive(Clone, PartialEq, Eq, Serialize)]
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

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ConversationSystemReferences {
    pub system_type: String,
    pub actor: Option<String>,
    pub subject: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ConversationReaction {
    pub emoji: String,
    pub count: usize,
    pub reactors: Vec<String>,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize)]
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
#[derive(Clone, PartialEq, Eq, Serialize)]
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
        page: &TimelinePage,
    ) -> Result<ConversationWindowPresentation, ConversationPresentationError> {
        if page.messages.len() > crate::MAX_TIMELINE_LIMIT {
            return Err(ConversationPresentationError::LimitExceeded);
        }
        if input.self_membership != state.authority.self_membership {
            return Err(ConversationPresentationError::MembershipMismatch);
        }
        let account = self.account_home().account(label).map_err(AppError::from)?;
        let storage = self.account_storage(label)?;
        if storage
            .chat_presentation_version()
            .map_err(AppError::from)?
            .store_epoch
            != input.source_version.store_epoch
        {
            return Err(ConversationPresentationError::StoreMismatch);
        }
        let mut ids = BTreeSet::new();
        // Reuse the existing selector to identify a possible presentation peer.
        let fallback = crate::chat_presentation::select_chat_presentation(
            input,
            &account.account_id_hex,
            None,
        );
        if let Some(peer) = &fallback.peer_id {
            ids.insert(peer.clone());
        }
        let mut messages = Vec::with_capacity(page.messages.len());
        for message in &page.messages {
            if message.group_id_hex != input.group_id_hex {
                return Err(ConversationPresentationError::GroupMismatch);
            }
            if message.message_id_hex.len() > MAX_REFERENCE_BYTES {
                return Err(ConversationPresentationError::LimitExceeded);
            }
            let trusted = storage
                .conversation_system_event_content(message)
                .map_err(AppError::from)?;
            let references = message_references(message, trusted.as_deref(), &mut ids);
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
                if fallback.peer_id.as_ref() == Some(&id) {
                    peer_profile = cached.profile.clone();
                }
                identities.insert(
                    id.clone(),
                    identity(
                        &id,
                        cached.profile.as_ref(),
                        cached.local_label.as_deref(),
                        &input.source_version.store_epoch,
                    ),
                );
            }
        }
        // Valid canonical identifiers always have a stable fallback, even if a
        // cache adapter cannot represent one. Dictionary completeness is total.
        for id in requested {
            identities
                .entry(id.clone())
                .or_insert_with(|| identity(&id, None, None, &input.source_version.store_epoch));
        }
        let selected = crate::chat_presentation::select_chat_presentation(
            input,
            &account.account_id_hex,
            fallback.peer_id.as_deref().zip(peer_profile.as_ref()),
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
        // Count encoded bytes without allocating a second, potentially large
        // serialized copy. This covers escaping and repeated reference keys.
        serde_json::to_writer(ByteBudget(MAX_CONVERSATION_PRESENTATION_BYTES), &result)
            .map_err(|_| ConversationPresentationError::LimitExceeded)?;
        Ok(result)
    }
}

struct ByteBudget(usize);
impl std::io::Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("conversation presentation byte limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
    store_epoch: &[u8],
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
        .map(|url| {
            let mut hash = Sha256::new();
            for part in [
                b"conversation-identity-avatar-v1".as_slice(),
                store_epoch,
                id.as_bytes(),
                url.as_bytes(),
            ] {
                hash.update((part.len() as u64).to_le_bytes());
                hash.update(part);
            }
            SelectedAvatar::RemoteImage {
                url,
                cache_key: hex::encode(hash.finalize()),
            }
        })
        .unwrap_or_else(|| SelectedAvatar::Placeholder {
            stable_seed: id.to_owned(),
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
    fn conversation_encoded_byte_budget_counts_json_escaping() {
        assert!(serde_json::to_writer(ByteBudget(7), &"\n\n\n").is_err());
        assert!(serde_json::to_writer(ByteBudget(8), &"\n\n\n").is_ok());
        let id = "bb".repeat(32);
        let profile = crate::UserProfileMetadata {
            display_name: Some(format!("\u{202e}{}", "🦫".repeat(5000))),
            picture: Some("https://127.0.0.1/private".into()),
            ..Default::default()
        };
        let projected = identity(&id, Some(&profile), None, &[1; 16]);
        assert_eq!(projected.display_name.len(), MAX_NAME_BYTES);
        assert!(matches!(
            projected.avatar,
            SelectedAvatar::Placeholder { .. }
        ));
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
