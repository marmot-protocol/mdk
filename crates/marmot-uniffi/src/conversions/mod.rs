//! FFI-friendly value types and conversions from marmot-app's internal types.
//!
//! Internal Rust types that don't map cleanly to UniFFI (byte newtypes,
//! enums-of-structs with associated payloads, types that aren't `Send`) are
//! re-exposed as plain records/enums here. Conversion is one-way for now
//! (Rust → FFI). When the iOS side needs to round-trip data back into
//! marmot-app we'll add the reverse direction explicitly.
//!
//! The conversions are split by domain into sibling sub-modules; every public
//! item is re-exported here so the rest of the crate keeps reaching them at
//! `crate::conversions::*`.

mod account;
mod agent_stream;
mod audit;
mod chat_list;
mod common;
mod event;
mod group;
mod media;
mod message;
mod notification;
mod push;
mod relay;
mod timeline;

pub use account::*;
pub use agent_stream::*;
pub use audit::*;
pub use chat_list::*;
pub use common::*;
pub use event::*;
pub use group::*;
pub use media::*;
pub use message::*;
pub use notification::*;
pub use push::*;
pub use relay::*;
pub use timeline::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::markdown::{MarkdownBlockFfi, MarkdownDocumentFfi, MarkdownInlineFfi};
    use marmot_app::{
        AppMessageRecord, TimelineMessageRecord, TimelinePage, TimelineReactionSummary,
        TimelineReplyPreview, TimelineUserReaction,
    };
    use std::collections::BTreeMap;

    fn group(admins: Vec<&str>) -> AppGroupRecordFfi {
        AppGroupRecordFfi {
            group_id_hex: "01".repeat(32),
            endpoint: "marmot:group:01".into(),
            name: "Test".into(),
            description: String::new(),
            admins: admins.into_iter().map(ToOwned::to_owned).collect(),
            relays: vec![],
            nostr_group_id_hex: "02".repeat(32),
            avatar_url: None,
            avatar_dim: None,
            avatar_thumbhash: None,
            encrypted_media: AppGroupEncryptedMediaComponentFfi {
                component_id: 0x8008,
                component: "marmot.group.encrypted-media.v1".into(),
                required: true,
                media_format: "encrypted-media-v1".into(),
                allowed_locator_kinds: vec!["blossom-v1".into()],
                default_blob_endpoints: vec![AppBlobEndpointFfi {
                    locator_kind: "blossom-v1".into(),
                    base_url: "https://blossom.primal.net".into(),
                }],
            },
            archived: false,
            pending_confirmation: false,
            welcomer_account_id_hex: None,
            via_welcome_message_id_hex: None,
        }
    }

    fn member(member_id_hex: &str, is_admin: bool, is_self: bool) -> GroupMemberDetailsFfi {
        GroupMemberDetailsFfi {
            member_id_hex: member_id_hex.to_owned(),
            account: None,
            local: is_self,
            is_admin,
            is_self,
            npub: "npub1placeholder".into(),
            display_name: None,
        }
    }

    #[test]
    fn group_management_state_marks_last_admin_self_demote_requirement() {
        let self_id = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let bob_id = "bb4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let details = GroupDetailsFfi {
            group: group(vec![self_id]),
            members: vec![member(self_id, true, true), member(bob_id, false, false)],
        };

        let state = group_management_state_ffi(self_id, &details);

        assert!(state.is_self_admin);
        assert!(state.is_last_admin);
        assert!(state.can_invite);
        assert!(!state.can_leave);
        assert!(state.requires_self_demote_before_leave);
        let self_action = state
            .member_actions
            .iter()
            .find(|action| action.member_id_hex == self_id)
            .expect("self action");
        assert!(!self_action.can_remove);
        assert!(!self_action.can_demote);
        let bob_action = state
            .member_actions
            .iter()
            .find(|action| action.member_id_hex == bob_id)
            .expect("bob action");
        assert!(bob_action.can_remove);
        assert!(bob_action.can_promote);
        assert!(!bob_action.can_demote);
    }

    #[test]
    fn timeline_message_record_ffi_preserves_materialized_metadata() {
        let record = TimelineMessageRecord {
            message_id_hex: "message-1".to_owned(),
            source_message_id_hex: Some("source-1".to_owned()),
            source_epoch: Some(7),
            direction: "received".to_owned(),
            group_id_hex: "11".repeat(32),
            sender: "aa".repeat(32),
            plaintext: "hello".to_owned(),
            kind: 9,
            tags: vec![vec!["q".to_owned(), "parent".to_owned()]],
            timeline_at: 10,
            received_at: 11,
            reply_to_message_id_hex: Some("parent".to_owned()),
            reply_preview: Some(TimelineReplyPreview {
                message_id_hex: "parent".to_owned(),
                sender: "bb".repeat(32),
                plaintext: "parent text".to_owned(),
                kind: 9,
                source_epoch: None,
                media: None,
                agent_text_stream: None,
                deleted: false,
            }),
            media: Some(serde_json::json!({
                "imeta": [["imeta", "url https://blob.example/file"]]
            })),
            agent_text_stream: Some(serde_json::json!({
                "stream_id_hex": "22"
            })),
            reactions: TimelineReactionSummary {
                by_emoji: BTreeMap::from([("+".to_owned(), vec!["bob".to_owned()])]),
                user_reactions: vec![TimelineUserReaction {
                    reaction_message_id_hex: "reaction-1".to_owned(),
                    target_message_id_hex: "message-1".to_owned(),
                    sender: "bob".to_owned(),
                    emoji: "+".to_owned(),
                    reacted_at: 12,
                }],
            },
            deleted: true,
            deleted_by_message_id_hex: Some("delete-1".to_owned()),
            invalidation_status: None,
        };

        let page = TimelinePageFfi::from(TimelinePage {
            messages: vec![record],
            has_more_before: true,
            has_more_after: false,
        });

        assert!(page.has_more_before);
        assert!(!page.has_more_after);
        let message = &page.messages[0];
        assert_eq!(message.message_id_hex, "message-1");
        assert_eq!(message.source_message_id_hex.as_deref(), Some("source-1"));
        assert_eq!(message.reply_to_message_id_hex.as_deref(), Some("parent"));
        assert!(matches!(
            &message.content_tokens.blocks[0],
            MarkdownBlockFfi::Paragraph { inlines }
                if matches!(
                    &inlines[0],
                    MarkdownInlineFfi::Text { content } if content == "hello"
                )
        ));
        let preview = message.reply_preview.as_ref().expect("reply preview");
        assert_eq!(preview.message_id_hex, "parent");
        assert_eq!(preview.sender, "bb".repeat(32));
        assert_eq!(preview.plaintext, "parent text");
        assert!(matches!(
            &preview.content_tokens.blocks[0],
            MarkdownBlockFfi::Paragraph { inlines }
                if matches!(
                    &inlines[0],
                    MarkdownInlineFfi::Text { content } if content == "parent text"
                )
        ));
        assert!(!preview.deleted);
        assert_eq!(message.tags[0].values, vec!["q", "parent"]);
        assert_eq!(
            message.media_json.as_deref(),
            Some(r#"{"imeta":[["imeta","url https://blob.example/file"]]}"#)
        );
        assert_eq!(
            message.agent_text_stream_json.as_deref(),
            Some(r#"{"stream_id_hex":"22"}"#)
        );
        assert!(message.group_system.is_none());
        assert_eq!(message.reactions.by_emoji[0].emoji, "+");
        assert_eq!(message.reactions.by_emoji[0].count, 1);
        assert_eq!(message.reactions.by_emoji[0].senders, vec!["bob"]);
        assert_eq!(
            message.reactions.user_reactions[0].reaction_message_id_hex,
            "reaction-1"
        );
        assert!(message.deleted);
        assert_eq!(
            message.deleted_by_message_id_hex.as_deref(),
            Some("delete-1")
        );
    }

    #[test]
    fn timeline_message_record_ffi_exposes_group_system_payload() {
        let content = cgka_traits::app_event::GroupSystemEvent::new(
            cgka_traits::app_event::GROUP_SYSTEM_TYPE_MEMBER_REMOVED,
            "Member removed",
            Some(serde_json::json!({
                cgka_traits::app_event::GROUP_SYSTEM_DATA_ACTOR: "aa".repeat(32),
                cgka_traits::app_event::GROUP_SYSTEM_DATA_SUBJECT: "bb".repeat(32),
            })),
        )
        .to_content()
        .unwrap();
        let record = TimelineMessageRecord {
            message_id_hex: "system-1".to_owned(),
            source_message_id_hex: None,
            source_epoch: Some(4),
            direction: "system".to_owned(),
            group_id_hex: "11".repeat(32),
            sender: "aa".repeat(32),
            plaintext: content,
            kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
            tags: vec![vec!["system".to_owned(), "member_removed".to_owned()]],
            timeline_at: 10,
            received_at: 11,
            reply_to_message_id_hex: None,
            reply_preview: None,
            media: None,
            agent_text_stream: None,
            reactions: TimelineReactionSummary::default(),
            deleted: false,
            deleted_by_message_id_hex: None,
            invalidation_status: None,
        };

        let ffi = TimelineMessageRecordFfi::from(record);

        assert_eq!(ffi.content_tokens, MarkdownDocumentFfi::default());
        let system = ffi.group_system.expect("group system payload");
        assert_eq!(system.system_type, "member_removed");
        assert_eq!(system.text, "Member removed");
        assert_eq!(
            system.actor_account_id_hex.as_deref(),
            Some("aa".repeat(32).as_str())
        );
        assert_eq!(
            system.subject_account_id_hex.as_deref(),
            Some("bb".repeat(32).as_str())
        );
    }

    #[test]
    fn timeline_message_record_ffi_ignores_malformed_group_system_payload() {
        let record = TimelineMessageRecord {
            message_id_hex: "system-bad".to_owned(),
            source_message_id_hex: None,
            source_epoch: Some(4),
            direction: "system".to_owned(),
            group_id_hex: "11".repeat(32),
            sender: "aa".repeat(32),
            plaintext: "not-json".to_owned(),
            kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
            tags: vec![vec!["system".to_owned(), "member_removed".to_owned()]],
            timeline_at: 10,
            received_at: 11,
            reply_to_message_id_hex: None,
            reply_preview: None,
            media: None,
            agent_text_stream: None,
            reactions: TimelineReactionSummary::default(),
            deleted: false,
            deleted_by_message_id_hex: None,
            invalidation_status: None,
        };

        let ffi = TimelineMessageRecordFfi::from(record);

        assert!(ffi.group_system.is_none());
    }

    #[test]
    fn app_message_record_ffi_leaves_non_chat_tokens_empty() {
        let record = AppMessageRecord {
            message_id_hex: "reaction-1".to_owned(),
            direction: "sent".to_owned(),
            group_id_hex: "11".repeat(32),
            sender: "aa".repeat(32),
            plaintext: "reaction".to_owned(),
            kind: 7,
            tags: vec![vec!["e".to_owned(), "target".to_owned()]],
            source_epoch: None,
            recorded_at: 10,
            received_at: 11,
        };

        let ffi = AppMessageRecordFfi::from(record);

        assert_eq!(ffi.kind, 7);
        assert_eq!(ffi.content_tokens, MarkdownDocumentFfi::default());
    }

    #[test]
    fn group_management_state_allows_demoting_another_admin_when_one_remains() {
        let self_id = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let bob_id = "bb4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let details = GroupDetailsFfi {
            group: group(vec![self_id, bob_id]),
            members: vec![member(self_id, true, true), member(bob_id, true, false)],
        };

        let state = group_management_state_ffi(self_id, &details);

        assert!(state.is_self_admin);
        assert!(!state.is_last_admin);
        let bob_action = state
            .member_actions
            .iter()
            .find(|action| action.member_id_hex == bob_id)
            .expect("bob action");
        assert!(bob_action.can_remove);
        assert!(!bob_action.can_promote);
        assert!(bob_action.can_demote);
    }

    #[test]
    fn group_management_state_keeps_non_admin_self_to_leave_only() {
        let self_id = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let alice_id = "cc4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let details = GroupDetailsFfi {
            group: group(vec![alice_id]),
            members: vec![member(self_id, false, true), member(alice_id, true, false)],
        };

        let state = group_management_state_ffi(self_id, &details);

        assert!(!state.is_self_admin);
        assert!(!state.is_last_admin);
        assert!(!state.can_invite);
        assert!(state.can_leave);
        assert!(!state.requires_self_demote_before_leave);
        assert!(
            state
                .member_actions
                .iter()
                .all(|action| !action.can_remove && !action.can_promote && !action.can_demote)
        );
    }
}
