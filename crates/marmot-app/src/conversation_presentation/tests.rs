use super::*;
use crate::*;
use std::collections::BTreeMap;
use storage_sqlite::{
    ChatListAvatar, ChatPresentationInput, StoredAppEvent, TimelineReactionSummary,
    TimelineReplyPreview,
};

fn authority() -> ConversationAuthority {
    ConversationAuthority {
        is_member: true,
        self_membership: SelfMembership::Member,
        is_admin: false,
        admin_count: 1,
        pending_confirmation: false,
        leave_request_pending: false,
        lifecycle: AppGroupLifecycleState::Stable,
        unrecoverable: false,
        disbanding: false,
        disbanding_enabled: true,
        has_disbanding_blockers: false,
    }
}
fn state() -> ConversationHeaderState {
    ConversationHeaderState {
        authority: authority(),
        archived: false,
        epoch: Some(1),
    }
}
fn setup() -> (tempfile::TempDir, MarmotApp, ChatPresentationInput) {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.ensure_account_state("alice").unwrap();
    let store = app.account_storage("alice").unwrap();
    let input = ChatPresentationInput {
        group_id_hex: "11".repeat(16),
        source_version: store.chat_presentation_version().unwrap(),
        row_epoch: vec![1; 16],
        group_name: String::new(),
        member_count: Some(2),
        self_membership: SelfMembership::Member,
        members: vec![account.account_id_hex, "bb".repeat(32)],
        avatar_url: None,
        avatar: None,
    };
    (dir, app, input)
}
fn message(group: &str, sender: &str) -> TimelineMessageRecord {
    TimelineMessageRecord {
        message_id_hex: "01".repeat(32),
        source_message_id_hex: Some("02".repeat(32)),
        source_epoch: Some(1),
        retention_seconds: None,
        retention_expires_at: None,
        direction: "received".into(),
        group_id_hex: group.into(),
        sender: sender.into(),
        plaintext: "hello".into(),
        kind: 9,
        tags: vec![],
        timeline_at: 1,
        received_at: 1,
        reply_to_message_id_hex: None,
        reply_preview: None,
        media: None,
        agent_text_stream: None,
        reactions: TimelineReactionSummary::default(),
        deleted: false,
        deleted_by_message_id_hex: None,
        invalidation_status: None,
    }
}
fn page(messages: Vec<TimelineMessageRecord>) -> TimelinePage {
    TimelinePage {
        messages,
        has_more_before: false,
        has_more_after: false,
    }
}
fn project(
    app: &MarmotApp,
    input: &ChatPresentationInput,
    page: &TimelinePage,
) -> ConversationWindowPresentation {
    app.conversation_window_presentation("alice", input, state(), page)
        .unwrap()
}
fn profile(app: &MarmotApp, id: &str, name: &str, at: u64) {
    let mut record = app.empty_directory_record(id);
    record.profile = Some(UserProfileMetadata {
        display_name: Some(name.into()),
        picture: Some("https://example.com/avatar.png".into()),
        created_at: at,
        ..Default::default()
    });
    app.save_directory_entry(&record).unwrap();
}

#[test]
fn conversation_capabilities_follow_membership_and_lifecycle_without_profiles() {
    let mut input = authority();
    let unknown = ConversationAuthority {
        is_member: false,
        ..input
    }
    .capabilities();
    assert_eq!(
        unknown.participation,
        ConversationParticipation::Unavailable
    );
    assert!(!unknown.can_send);
    assert!(input.capabilities().can_send && input.capabilities().can_leave);
    input.is_admin = true;
    assert!(input.capabilities().can_invite && input.capabilities().is_last_admin);
    assert!(!input.capabilities().can_leave);
    assert!(!input.member_actions(true, true).can_remove);
    assert!(!input.member_actions(false, true).can_demote);
    input.admin_count = 2;
    assert!(input.member_actions(false, true).can_demote);
    for (membership, leaving, pending, lifecycle, expected) in [
        (
            SelfMembership::Member,
            false,
            true,
            AppGroupLifecycleState::Stable,
            ConversationParticipation::PendingInvitation,
        ),
        (
            SelfMembership::Member,
            true,
            false,
            AppGroupLifecycleState::Stable,
            ConversationParticipation::Leaving,
        ),
        (
            SelfMembership::Left,
            true,
            false,
            AppGroupLifecycleState::Stable,
            ConversationParticipation::Leaving,
        ),
        (
            SelfMembership::Left,
            false,
            false,
            AppGroupLifecycleState::Stable,
            ConversationParticipation::Left,
        ),
        (
            SelfMembership::Removed,
            false,
            false,
            AppGroupLifecycleState::Stable,
            ConversationParticipation::Removed,
        ),
        (
            SelfMembership::Member,
            false,
            false,
            AppGroupLifecycleState::Disbanded,
            ConversationParticipation::Disbanded,
        ),
    ] {
        let a = ConversationAuthority {
            self_membership: membership,
            leave_request_pending: leaving,
            pending_confirmation: pending,
            lifecycle,
            ..input
        };
        let c = a.capabilities();
        assert_eq!(c.participation, expected);
        assert!(!c.can_send && !c.can_invite && !c.can_disband && !c.can_leave);
        assert!(!a.member_actions(false, false).can_promote);
    }
    input.unrecoverable = true;
    assert!(!input.capabilities().can_send);
    input.unrecoverable = false;
    input.disbanding = true;
    assert!(!input.capabilities().can_send);
}

#[test]
fn conversation_dictionary_includes_former_members_replies_mentions_and_peer() {
    let (_dir, app, input) = setup();
    let former = "cc".repeat(32);
    let reply = "dd".repeat(32);
    let mentioned = "ee".repeat(32);
    let mut row = message(&input.group_id_hex, &former.to_uppercase());
    row.plaintext = format!("hello @{}", npub_for_account_id(&mentioned).unwrap());
    row.reply_preview = Some(TimelineReplyPreview {
        message_id_hex: "03".repeat(32),
        sender: reply.clone(),
        plaintext: "earlier".into(),
        kind: 9,
        source_epoch: Some(0),
        media: None,
        agent_text_stream: None,
        deleted: false,
        invalidation_status: None,
    });
    let result = project(&app, &input, &page(vec![row]));
    assert_eq!(result.identities.len(), 4);
    for id in [&former, &reply, &mentioned, &"bb".repeat(32)] {
        assert!(result.identities.contains_key(id));
        assert!(!result.identities[id].display_name.is_empty());
    }
    assert_eq!(result.messages[0].sender.as_ref(), Some(&former));
    assert_eq!(result.messages[0].reply_author.as_ref(), Some(&reply));
    assert_eq!(result.messages[0].mentions, vec![mentioned]);
    assert!(!result.depends_on_profile(&"ff".repeat(32)));
    assert!(result.depends_on_profile(&former.to_uppercase()));
}

#[test]
fn conversation_header_reuses_custom_name_and_encrypted_avatar_precedence() {
    let (_dir, app, mut input) = setup();
    profile(&app, &"bb".repeat(32), "Peer", 1);
    let empty = page(vec![]);
    let initial = project(&app, &input, &empty);
    assert!(initial.header.selected.title == PresentationText::Literal("Peer".into()));
    input.group_name = "Custom".into();
    input.avatar_url = Some("https://example.com/group.png".into());
    input.avatar = Some(ChatListAvatar {
        image_hash_hex: "11".repeat(32),
        image_key_hex: "22".repeat(32),
        image_nonce_hex: "33".repeat(12),
        image_upload_key_hex: "44".repeat(32),
        media_type: Some("image/png".into()),
    });
    let result = project(&app, &input, &empty);
    assert!(result.header.selected.title == PresentationText::Literal("Custom".into()));
    assert!(matches!(
        result.header.selected.avatar,
        SelectedAvatar::EncryptedGroupImage { .. }
    ));
}

#[test]
fn conversation_profile_only_commit_invalidates_historical_author_and_refreshes() {
    let (_dir, app, input) = setup();
    let id = "cc".repeat(32);
    let page = page(vec![message(&input.group_id_hex, &id)]);
    let before = project(&app, &input, &page);
    let mut signals = app.presentation_signals.profile_updates.subscribe();
    profile(&app, &id, "New name", 1);
    let changed = signals.try_recv().unwrap();
    assert!(before.depends_on_profile(&changed));
    let after = project(&app, &input, &page);
    assert_eq!(after.identities[&id].display_name, "New name");
    assert!(after.header == before.header);
    assert!(after.messages == before.messages);
    assert!(format!("{after:?}").contains("identities"));
    assert!(!format!("{after:?}").contains(&id));
}

#[test]
fn conversation_bounds_ancillary_references_but_preserves_reaction_counts() {
    let (_dir, app, input) = setup();
    let mut row = message(&input.group_id_hex, &"aa".repeat(32));
    for i in 0..40 {
        row.tags.push(vec!["p".into(), format!("{i:064x}")]);
    }
    row.reactions.by_emoji = (0..12)
        .map(|i| {
            (
                format!("emoji{i:02}"),
                (0..30)
                    .map(|j| format!("{:064x}", 100 + i * 30 + j))
                    .collect(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    row.reactions.by_emoji.insert(
        "emoji11".into(),
        (0..100).map(|i| format!("{:064x}", 1000 + i)).collect(),
    );
    let result = project(&app, &input, &page(vec![row]));
    let row = &result.messages[0];
    assert!(row.mentions_truncated);
    assert_eq!(row.mentions.len(), MAX_CONVERSATION_MENTIONS);
    assert_eq!(row.reactions.total_count, 430);
    assert_eq!(row.reactions.items[0].emoji, "emoji11");
    assert_eq!(row.reactions.omitted_kinds, 4);
    for reaction in &row.reactions.items {
        assert_eq!(
            reaction.count,
            if reaction.emoji == "emoji11" { 100 } else { 30 }
        );
        assert_eq!(reaction.reactors.len(), MAX_CONVERSATION_REACTOR_PREVIEWS);
        assert!(
            reaction
                .reactors
                .iter()
                .all(|id| result.identities.contains_key(id))
        );
    }
    assert!(result.identities.len() < 40);
    assert!(serde_json::to_vec(&result).unwrap().len() < MAX_CONVERSATION_PRESENTATION_BYTES);
}

#[test]
fn conversation_system_references_require_matching_stored_commit_provenance() {
    let (_dir, app, input) = setup();
    let store = app.account_storage("alice").unwrap();
    let actor = "cc".repeat(32);
    let subject = "dd".repeat(32);
    let mut row = message(&input.group_id_hex, &"bb".repeat(32));
    row.kind = MARMOT_APP_EVENT_KIND_GROUP_SYSTEM;
    row.plaintext = format!(
        r#"{{"v":1,"system_type":"member_added","text":"added","data":{{"actor":"{actor}","subject":"{subject}"}}}}"#
    );
    // Parsing member-authored JSON is not evidence.
    let untrusted = project(&app, &input, &page(vec![row.clone()]));
    assert!(untrusted.messages[0].system.is_none());
    row.direction = "system".into();
    row.source_message_id_hex = None;
    store
        .record_app_event(&StoredAppEvent {
            group_id_hex: row.group_id_hex.clone(),
            message_id_hex: row.message_id_hex.clone(),
            source_message_id_hex: None,
            source_epoch: row.source_epoch,
            direction: row.direction.clone(),
            sender: row.sender.clone(),
            plaintext: row.plaintext.clone(),
            kind: row.kind,
            tags: vec![],
            recorded_at: 1,
            received_at: 1,
            origin_commit_id: Some("aa".repeat(32)),
            moderation_grant: false,
        })
        .unwrap();
    let trusted = project(&app, &input, &page(vec![row.clone()]));
    let system = trusted.messages[0]
        .system
        .as_ref()
        .expect("synthesized system");
    assert_eq!(system.actor.as_ref(), Some(&actor));
    assert_eq!(system.subject.as_ref(), Some(&subject));
    assert!(trusted.identities.contains_key(&subject));
    row.plaintext.push(' ');
    assert!(
        project(&app, &input, &page(vec![row])).messages[0]
            .system
            .is_none()
    );
}

#[test]
fn conversation_scope_and_row_limit_fail_before_directory_hydration() {
    let (_dir, app, mut input) = setup();
    let row = message("22", &"aa".repeat(32));
    assert!(matches!(
        app.conversation_window_presentation("alice", &input, state(), &page(vec![row])),
        Err(ConversationPresentationError::GroupMismatch)
    ));
    let row = message(&input.group_id_hex, &"aa".repeat(32));
    assert!(matches!(
        app.conversation_window_presentation("alice", &input, state(), &page(vec![row; 201])),
        Err(ConversationPresentationError::LimitExceeded)
    ));
    // Opaque MLS ids are not pubkeys or 32-byte routing ids. The input id is
    // not copied into this bounded output, so do not impose a new length rule.
    input.group_id_hex = "ab".repeat(600);
    project(&app, &input, &page(vec![]));
    input.source_version.store_epoch = vec![0; 32];
    assert!(matches!(
        app.conversation_window_presentation("alice", &input, state(), &page(vec![])),
        Err(ConversationPresentationError::StoreMismatch)
    ));
}
