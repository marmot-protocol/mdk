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
        revision_id_hex: String::new(),
        moderation: storage_sqlite::MessageModerationSummary::default(),
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
    let prepared = prepare(app, page.clone());
    app.conversation_window_presentation("alice", input, state(), &prepared)
        .unwrap()
}
fn prepare(app: &MarmotApp, page: TimelinePage) -> ConversationPresentationPage {
    app.account_storage("alice")
        .unwrap()
        .conversation_presentation_page(page)
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
        assert_eq!(c.is_self_admin, membership == SelfMembership::Member);
        assert!(!c.is_last_admin); // Two actual admins in this fixture.
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
    // Matching trusted storage must not bless a caller row with different
    // direction, inner-source provenance or epoch.
    for forged in 0..3 {
        let mut altered = row.clone();
        match forged {
            0 => altered.direction = "received".into(),
            1 => altered.source_message_id_hex = Some("ff".repeat(32)),
            _ => altered.source_epoch = Some(2),
        }
        assert!(
            project(&app, &input, &page(vec![altered])).messages[0]
                .system
                .is_none()
        );
    }
    // Capture in the existing caller-owned account transaction; enrichment
    // happens afterwards. The wrapper owns exactly the checked page.
    use cgka_traits::StorageProvider;
    let captured = store
        .with_transaction::<_, cgka_traits::storage::StorageError, _>(|store| {
            store.conversation_presentation_page(page(vec![row.clone(); MAX_TIMELINE_LIMIT]))
        })
        .unwrap();
    assert_eq!(captured.page().messages.len(), MAX_TIMELINE_LIMIT);
    for index in 0..MAX_TIMELINE_LIMIT {
        assert_eq!(
            captured.authenticated_system_content(index),
            Some(row.plaintext.as_str())
        );
    }
    assert!(
        captured
            .authenticated_system_content(MAX_TIMELINE_LIMIT)
            .is_none()
    );
    assert_eq!(
        app.conversation_window_presentation("alice", &input, state(), &captured)
            .unwrap()
            .messages
            .iter()
            .filter(|m| m.system.is_some())
            .count(),
        MAX_TIMELINE_LIMIT
    );
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
        app.conversation_window_presentation(
            "alice",
            &input,
            state(),
            &prepare(&app, page(vec![row]))
        ),
        Err(ConversationPresentationError::GroupMismatch)
    ));
    let row = message(&input.group_id_hex, &"aa".repeat(32));
    assert!(
        app.account_storage("alice")
            .unwrap()
            .conversation_presentation_page(page(vec![row; 201]))
            .is_err()
    );
    // Opaque MLS ids are not pubkeys or 32-byte routing ids. The input id is
    // not copied into this bounded output, so do not impose a new length rule.
    input.group_id_hex = "ab".repeat(600);
    project(&app, &input, &page(vec![]));
    input.source_version.store_epoch = vec![0; 32];
    assert!(matches!(
        app.conversation_window_presentation(
            "alice",
            &input,
            state(),
            &prepare(&app, page(vec![]))
        ),
        Err(ConversationPresentationError::StoreMismatch)
    ));
}

#[test]
fn conversation_prepared_page_cannot_cross_account_stores() {
    let (_dir, app, input) = setup();
    let (_other_dir, other, _) = setup();
    let prepared = prepare(&other, page(vec![]));
    assert!(matches!(
        app.conversation_window_presentation("alice", &input, state(), &prepared),
        Err(ConversationPresentationError::StoreMismatch)
    ));
}

#[test]
fn conversation_peer_avatar_keys_match_header_and_change_with_store_identity() {
    let (_dir, app, mut input) = setup();
    let peer = "bb".repeat(32);
    let fallback = project(&app, &input, &page(vec![]));
    assert!(fallback.header.selected.avatar == fallback.identities[&peer].avatar);
    profile(&app, &peer, "Peer", 1);
    let loaded = project(&app, &input, &page(vec![]));
    assert!(loaded.header.selected.avatar == loaded.identities[&peer].avatar);
    let local = app.account_home().account("alice").unwrap().account_id_hex;
    input.source_version.store_epoch.reverse();
    input.source_version.store_epoch.push(1);
    let reset = crate::chat_presentation::select_chat_presentation(&input, &local, None);
    assert!(reset.avatar != fallback.header.selected.avatar);
}

#[test]
fn conversation_review_mentions_keep_visible_document_order_before_tags() {
    let (_dir, app, input) = setup();
    let visible: Vec<_> = (0..9).rev().map(|i| format!("{:064x}", 1000 + i)).collect();
    let mut row = message(&input.group_id_hex, &"bb".repeat(32));
    row.plaintext = format!("hello @{}", npub_for_account_id(&visible[0]).unwrap());
    row.tags = (0..8)
        .map(|i| vec!["p".into(), format!("{i:064x}")])
        .collect();
    let result = project(&app, &input, &page(vec![row.clone()]));
    assert_eq!(result.messages[0].mentions.first(), Some(&visible[0]));
    assert!(result.identities.contains_key(&visible[0]));
    row.plaintext = visible
        .iter()
        .map(|id| format!("@{}", npub_for_account_id(id).unwrap()))
        .collect::<Vec<_>>()
        .join(" ");
    row.tags.clear();
    let result = project(&app, &input, &page(vec![row]));
    assert_eq!(result.messages[0].mentions, visible[..8]);
    assert!(result.messages[0].mentions_truncated);
}

#[test]
fn conversation_review_large_window_acquires_directory_handles_once() {
    let (_dir, app, input) = setup();
    let rows = (1000..1200)
        .map(|i| message(&input.group_id_hex, &format!("{i:064x}")))
        .collect();
    let before = app.directory_handle_acquire_count_for_test();
    let result = project(&app, &input, &page(rows));
    assert_eq!(result.identities.len(), 201);
    assert_eq!(app.directory_handle_acquire_count_for_test(), before + 1);
}

#[test]
fn conversation_input_guards_reject_inconsistent_membership_and_oversized_fields() {
    let (_dir, app, mut input) = setup();
    let prepared = prepare(&app, page(vec![]));
    let mut stale = state();
    stale.authority.self_membership = SelfMembership::Left;
    assert!(matches!(
        app.conversation_window_presentation("alice", &input, stale, &prepared),
        Err(ConversationPresentationError::MembershipMismatch)
    ));
    let mut row = message(&input.group_id_hex, &"bb".repeat(32));
    row.message_id_hex = "a".repeat(1025);
    let long_id = prepare(&app, page(vec![row]));
    assert!(matches!(
        app.conversation_window_presentation("alice", &input, state(), &long_id),
        Err(ConversationPresentationError::LimitExceeded)
    ));
    input.avatar = Some(ChatListAvatar {
        image_hash_hex: "11".repeat(32),
        image_key_hex: "22".repeat(32),
        image_nonce_hex: "33".repeat(12),
        image_upload_key_hex: "44".repeat(32),
        media_type: Some("a".repeat(129)),
    });
    assert!(matches!(
        app.conversation_window_presentation("alice", &input, state(), &prepared),
        Err(ConversationPresentationError::LimitExceeded)
    ));
}

#[test]
fn conversation_reply_mentions_have_independent_limits_and_complete_identities() {
    let (_dir, app, input) = setup();
    let main = "aa".repeat(32);
    let reply_author = "cc".repeat(32);
    let reply_ids: Vec<_> = (1000..1009).rev().map(|i| format!("{i:064x}")).collect();
    let mut row = message(&input.group_id_hex, &"bb".repeat(32));
    row.plaintext = format!("@{}", npub_for_account_id(&main).unwrap());
    row.reply_preview = Some(TimelineReplyPreview {
        message_id_hex: "03".repeat(32),
        sender: reply_author.clone(),
        plaintext: reply_ids
            .iter()
            .map(|id| format!("@{}", npub_for_account_id(id).unwrap()))
            .collect::<Vec<_>>()
            .join(" "),
        kind: 9,
        source_epoch: Some(0),
        media: None,
        agent_text_stream: None,
        deleted: false,
        invalidation_status: None,
    });
    let result = project(&app, &input, &page(vec![row.clone()]));
    assert_eq!(result.messages[0].mentions, vec![main]);
    assert!(!result.messages[0].mentions_truncated);
    assert_eq!(result.messages[0].reply_mentions, reply_ids[..8]);
    assert!(result.messages[0].reply_mentions_truncated);
    assert!(result.identities.contains_key(&reply_author));
    for id in &reply_ids[..8] {
        assert!(result.identities.contains_key(id));
        assert!(result.depends_on_profile(id));
    }
    assert!(!result.identities.contains_key(&reply_ids[8]));
    let mention = format!("@{}", npub_for_account_id(&reply_ids[0]).unwrap());
    row.reply_preview.as_mut().unwrap().plaintext = format!("{mention} {mention}");
    let complete = project(&app, &input, &page(vec![row]));
    assert_eq!(complete.messages[0].reply_mentions, reply_ids[..1]);
    assert!(!complete.messages[0].reply_mentions_truncated);
}

#[test]
fn conversation_viewer_reaction_is_account_scoped_and_independent_of_preview() {
    let (_dir, app, input) = setup();
    let viewer = app.account_home().account("alice").unwrap().account_id_hex;
    let previews = vec!["00".repeat(32), format!("{:064x}", 1)];
    let mut row = message(&input.group_id_hex, &"ff".repeat(32));
    let mut reactors = previews.clone();
    // The viewing account must not need an identity slot to highlight its reaction.
    reactors.push(viewer.to_uppercase());
    row.reactions.by_emoji.insert("👍".into(), reactors);
    row.reactions.by_emoji.insert("🎉".into(), previews.clone());
    let result = project(&app, &input, &page(vec![row.clone()]));
    let reactions = &result.messages[0].reactions;
    let mine = reactions.items.iter().find(|r| r.emoji == "👍").unwrap();
    assert!(mine.viewer_reacted);
    assert_eq!(mine.count, 3);
    assert_eq!(mine.reactors, previews);
    assert!(!result.identities.contains_key(&viewer));
    assert!(
        !reactions
            .items
            .iter()
            .find(|r| r.emoji == "🎉")
            .unwrap()
            .viewer_reacted
    );
    assert_eq!(reactions.total_count, 5);

    // The same reaction content viewed by a different account is not "mine".
    let (_other_dir, other_app, other_input) = setup();
    let other = project(&other_app, &other_input, &page(vec![row.clone()]));
    assert!(
        other.messages[0]
            .reactions
            .items
            .iter()
            .all(|r| !r.viewer_reacted)
    );

    // Removing the viewer leaves peers' reactions visible but unselected.
    row.reactions.by_emoji.get_mut("👍").unwrap().pop();
    let removed = project(&app, &input, &page(vec![row]));
    let reaction = removed.messages[0]
        .reactions
        .items
        .iter()
        .find(|r| r.emoji == "👍")
        .unwrap();
    assert!(!reaction.viewer_reacted);
    assert_eq!(reaction.count, 2);
    assert_eq!(reaction.reactors, previews);
}
