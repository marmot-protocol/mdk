use super::*;
use crate::*;
use storage_sqlite::{
    ChatPresentationRead, PresentationText, PublicDirectoryUserRecord, StoredAccountState,
};
fn seed(account: &SqliteAccountStorage, id: &str, name: &str) {
    let routing = AppGroupNostrRoutingComponent::new(cgka_traits::app_components::NostrRoutingV1 {
        nostr_group_id: [1; 32],
        relays: vec!["wss://relay.example.com".into()],
    })
    .unwrap();
    let mut group = AppGroupRecord::new(
        id.into(),
        routing,
        name.into(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );
    group.member_count = Some(2);
    group.presentation_member_ids_hex = Some(vec!["aa".repeat(32), "bb".repeat(32)]);
    let state = StoredAccountState {
        label: "fixture".into(),
        groups: vec![crate::conversions::stored_group_from_app_group(&group)],
        ..Default::default()
    };
    account.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(&state,100,120,&[],&[]).unwrap();
    account
        .refresh_chat_list_row(&"aa".repeat(32), id, &|_, _| false)
        .unwrap();
}
fn profile(shared: &SqliteSharedStorage, name: Option<&str>) {
    shared
        .put_public_directory_user(&PublicDirectoryUserRecord {
            account_id_hex: "bb".repeat(32),
            npub: "fixture".into(),
            profile_json: name.map(|name| {
                serde_json::to_string(&UserProfileMetadata {
                    display_name: Some(name.into()),
                    picture: Some("https://example.com/avatar".into()),
                    ..Default::default()
                })
                .unwrap()
            }),
            relay_lists_json: "{}".into(),
            key_package_json: None,
            event_id_hex: None,
            event_kind: None,
            event_created_at: None,
            follows: vec![],
        })
        .unwrap();
}
fn drain(account: &SqliteAccountStorage, shared: &SqliteSharedStorage) {
    for _ in 0..100 {
        if !maintain(account, shared, &"aa".repeat(32)).unwrap() {
            return;
        }
    }
    panic!("presentation maintenance did not quiesce");
}
fn title(account: &SqliteAccountStorage, id: &str) -> PresentationText {
    match account.chat_presentation(id).unwrap() {
        ChatPresentationRead::Ready(value) => value.presentation.title,
        _ => panic!("presentation was not prepared"),
    }
}
#[test]
fn cached_before_creation_and_later_profile_changes_apply_without_a_subscriber() {
    let account = SqliteAccountStorage::in_memory().unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    profile(&shared, Some("First"));
    seed(&account, "11", "");
    drain(&account, &shared);
    assert!(title(&account, "11") == PresentationText::Literal("First".into()));
    profile(&shared, Some("Second"));
    drain(&account, &shared);
    assert!(title(&account, "11") == PresentationText::Literal("Second".into()));
}

#[test]
fn dirty_same_subject_display_survives_until_maintenance_and_new_titles_notify_once() {
    let account = SqliteAccountStorage::in_memory().unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    profile(&shared, Some("Peer"));
    seed(&account, "11", "");
    drain(&account, &shared);
    let before = account.chat_presentation_version().unwrap();
    let mut state = account
        .load_account_projection_state("fixture", 100)
        .unwrap();
    state.groups[0].image_media_type = Some("image/jpeg".into());
    account.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
        &state, 101, 121, &[], &[],
    ).unwrap();
    let ChatPresentationRead::Ready(value) = account.chat_presentation("11").unwrap() else {
        panic!("same-subject display was erased");
    };
    assert_eq!(
        value.presentation.resolution,
        storage_sqlite::PresentationResolution::LastKnown
    );
    assert!(value.presentation.title == PresentationText::Literal("Peer".into()));
    drain(&account, &shared);
    assert_eq!(account.chat_presentation_version().unwrap(), before);
    state.groups[0].profile_name = "Custom".into();
    account.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
        &state, 102, 122, &[], &[],
    ).unwrap();
    drain(&account, &shared);
    assert!(title(&account, "11") == PresentationText::Literal("Custom".into()));
    assert_eq!(
        account.chat_presentation_version().unwrap().revision,
        before.revision + 1
    );
    state.groups[0].profile_name.clear();
    account.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
        &state, 103, 123, &[], &[],
    ).unwrap();
    assert_eq!(
        account.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    );
    drain(&account, &shared);
    assert!(title(&account, "11") == PresentationText::Literal("Peer".into()));
    assert!(
        account
            .pending_chat_presentation_inputs()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn restart_mid_fanout_and_coalesced_newer_profiles_do_not_skip_other_identities() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("account.db");
    let key = storage_sqlite::SqlCipherKey::new("presentation test key").unwrap();
    let account = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    profile(&shared, Some("Original"));
    for i in 0..65 {
        seed(&account, &format!("{i:04x}"), "");
    }
    seed(&account, "cc", "");
    account
        .set_chat_presentation_members("cc", &["aa".repeat(32), "cc".repeat(32)])
        .unwrap();
    drain(&account, &shared);
    profile(&shared, Some("First update"));
    // Select the changed identity, then commit one bounded group page.
    assert!(maintain(&account, &shared, &"aa".repeat(32)).unwrap());
    assert!(maintain(&account, &shared, &"aa".repeat(32)).unwrap());
    let checkpoint = account.chat_presentation_checkpoint().unwrap();
    assert!(
        checkpoint
            .state
            .active
            .as_ref()
            .unwrap()
            .after_group
            .is_some()
    );
    drop(account);
    // Another identity lands between this peer's old and new coalesced revisions.
    shared
        .put_public_directory_user(&PublicDirectoryUserRecord {
            account_id_hex: "cc".repeat(32),
            npub: "fixture".into(),
            profile_json: Some(
                serde_json::to_string(&UserProfileMetadata {
                    name: Some("Other peer".into()),
                    ..Default::default()
                })
                .unwrap(),
            ),
            relay_lists_json: "{}".into(),
            key_package_json: None,
            event_id_hex: None,
            event_kind: None,
            event_created_at: None,
            follows: vec![],
        })
        .unwrap();
    profile(&shared, Some("Latest update"));
    let account = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    drain(&account, &shared);
    for i in 0..65 {
        assert!(
            title(&account, &format!("{i:04x}"))
                == PresentationText::Literal("Latest update".into())
        );
    }
    assert!(title(&account, "cc") == PresentationText::Literal("Other peer".into()));
}

#[test]
fn removal_store_replacement_and_new_dependency_after_watermark_clear_stale_data() {
    let account = SqliteAccountStorage::in_memory().unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    profile(&shared, Some("Cached"));
    seed(&account, "11", "");
    drain(&account, &shared);
    let before = account.chat_list_row("11").unwrap();
    seed(&account, "22", "");
    drain(&account, &shared);
    assert!(title(&account, "22") == PresentationText::Literal("Cached".into()));
    profile(&shared, None);
    drain(&account, &shared);
    assert!(
        title(&account, "11")
            == PresentationText::Literal(crate::default_profile_pseudonym(&"bb".repeat(32)))
    );
    assert_eq!(account.chat_list_row("11").unwrap(), before);
    profile(&shared, Some("Cached again"));
    drain(&account, &shared);
    let replacement = SqliteSharedStorage::in_memory().unwrap();
    drain(&account, &replacement);
    assert!(
        title(&account, "11")
            == PresentationText::Literal(crate::default_profile_pseudonym(&"bb".repeat(32)))
    );
    let generation = account.chat_presentation_checkpoint().unwrap().generation;
    let version = account.chat_presentation_version().unwrap();
    assert!(!maintain(&account, &replacement, &"aa".repeat(32)).unwrap());
    assert_eq!(
        account.chat_presentation_checkpoint().unwrap().generation,
        generation
    );
    assert_eq!(account.chat_presentation_version().unwrap(), version);
}

#[test]
fn named_pair_depends_on_peer_avatar_and_membership_changes_clear_old_peer_immediately() {
    let account = SqliteAccountStorage::in_memory().unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    profile(&shared, Some("Peer"));
    seed(&account, "11", "Custom");
    drain(&account, &shared);
    assert_eq!(
        account
            .chat_presentation_dependents(&"bb".repeat(32), None)
            .unwrap(),
        ["11"]
    );
    assert!(title(&account, "11") == PresentationText::Literal("Custom".into()));
    account
        .set_chat_presentation_members("11", &["aa".repeat(32), "cc".repeat(32)])
        .unwrap();
    assert!(matches!(
        account.chat_presentation("11").unwrap(),
        ChatPresentationRead::Pending
    ));
    assert!(
        account
            .chat_presentation_dependents(&"bb".repeat(32), None)
            .unwrap()
            .is_empty()
    );
    drain(&account, &shared);
    let ChatPresentationRead::Ready(selected) = account.chat_presentation("11").unwrap() else {
        panic!("not ready")
    };
    assert_eq!(selected.presentation.peer_id, Some("cc".repeat(32)));
    assert!(matches!(
        selected.presentation.avatar,
        storage_sqlite::SelectedAvatar::Placeholder { .. }
    ));
    account
        .set_group_self_membership("11", storage_sqlite::SelfMembership::Left)
        .unwrap();
    drain(&account, &shared);
    let ChatPresentationRead::Ready(selected) = account.chat_presentation("11").unwrap() else {
        panic!("not ready")
    };
    assert!(selected.presentation.peer_id.is_none());
}

#[test]
fn unrelated_directory_history_is_skipped_and_new_unrelated_changes_are_batched() {
    let account = SqliteAccountStorage::in_memory().unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    for i in 0..250 {
        shared
            .put_public_directory_user(&PublicDirectoryUserRecord {
                account_id_hex: format!("{i:064x}"),
                npub: "fixture".into(),
                profile_json: Some("{\"name\":\"Unrelated\"}".into()),
                relay_lists_json: "{}".into(),
                key_package_json: None,
                event_id_hex: None,
                event_kind: None,
                event_created_at: None,
                follows: vec![],
            })
            .unwrap();
    }
    profile(&shared, Some("Relevant"));
    seed(&account, "11", "");
    assert!(maintain(&account, &shared, &"aa".repeat(32)).unwrap());
    assert!(maintain(&account, &shared, &"aa".repeat(32)).unwrap());
    assert!(
        !maintain(&account, &shared, &"aa".repeat(32)).unwrap(),
        "initial reconciliation must not replay pre-existing unrelated changes"
    );
    let version = account.chat_presentation_version().unwrap();
    for i in 0..100 {
        let mut record = shared
            .public_directory_user(&format!("{i:064x}"))
            .unwrap()
            .unwrap();
        record.profile_json = Some("{\"name\":\"Changed unrelated\"}".into());
        shared.put_public_directory_user(&record).unwrap();
    }
    assert!(maintain(&account, &shared, &"aa".repeat(32)).unwrap());
    assert!(maintain(&account, &shared, &"aa".repeat(32)).unwrap());
    assert!(
        !maintain(&account, &shared, &"aa".repeat(32)).unwrap(),
        "unrelated changes should advance 50 identities per batch"
    );
    assert_eq!(account.chat_presentation_version().unwrap(), version);
}

#[test]
fn rejected_pending_presentation_yields_until_new_evidence_allows_progress() {
    let account = SqliteAccountStorage::in_memory().unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    profile(&shared, Some("First"));
    seed(&account, "11", "");
    drain(&account, &shared);
    let input = account.chat_presentation_input("11").unwrap().unwrap();
    let ChatPresentationRead::Ready(mut future) = account.chat_presentation("11").unwrap() else {
        panic!("initial presentation");
    };
    future.profile_version.as_mut().unwrap().revision += 1;
    account.store_chat_presentation(&input, &future).unwrap();
    let mut state = account
        .load_account_projection_state("fixture", 100)
        .unwrap();
    state.groups[0].image_media_type = Some("image/png".into());
    account.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
        &state, 101, 121, &[], &[],
    ).unwrap();
    let generation = account.chat_presentation_checkpoint().unwrap().generation;
    assert!(
        !maintain(&account, &shared, &"aa".repeat(32)).unwrap(),
        "an entirely rejected pending batch must wait instead of scheduling a hot loop"
    );
    assert_eq!(
        account.chat_presentation_checkpoint().unwrap().generation,
        generation
    );
    assert_eq!(account.pending_chat_presentation_inputs().unwrap().len(), 1);
    profile(&shared, Some("Second"));
    drain(&account, &shared);
    assert!(title(&account, "11") == PresentationText::Literal("Second".into()));
    assert!(
        account
            .pending_chat_presentation_inputs()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn account_catchup_and_replacement_cannot_restore_another_accounts_deleted_chat() {
    let first = SqliteAccountStorage::in_memory().unwrap();
    let second = SqliteAccountStorage::in_memory().unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    profile(&shared, Some("Initial"));
    seed(&first, "11", "");
    seed(&second, "11", "");
    second
        .set_chat_presentation_members("11", &["cc".repeat(32), "bb".repeat(32)])
        .unwrap();
    drain(&first, &shared);
    for _ in 0..100 {
        if !maintain(&second, &shared, &"cc".repeat(32)).unwrap() {
            break;
        }
    }
    assert!(title(&second, "11") == PresentationText::Literal("Initial".into()));
    let delayed_input = first.chat_presentation_input("11").unwrap().unwrap();
    let ChatPresentationRead::Ready(delayed_value) = first.chat_presentation("11").unwrap() else {
        panic!("first presentation");
    };
    assert_eq!(
        second
            .store_chat_presentation(&delayed_input, &delayed_value)
            .unwrap(),
        storage_sqlite::ChatPresentationWrite::Stale
    );
    second.delete_local_group_data("11").unwrap();
    let second_checkpoint = second.chat_presentation_checkpoint().unwrap();
    let second_version = second.chat_presentation_version().unwrap();
    profile(&shared, Some("Updated"));
    drain(&first, &shared);
    assert!(title(&first, "11") == PresentationText::Literal("Updated".into()));
    assert_eq!(
        second.chat_presentation_checkpoint().unwrap().generation,
        second_checkpoint.generation
    );
    assert_eq!(second.chat_presentation_version().unwrap(), second_version);
    assert_eq!(
        second.chat_presentation("11").unwrap(),
        ChatPresentationRead::Missing
    );
    let replacement = SqliteSharedStorage::in_memory().unwrap();
    drain(&first, &replacement);
    for _ in 0..100 {
        if !maintain(&second, &replacement, &"cc".repeat(32)).unwrap() {
            break;
        }
    }
    assert_eq!(
        second.chat_presentation("11").unwrap(),
        ChatPresentationRead::Missing
    );
    assert!(
        second
            .chat_presentation_dependents(&"bb".repeat(32), None)
            .unwrap()
            .is_empty()
    );
    let replacement_account = SqliteAccountStorage::in_memory().unwrap();
    seed(&replacement_account, "11", "");
    drain(&replacement_account, &replacement);
    assert_eq!(
        replacement_account
            .store_chat_presentation(&delayed_input, &delayed_value)
            .unwrap(),
        storage_sqlite::ChatPresentationWrite::Stale
    );
}

#[test]
fn named_pair_roster_matches_durable_order_and_unchanged_hydration_stays_clean() {
    let account = SqliteAccountStorage::in_memory().unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    seed(&account, "11", "Named pair");
    drain(&account, &shared);
    let mut state = account
        .load_account_projection_state("fixture", 100)
        .unwrap();
    let mut group =
        crate::conversions::app_group_from_stored_group(state.groups[0].clone()).unwrap();
    let before = group.presentation_member_ids_hex.clone();
    let members = ["bb", "aa"].map(|id| cgka_traits::group::Member {
        id: cgka_traits::MemberId::new(hex::decode(id.repeat(32)).unwrap()),
        credential: vec![],
    });
    group.set_direct_member_ids_from_roster(&members);
    assert_eq!(
        group.presentation_member_ids_hex, before,
        "MLS leaf order must not appear as a source change after a durable reload"
    );
    assert!(group.direct_member_ids_hex.is_none());
    let version = account.chat_presentation_version().unwrap();
    let input = account.chat_presentation_input("11").unwrap().unwrap();
    state.groups[0] = crate::conversions::stored_group_from_app_group(&group);
    account.save_account_projection_delta_clearing_local_group_deletion_frontiers_and_acking_application_events(
        &state, 101, 121, &[], &[],
    ).unwrap();
    assert_eq!(
        account
            .chat_presentation_input("11")
            .unwrap()
            .unwrap()
            .source_version,
        input.source_version
    );
    assert!(!maintain(&account, &shared, &"aa".repeat(32)).unwrap());
    assert_eq!(account.chat_presentation_version().unwrap(), version);
    group.profile.name.clear();
    group.set_direct_member_ids_from_roster(&members);
    assert_eq!(group.direct_member_ids_hex, before);
    group.set_direct_member_ids_from_roster(&[members[0].clone(), members[0].clone()]);
    assert!(group.presentation_member_ids_hex.is_none());
    assert!(group.direct_member_ids_hex.is_none());
}
