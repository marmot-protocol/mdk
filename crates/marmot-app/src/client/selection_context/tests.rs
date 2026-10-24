use super::*;
use crate::smart_folder::*;
use crate::*;
use cgka_traits::storage::GroupStorage;
use cgka_traits::{EpochId, Group, GroupId, Member, MemberId};
use marmot_account::AccountHome;
use std::sync::Arc;
use storage_sqlite::StoredAccountState;

fn key(n: usize) -> [u8; 32] {
    let mut key = [0; 32];
    key[..8].copy_from_slice(&(n as u64).to_le_bytes());
    key
}
fn leaf(
    values: impl IntoIterator<Item = usize>,
    mode: SmartFolderMode,
    not: bool,
) -> SmartFolderPredicate {
    SmartFolderPredicate::Condition {
        field: SmartFolderField::Participants,
        mode,
        values: values.into_iter().map(|n| hex::encode(key(n))).collect(),
        not,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_composition_uses_whole_union_and_matches_independent_leaf_truth() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
    let client = app.client("alice").await.unwrap();
    let store = app.account_storage("alice").unwrap();
    let epoch = store
        .app_storage()
        .chat_presentation_version()
        .unwrap()
        .store_epoch;
    client
        .runtime
        .session()
        .with_members_read_snapshot::<_, cgka_traits::StorageError>(|exact, _| {
            assert!(
                !exact.shares_connection_with(&store),
                "production session owns a distinct connection"
            );
            assert_eq!(
                exact.app_storage().chat_presentation_version()?.store_epoch,
                epoch
            );
            Ok(())
        })
        .unwrap();
    let id = GroupId::new(vec![1; 4]);
    let group = Group {
        id: id.clone(),
        name: "Native".into(),
        description: String::new(),
        epoch: EpochId(0),
        members: [63, 64, 127]
            .into_iter()
            .map(|n| Member {
                id: MemberId::new(key(n).to_vec()),
                credential: vec![],
            })
            .collect(),
        required_capabilities: Default::default(),
        protocol_profile: cgka_traits::group::ProtocolProfile::Legacy,
        removed: false,
        unrecoverable: false,
        disbanded: None,
        join_epoch: EpochId(0),
        local_copy_install_epoch: EpochId(0),
        local_copy_welcome_created_at: None,
    };
    // A foreign write before capture is intentionally accepted by the same live
    // owner's shipped members path too; this is not a new provenance guarantee.
    store.put_group(&group).unwrap();
    assert_eq!(client.runtime.session().members(&id).unwrap().len(), 3);
    let row = AppGroupRecord::new(
        hex::encode(id.as_slice()),
        AppGroupNostrRoutingComponent::new(cgka_traits::app_components::NostrRoutingV1 {
            nostr_group_id: [1; 32],
            relays: vec!["wss://relay.example".into()],
        })
        .unwrap(),
        "Native".into(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(vec![]),
        AppGroupMessageRetentionComponent::disabled(),
    );
    store
        .app_storage()
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".into(),
                groups: vec![crate::conversions::stored_group_from_app_group(&row)],
                ..Default::default()
            },
            100,
            120,
        )
        .unwrap();
    store
        .app_storage()
        .refresh_chat_list_rows(&account.account_id_hex, &|_, _| false)
        .unwrap();
    let rule = SmartFolderPredicate::Group {
        all: true,
        not: false,
        children: vec![
            leaf(0..64, SmartFolderMode::AnyOf, false),
            leaf(64..128, SmartFolderMode::AllOf, true),
            leaf([64, 128], SmartFolderMode::AnyOf, false),
            leaf([128], SmartFolderMode::Excludes, false),
        ],
    };
    let compiled = CompiledNativeFolder::new(&rule).unwrap();
    assert_eq!(compiled.keys.as_ref().unwrap().len(), 129);
    assert_eq!(compiled.keys.as_ref().unwrap().index_of(&key(64)), Some(64));
    assert_eq!(
        client
            .capture_native_folder_context(ChatListView::Chats, &rule, 1000, &|| false)
            .unwrap(),
        vec![hex::encode(id.as_slice())]
    );
    let folded: HashSet<_> = [63, 64, 127]
        .into_iter()
        .map(|n| hex::encode(key(n)))
        .collect();
    for mode in [
        SmartFolderMode::AnyOf,
        SmartFolderMode::AllOf,
        SmartFolderMode::Excludes,
    ] {
        for not in [false, true] {
            for values in [vec![63], vec![63, 128], vec![128]] {
                let rule = leaf(values, mode, not);
                let expected = evaluate_smart_folder_with_context(
                    &rule,
                    &SmartFolderContext {
                        participants: Some(SmartFolderParticipants {
                            folded_member_ids: &folded,
                            resolved_peer: None,
                            roster_nonempty: true,
                            conversation_kind: ChatConversationKind::Group,
                        }),
                        ..Default::default()
                    },
                )
                .unwrap();
                let ids = client
                    .capture_native_folder_context(ChatListView::Chats, &rule, 1000, &|| false)
                    .unwrap();
                assert_eq!(
                    !ids.is_empty(),
                    expected == FolderTruth::True,
                    "{mode:?}/{not}"
                );
            }
        }
    }
    let zero = SmartFolderPredicate::Group {
        all: true,
        children: vec![],
        not: true,
    };
    assert!(CompiledNativeFolder::new(&zero).unwrap().keys.is_none());
    assert!(
        client
            .capture_native_folder_context(ChatListView::Chats, &zero, 1000, &|| false)
            .unwrap()
            .is_empty()
    );
    assert!(
        client
            .capture_native_folder_context(ChatListView::Chats, &rule, 1000, &|| true)
            .is_err()
    );
    // A real different store epoch must fail even when that cached handle is
    // current. Never substitute it for the live session's dedicated SQL store.
    let other = storage_sqlite::SqliteAccountStorage::in_memory().unwrap();
    assert_ne!(
        other
            .app_storage()
            .chat_presentation_version()
            .unwrap()
            .store_epoch,
        epoch
    );
    let original = app
        .account_storages
        .lock()
        .unwrap()
        .insert("alice".into(), other)
        .unwrap();
    assert!(matches!(
        client.capture_native_folder_context(ChatListView::Chats, &rule, 1000, &|| false),
        Err(NativeFolderCaptureError::App(AppError::RuntimeStopping))
    ));
    app.account_storages
        .lock()
        .unwrap()
        .insert("alice".into(), original);
    app.drop_account_caches("alice");
    assert!(matches!(
        client.capture_native_folder_context(ChatListView::Chats, &rule, 1000, &|| false),
        Err(NativeFolderCaptureError::App(AppError::RuntimeStopping))
    ));
    assert!(
        !app.account_storage_cached_for_test("alice"),
        "rejected capture must not lazily reopen a cache"
    );
    app.close_storage().unwrap();
    app.account_home().remove_account("alice").unwrap();
    assert!(app.account_home().account("alice").is_err());
    assert!(
        client
            .capture_native_folder_context(ChatListView::Chats, &rule, 1000, &|| false)
            .is_err()
    );
}

#[test]
fn complete_tree_validation_preserves_existing_limits_without_global64_cap() {
    let max = SmartFolderPredicate::Group {
        all: true,
        not: false,
        children: (0..63)
            .map(|leaf_index| {
                leaf(
                    leaf_index * 64..(leaf_index + 1) * 64,
                    SmartFolderMode::AnyOf,
                    false,
                )
            })
            .collect(),
    };
    let compiled = CompiledNativeFolder::new(&max).unwrap();
    let keys = compiled.keys.as_ref().unwrap();
    assert_eq!(keys.len(), 4032);
    assert_eq!(keys.index_of(&key(4031)), Some(4031));
    let invalid = SmartFolderPredicate::Group {
        all: false,
        not: false,
        children: vec![
            leaf([1], SmartFolderMode::AnyOf, false),
            leaf([1, 1], SmartFolderMode::AnyOf, false),
        ],
    };
    assert!(matches!(
        CompiledNativeFolder::new(&invalid),
        Err(SmartFolderError::InvalidValues)
    ));
    for field in [
        SmartFolderField::Accepted,
        SmartFolderField::PendingSend,
        SmartFolderField::Title,
    ] {
        let rule = SmartFolderPredicate::Group {
            all: false,
            not: false,
            children: vec![
                leaf([1], SmartFolderMode::AnyOf, false),
                SmartFolderPredicate::Condition {
                    field,
                    mode: SmartFolderMode::Present,
                    values: vec![],
                    not: false,
                },
            ],
        };
        assert!(
            matches!(CompiledNativeFolder::new(&rule),Err(SmartFolderError::UnsupportedField(actual)) if actual==field)
        );
    }
}
