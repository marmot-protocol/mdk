use super::*;
use crate::chat_selection::capture::HostOverlays;
use crate::chat_selection::presentation::{HostContextIdentity, PresentationAnswer};
use crate::chat_selection::scope::{AutomaticRule, FolderScope, ScopeRequest};
use crate::smart_folder::{SmartFolderField, SmartFolderMode, SmartFolderPredicate};
use crate::*;
use cgka_traits::storage::GroupStorage;
use cgka_traits::{EpochId, Group, GroupId, Member, MemberId};
use marmot_account::AccountHome;
use std::collections::HashSet;
use std::sync::{Arc, atomic::AtomicBool};
use storage_sqlite::{
    ConversationPresentation, PresentationResolution, PresentationSource, PresentationText,
    SelectedAvatar, SelectionBaseScope, StoredAccountState, StoredChatPresentation,
};
fn scope() -> ScopeRequest {
    ScopeRequest {
        selected_folder: None,
        filter_folders: None,
        named_chats: None,
        direct: false,
        groups: false,
        search: None,
    }
}
fn request(account: &str) -> CaptureRequest {
    CaptureRequest {
        scope: scope(),
        base: SelectionBaseScope::ActiveAndArchived,
        original_ids: None,
        action_hints: false,
        excluded_cost: (0, 0),
        host: HostContextIdentity {
            account_id_hex: account.into(),
            runtime_generation: 1,
            selection_generation: 1,
            presentation_context_id: 1,
        },
        overlays: HostOverlays::default(),
        revision: 1,
        capture_now_ms: 1000,
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_capture_app_two_phase_union_and_keyed_shrink() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
    let client = app.client("alice").await.unwrap();
    let store = app.account_storage("alice").unwrap();
    let active = hex::decode(&account.account_id_hex).unwrap();
    let remote = vec![9; 32];
    let mut rows = Vec::new();
    for (n, name, archived) in [(1, "Alpha", false), (2, "Beta", true), (3, "Gamma", false)] {
        let id = GroupId::new(vec![n; 4]);
        store
            .put_group(&Group {
                id: id.clone(),
                name: name.into(),
                description: String::new(),
                epoch: EpochId(0),
                members: [active.clone(), remote.clone()]
                    .into_iter()
                    .map(|id| Member {
                        id: MemberId::new(id),
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
            })
            .unwrap();
        let mut row = AppGroupRecord::new(
            hex::encode(id.as_slice()),
            AppGroupNostrRoutingComponent::new(cgka_traits::app_components::NostrRoutingV1 {
                nostr_group_id: [n; 32],
                relays: vec!["wss://relay.example".into()],
            })
            .unwrap(),
            name.into(),
            String::new(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(vec![]),
            AppGroupMessageRetentionComponent::disabled(),
        );
        row.archived = archived;
        row.member_count = Some(2);
        row.presentation_member_ids_hex =
            Some(vec![account.account_id_hex.clone(), hex::encode(&remote)]);
        rows.push(crate::conversions::stored_group_from_app_group(&row));
    }
    store
        .app_storage()
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".into(),
                groups: rows,
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
    for n in 1..=3 {
        let id = hex::encode([n; 4]);
        let input = store
            .app_storage()
            .chat_presentation_input(&id)
            .unwrap()
            .unwrap();
        let name = match n {
            1 => "Alpha",
            2 => "Beta",
            _ => "Gamma",
        };
        let value = StoredChatPresentation {
            presentation: ConversationPresentation {
                title: PresentationText::Literal(name.into()),
                avatar: SelectedAvatar::Placeholder {
                    stable_seed: "private-avatar-sentinel".into(),
                    source: PresentationSource::Group,
                },
                title_source: PresentationSource::Group,
                avatar_source: PresentationSource::Group,
                peer_id: None,
                resolution: PresentationResolution::Cached,
            },
            profile_version: None,
        };
        assert!(!matches!(
            store
                .app_storage()
                .store_chat_presentation(&input, &value)
                .unwrap(),
            storage_sqlite::ChatPresentationWrite::Stale
        ));
    }
    let all = client
        .capture_complete_selection(request(&account.account_id_hex), &|| false)
        .unwrap()
        .complete()
        .unwrap();
    assert_eq!(all.len(), 3);
    let mut req = request(&account.account_id_hex);
    req.base = SelectionBaseScope::View(ChatListView::Chats);
    req.original_ids = Some(vec![hex::encode([2; 4]), hex::encode([1; 4])]);
    assert_eq!(
        client
            .capture_complete_selection(req, &|| false)
            .unwrap()
            .complete()
            .unwrap(),
        vec![hex::encode([1; 4])]
    );
    let mut req = request(&account.account_id_hex);
    let identity = req.host.clone();
    req.scope.selected_folder = Some(FolderScope {
        manual: HashSet::new(),
        excluded: HashSet::new(),
        automatic: AutomaticRule::Smart(SmartFolderPredicate::Condition {
            field: SmartFolderField::Title,
            mode: SmartFolderMode::Contains,
            values: vec!["Alpha".into()],
            not: false,
        }),
    });
    let mut captured = client.capture_complete_selection(req, &|| false).unwrap();
    let operands = captured
        .presentation
        .as_ref()
        .unwrap()
        .page(0, 200)
        .unwrap();
    assert_eq!(operands.len(), 3);
    let answers: Vec<_> = operands
        .iter()
        .flat_map(|operand| {
            assert!(operand.roster_peer_present);
            assert_eq!(operand.roster_member_count, 2);
            operand
                .leaves
                .iter()
                .map(|leaf| PresentationAnswer {
                    candidate_slot: operand.candidate_slot,
                    leaf_slot: leaf.slot,
                    matches: operand.row_group_name == "Alpha",
                })
                .collect::<Vec<_>>()
        })
        .collect();
    captured.submit(1, &identity, &answers).unwrap();
    assert_eq!(captured.complete().unwrap(), vec![hex::encode([1; 4])]);
    app.close_storage().unwrap();
}
