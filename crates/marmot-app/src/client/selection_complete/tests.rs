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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_mutation_frontguards_are_known_non_effects_without_deleting_rows() {
    use crate::chat_selection::capture::SelectionMutation;
    use cgka_traits::storage::{DisbandRequest, DisbandRequestStatus, DisbandRequestStorage};
    for case in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("Front guard", &[]).await.unwrap();
        let id = hex::encode(group.as_slice());
        let store = app.account_storage("alice").unwrap();
        store
            .app_storage()
            .refresh_chat_list_rows(&account.account_id_hex, &|_, _| false)
            .unwrap();
        let shared = app.shared_storage().unwrap();
        let mut settled = false;
        for _ in 0..32 {
            if !crate::chat_presentation::maintenance::prepare_batch(
                &store,
                &shared,
                &account.account_id_hex,
            )
            .unwrap()
            {
                settled = true;
                break;
            }
        }
        assert!(settled);
        let mut input = request(&account.account_id_hex);
        input.original_ids = Some(vec![id.clone()]);
        let bound = client
            .capture_complete_selection(input.clone(), &|| false)
            .unwrap();
        assert_eq!(bound.resolved_ids().unwrap(), vec![id.clone()]);
        if case == 0 {
            // Fresh native row still exists; the worker's actual archive source
            // has no matching group. This is before the archive primitive.
            client
                .state
                .groups
                .retain(|current| current.group_id_hex != id);
        } else {
            store
                .put_disband_request(&DisbandRequest {
                    group_id: group.clone(),
                    requested_at_ms: 1000,
                    status: DisbandRequestStatus::Pending,
                    last_prepared_epoch: None,
                })
                .unwrap();
            assert!(client.runtime.disbanding_in_progress(&group).unwrap());
        }
        let probe = client
            .capture_complete_selection(input.clone(), &|| false)
            .unwrap();
        eprintln!(
            "selection frontguard diagnostic: case={} fresh_count={} state_has_group={} owner_current={} epoch_equal={}",
            case,
            probe.resolved_ids().unwrap().len(),
            client
                .state
                .groups
                .iter()
                .any(|current| current.group_id_hex == id),
            app.account_storage_is_current("alice", &bound.owner),
            probe.owner_epoch == bound.owner_epoch,
        );
        if case < 2 {
            let mutation = if case == 0 {
                SelectionMutation::Archive { archived: true }
            } else {
                SelectionMutation::DeleteLocal
            };
            let outcome = client
                .apply_complete_selection(
                    input,
                    None,
                    bound.owner,
                    bound.owner_epoch,
                    mutation,
                    1,
                    902,
                    &|| false,
                )
                .await
                .unwrap();
            let SelectionApplyOutcome::Applied {
                report, changed, ..
            } = outcome
            else {
                panic!("unexpected host presentation request")
            };
            assert!(report.applied_group_ids.is_empty());
            assert!(changed.is_empty());
            if case == 0 {
                // Missing worker state reaches the explicit archive front guard.
                assert_eq!(report.failed_group_id, Some(id.clone()));
                assert_eq!(report.remaining, 1);
            } else {
                // The newly pending disband is already outside the fresh scope;
                // it is removed before the local-delete primitive is considered.
                assert_eq!(report.failed_group_id, None);
                assert_eq!(report.remaining, 0);
            }
            assert!(!report.uncertain);
        } else {
            let outcome = client
                .depart_complete_selection(
                    input,
                    None,
                    bound.owner,
                    bound.owner_epoch,
                    id.clone(),
                    crate::runtime::ChatSelectionDepartureStep::DeleteLocal,
                    false,
                    &|| false,
                )
                .await
                .unwrap();
            assert!(matches!(
                outcome,
                super::departure::SelectionDepartureOutcome::Effect {
                    changed: false,
                    skipped: true,
                    error: None,
                    refused_before_effect: true,
                    ..
                }
            ));
        }
        let row = store.app_storage().chat_list_row(&id).unwrap().unwrap();
        assert!(!row.archived);
        assert_eq!(store.get_group(&group).unwrap().id, group);
        drop(client);
        app.close_storage().unwrap();
    }
}
