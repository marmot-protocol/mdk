use super::*;
use crate::ChatListSelectionSnapshot;
use cgka_traits::group::Member;
use cgka_traits::storage::GroupStorage;
use cgka_traits::types::{GroupId, MemberId};

fn seed(
    store: &SqliteAccountStorage,
    n: usize,
    archive: bool,
    unread: bool,
    title: &str,
    member: u8,
) -> String {
    let id = format!("{n:08x}");
    let mut group =
        crate::storage::test_support::sample_group(GroupId::new(hex::decode(&id).unwrap()), 0, 0);
    group.members = vec![Member {
        id: MemberId::new(vec![member; 32]),
        credential: vec![],
    }];
    store.put_group(&group).unwrap();
    let conn = store.lock().unwrap();
    conn.execute("INSERT INTO account_groups(group_id_hex,endpoint,updated_at,archived,member_count,profile_description)
        VALUES(?1,'',0,?2,3,'description')", params![id,archive]).unwrap();
    conn.execute("INSERT INTO chat_list_rows(group_id_hex,updated_at,archived,group_name,unread_count,
        presentation_json,presentation_applied_source_revision,folder_title_fold,folder_description_fold)
        VALUES(?1,0,?2,?3,?4,x'7b7d',0,?5,'description')",params![id,archive,title,unread as i64,fold_literal(title)]).unwrap();
    conn.execute(
        "DELETE FROM chat_presentation_row_work WHERE group_id_hex=?1",
        [&id],
    )
    .unwrap();
    id
}
fn ids(store: &SqliteAccountStorage, rule: ChatFolderSelectionRule) -> Vec<String> {
    snapshot_ids(store, &store.chat_folder_selection_snapshot(rule).unwrap())
}
fn snapshot_ids(store: &SqliteAccountStorage, snapshot: &ChatListSelectionSnapshot) -> Vec<String> {
    let count = store.chat_list_selection_count(snapshot).unwrap();
    (0..count)
        .step_by(200)
        .flat_map(|n| store.chat_list_selection_page(snapshot, n, 200).unwrap())
        .collect()
}

#[test]
fn full_folder_matches_beyond_two_hundred_without_loading_history() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..501 {
        seed(&store, n, false, true, "Project", 1);
    }
    let rule = ChatFolderSelectionRule {
        keyword: Some("project".into()),
        ..Default::default()
    };
    assert_eq!(ids(&store, rule).len(), 501);
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM cgka_messages", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn empty_is_manual_only_and_exclusions_win_across_archive_and_mute() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = seed(&store, 1, false, false, "A", 1);
    let b = seed(&store, 2, true, false, "B", 2);
    assert!(ids(&store, ChatFolderSelectionRule::default()).is_empty());
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO chat_notification_settings VALUES(?1,NULL,0)",
            [&b],
        )
        .unwrap();
    assert_eq!(
        ids(
            &store,
            ChatFolderSelectionRule {
                manual_include_ids: vec![a.clone(), b.clone(), "ff".into()],
                manual_exclude_ids: vec![a],
                ..Default::default()
            }
        ),
        [b]
    );
}

#[test]
fn member_or_keyword_then_categories_matches_existing_android_rules() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = seed(&store, 1, false, true, "Other", 1);
    let b = seed(&store, 2, false, true, "Project", 2);
    seed(&store, 3, false, false, "Project", 2);
    seed(&store, 4, true, true, "Project", 1);
    let muted = seed(&store, 5, false, true, "Project", 1);
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO chat_notification_settings VALUES(?1,NULL,0)",
            [&muted],
        )
        .unwrap();
    let rule = ChatFolderSelectionRule {
        include_member_ids: vec!["01".repeat(32)],
        keyword: Some("project".into()),
        unread_only: true,
        groups_only: true,
        ..Default::default()
    };
    assert_eq!(ids(&store, rule.clone()), [a, b]);
    assert_eq!(
        ids(
            &store,
            ChatFolderSelectionRule {
                include_muted: true,
                ..rule
            }
        )
        .len(),
        3
    );
    assert_eq!(
        ids(
            &store,
            ChatFolderSelectionRule {
                archived_only: true,
                include_muted: true,
                ..Default::default()
            }
        ),
        ["00000004"]
    );
}

#[test]
fn unicode_literal_matching_has_no_sql_like_wildcards_or_locale_dependency() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = seed(&store, 1, false, false, "ÄΣΟΣ 中文 100%_", 1);
    for text in ["äσος", "中文", "%_"] {
        assert_eq!(
            ids(
                &store,
                ChatFolderSelectionRule {
                    keyword: Some(text.into()),
                    ..Default::default()
                }
            ),
            std::slice::from_ref(&a)
        );
    }
    assert!(
        ids(
            &store,
            ChatFolderSelectionRule {
                keyword: Some("%anything".into()),
                ..Default::default()
            }
        )
        .is_empty()
    );
    assert_eq!(fold_literal("İ"), "i\u{307}");
}

#[test]
fn frozen_folder_revalidation_only_removes_after_rule_inputs_change() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = seed(&store, 1, false, false, "Project", 1);
    let b = seed(&store, 2, false, false, "Project", 1);
    let snapshot = store
        .chat_folder_selection_snapshot(ChatFolderSelectionRule {
            keyword: Some("project".into()),
            ..Default::default()
        })
        .unwrap();
    seed(&store, 3, false, false, "Project", 1);
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_list_rows SET folder_title_fold='other' WHERE group_id_hex=?1",
            [&b],
        )
        .unwrap();
    assert_eq!(snapshot_ids(&store, &snapshot), [a.clone(), b]);
    assert_eq!(
        snapshot_ids(
            &store,
            &store.revalidate_chat_list_selection(&snapshot).unwrap()
        ),
        [a]
    );
}

#[test]
fn unknown_required_roster_or_stale_text_never_returns_partial_success() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = seed(&store, 1, false, false, "Project", 1);
    let b = seed(&store, 2, false, false, "Project", 2);
    let keyword = ChatFolderSelectionRule {
        keyword: Some("project".into()),
        ..Default::default()
    };
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_list_rows SET presentation_source_revision=1 WHERE group_id_hex=?1",
            [&b],
        )
        .unwrap();
    assert!(matches!(
        store.chat_folder_selection_snapshot(keyword),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
    let members = ChatFolderSelectionRule {
        include_member_ids: vec!["01".repeat(32)],
        ..Default::default()
    };
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM chat_folder_rosters WHERE group_id_hex=?1",
            [&b],
        )
        .unwrap();
    assert!(matches!(
        store.chat_folder_selection_snapshot(members.clone()),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
    assert_eq!(
        ids(
            &store,
            ChatFolderSelectionRule {
                manual_exclude_ids: vec![b],
                ..members
            }
        ),
        [a]
    );
}

#[test]
fn same_epoch_same_size_roster_replacement_and_raw_restore_invalidate_index() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = seed(&store, 1, false, false, "Group", 1);
    let id = GroupId::new(hex::decode(&a).unwrap());
    let rule = ChatFolderSelectionRule {
        include_member_ids: vec!["01".repeat(32)],
        ..Default::default()
    };
    assert_eq!(ids(&store, rule.clone()), [a]);
    let old = store.get_group(&id).unwrap();
    let mut next = old.clone();
    next.members[0].id = MemberId::new(vec![2; 32]);
    store.put_group(&next).unwrap();
    assert!(ids(&store, rule.clone()).is_empty());
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE cgka_groups SET record=?2 WHERE id=?1",
            params![id.as_slice(), crate::serialize(&old).unwrap()],
        )
        .unwrap();
    assert!(matches!(
        store.chat_folder_selection_snapshot(rule.clone()),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
    assert!(!store.prepare_chat_folder_rosters().unwrap());
    assert_eq!(ids(&store, rule), ["00000001"]);
}

#[test]
fn roster_backfill_is_bounded_and_does_not_change_two_member_presentation_index() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..51 {
        seed(&store, n, false, false, "Group", 1);
    }
    store.lock().unwrap().execute_batch("DELETE FROM chat_folder_rosters; INSERT INTO chat_folder_roster_work SELECT id FROM cgka_groups;").unwrap();
    assert!(store.prepare_chat_folder_rosters().unwrap());
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM chat_folder_roster_work", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(!store.prepare_chat_folder_rosters().unwrap());
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM chat_presentation_members", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
}

#[test]
fn group_category_matches_native_kind_including_small_and_unknown_rosters() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for (n, count) in [(0, 0), (1, 1), (2, 2), (3, 3)] {
        let id = seed(&store, n, false, false, "\u{00a0}", 1);
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_groups SET member_count=?2 WHERE group_id_hex=?1",
                params![id, count],
            )
            .unwrap();
    }
    let rule = ChatFolderSelectionRule {
        groups_only: true,
        ..Default::default()
    };
    assert_eq!(
        ids(&store, rule.clone()),
        ["00000000", "00000001", "00000003"]
    );
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET member_count=NULL WHERE group_id_hex='00000002'",
            [],
        )
        .unwrap();
    assert!(matches!(
        store.chat_folder_selection_snapshot(rule),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
}

#[test]
fn malformed_excessive_or_unsupported_rules_are_typed_errors() {
    for rule in [
        ChatFolderSelectionRule {
            version: 2,
            ..Default::default()
        },
        ChatFolderSelectionRule {
            include_member_ids: vec!["wrong".into()],
            ..Default::default()
        },
        ChatFolderSelectionRule {
            manual_include_ids: vec!["1".into()],
            ..Default::default()
        },
        ChatFolderSelectionRule {
            keyword: Some("x".repeat(1025)),
            ..Default::default()
        },
        ChatFolderSelectionRule {
            manual_include_ids: vec!["aa".into(); 1025],
            ..Default::default()
        },
    ] {
        assert!(matches!(
            rule.validate(),
            Err(ChatListSelectionError::InvalidFilter)
        ));
    }
}

#[test]
fn required_input_checks_and_member_match_use_compact_indexes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, 1, false, false, "Group", 1);
    let conn = store.lock().unwrap();
    let mut statement=conn.prepare("EXPLAIN QUERY PLAN SELECT r.group_id_hex FROM chat_list_rows r INDEXED BY idx_chat_list_page
        WHERE list_scope IN (0,1) AND EXISTS(SELECT 1 FROM chat_folder_rosters roster
        JOIN chat_folder_members member ON member.group_id=roster.group_id
        WHERE roster.group_id_hex=r.group_id_hex AND member.member_id_hex=?1)").unwrap();
    let details = statement
        .query_map(["01".repeat(32)], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" ");
    assert!(details.contains("idx_chat_list_page"), "{details}");
    assert!(
        details.contains("INDEX") && !details.contains("SCAN member"),
        "{details}"
    );
}

#[test]
fn explicit_all_mentions_direct_and_pinned_legacy_flags_have_native_parity() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = seed(&store, 1, false, true, "", 1);
    let b = seed(&store, 2, false, true, "Group", 2);
    {
        let conn = store.lock().unwrap();
        conn.execute(
            "UPDATE account_groups SET member_count=2 WHERE group_id_hex=?1",
            [&a],
        )
        .unwrap();
        conn.execute(
            "UPDATE chat_list_rows SET unread_mention_count=1 WHERE group_id_hex=?1",
            [&a],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_pin_positions(group_id_hex,ordinal) VALUES(?1,0)",
            [&a],
        )
        .unwrap();
    }
    assert_eq!(
        ids(
            &store,
            ChatFolderSelectionRule {
                include_all: true,
                ..Default::default()
            }
        ),
        [a.clone(), b]
    );
    assert_eq!(
        ids(
            &store,
            ChatFolderSelectionRule {
                unread_mentions_only: true,
                direct_chats_only: true,
                pinned_only: true,
                ..Default::default()
            }
        ),
        [a]
    );
    assert!(
        ids(
            &store,
            ChatFolderSelectionRule {
                groups_only: true,
                direct_chats_only: true,
                ..Default::default()
            }
        )
        .is_empty()
    );
}

fn condition(field: &str, mode: &str, values: Vec<String>, not: bool) -> serde_json::Value {
    serde_json::json!({"kind":"condition","field":field,"mode":mode,"values":values,"not":not})
}
fn smart_rule(children: Vec<serde_json::Value>, all: bool, not: bool) -> ChatFolderSelectionRule {
    ChatFolderSelectionRule{smart_filter_json:Some(serde_json::json!({"version":1,"root":{"kind":"group","all":all,"not":not,"children":children}}).to_string()),..Default::default()}
}

#[test]
fn smart_all_any_not_manual_overrides_and_archive_cross_scope_are_complete() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = seed(&store, 1, false, true, "Project", 1);
    let b = seed(&store, 2, true, false, "Other", 2);
    let c = seed(&store, 3, false, false, "Third", 3);
    let keyword = condition("TITLE", "CONTAINS", vec!["project".into()], false);
    let archive = condition("ARCHIVED", "PRESENT", vec![], false);
    assert_eq!(
        ids(
            &store,
            smart_rule(vec![keyword.clone(), archive.clone()], false, false)
        ),
        [a.clone(), b.clone()]
    );
    assert!(
        ids(
            &store,
            smart_rule(vec![keyword.clone(), archive.clone()], true, false)
        )
        .is_empty()
    );
    assert_eq!(
        ids(&store, smart_rule(vec![keyword, archive], false, true)),
        std::slice::from_ref(&c)
    );
    assert!(ids(&store, smart_rule(vec![], true, true)).is_empty());
    assert_eq!(
        ids(
            &store,
            ChatFolderSelectionRule {
                manual_include_ids: vec![b.clone()],
                manual_exclude_ids: vec![a],
                ..smart_rule(
                    vec![condition("UNREAD", "PRESENT", vec![], false)],
                    true,
                    false
                )
            }
        ),
        [b]
    );
    assert_eq!(
        ids(
            &store,
            smart_rule(
                vec![condition("UNREAD", "NONE", vec![], false)],
                true,
                false
            )
        )
        .len(),
        2
    );
}

#[test]
fn smart_participant_truth_and_title_parameterization_do_not_expand_input() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = seed(&store, 1, false, false, "literal ' OR 1=1 --", 1);
    let b = seed(&store, 2, false, false, "Other", 2);
    assert_eq!(
        ids(
            &store,
            smart_rule(
                vec![condition(
                    "PARTICIPANTS",
                    "ANY_OF",
                    vec!["01".repeat(32)],
                    false
                )],
                true,
                false
            )
        ),
        std::slice::from_ref(&a)
    );
    assert!(
        ids(
            &store,
            smart_rule(
                vec![condition(
                    "PARTICIPANTS",
                    "ALL_OF",
                    vec!["01".repeat(32), "02".repeat(32)],
                    false
                )],
                true,
                false
            )
        )
        .is_empty()
    );
    assert_eq!(
        ids(
            &store,
            smart_rule(
                vec![condition(
                    "PARTICIPANTS",
                    "EXCLUDES",
                    vec!["01".repeat(32)],
                    false
                )],
                true,
                false
            )
        ),
        [b]
    );
    assert_eq!(
        ids(
            &store,
            smart_rule(
                vec![condition(
                    "TITLE",
                    "CONTAINS",
                    vec!["' OR 1=1 --".into()],
                    false
                )],
                true,
                false
            )
        ),
        std::slice::from_ref(&a)
    );
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM chat_folder_rosters WHERE group_id_hex=?1",
            [&a],
        )
        .unwrap();
    assert!(matches!(
        store.chat_folder_selection_snapshot(smart_rule(
            vec![condition(
                "PARTICIPANTS",
                "EXCLUDES",
                vec!["01".repeat(32)],
                false
            )],
            true,
            false
        )),
        Err(ChatListSelectionError::ProjectionNotReady)
    ));
}

#[test]
fn smart_draft_and_complete_pending_send_use_current_sources_not_latest_preview() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = seed(&store, 1, false, false, "A", 1);
    let b = seed(&store, 2, false, false, "B", 2);
    store
        .save_message_draft(&a, "\u{00a0} \n", None, &[])
        .unwrap();
    assert!(
        ids(
            &store,
            smart_rule(
                vec![condition("DRAFT", "PRESENT", vec![], false)],
                true,
                false
            )
        )
        .is_empty()
    );
    store.save_message_draft(&a, "draft", None, &[]).unwrap();
    assert_eq!(
        ids(
            &store,
            smart_rule(
                vec![condition("DRAFT", "PRESENT", vec![], false)],
                true,
                false
            )
        ),
        [a]
    );
    store
        .insert_local_submission(&crate::LocalSubmission {
            group_id_hex: b.clone(),
            client_token: "fixture".into(),
            message_id_hex: "aa".repeat(32),
            request_hash: vec![0; 32],
            payload_hash: vec![0; 32],
            payload: None,
            request_json: None,
            state: 0,
            outcome_json: None,
        })
        .unwrap();
    let pending = smart_rule(
        vec![condition("PENDING_SEND", "PRESENT", vec![], false)],
        true,
        false,
    );
    assert_eq!(ids(&store, pending.clone()), std::slice::from_ref(&b));
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE local_message_submissions SET state=1 WHERE group_id_hex=?1",
            [&b],
        )
        .unwrap();
    assert!(ids(&store, pending.clone()).is_empty());
    // An older local send still counts even when the latest preview is received.
    store.lock().unwrap().execute(
        "INSERT INTO message_timeline(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json)
            VALUES(?1,?2,'sent','self','older',9,'[]',1,1,'[]')",
        params![b, "ab".repeat(32)],
    ).unwrap();
    assert_eq!(ids(&store, pending.clone()), std::slice::from_ref(&b));
    let plan: Vec<String> = store.lock().unwrap().prepare(
        "EXPLAIN QUERY PLAN SELECT 1 FROM message_timeline pending INDEXED BY idx_chat_folder_pending_send WHERE group_id_hex=?1 AND direction='sent' AND source_message_id_hex IS NULL AND invalidation_status IS NULL AND deleted=0",
    ).unwrap().query_map([&b], |row| row.get(3)).unwrap().collect::<Result<_,_>>().unwrap();
    assert!(
        plan.iter()
            .any(|line| line.contains("SEARCH pending USING INDEX idx_chat_folder_pending_send")),
        "{plan:?}"
    );
    for change in [
        "deleted=1",
        "deleted=0,invalidation_status='failed'",
        "invalidation_status=NULL,source_message_id_hex='confirmed'",
    ] {
        store
            .lock()
            .unwrap()
            .execute(
                &format!("UPDATE message_timeline SET {change} WHERE group_id_hex=?1"),
                [&b],
            )
            .unwrap();
        assert!(ids(&store, pending.clone()).is_empty());
    }
}

#[test]
fn smart_invalid_subtrees_versions_depth_nodes_and_values_fail_whole_rule() {
    for rule in [
        smart_rule(
            vec![condition("TITLE", "CONTAINS", vec!["x".repeat(257)], false)],
            true,
            false,
        ),
        smart_rule(
            vec![condition(
                "PARTICIPANTS",
                "ANY_OF",
                vec!["AB".repeat(32)],
                false,
            )],
            true,
            false,
        ),
        smart_rule(
            vec![condition(
                "UNREAD",
                "PRESENT",
                vec!["unexpected".into()],
                false,
            )],
            true,
            false,
        ),
        smart_rule(
            vec![condition("UNREAD", "PRESENT", vec![], false); 64],
            true,
            false,
        ),
        smart_rule(
            vec![serde_json::json!({"kind":"group","all":true,"not":true,"children":[]})],
            true,
            false,
        ),
        ChatFolderSelectionRule {
            smart_filter_json: Some("{\"version\":2,\"root\":{}}".into()),
            ..Default::default()
        },
        ChatFolderSelectionRule {
            smart_filter_json: Some(" ".repeat(65537)),
            ..Default::default()
        },
    ] {
        assert!(matches!(
            rule.validate(),
            Err(ChatListSelectionError::InvalidFilter)
        ));
    }
    let mut root = condition("UNREAD", "PRESENT", vec![], false);
    for _ in 0..6 {
        root = serde_json::json!({"kind":"group","all":true,"not":false,"children":[root]});
    }
    assert!(matches!(
        smart_rule(vec![root], true, false).validate(),
        Err(ChatListSelectionError::InvalidFilter)
    ));
}
