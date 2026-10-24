use super::*;
use FolderTruth::{False, True, Unknown};

fn projection() -> SmartFolderProjection {
    SmartFolderProjection {
        has_unread: true,
        manually_marked_unread: false,
        unread_count: 0,
        has_unread_mention: false,
        unread_mention_count: 0,
        muted: false,
        pinned: false,
        archived: false,
        conversation_kind: ChatConversationKind::Unknown,
    }
}
fn condition(field: SmartFolderField, mode: SmartFolderMode, not: bool) -> SmartFolderPredicate {
    SmartFolderPredicate::Condition {
        field,
        mode,
        values: vec![],
        not,
    }
}
fn truth_node(truth: FolderTruth) -> SmartFolderPredicate {
    match truth {
        True => condition(SmartFolderField::Unread, SmartFolderMode::Present, false),
        False => condition(SmartFolderField::Muted, SmartFolderMode::Present, false),
        Unknown => condition(SmartFolderField::Type, SmartFolderMode::Direct, false),
    }
}

/// Android SmartFolderMatching.kt: False dominates All, True dominates Any;
/// otherwise Unknown survives. These nine rows are the complete binary oracle.
#[test]
fn android_all_any_not_truth_table() {
    let rows = [
        (True, True, True, True, False, False),
        (True, False, False, True, True, False),
        (True, Unknown, Unknown, True, Unknown, False),
        (False, True, False, True, True, False),
        (False, False, False, False, True, True),
        (False, Unknown, False, Unknown, True, Unknown),
        (Unknown, True, Unknown, True, Unknown, False),
        (Unknown, False, False, Unknown, True, Unknown),
        (Unknown, Unknown, Unknown, Unknown, Unknown, Unknown),
    ];
    for (left, right, all_expected, any_expected, not_all, not_any) in rows {
        for (all, positive, negative) in [
            (true, all_expected, not_all),
            (false, any_expected, not_any),
        ] {
            for (not, expected) in [(false, positive), (true, negative)] {
                let group = SmartFolderPredicate::Group {
                    all,
                    children: vec![truth_node(left), truth_node(right)],
                    not,
                };
                assert_eq!(
                    evaluate_smart_folder(&group, Some(&projection())),
                    Ok(expected)
                );
            }
        }
    }
}

#[test]
fn android_empty_and_missing_projection_remain_unknown_under_not() {
    for all in [false, true] {
        for not in [false, true] {
            assert_eq!(
                evaluate_smart_folder(
                    &SmartFolderPredicate::Group {
                        all,
                        children: vec![],
                        not
                    },
                    Some(&projection())
                ),
                Ok(Unknown),
            );
        }
    }
    for field in [
        SmartFolderField::Unread,
        SmartFolderField::Mentions,
        SmartFolderField::Muted,
        SmartFolderField::Pinned,
        SmartFolderField::Archived,
    ] {
        for mode in [SmartFolderMode::Present, SmartFolderMode::None] {
            for not in [false, true] {
                assert_eq!(
                    evaluate_smart_folder(&condition(field, mode, not), None),
                    Ok(Unknown)
                );
            }
        }
    }
    for mode in [SmartFolderMode::Direct, SmartFolderMode::Group] {
        for not in [false, true] {
            assert_eq!(
                evaluate_smart_folder(&condition(SmartFolderField::Type, mode, not), None),
                Ok(Unknown)
            );
        }
    }
}

#[test]
fn android_scalar_sources_and_none_then_not_parity() {
    let unread_rows = [
        (false, false, 0, False),
        (true, false, 0, True),
        (false, true, 0, True),
        (false, false, 1, True),
        (true, true, 0, True),
        (true, false, u64::MAX, True),
        (false, true, 1, True),
        (true, true, 1, True),
    ];
    for (has_unread, manually_marked_unread, unread_count, expected) in unread_rows {
        let input = SmartFolderProjection {
            has_unread,
            manually_marked_unread,
            unread_count,
            ..projection()
        };
        assert_eq!(
            evaluate_smart_folder(&truth_node(True), Some(&input)),
            Ok(expected)
        );
    }
    for (has_unread_mention, unread_mention_count, expected) in [
        (false, 0, False),
        (true, 0, True),
        (false, 1, True),
        (true, u64::MAX, True),
    ] {
        let input = SmartFolderProjection {
            has_unread: false,
            has_unread_mention,
            unread_mention_count,
            ..projection()
        };
        assert_eq!(
            evaluate_smart_folder(
                &condition(SmartFolderField::Mentions, SmartFolderMode::Present, false),
                Some(&input)
            ),
            Ok(expected)
        );
    }
    for field in [
        SmartFolderField::Muted,
        SmartFolderField::Pinned,
        SmartFolderField::Archived,
    ] {
        for (value, present, none) in [(false, False, True), (true, True, False)] {
            let input = SmartFolderProjection {
                muted: value,
                pinned: value,
                archived: value,
                ..projection()
            };
            for (mode, not, expected) in [
                (SmartFolderMode::Present, false, present),
                (SmartFolderMode::None, false, none),
                (SmartFolderMode::Present, true, none),
                (SmartFolderMode::None, true, present),
            ] {
                assert_eq!(
                    evaluate_smart_folder(&condition(field, mode, not), Some(&input)),
                    Ok(expected)
                );
            }
        }
    }
}

#[test]
fn android_type_direct_group_unknown_parity() {
    for (kind, direct, group) in [
        (ChatConversationKind::Direct, True, False),
        (ChatConversationKind::Group, False, True),
        (ChatConversationKind::Unknown, Unknown, Unknown),
    ] {
        let input = SmartFolderProjection {
            conversation_kind: kind,
            ..projection()
        };
        for (mode, expected) in [
            (SmartFolderMode::Direct, direct),
            (SmartFolderMode::Group, group),
        ] {
            for (not, expected) in [(false, expected), (true, expected.inverted())] {
                assert_eq!(
                    evaluate_smart_folder(
                        &condition(SmartFolderField::Type, mode, not),
                        Some(&input)
                    ),
                    Ok(expected)
                );
            }
        }
    }
}

#[test]
fn unsupported_fields_and_invalid_modes_reject_before_short_circuit() {
    for field in [SmartFolderField::Title] {
        for all in [false, true] {
            for unsupported_first in [false, true] {
                let unsupported = condition(field, SmartFolderMode::Present, false);
                let decisive = truth_node(if all { False } else { True });
                let children = if unsupported_first {
                    vec![unsupported, decisive]
                } else {
                    vec![decisive, unsupported]
                };
                let group = SmartFolderPredicate::Group {
                    all,
                    children,
                    not: false,
                };
                assert_eq!(
                    evaluate_smart_folder(&group, Some(&projection())),
                    Err(SmartFolderError::UnsupportedField(field))
                );
            }
        }
    }
    for field in [
        SmartFolderField::Unread,
        SmartFolderField::Mentions,
        SmartFolderField::Muted,
        SmartFolderField::Pinned,
        SmartFolderField::Archived,
        SmartFolderField::Type,
    ] {
        let modes = if field == SmartFolderField::Type {
            [SmartFolderMode::Present, SmartFolderMode::None]
        } else {
            [SmartFolderMode::Direct, SmartFolderMode::Group]
        };
        for mode in modes {
            let group = SmartFolderPredicate::Group {
                all: false,
                children: vec![truth_node(True), condition(field, mode, false)],
                not: false,
            };
            assert_eq!(
                evaluate_smart_folder(&group, Some(&projection())),
                Err(SmartFolderError::InvalidMode)
            );
        }
    }
}

#[test]
fn manual_union_exclusion_and_native_eligibility_never_resurrect() {
    let invalid = Err(SmartFolderError::UnsupportedField(SmartFolderField::Draft));
    for automatic in [Ok(True), Ok(False), Ok(Unknown), invalid] {
        for (manual, excluded, expected) in [
            (false, false, automatic == Ok(True)),
            (true, false, true),
            (false, true, false),
            (true, true, false),
        ] {
            assert_eq!(
                smart_folder_member(true, manual, excluded, automatic),
                expected
            );
            for reason in ["missing", "hidden", "blocked"] {
                assert!(
                    !smart_folder_member(false, manual, excluded, automatic),
                    "{reason}"
                );
            }
        }
    }
}

#[test]
fn existing_codec_depth_and_node_limits_are_explicit_errors() {
    let mut predicate = truth_node(True);
    for _ in 0..MAX_DEPTH {
        predicate = SmartFolderPredicate::Group {
            all: true,
            children: vec![predicate],
            not: false,
        };
    }
    assert_eq!(
        evaluate_smart_folder(&predicate, Some(&projection())),
        Ok(True)
    );
    predicate = SmartFolderPredicate::Group {
        all: true,
        children: vec![predicate],
        not: false,
    };
    assert_eq!(
        evaluate_smart_folder(&predicate, Some(&projection())),
        Err(SmartFolderError::TooDeep)
    );
    for (children, expected) in [
        (MAX_NODES - 1, Ok(True)),
        (MAX_NODES, Err(SmartFolderError::TooManyNodes)),
    ] {
        let predicate = SmartFolderPredicate::Group {
            all: false,
            children: vec![truth_node(True); children],
            not: false,
        };
        assert_eq!(
            evaluate_smart_folder(&predicate, Some(&projection())),
            expected
        );
    }
}

#[test]
fn android_accepted_exclusion_and_unresolved_truth_table() {
    let accepted = SmartFolderAccepted {
        self_is_member: true,
        ..Default::default()
    };
    let mut rows = vec![(None, Unknown), (Some(accepted), True)];
    for flag in 0..7 {
        let mut evidence = accepted;
        match flag {
            0 => evidence.removed = true,
            1 => evidence.pending_confirmation = true,
            2 => evidence.self_is_member = false,
            3 => evidence.leave_request_pending = true,
            4 => evidence.disbanding = true,
            5 => evidence.disbanded = true,
            _ => evidence.unrecoverable = true,
        }
        rows.push((Some(evidence), False));
        evidence.invite_confirmation_unresolved = true;
        rows.push((Some(evidence), Unknown));
    }
    rows.push((
        Some(SmartFolderAccepted {
            invite_confirmation_unresolved: true,
            ..accepted
        }),
        Unknown,
    ));
    for (accepted, expected) in rows {
        for mode in [SmartFolderMode::Present, SmartFolderMode::None] {
            for not in [false, true] {
                let mut truth = expected;
                if mode == SmartFolderMode::None {
                    truth = truth.inverted();
                }
                if not {
                    truth = truth.inverted();
                }
                assert_eq!(
                    evaluate_smart_folder_with_context(
                        &condition(SmartFolderField::Accepted, mode, not),
                        &SmartFolderContext {
                            accepted,
                            ..Default::default()
                        }
                    ),
                    Ok(truth)
                );
            }
        }
    }
}

#[test]
fn android_selected_draft_and_pending_send_optional_evidence() {
    for value in [None, Some(false), Some(true)] {
        for field in [SmartFolderField::Draft, SmartFolderField::PendingSend] {
            let context = SmartFolderContext {
                selected_preview_has_draft: value,
                sending: value,
                ..Default::default()
            };
            let expected = match (field, value) {
                (_, Some(true)) => True,
                (SmartFolderField::Draft, Some(false)) => False,
                _ => Unknown,
            };
            for mode in [SmartFolderMode::Present, SmartFolderMode::None] {
                for not in [false, true] {
                    let mut truth = expected;
                    if mode == SmartFolderMode::None {
                        truth = truth.inverted();
                    }
                    if not {
                        truth = truth.inverted();
                    }
                    assert_eq!(
                        evaluate_smart_folder_with_context(&condition(field, mode, not), &context),
                        Ok(truth)
                    );
                }
            }
        }
    }
}

fn participants(values: Vec<String>, mode: SmartFolderMode, not: bool) -> SmartFolderPredicate {
    SmartFolderPredicate::Condition {
        field: SmartFolderField::Participants,
        values,
        mode,
        not,
    }
}

#[test]
fn android_participants_partial_complete_and_resolved_peer_truth_table() {
    let first = "a".repeat(64);
    let second = "b".repeat(64);
    let empty = HashSet::new();
    let one = HashSet::from([first.clone()]);
    let both = HashSet::from([first.clone(), second.clone()]);
    // ALL can prove a positive hit without completeness; only absence needs completeness.
    for (ids, peer, nonempty, kind, expected) in [
        (
            &empty,
            None,
            false,
            ChatConversationKind::Group,
            [Unknown, Unknown, Unknown],
        ),
        (
            &one,
            None,
            true,
            ChatConversationKind::Unknown,
            [True, Unknown, False],
        ),
        (
            &one,
            None,
            true,
            ChatConversationKind::Direct,
            [True, Unknown, False],
        ),
        (
            &one,
            None,
            true,
            ChatConversationKind::Group,
            [True, False, False],
        ),
        (
            &one,
            Some(second.as_str()),
            true,
            ChatConversationKind::Direct,
            [True, True, False],
        ),
        (
            &empty,
            Some(second.as_str()),
            false,
            ChatConversationKind::Direct,
            [True, Unknown, False],
        ),
        (
            &both,
            None,
            true,
            ChatConversationKind::Unknown,
            [True, True, False],
        ),
    ] {
        let context = SmartFolderContext {
            participants: Some(SmartFolderParticipants {
                folded_member_ids: ids,
                resolved_peer: peer,
                roster_nonempty: nonempty,
                conversation_kind: kind,
            }),
            ..Default::default()
        };
        for (mode, truth) in [
            SmartFolderMode::AnyOf,
            SmartFolderMode::AllOf,
            SmartFolderMode::Excludes,
        ]
        .into_iter()
        .zip(expected)
        {
            for not in [false, true] {
                assert_eq!(
                    evaluate_smart_folder_with_context(
                        &participants(vec![first.clone(), second.clone()], mode, not),
                        &context
                    ),
                    Ok(if not { truth.inverted() } else { truth })
                );
            }
        }
    }
    let missing = "c".repeat(64);
    for kind in [ChatConversationKind::Group, ChatConversationKind::Direct] {
        let context = SmartFolderContext {
            participants: Some(SmartFolderParticipants {
                folded_member_ids: &one,
                resolved_peer: Some(second.as_str()),
                roster_nonempty: true,
                conversation_kind: kind,
            }),
            ..Default::default()
        };
        for (mode, truth) in [
            (SmartFolderMode::AnyOf, False),
            (SmartFolderMode::AllOf, False),
            (SmartFolderMode::Excludes, True),
        ] {
            assert_eq!(
                evaluate_smart_folder_with_context(
                    &participants(vec![missing.clone()], mode, false),
                    &context
                ),
                Ok(truth)
            );
            assert_eq!(
                evaluate_smart_folder_with_context(
                    &participants(vec![missing.clone()], mode, false),
                    &SmartFolderContext::default()
                ),
                Ok(Unknown)
            );
        }
    }
}

#[test]
fn android_participant_codec_rejection_precedes_decisive_branches() {
    let valid = "a".repeat(64);
    for values in [
        vec![],
        vec![valid.clone(), valid.clone()],
        vec!["A".repeat(64)],
        vec!["g".repeat(64)],
        vec!["0".repeat(63)],
        vec!["0".repeat(65)],
        (0..65).map(|i| format!("{i:064x}")).collect(),
    ] {
        for all in [false, true] {
            let predicate = SmartFolderPredicate::Group {
                all,
                children: vec![
                    truth_node(if all { False } else { True }),
                    participants(values.clone(), SmartFolderMode::AnyOf, false),
                ],
                not: false,
            };
            assert_eq!(
                evaluate_smart_folder(&predicate, Some(&projection())),
                Err(SmartFolderError::InvalidValues)
            );
        }
    }
    let maximum = (0..64).map(|i| format!("{i:064x}")).collect();
    assert_eq!(
        evaluate_smart_folder(&participants(maximum, SmartFolderMode::AllOf, false), None),
        Ok(Unknown)
    );
    for mode in [
        SmartFolderMode::Present,
        SmartFolderMode::None,
        SmartFolderMode::Direct,
        SmartFolderMode::Group,
    ] {
        assert_eq!(
            evaluate_smart_folder(&participants(vec![valid.clone()], mode, false), None),
            Err(SmartFolderError::InvalidMode)
        );
    }
    let mut scalar = condition(SmartFolderField::Draft, SmartFolderMode::Present, false);
    if let SmartFolderPredicate::Condition { values, .. } = &mut scalar {
        values.push(valid);
    }
    assert_eq!(
        evaluate_smart_folder(&scalar, None),
        Err(SmartFolderError::InvalidValues)
    );
}

#[test]
fn predicate_debug_redacts_identities_and_unadmitted_title_text() {
    let key = "1234567890abcdef".repeat(4);
    let title = "private-title-sentinel-9452".to_owned();
    for predicate in [
        participants(vec![key.clone()], SmartFolderMode::AnyOf, false),
        SmartFolderPredicate::Condition {
            field: SmartFolderField::Title,
            mode: SmartFolderMode::Present,
            values: vec![title.clone()],
            not: false,
        },
    ] {
        let debug = format!("{predicate:?}");
        assert!(!debug.contains(&key));
        assert!(!debug.contains(&title));
        assert!(debug.contains("value_count: 1"));
        let nested = SmartFolderPredicate::Group {
            all: true,
            children: vec![predicate],
            not: false,
        };
        let debug = format!("{nested:?}");
        assert!(!debug.contains(&key));
        assert!(!debug.contains(&title));
        assert!(debug.contains("child_count: 1"));
    }
}
