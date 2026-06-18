use super::*;

fn system_value(from: &str, from_display_name: Option<&str>) -> Value {
    let mut value = serde_json::json!({ "from": from });
    if let Some(name) = from_display_name {
        value["from_display_name"] = Value::String(name.to_owned());
    }
    value
}

#[test]
fn group_system_summary_formats_known_types() {
    let value = system_value(&"aa".repeat(32), Some("alice"));
    let added = r#"{"v":1,"system_type":"member_added","text":"Member added","data":{"subject":"bbbbbbbb"}}"#;
    assert_eq!(
        group_system_summary(&value, added).as_deref(),
        Some("alice added bbbbbbbb")
    );

    let left = r#"{"v":1,"system_type":"member_left","text":"Member left","data":{}}"#;
    assert_eq!(
        group_system_summary(&value, left).as_deref(),
        Some("alice left")
    );

    let admin =
        r#"{"v":1,"system_type":"admin_added","text":"Admin added","data":{"subject":"bbbbbbbb"}}"#;
    assert_eq!(
        group_system_summary(&value, admin).as_deref(),
        Some("alice made bbbbbbbb an admin")
    );

    let renamed =
        r#"{"v":1,"system_type":"group_renamed","text":"Group renamed","data":{"name":"ops"}}"#;
    assert_eq!(
        group_system_summary(&value, renamed).as_deref(),
        Some("alice renamed the group to \"ops\"")
    );

    let avatar = r#"{"v":1,"system_type":"group_avatar_changed","text":"Group avatar changed"}"#;
    assert_eq!(
        group_system_summary(&value, avatar).as_deref(),
        Some("alice changed the group avatar")
    );
}

#[test]
fn group_system_summary_falls_back_for_unknown_type() {
    let value = system_value(&"aa".repeat(32), Some("alice"));
    let with_text = r#"{"v":1,"system_type":"mystery","text":"Something happened","data":{}}"#;
    assert_eq!(
        group_system_summary(&value, with_text).as_deref(),
        Some("Something happened")
    );
    // Unknown type with no text falls back to the system_type string.
    let bare = r#"{"v":1,"system_type":"mystery"}"#;
    assert_eq!(
        group_system_summary(&value, bare).as_deref(),
        Some("mystery")
    );
}

#[test]
fn group_system_summary_handles_missing_actor_and_subject() {
    // No display name: actor falls back to the shortened "from" pubkey, and a
    // missing subject renders as "someone".
    let value = serde_json::json!({ "from": "aa".repeat(32) });
    let added = r#"{"v":1,"system_type":"member_added","data":{}}"#;
    let summary = group_system_summary(&value, added).unwrap();
    assert!(summary.ends_with("added someone"), "got {summary}");
    assert!(
        !summary.starts_with("someone"),
        "actor should be the pubkey"
    );
}

#[test]
fn group_system_summary_renders_passive_for_unattributed() {
    // An unattributed row (convergence reorg) has an empty `from` and no
    // display name; render the passive voice instead of fabricating an actor.
    let value = serde_json::json!({ "from": "" });
    let added = r#"{"v":1,"system_type":"member_added","data":{"subject":"bbbbbbbb"}}"#;
    assert_eq!(
        group_system_summary(&value, added).as_deref(),
        Some("bbbbbbbb was added")
    );

    let removed = r#"{"v":1,"system_type":"member_removed","data":{"subject":"bbbbbbbb"}}"#;
    assert_eq!(
        group_system_summary(&value, removed).as_deref(),
        Some("bbbbbbbb was removed")
    );

    let renamed = r#"{"v":1,"system_type":"group_renamed","data":{"name":"ops"}}"#;
    assert_eq!(
        group_system_summary(&value, renamed).as_deref(),
        Some("the group was renamed to \"ops\"")
    );
}

#[test]
fn group_system_summary_rejects_non_system_content() {
    let value = system_value(&"aa".repeat(32), Some("alice"));
    assert_eq!(group_system_summary(&value, "not json"), None);
    assert_eq!(
        group_system_summary(&value, r#"{"text":"no system_type"}"#),
        None
    );
}

#[test]
fn slash_command_parser_understands_core_commands() {
    assert_eq!(parse_slash_command("/help"), Ok(SlashCommand::Help));
    assert!(parse_slash_command("/sync").is_err());
    assert_eq!(
        parse_slash_command("/account npub1abc"),
        Ok(SlashCommand::Account("npub1abc".to_owned()))
    );
    assert!(parse_slash_command("/new general npub1bob").is_err());
}

#[test]
fn slash_command_suggestions_open_on_bare_slash_and_filter_nested_commands() {
    let bare = slash_command_suggestions("/")
        .iter()
        .map(|suggestion| suggestion.usage)
        .collect::<Vec<_>>();

    assert!(bare.contains(&"/help"));
    assert!(bare.contains(&"/chat new <name> [member-npub-or-hex ...]"));
    assert!(bare.contains(&"/members add <npub-or-hex> [...]"));

    let chat_rename = slash_command_suggestions("/chat r")
        .iter()
        .map(|suggestion| suggestion.usage)
        .collect::<Vec<_>>();
    assert_eq!(chat_rename, vec!["/chat rename <name>"]);

    let chat_new_with_name = slash_command_suggestions("/chat new general")
        .iter()
        .map(|suggestion| suggestion.usage)
        .collect::<Vec<_>>();
    assert_eq!(
        chat_new_with_name,
        vec!["/chat new <name> [member-npub-or-hex ...]"]
    );

    assert!(slash_command_suggestions("/daemon status now").is_empty());
    assert!(slash_command_suggestions("hello").is_empty());
}

#[test]
fn composer_renders_filtered_slash_command_popup() {
    let mut app = test_tui_app(
        test_unused_client(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    app.input = "/chat r".to_owned();

    let backend = ratatui::backend::TestBackend::new(100, 30);
    let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
    terminal.draw(|frame| app.render(frame)).expect("draw TUI");

    let rendered = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();

    assert!(rendered.contains("Commands"));
    assert!(rendered.contains("/chat rename <name>"));
    assert!(!rendered.contains("/members add <npub-or-hex>"));
}

#[test]
fn slash_command_parser_handles_key_package_commands() {
    assert_eq!(
        parse_slash_command("/keys fetch npub1bob"),
        Ok(SlashCommand::KeysFetch("npub1bob".to_owned()))
    );
    assert_eq!(
        parse_slash_command("/keys rotate"),
        Ok(SlashCommand::KeysRotate)
    );
    assert!(parse_slash_command("/keys publish").is_err());
    assert!(parse_slash_command("/keys").is_err());
}

#[test]
fn slash_command_parser_handles_profile_name_updates() {
    assert_eq!(
        parse_slash_command("/name Alice Example"),
        Ok(SlashCommand::ProfileName("Alice Example".to_owned()))
    );
    assert_eq!(
        parse_slash_command("/profile name Bob Example"),
        Ok(SlashCommand::ProfileName("Bob Example".to_owned()))
    );
    assert!(parse_slash_command("/name").is_err());
    assert!(parse_slash_command("/profile name").is_err());
}

#[test]
fn slash_command_parser_handles_stream_commands() {
    assert_eq!(
        parse_slash_command("/stream"),
        Ok(SlashCommand::StreamCompose {
            stream_id: None,
            quic_candidates: vec![DEFAULT_STREAM_CANDIDATE.to_owned()],
        })
    );
    assert_eq!(
        parse_slash_command("/stream --stream-id aa --quic-candidate quic://127.0.0.1:4451"),
        Ok(SlashCommand::StreamCompose {
            stream_id: Some("aa".to_owned()),
            quic_candidates: vec!["quic://127.0.0.1:4451".to_owned()],
        })
    );
    assert_eq!(
        parse_slash_command("/stream start --stream-id aa --quic-candidate quic://127.0.0.1:4450"),
        Ok(SlashCommand::StreamStart {
            stream_id: Some("aa".to_owned()),
            quic_candidates: vec!["quic://127.0.0.1:4450".to_owned()],
        })
    );
    assert_eq!(
        parse_slash_command("/stream watch --stream-id aa --insecure-local"),
        Ok(SlashCommand::StreamWatch {
            stream_id: Some("aa".to_owned()),
            insecure_local: true,
        })
    );
    assert_eq!(
        parse_slash_command("/stream watch aa"),
        Ok(SlashCommand::StreamWatch {
            stream_id: Some("aa".to_owned()),
            insecure_local: false,
        })
    );
    assert_eq!(
        parse_slash_command("/stream status"),
        Ok(SlashCommand::StreamStatus)
    );
    assert_eq!(
        parse_slash_command("/stream finish aa bb 2 hello world"),
        Ok(SlashCommand::StreamFinish {
            stream_id: "aa".to_owned(),
            transcript_hash: "bb".to_owned(),
            chunk_count: 2,
            text: "hello world".to_owned(),
        })
    );
    assert_eq!(
        parse_slash_command("/stream verify aa bb 2"),
        Ok(SlashCommand::StreamVerify {
            stream_id: "aa".to_owned(),
            transcript_hash: "bb".to_owned(),
            chunk_count: Some(2),
        })
    );
}

#[test]
fn slash_command_parser_handles_account_onboarding_commands() {
    assert_eq!(
        parse_slash_command("/create-identity"),
        Ok(SlashCommand::AccountCreate)
    );
    assert_eq!(
        parse_slash_command("/login npub1bob"),
        Ok(SlashCommand::AccountAddPublic("npub1bob".to_owned()))
    );
    assert_eq!(
        parse_slash_command("/login nsec1secret"),
        Ok(SlashCommand::AccountImportSecret("nsec1secret".to_owned()))
    );
    assert!(parse_slash_command("/account create").is_err());
}

#[test]
fn slash_command_parser_handles_daemon_commands() {
    assert_eq!(
        parse_slash_command("/daemon status"),
        Ok(SlashCommand::DaemonStatus)
    );
    assert_eq!(
        parse_slash_command("/daemon start"),
        Ok(SlashCommand::DaemonStart)
    );
    assert!(parse_slash_command("/daemon start 750").is_err());
    assert_eq!(
        parse_slash_command("/daemon stop"),
        Ok(SlashCommand::DaemonStop)
    );
    assert!(parse_slash_command("/daemon sync-now").is_err());
    assert!(parse_slash_command("/daemon restart").is_err());
}

#[test]
fn slash_command_parser_handles_chat_and_member_management_commands() {
    assert_eq!(
        parse_slash_command("/chat new general npub1bob deadbeef"),
        Ok(SlashCommand::ChatNew {
            name: "general".to_owned(),
            members: vec!["npub1bob".to_owned(), "deadbeef".to_owned()],
        })
    );
    assert_eq!(
        parse_slash_command("/chat new \"Project Room\" npub1bob deadbeef"),
        Ok(SlashCommand::ChatNew {
            name: "Project Room".to_owned(),
            members: vec!["npub1bob".to_owned(), "deadbeef".to_owned()],
        })
    );
    assert_eq!(
        parse_slash_command("/chat rename Project Room"),
        Ok(SlashCommand::ChatRename("Project Room".to_owned()))
    );
    assert_eq!(
        parse_slash_command("/chat rename Jeff's Room"),
        Ok(SlashCommand::ChatRename("Jeff's Room".to_owned()))
    );
    assert!(parse_slash_command("/chat new \"Project Room npub1bob").is_err());
    assert_eq!(
        parse_slash_command("/chat describe planning space"),
        Ok(SlashCommand::ChatDescribe("planning space".to_owned()))
    );
    assert_eq!(
        parse_slash_command("/chat archive"),
        Ok(SlashCommand::ChatArchive)
    );
    assert_eq!(
        parse_slash_command("/chat unarchive"),
        Ok(SlashCommand::ChatUnarchive)
    );
    assert_eq!(
        parse_slash_command("/chat archived"),
        Ok(SlashCommand::ChatArchived(true))
    );
    assert_eq!(
        parse_slash_command("/chat archived off"),
        Ok(SlashCommand::ChatArchived(false))
    );
    assert_eq!(
        parse_slash_command("/members add npub1bob npub1carol"),
        Ok(SlashCommand::MembersAdd(vec![
            "npub1bob".to_owned(),
            "npub1carol".to_owned(),
        ]))
    );
    assert_eq!(
        parse_slash_command("/members remove npub1bob npub1carol"),
        Ok(SlashCommand::MembersRemove(vec![
            "npub1bob".to_owned(),
            "npub1carol".to_owned(),
        ]))
    );
    assert_eq!(
        parse_slash_command("/members list"),
        Ok(SlashCommand::MembersList)
    );
    assert!(parse_slash_command("/members clear").is_err());
    assert!(parse_slash_command("/invite npub1bob").is_err());
    assert!(parse_slash_command("/remove npub1bob").is_err());
}

#[test]
fn group_members_status_summarizes_member_records() {
    let status = group_members_status(&serde_json::json!({
        "members": [
            {"npub": "npub1bob"},
            {"member_id": "0123456789abcdef"}
        ]
    }));

    assert!(status.starts_with("members: "));
    assert!(status.contains("npub1bob"));
    assert!(status.contains("01234"));
}

#[test]
fn status_panel_lines_show_latest_status_then_mls_and_components() {
    let diagnostics = parse_group_diagnostics(&serde_json::json!({
        "group": {
            "group_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "profile": {
                "component_id": 32769,
                "component": "marmot.group.profile.v1",
                "data_hex": "010203"
            },
            "admin_policy": {
                "component_id": 32771,
                "component": "marmot.group.admin-policy.v1",
                "data_hex": "aabbcc"
            },
            "agent_text_stream": {
                "component_id": 32774,
                "component": "marmot.group.agent-text-stream.quic.v1",
                "data_hex": "ffee"
            }
        },
        "mls": {
            "epoch": 7,
            "member_count": 3
        }
    }))
    .expect("diagnostics");

    let rendered = status_panel_lines("loaded 2 message(s)", Some(&diagnostics))
        .iter()
        .map(line_text)
        .collect::<Vec<_>>();

    assert_eq!(rendered[0], "loaded 2 message(s)");
    assert_eq!(rendered[1], "");
    assert_eq!(rendered[2], "");
    assert_eq!(
        rendered[3],
        "MLS epoch=7 group=aaaaaaa...aaaaaaaa members=3"
    );
    assert_eq!(rendered[4], "components:");
    assert!(
        rendered
            .iter()
            .any(|line| line == "marmot.group.profile.v1 id=32769 data=010203")
    );
    assert!(
        rendered
            .iter()
            .any(|line| line == "marmot.group.admin-policy.v1 id=32771 data=aabbcc")
    );
    assert!(
        rendered
            .iter()
            .any(|line| line == "marmot.group.agent-text-stream.quic.v1 id=32774 data=ffee")
    );
}

#[test]
fn group_state_subscription_update_triggers_selected_group_refresh() {
    let selected_group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let other_group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let update = group_state_subscription_update(
        &serde_json::json!({
            "trigger": "GroupStateUpdated",
            "type": "group_state",
            "group_id": selected_group_id,
            "group": {
                "group_id": selected_group_id,
                "profile": {"name": "renamed room"},
                "archived": false
            },
            "mls": {
                "epoch": 8,
                "member_count": 2
            }
        }),
        selected_group_id,
    )
    .expect("selected group update");
    assert_eq!(update.group_id, selected_group_id);
    assert_eq!(
        update.status.as_deref(),
        Some("live group state update: renamed room")
    );
    let diagnostics = update.diagnostics.expect("diagnostics");
    assert_eq!(diagnostics.group_id, selected_group_id);
    assert_eq!(diagnostics.epoch, Some(8));
    assert_eq!(diagnostics.member_count, Some(2));

    let initial = group_state_subscription_update(
        &serde_json::json!({
            "trigger": "InitialGroupState",
            "type": "group_state",
            "group_id": selected_group_id,
            "group": {
                "group_id": selected_group_id,
                "profile": {"name": "renamed room"},
                "archived": false
            }
        }),
        selected_group_id,
    )
    .expect("initial selected group state");
    assert_eq!(initial.status, None);
    assert!(initial.diagnostics.is_some());

    assert_eq!(
        group_state_subscription_update(
            &serde_json::json!({
                "trigger": "GroupStateUpdated",
                "type": "group_state",
                "group_id": other_group_id,
                "group": {
                    "group_id": other_group_id,
                    "profile": {"name": "other room"},
                    "archived": false
                }
            }),
            selected_group_id,
        ),
        None
    );
}

#[test]
fn selected_row_label_style_keeps_text_readable() {
    assert_eq!(row_label_style(true, Color::Cyan).fg, Some(Color::Black));
    assert_eq!(row_label_style(true, Color::Green).fg, Some(Color::Black));
    assert_eq!(
        row_label_style(false, ACCOUNT_ACCENT).fg,
        Some(Color::White)
    );
}

#[test]
fn chat_row_line_shows_unread_count_in_bold() {
    let chat = ChatRow {
        group_id: "group-a".to_owned(),
        name: "Project Room".to_owned(),
        archived: false,
    };

    let line = chat_row_line(&chat, false, 3);

    assert_eq!(line_text(&line), "  Project Room (3)");
    assert!(line.spans[0].style.add_modifier.contains(Modifier::BOLD));
    assert!(line.spans[1].style.add_modifier.contains(Modifier::BOLD));
    assert_eq!(line.spans[1].style.fg, Some(Color::Green));
}

#[test]
fn chat_label_keeps_unread_count_when_truncated() {
    assert_eq!(
        chat_label("A very long group display name", 12, 18),
        "A very ...ame (12)"
    );
}

#[test]
fn message_lines_keep_chronological_order_and_summarize_stream_markers() {
    let mut messages = [
            serde_json::json!({
                "message_id": "03",
                "recorded_at": 30,
                "received_at": 30,
                "direction": "sent",
                "from": "alice",
                "plaintext": "{\"marmot_payload\":\"marmot.agent_text_stream.v1\"}",
                "agent_text_stream": {
                    "kind": "final",
                    "stream_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "final_text_or_reference": "hello from the stream",
                    "transcript_hash": "4c88175697a7232454d93beeeb3d97eb487d9042fc5d37f75e3f9297e626ad5e",
                    "chunk_count": 3
                }
            }),
            serde_json::json!({
                "message_id": "01",
                "recorded_at": 10,
                "received_at": 30,
                "direction": "sent",
                "from": "alice",
                "plaintext": "hello bob from alice"
            }),
            serde_json::json!({
                "message_id": "02",
                "recorded_at": 20,
                "received_at": 30,
                "direction": "sent",
                "from": "alice",
                "plaintext": "{\"marmot_payload\":\"marmot.agent_text_stream.v1\"}",
                "agent_text_stream": {
                    "kind": "start",
                    "stream_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "route": "brokered_quic",
                    "quic_candidates": ["quic://127.0.0.1:4450"]
                }
            }),
        ]
        .iter()
        .filter_map(parse_message)
        .collect::<Vec<_>>();
    sort_messages_chronologically(&mut messages);

    let rendered = message_lines(&messages, None)
        .iter()
        .map(line_text)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    assert_eq!(rendered[0], "me: hello bob from alice");
    assert_eq!(rendered[1], "me: hello from the stream");
    assert!(rendered.iter().all(|line| !line.contains("marmot_payload")));
    assert!(rendered.iter().all(|line| !line.contains("stream start")));
}

#[test]
fn render_lines_strip_terminal_control_sequences_from_untrusted_text() {
    let messages = vec![MessageRow {
        message_id: "01".to_owned(),
        direction: "received".to_owned(),
        from: "alice".to_owned(),
        from_display_name: Some("ali\u{1b}]0;pwn\u{7}ce".to_owned()),
        plaintext: "hi\u{1b}[2J\nbob".to_owned(),
        display_text: "hi\u{1b}[2J\nbob".to_owned(),
        recorded_at: 1,
        received_at: 1,
    }];
    let rendered = message_lines(&messages, None)
        .into_iter()
        .map(|line| line_text(&line))
        .collect::<Vec<_>>();
    assert_eq!(rendered[0], "ali]0;pwnce: hi[2Jbob");

    let previews = vec![LiveStreamPreview {
        group_id: "group-a".to_owned(),
        stream_id: "stream-a".to_owned(),
        author: "stream\u{1b}[31m".to_owned(),
        status: "running".to_owned(),
        text: "part\u{9b}31mial\u{7}".to_owned(),
        error: None,
        optimistic: false,
    }];
    let preview_lines = stream_preview_lines(&DaemonView::default(), &previews, Some("group-a"));
    assert_eq!(line_text(&preview_lines[1]), "stream[31m: part31mial");

    let chat = ChatRow {
        group_id: "group-a".to_owned(),
        name: "ops\u{1b}[5m".to_owned(),
        archived: false,
    };
    assert_eq!(line_text(&chat_row_line(&chat, false, 0)), "  ops[5m");

    let status = status_panel_lines(
        "ready\u{1b}[2J",
        Some(&GroupDiagnostics::unavailable("aa", "bad\u{1b}[31m")),
    );
    assert_eq!(line_text(&status[0]), "ready[2J");
    assert_eq!(line_text(&status[3]), "MLS group=aa unavailable: bad[31m");
}

#[test]
fn slash_command_parser_rejects_unimplemented_image_send() {
    assert!(parse_slash_command("/image /tmp/photo.jpg").is_err());
}

#[test]
fn daemon_status_json_becomes_header_and_status_text() {
    let daemon = parse_daemon_view(&serde_json::json!({
        "running": true,
        "pid": 1234,
        "last_runtime_activity": {
            "accounts": 2,
            "events": 3,
            "joined_groups": 1,
            "messages": 4,
            "errors": ["relay unavailable"]
        }
    }));

    assert_eq!(
        daemon_header_label(&daemon),
        "on pid=1234 activity=3/1/4 errors=1"
    );
    assert_eq!(
        daemon_status_sentence(&daemon),
        "daemon running last-activity accounts=2 events=3 joined=1 messages=4 errors=1"
    );
    assert_eq!(
        daemon_status_sentence(&parse_daemon_view(&serde_json::json!({"running": false}))),
        "daemon not running"
    );
}

#[test]
fn daemon_stream_watches_become_status_and_preview_rows() {
    let group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let stream_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let daemon = parse_daemon_view(&serde_json::json!({
        "running": true,
        "pid": 1234,
        "stream_watches": [
            {
                "watch_id": "watch-1",
                "group_id": group_id,
                "stream_id": stream_id,
                "status": "running",
                "text": "daemon live text"
            },
            {
                "watch_id": "watch-2",
                "group_id": group_id,
                "stream_id": stream_id,
                "status": "completed",
                "text": "daemon preview text",
                "transcript_hash": "cccc",
                "chunk_count": 2
            }
        ]
    }));

    assert_eq!(daemon_header_label(&daemon), "on pid=1234 streams=1");
    assert_eq!(
        daemon_status_sentence(&daemon),
        "daemon running streams: running=1 completed=1 failed=0 latest=bbbbbbb...bbbbbbbb"
    );

    let preview_lines = stream_preview_lines(&daemon, &[], Some(group_id));
    let rendered_preview = preview_lines[1]
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();
    assert_eq!(rendered_preview, "stream: daemon live text");
    assert_eq!(preview_lines.len(), 2);
    assert!(stream_preview_lines(&daemon, &[], Some("different-group")).is_empty());
}

#[test]
fn active_stream_preview_pins_to_open_time_group_after_selection_shift() {
    // Regression for issue #198: the stream composer must key its live
    // preview upsert/cleanup on the group selected when the stream was
    // opened, not on the chat that happens to be selected now. A
    // background chat-subscription tick can shift selected_chat while
    // streaming (e.g. the streamed-into chat is archived/removed by
    // another member/device). Before the fix, keystrokes upserted the
    // streamed text under the wrong group and finish/cancel left a ghost
    // row under the original group.
    let stream_group = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let other_group = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let stream_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let account_id = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    // compose-cancel response; cancel_stream_composer ignores the value.
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{}}"#);
    let mut app = test_tui_app(client, account_id);
    app.chats = vec![ChatRow {
        group_id: other_group.to_owned(),
        name: "other".to_owned(),
        archived: false,
    }];
    // Selection now points at a DIFFERENT group than the streamed-into one.
    app.selected_chat = 0;
    app.streaming = Some(StreamComposer {
        stream_id: stream_id.to_owned(),
        group_id: stream_group.to_owned(),
        pending_text: String::new(),
        last_flush: Instant::now(),
    });
    app.input = "hello".to_owned();

    // A keystroke-driven preview upsert must land under the pinned group.
    app.upsert_active_stream_preview(stream_id);
    assert_eq!(app.live_stream_previews.len(), 1);
    let preview = &app.live_stream_previews[0];
    assert_eq!(preview.group_id, stream_group);
    assert_eq!(preview.stream_id, stream_id);
    assert_eq!(preview.text, "hello");

    // Cancel must remove the preview from the pinned group, not the
    // currently-selected one, so no ghost streaming row is left behind.
    app.cancel_stream_composer()
        .expect("cancel stream composer");
    assert!(app.live_stream_previews.is_empty());
    assert!(app.streaming.is_none());
}

#[test]
fn stream_preview_lines_hide_empty_and_completed_previews() {
    let group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let stream_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let daemon = parse_daemon_view(&serde_json::json!({
        "running": true,
        "pid": 1234,
        "stream_watches": [
            {
                "watch_id": "watch-1",
                "group_id": group_id,
                "stream_id": stream_id,
                "status": "completed",
                "text": "final text should be rendered from MLS instead"
            }
        ]
    }));
    let previews = vec![LiveStreamPreview {
        group_id: group_id.to_owned(),
        stream_id: stream_id.to_owned(),
        author: "me".to_owned(),
        status: "streaming".to_owned(),
        text: String::new(),
        error: None,
        optimistic: true,
    }];

    assert!(stream_preview_lines(&daemon, &previews, Some(group_id)).is_empty());
}

#[test]
fn subscription_stream_deltas_update_live_preview_text() {
    let group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let stream_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut messages = Vec::new();
    let mut previews = Vec::new();

    apply_subscription_result(
        &mut messages,
        &mut previews,
        &serde_json::json!({
            "type": "agent_stream_delta",
            "agent_stream_delta": {
                "group_id": group_id,
                "stream_id": stream_id,
                "text": "hello "
            }
        }),
        false,
    );
    apply_subscription_result(
        &mut messages,
        &mut previews,
        &serde_json::json!({
            "type": "agent_stream_delta",
            "agent_stream_delta": {
                "group_id": group_id,
                "stream_id": stream_id,
                "text": "stream"
            }
        }),
        false,
    );

    let rendered_preview = stream_preview_lines(&DaemonView::default(), &previews, Some(group_id))
        [1]
    .spans
    .iter()
    .map(|span| span.content.as_ref())
    .collect::<String>();
    assert_eq!(rendered_preview, "stream: hello stream");
}

#[test]
fn subscription_messages_keep_bounded_scrollback() {
    let mut messages = Vec::new();
    let mut previews = Vec::new();

    for index in 0..(TUI_MESSAGE_SCROLLBACK_LIMIT + 5) {
        let message_id = format!("{index:04}");
        apply_subscription_result(
            &mut messages,
            &mut previews,
            &serde_json::json!({
                "type": "message",
                "message": {
                    "message_id": message_id,
                    "direction": "received",
                    "from": "alice",
                    "plaintext": "hello",
                    "recorded_at": index,
                    "received_at": index
                }
            }),
            false,
        );
    }

    assert_eq!(messages.len(), TUI_MESSAGE_SCROLLBACK_LIMIT);
    assert_eq!(
        messages.first().map(|message| message.message_id.as_str()),
        Some("0005")
    );
    assert_eq!(
        messages.last().map(|message| message.message_id.as_str()),
        Some("1004")
    );
}

#[test]
fn stream_previews_keep_bounded_rows_and_tail_text() {
    let group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let long_text = format!("{}\u{00e9}", "a".repeat(TUI_LIVE_STREAM_TEXT_LIMIT));
    let mut previews = Vec::new();

    append_live_stream_delta(
        &mut previews,
        group_id.to_owned(),
        "stream-long".to_owned(),
        long_text,
    );

    assert!(previews[0].text.len() <= TUI_LIVE_STREAM_TEXT_LIMIT);
    assert!(previews[0].text.ends_with('\u{00e9}'));

    let mut previews = Vec::new();
    for index in 0..(TUI_LIVE_STREAM_PREVIEW_LIMIT + 2) {
        upsert_live_stream_preview(
            &mut previews,
            LiveStreamPreview {
                group_id: group_id.to_owned(),
                stream_id: format!("stream-{index}"),
                author: "stream".to_owned(),
                status: "streaming".to_owned(),
                text: "partial".to_owned(),
                error: None,
                optimistic: false,
            },
            true,
        );
    }

    assert_eq!(previews.len(), TUI_LIVE_STREAM_PREVIEW_LIMIT);
    assert_eq!(
        previews.first().map(|preview| preview.stream_id.as_str()),
        Some("stream-2")
    );
}

#[test]
fn idle_tick_does_not_request_redraw() {
    let mut app = test_tui_app(
        test_unused_client(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    assert!(!app.tick());
}

#[test]
fn chat_subscription_result_inserts_live_invite_without_account_switch() {
    let group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut chats = Vec::new();
    let mut selected_chat = 0;

    let status = apply_chat_subscription_result(
        &mut chats,
        &mut selected_chat,
        false,
        &serde_json::json!({
            "trigger": "ChatUpdated",
            "type": "chat",
            "group_id": group_id,
            "chat": {
                "group_id": group_id,
                "profile": {"name": "new invite"},
                "archived": false
            }
        }),
    );

    assert_eq!(status.as_deref(), Some("live chat update: chats=1"));
    assert_eq!(selected_chat, 0);
    assert_eq!(
        chats,
        vec![ChatRow {
            group_id: group_id.to_owned(),
            name: "new invite".to_owned(),
            archived: false,
        }]
    );
}

#[test]
fn local_stream_preview_ignores_echoed_deltas() {
    let group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let stream_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut previews = vec![LiveStreamPreview {
        group_id: group_id.to_owned(),
        stream_id: stream_id.to_owned(),
        author: "me".to_owned(),
        status: "streaming".to_owned(),
        text: "hello stream".to_owned(),
        error: None,
        optimistic: true,
    }];

    append_live_stream_delta(
        &mut previews,
        group_id.to_owned(),
        stream_id.to_owned(),
        "eam".to_owned(),
    );

    assert_eq!(previews[0].text, "hello stream");
}

#[test]
fn subscription_final_message_replaces_stream_marker_with_mls_text() {
    let mut messages = Vec::new();
    let mut previews = Vec::new();

    apply_subscription_result(
        &mut messages,
        &mut previews,
        &serde_json::json!({
            "type": "agent_stream_start",
            "message": {
                "message_id": "start",
                "direction": "received",
                "group_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "from": "alice",
                "plaintext": "{\"marmot_payload\":\"marmot.agent_text_stream.v1\"}",
                "agent_text_stream": {
                    "kind": "start",
                    "stream_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                }
            }
        }),
        false,
    );
    assert_eq!(previews.len(), 1);
    apply_subscription_result(
        &mut messages,
        &mut previews,
        &serde_json::json!({
            "type": "agent_stream_final",
            "message": {
                "message_id": "final",
                "direction": "received",
                "group_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "from": "alice",
                "plaintext": "{\"marmot_payload\":\"marmot.agent_text_stream.v1\"}",
                "agent_text_stream": {
                    "kind": "final",
                    "stream_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "final_text_or_reference": "hello from MLS"
                }
            }
        }),
        false,
    );

    let rendered = message_lines(&messages, None)
        .iter()
        .map(line_text)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(rendered, vec!["alice: hello from MLS"]);
    assert!(previews.is_empty());
}

#[test]
fn all_chat_subscription_marks_nonselected_messages_unread() {
    let selected_group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let unread_group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut messages = Vec::new();
    let mut previews = Vec::new();
    let mut unread_counts = HashMap::new();

    let status = apply_tui_subscription_result(
        &mut messages,
        &mut previews,
        &mut unread_counts,
        Some(selected_group_id),
        &serde_json::json!({
            "trigger": "MessageReceived",
            "type": "message",
            "message": {
                "message_id": "02",
                "direction": "received",
                "group_id": unread_group_id,
                "from": "alice",
                "plaintext": "hello elsewhere"
            }
        }),
    );

    assert_eq!(messages.len(), 0);
    assert_eq!(unread_counts.get(unread_group_id), Some(&1));
    assert_eq!(
        status,
        Some("unread message in bbbbbbb...bbbbbbbb; count=1".to_owned())
    );
}

#[test]
fn all_chat_subscription_cleans_up_off_chat_stream_preview_without_appending_message() {
    let selected_group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let unread_group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let stream_id = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let mut messages = Vec::new();
    let mut previews = vec![LiveStreamPreview {
        group_id: unread_group_id.to_owned(),
        stream_id: stream_id.to_owned(),
        author: "alice".to_owned(),
        status: "streaming".to_owned(),
        text: "partial".to_owned(),
        error: None,
        optimistic: false,
    }];
    let mut unread_counts = HashMap::new();

    apply_tui_subscription_result(
        &mut messages,
        &mut previews,
        &mut unread_counts,
        Some(selected_group_id),
        &serde_json::json!({
            "trigger": "AgentStreamFinalized",
            "type": "agent_stream_final",
            "message": {
                "message_id": "final",
                "direction": "received",
                "group_id": unread_group_id,
                "from": "alice",
                "plaintext": "{\"marmot_payload\":\"marmot.agent_text_stream.v1\"}",
                "agent_text_stream": {
                    "kind": "final",
                    "stream_id": stream_id,
                    "final_text_or_reference": "finished elsewhere"
                }
            }
        }),
    );

    assert!(messages.is_empty());
    assert!(previews.is_empty());
    assert_eq!(unread_counts.get(unread_group_id), Some(&1));
}

#[test]
fn all_chat_subscription_applies_selected_messages_without_unread_count() {
    let selected_group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut messages = Vec::new();
    let mut previews = Vec::new();
    let mut unread_counts = HashMap::new();

    apply_tui_subscription_result(
        &mut messages,
        &mut previews,
        &mut unread_counts,
        Some(selected_group_id),
        &serde_json::json!({
            "trigger": "MessageReceived",
            "type": "message",
            "message": {
                "message_id": "01",
                "direction": "received",
                "group_id": selected_group_id,
                "from": "alice",
                "plaintext": "hello here"
            }
        }),
    );

    assert_eq!(unread_counts.get(selected_group_id), None);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].display_text, "hello here");
}

#[test]
fn all_chat_subscription_ignores_initial_replay_for_unread_counts() {
    let selected_group_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let replay_group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut messages = Vec::new();
    let mut previews = Vec::new();
    let mut unread_counts = HashMap::new();

    let status = apply_tui_subscription_result(
        &mut messages,
        &mut previews,
        &mut unread_counts,
        Some(selected_group_id),
        &serde_json::json!({
            "trigger": "InitialMessage",
            "type": "message",
            "message": {
                "message_id": "old",
                "direction": "received",
                "group_id": replay_group_id,
                "from": "alice",
                "plaintext": "old message"
            }
        }),
    );

    assert_eq!(status, None);
    assert!(messages.is_empty());
    assert!(unread_counts.is_empty());
}

#[test]
fn message_subscription_gates_on_loaded_chat_not_highlighted_chat() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let loaded_group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let highlighted_group_id = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let mut app = test_tui_app(test_unused_client(), account_id);
    app.chats = vec![
        ChatRow {
            group_id: loaded_group_id.to_owned(),
            name: "loaded".to_owned(),
            archived: false,
        },
        ChatRow {
            group_id: highlighted_group_id.to_owned(),
            name: "highlighted".to_owned(),
            archived: false,
        },
    ];
    app.selected_chat = 1;
    app.messages_group_id = Some(loaded_group_id.to_owned());
    let (tx, rx) = mpsc::channel();
    app.message_subscription = Some(MessageSubscription {
        account_id: account_id.to_owned(),
        child: test_sleep_child(),
        rx,
    });

    tx.send(SubscriptionEvent::Result(serde_json::json!({
        "trigger": "MessageReceived",
        "type": "message",
        "message": {
            "message_id": "highlighted",
            "direction": "received",
            "group_id": highlighted_group_id,
            "from": "alice",
            "plaintext": "hello highlighted"
        }
    })))
    .expect("send highlighted message event");

    assert!(app.drain_message_subscription());
    assert!(app.messages.is_empty());
    assert_eq!(app.unread_counts.get(highlighted_group_id), Some(&1));

    tx.send(SubscriptionEvent::Result(serde_json::json!({
        "trigger": "MessageReceived",
        "type": "message",
        "message": {
            "message_id": "loaded",
            "direction": "received",
            "group_id": loaded_group_id,
            "from": "bob",
            "plaintext": "hello loaded"
        }
    })))
    .expect("send loaded message event");

    assert!(app.drain_message_subscription());
    assert_eq!(app.unread_counts.get(loaded_group_id), None);
    assert_eq!(app.messages.len(), 1);
    assert_eq!(app.messages[0].message_id, "loaded");
    assert_eq!(app.messages[0].display_text, "hello loaded");
}

#[test]
fn selected_message_subscription_retains_account_wide_stream_without_selected_chat() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut app = test_tui_app(test_unused_client(), account_id);
    app.message_subscription = Some(test_message_subscription(account_id));

    app.ensure_selected_message_subscription();

    assert_eq!(
        app.message_subscription
            .as_ref()
            .map(|subscription| subscription.account_id.as_str()),
        Some(account_id)
    );
}

#[test]
fn refresh_accounts_clears_unread_counts_when_no_accounts_remain() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"accounts":[]}}"#);
    let mut app = test_tui_app(client, account_id);
    app.chats = vec![ChatRow {
        group_id: group_id.to_owned(),
        name: "general".to_owned(),
        archived: false,
    }];
    app.unread_counts.insert(group_id.to_owned(), 3);
    app.chat_subscription = Some(test_chat_subscription(account_id, false));
    app.message_subscription = Some(test_message_subscription(account_id));
    app.group_diagnostics = Some(GroupDiagnostics::unavailable(group_id, "old"));

    app.refresh_accounts().expect("refresh accounts");

    assert!(app.accounts.is_empty());
    assert!(app.chats.is_empty());
    assert!(app.messages.is_empty());
    assert!(app.unread_counts.is_empty());
    assert!(app.chat_subscription.is_none());
    assert!(app.message_subscription.is_none());
    assert!(app.group_diagnostics.is_none());
}

#[test]
fn refresh_chats_starts_account_wide_stream_when_no_chats_are_visible() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"chats":[]}}"#);
    let mut app = test_tui_app(client, account_id);
    app.chat_subscription = Some(test_chat_subscription(account_id, false));
    app.group_diagnostics = Some(GroupDiagnostics::unavailable(group_id, "old"));

    app.refresh_chats().expect("refresh chats");

    assert!(app.chats.is_empty());
    assert!(app.messages.is_empty());
    assert_eq!(
        app.message_subscription
            .as_ref()
            .map(|subscription| subscription.account_id.as_str()),
        Some(account_id)
    );
    assert!(app.group_diagnostics.is_some());
}

#[test]
fn refresh_chats_clears_stale_send_targets_for_public_only_account() {
    // Regression for issue #196: logging in a public-only identity must not
    // leave messages_account_id/messages_group_id (and the prior account's
    // subscriptions) pointing at the previous local account/chat, or Enter
    // would silently send from the old account into the old chat.
    let previous_account = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let previous_group = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let public_only = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"accounts":[]}}"#);
    let mut app = test_tui_app(client, previous_account);
    // Stand in for the prior refresh against local signing account A.
    app.accounts.push(AccountRow {
        account_id: public_only.to_owned(),
        npub: "npub1public".to_owned(),
        display_name: Some("Public".to_owned()),
        local_signing: false,
    });
    app.selected_account = 1;
    app.chats = vec![ChatRow {
        group_id: previous_group.to_owned(),
        name: "general".to_owned(),
        archived: false,
    }];
    app.messages_account_id = Some(previous_account.to_owned());
    app.messages_group_id = Some(previous_group.to_owned());
    app.chat_subscription = Some(test_chat_subscription(previous_account, false));
    app.message_subscription = Some(test_message_subscription(previous_account));
    app.group_diagnostics = Some(GroupDiagnostics::unavailable(previous_group, "old"));

    app.refresh_chats().expect("refresh chats");

    assert!(app.chats.is_empty());
    assert!(app.messages.is_empty());
    assert!(app.messages_account_id.is_none());
    assert!(app.messages_group_id.is_none());
    assert!(app.chat_subscription.is_none());
    assert!(app.message_subscription.is_none());
    assert!(app.group_state_subscription.is_none());
    assert!(app.group_diagnostics.is_none());
}

#[test]
fn message_subscription_skips_initial_replay() {
    assert_eq!(
        message_subscription_args(),
        vec![
            "messages".to_owned(),
            "subscribe".to_owned(),
            "--limit".to_owned(),
            "0".to_owned(),
        ]
    );
}

#[test]
fn composer_redacts_nsec_imports_without_hiding_other_input() {
    assert_eq!(
        composer_display_text("/login nsec1secret"),
        "/login <hidden nsec>"
    );
    assert_eq!(
        composer_display_text("/login  nsec1secret"),
        "/login <hidden nsec>"
    );
    assert_eq!(
        composer_display_text(" /login nsec1secret"),
        "/login <hidden nsec>"
    );
    assert_eq!(
        composer_display_text("/login\tnsec1secret"),
        "/login <hidden nsec>"
    );
    assert_eq!(
        composer_display_text("/ login nsec1secret"),
        "/login <hidden nsec>"
    );
    assert_eq!(
        composer_display_text("/  login nsec1secret"),
        "/login <hidden nsec>"
    );
    assert_eq!(
        composer_display_text("/\tlogin nsec1secret"),
        "/login <hidden nsec>"
    );
    assert_eq!(
        composer_display_text(" / login nsec1secret"),
        "/login <hidden nsec>"
    );
    assert_eq!(composer_display_text("/login npub1bob"), "/login npub1bob");
    assert_eq!(
        composer_display_text("/ login npub1bob"),
        "/ login npub1bob"
    );
}

#[test]
fn account_setup_invocation_pipes_nsec_imports_to_stdin() {
    assert_eq!(
        account_setup_invocation(Some("nsec1secret".to_owned())),
        DmInvocation {
            args: vec!["login".to_owned(), "--nsec-stdin".to_owned()],
            stdin: Some("nsec1secret\n".to_owned()),
        }
    );
    assert_eq!(
        account_setup_invocation(Some("npub1bob".to_owned())),
        DmInvocation {
            args: vec!["login".to_owned(), "npub1bob".to_owned()],
            stdin: None,
        }
    );
}

#[test]
fn subscription_reader_accepts_daemon_stream_frames() {
    match subscription_event_from_json(serde_json::json!({
        "result": {
            "type": "message",
            "message": {
                "message_id": "abc",
                "plaintext": "hello"
            }
        }
    })) {
        SubscriptionEvent::Result(result) => {
            assert_eq!(result["type"], "message");
            assert_eq!(result["message"]["plaintext"], "hello");
        }
        other => panic!("expected result event, got {other:?}"),
    }

    match subscription_event_from_json(serde_json::json!({
        "error": {
            "message": "app runtime is not running"
        }
    })) {
        SubscriptionEvent::Error(message) => {
            assert_eq!(message, "app runtime is not running");
        }
        other => panic!("expected error event, got {other:?}"),
    }

    assert!(matches!(
        subscription_event_from_json(serde_json::json!({"stream_end": true})),
        SubscriptionEvent::Ended
    ));
}

#[test]
fn account_rows_prefer_profile_display_name_then_name_then_npub() {
    let with_display_name = parse_account(&serde_json::json!({
        "account_id": "abc123",
        "npub": "npub1abc",
        "local_signing": true,
        "profile": {
            "name": "alice",
            "display_name": "Alice Example"
        }
    }))
    .expect("account");
    assert_eq!(account_display_label(&with_display_name), "Alice Example");

    let with_name = parse_account(&serde_json::json!({
        "account_id": "def456",
        "npub": "npub1def",
        "local_signing": true,
        "profile": {
            "name": "bob"
        }
    }))
    .expect("account");
    assert_eq!(account_display_label(&with_name), "bob");

    let without_profile = parse_account(&serde_json::json!({
        "account_id": "0123456789abcdef",
        "npub": "npub1fallback",
        "local_signing": false
    }))
    .expect("account");
    assert_eq!(account_display_label(&without_profile), "npub1fallback");
}

#[test]
fn message_lines_use_sender_display_name_when_available() {
    let messages = [serde_json::json!({
        "message_id": "01",
        "recorded_at": 10,
        "received_at": 10,
        "direction": "received",
        "from": "abc123",
        "from_display_name": "Alice Example",
        "plaintext": "hello"
    })]
    .iter()
    .filter_map(parse_message)
    .collect::<Vec<_>>();

    let rendered = message_lines(&messages, None)
        .iter()
        .map(line_text)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    assert_eq!(rendered, vec!["Alice Example: hello"]);
}

#[test]
fn message_account_row_uses_loaded_account_not_highlighted_account() {
    let alice = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let bob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let mut app = test_tui_app(test_unused_client(), alice);
    app.accounts.push(AccountRow {
        account_id: bob.to_owned(),
        npub: "npub1bob".to_owned(),
        display_name: Some("Bob".to_owned()),
        local_signing: true,
    });
    app.selected_account = 1;
    app.messages_account_id = Some(alice.to_owned());

    let rendered = message_lines(
        &[
            MessageRow {
                message_id: "01".to_owned(),
                direction: "sent".to_owned(),
                from: alice.to_owned(),
                from_display_name: None,
                plaintext: "from alice".to_owned(),
                display_text: "from alice".to_owned(),
                recorded_at: 1,
                received_at: 1,
            },
            MessageRow {
                message_id: "02".to_owned(),
                direction: "received".to_owned(),
                from: bob.to_owned(),
                from_display_name: Some("Bob".to_owned()),
                plaintext: "from bob".to_owned(),
                display_text: "from bob".to_owned(),
                recorded_at: 2,
                received_at: 2,
            },
        ],
        app.message_account_row(),
    )
    .iter()
    .map(line_text)
    .filter(|line| !line.is_empty())
    .collect::<Vec<_>>();

    assert_eq!(rendered, vec!["me: from alice", "Bob: from bob"]);
}

#[test]
fn account_selection_matches_npub_or_hex_pubkey() {
    let account = AccountRow {
        account_id: "abc123".to_owned(),
        npub: "npub1abc".to_owned(),
        display_name: None,
        local_signing: true,
    };

    assert!(account_matches(&account, "abc123"));
    assert!(account_matches(&account, "npub1abc"));
    assert!(!account_matches(&account, "abc"));
}

#[test]
fn move_index_clamps_at_list_edges() {
    assert_eq!(move_index(0, 3, -1), 0);
    assert_eq!(move_index(0, 3, 1), 1);
    assert_eq!(move_index(2, 3, 1), 2);
    assert_eq!(move_index(0, 0, 1), 0);
}

#[test]
fn messages_scroll_offsets_anchor_to_bottom_and_clamp() {
    // Content fits the viewport: no scrolling is possible.
    assert_eq!(messages_scroll_offsets(5, 10, 0), (0, 0));
    assert_eq!(messages_scroll_offsets(5, 10, 4), (0, 0));
    // Pinned to the bottom shows the newest lines (offset = overflow).
    assert_eq!(messages_scroll_offsets(40, 10, 0), (0, 30));
    // Scrolling up moves the top offset toward the first line.
    assert_eq!(messages_scroll_offsets(40, 10, 12), (12, 18));
    // Scrollback past the top clamps to the first line.
    assert_eq!(messages_scroll_offsets(40, 10, u16::MAX), (30, 0));
}

fn char_key(character: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE)
}

#[test]
fn leading_question_mark_inserts_into_empty_composer() {
    // Regression for darkmatter#200: a leading '?' in an empty composer
    // used to toggle help and was swallowed instead of being inserted.
    let mut app = test_tui_app(test_unused_client(), "aa".repeat(32).as_str());
    app.focus = Focus::Composer;
    assert!(app.input.is_empty());
    assert!(!app.show_help);

    app.handle_key(char_key('?')).expect("handle '?'");

    assert_eq!(app.input, "?");
    assert!(!app.show_help, "'?' in composer must not toggle help");

    app.handle_key(char_key('h')).expect("handle 'h'");
    app.handle_key(char_key('i')).expect("handle 'i'");
    assert_eq!(app.input, "?hi");
}

#[test]
fn question_mark_toggles_help_outside_composer() {
    // '?' still toggles help when the composer is not focused.
    let mut app = test_tui_app(test_unused_client(), "aa".repeat(32).as_str());
    app.focus = Focus::Chats;
    assert!(!app.show_help);

    app.handle_key(char_key('?')).expect("handle '?'");
    assert!(app.show_help, "'?' outside composer toggles help on");
    assert!(app.input.is_empty());

    app.handle_key(char_key('?')).expect("handle '?'");
    assert!(!app.show_help, "'?' outside composer toggles help off");
}

fn line_text(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>()
}

fn test_tui_app(client: DmClient, account_id: &str) -> TuiApp {
    TuiApp {
        client,
        initial_account: None,
        running: true,
        focus: Focus::Composer,
        accounts: vec![AccountRow {
            account_id: account_id.to_owned(),
            npub: "npub1alice".to_owned(),
            display_name: None,
            local_signing: true,
        }],
        selected_account: 0,
        chats: Vec::new(),
        selected_chat: 0,
        messages_account_id: None,
        messages_group_id: None,
        unread_counts: HashMap::new(),
        show_archived_chats: false,
        messages: Vec::new(),
        messages_scroll: 0,
        messages_viewport: 0,
        live_stream_previews: Vec::new(),
        chat_subscription: None,
        message_subscription: None,
        group_state_subscription: None,
        daemon: DaemonView {
            running: true,
            ..DaemonView::default()
        },
        group_diagnostics: None,
        input: String::new(),
        streaming: None,
        status: String::new(),
        show_help: false,
    }
}

fn test_unused_client() -> DmClient {
    DmClient {
        exe: PathBuf::from("unused"),
        home: None,
        socket: None,
        relay: None,
        secret_store: None,
        keychain_service: None,
    }
}

fn test_json_client(response: &str) -> (tempfile::TempDir, DmClient) {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let exe = test_json_executable(tempdir.path(), response);
    let client = DmClient {
        exe,
        home: None,
        socket: None,
        relay: None,
        secret_store: None,
        keychain_service: None,
    };
    (tempdir, client)
}

#[cfg(unix)]
fn test_json_executable(dir: &std::path::Path, response: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let exe = dir.join("dm-json");
    std::fs::write(&exe, format!("#!/bin/sh\ncat <<'JSON'\n{response}\nJSON\n"))
        .expect("write fake dm");
    let mut permissions = std::fs::metadata(&exe)
        .expect("fake dm metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&exe, permissions).expect("chmod fake dm");
    exe
}

#[cfg(windows)]
fn test_json_executable(dir: &std::path::Path, response: &str) -> PathBuf {
    let exe = dir.join("dm-json.cmd");
    std::fs::write(&exe, format!("@echo off\r\necho {response}\r\n")).expect("write fake dm");
    exe
}

fn test_chat_subscription(account_id: &str, include_archived: bool) -> ChatSubscription {
    let child = test_sleep_child();
    let (_tx, rx) = mpsc::channel();
    ChatSubscription {
        account_id: account_id.to_owned(),
        include_archived,
        child,
        rx,
    }
}

#[test]
fn failed_due_stream_append_updates_last_flush_to_back_off_tick_retry() {
    // Regression for darkmatter#197: automatic stream-append retries come from
    // tick(), which runs every UI event interval. A failing append must move the
    // retry gate forward so a down daemon/broker does not spawn a blocking `dm`
    // subprocess on every tick.
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (_tempdir, client) =
        test_json_client(r#"{"ok":false,"error":{"message":"broker offline"}}"#);
    let mut app = test_tui_app(client, account_id);
    let first_due = Instant::now();
    let stale_flush = first_due - STREAM_APPEND_FLUSH_INTERVAL - Duration::from_millis(1);
    app.streaming = Some(StreamComposer {
        stream_id: "stream-197".to_owned(),
        group_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        pending_text: "queued".to_owned(),
        last_flush: stale_flush,
    });

    let first = app.flush_stream_append_if_due(first_due);

    assert!(
        first.is_err(),
        "first due flush should report the append failure"
    );
    let streaming = app.streaming.as_ref().expect("composer remains active");
    assert_eq!(streaming.pending_text, "queued");
    assert!(streaming.last_flush >= first_due);
    let retry_gate = streaming.last_flush;

    let second = app.flush_stream_append_if_due(retry_gate + UI_EVENT_WAIT);

    assert!(!second.expect("retry gate should suppress immediate retry"));
    let streaming = app.streaming.as_ref().expect("composer remains active");
    assert_eq!(streaming.pending_text, "queued");
    assert_eq!(streaming.last_flush, retry_gate);
}

#[test]
fn streaming_enter_failure_is_caught_into_status_and_keeps_tui_running() {
    // Regression for issue #194: a fallible streaming finish (daemon gone,
    // broker/QUIC error, relay publish ok=false) must not propagate out of
    // handle_key and tear down the whole TUI. It should be caught into the
    // status line, mirroring the non-streaming Enter path and tick().
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (_tempdir, client) = test_json_client(r#"{"ok":false,"error":{"message":"daemon gone"}}"#);
    let mut app = test_tui_app(client, account_id);
    app.streaming = Some(StreamComposer {
        stream_id: "stream-194".to_owned(),
        group_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        pending_text: String::new(),
        last_flush: Instant::now(),
    });
    app.input = "hello".to_owned();

    let outcome = app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

    // The key handler must succeed so run() keeps looping instead of exiting.
    assert!(outcome.is_ok(), "handle_key must not propagate the error");
    assert!(
        app.running,
        "TUI must stay running after a streaming failure"
    );
    assert!(
        app.status.contains("daemon gone"),
        "error must surface in the status line, got: {}",
        app.status
    );
    // The compose-finish call consumes the composer before running the
    // fallible `dm stream compose-finish`. On failure it must be restored so
    // the draft text in `self.input` is not silently re-sent as a normal
    // message through the non-streaming Enter path on the next keypress.
    assert!(
        app.streaming.is_some(),
        "composer must be restored after a compose-finish failure so Enter/Esc retries the stream"
    );
    assert_eq!(
        app.input, "hello",
        "draft text must be preserved for retry after a compose-finish failure"
    );
}

#[test]
fn streaming_enter_failure_before_finish_preserves_composer() {
    // When the failure occurs before the compose-finish call consumes the
    // composer (here: empty input short-circuits, then a pending append
    // flush fails), the composer state is kept so the user can retry.
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (_tempdir, client) =
        test_json_client(r#"{"ok":false,"error":{"message":"broker offline"}}"#);
    let mut app = test_tui_app(client, account_id);
    app.streaming = Some(StreamComposer {
        stream_id: "stream-194".to_owned(),
        group_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        pending_text: "queued".to_owned(),
        last_flush: Instant::now(),
    });
    app.input = "queued".to_owned();

    let outcome = app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

    assert!(outcome.is_ok(), "handle_key must not propagate the error");
    assert!(
        app.running,
        "TUI must stay running after a streaming failure"
    );
    assert!(
        app.status.contains("broker offline"),
        "error must surface in the status line, got: {}",
        app.status
    );
    assert!(
        app.streaming.is_some(),
        "composer must be preserved on a pre-finish failure so Enter/Esc can retry"
    );
}

fn test_message_subscription(account_id: &str) -> MessageSubscription {
    let child = test_sleep_child();
    let (_tx, rx) = mpsc::channel();
    MessageSubscription {
        account_id: account_id.to_owned(),
        child,
        rx,
    }
}

#[cfg(not(windows))]
fn test_sleep_child() -> Child {
    StdCommand::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleep test process")
}

#[cfg(windows)]
fn test_sleep_child() -> Child {
    StdCommand::new("cmd")
        .args(["/C", "timeout", "/T", "60", "/NOBREAK"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn timeout test process")
}
