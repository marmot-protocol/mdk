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
fn group_system_summary_prefers_structured_self_removal_summary() {
    let value = serde_json::json!({
        "from": "aa".repeat(32),
        "from_display_name": "alice",
        "group_system": {
            "system_type": "member_removed",
            "actor": "aa".repeat(32),
            "actor_display_name": "alice",
            "subject": "bb".repeat(32),
            "subject_is_self": true,
            "summary": "You were removed from the group by alice"
        }
    });
    let removed = r#"{"v":1,"system_type":"member_removed","text":"Member removed","data":{"subject":"bbbbbbbb"}}"#;
    assert_eq!(
        group_system_summary(&value, removed).as_deref(),
        Some("You were removed from the group by alice")
    );
}

#[test]
fn group_system_summary_ignores_blank_structured_summary() {
    let value = serde_json::json!({
        "from": "aa".repeat(32),
        "from_display_name": "alice",
        "group_system": {
            "summary": "   "
        }
    });
    let removed = r#"{"v":1,"system_type":"member_removed","text":"Member removed","data":{"subject":"bbbbbbbb"}}"#;
    assert_eq!(
        group_system_summary(&value, removed).as_deref(),
        Some("alice removed bbbbbbbb")
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
    assert!(bare.contains(&"/image <file-path> [caption]"));

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
    app.input.set_value("/chat r");

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
fn chat_list_scrolls_the_selection_into_view() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    // A chat list far taller than the panel, with the selection at the bottom.
    app.chats = (0..40)
        .map(|i| projected_chat(&format!("group{i:02}"), &format!("room{i:02}"), 0, Some(i)))
        .collect();
    let last = app.chats.len() - 1;
    app.chats[last].name = "BOTTOMROOM".to_owned();
    app.selected_chat = last;
    app.focus = Focus::Chats;

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

    assert!(
        rendered.contains("BOTTOMROOM"),
        "the selected chat at the bottom must scroll into view, not clip off-panel"
    );
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
fn slash_command_parser_handles_logout() {
    // `/logout` acts on the currently selected account and takes no arguments, so
    // a stray argument is a parse error rather than a silently ignored token.
    assert_eq!(parse_slash_command("/logout"), Ok(SlashCommand::Logout));
    assert!(parse_slash_command("/logout npub1bob").is_err());
}

#[test]
fn logout_local_signing_account_arms_typed_token_popup() {
    // A local-signing logout is irreversible (the signing key is destroyed with
    // the local data), so `/logout` arms a typed-token confirmation for the
    // selected account rather than a one-key confirm. The body must state
    // honestly that the wipe is permanent, deletes the signing key, and cannot be
    // undone, and must instruct the user to type the token — a destructive
    // action's description is never softened.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout arms the popup");

    match &app.popup {
        Some(Popup::Text {
            purpose:
                TextPurpose::ConfirmLogout {
                    account_id: target,
                    npub,
                },
            title,
            body,
            input,
        }) => {
            assert_eq!(target, &account_id, "popup targets the selected account");
            assert_eq!(npub, "npub1alice");
            assert_eq!(title, "Log Out");
            assert!(input.value().is_empty(), "the token field starts empty");
            let text = body.join(" ");
            assert!(
                text.contains("permanently"),
                "wording must be honest about permanence: {text:?}"
            );
            assert!(
                text.contains("signing key"),
                "a local-signing account is told its key is deleted: {text:?}"
            );
            assert!(
                text.contains("device"),
                "wording must scope the wipe to this device: {text:?}"
            );
            assert!(
                text.contains(&format!("Type {LOGOUT_CONFIRMATION_TOKEN}")),
                "the body instructs the user to type the token: {text:?}"
            );
        }
        other => panic!("expected a typed-token logout popup, got {other:?}"),
    }
}

#[test]
fn logout_confirm_body_omits_signing_key_line_for_public_only_accounts() {
    // A public-only account has no signing key to erase, so the honest wording
    // must not claim one is deleted; it warns about the unrecoverable local data
    // instead.
    let account_id = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.accounts[0].local_signing = false;

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout arms the popup");

    match &app.popup {
        Some(Popup::Confirm { body, .. }) => {
            let text = body.join(" ");
            assert!(
                !text.contains("signing key"),
                "public-only account has no signing key to mention: {text:?}"
            );
            assert!(
                text.contains("recover"),
                "public-only wording still warns the local data is unrecoverable: {text:?}"
            );
        }
        other => panic!("expected a logout confirm popup, got {other:?}"),
    }
}

#[test]
fn logout_popup_shows_the_npub_even_with_a_display_name() {
    // The npub is the unambiguous identifier for which account is about to be
    // destroyed. A display name must not hide it: the body shows the npub for
    // both account types even when a display name is set.
    for local_signing in [true, false] {
        let account_id = "aa".repeat(32);
        let mut app = test_tui_app(test_unused_client(), &account_id);
        app.accounts[0].display_name = Some("Alice".to_owned());
        app.accounts[0].local_signing = local_signing;

        app.run_slash_command(SlashCommand::Logout)
            .expect("/logout arms the popup");

        let body = match &app.popup {
            Some(Popup::Text { body, .. } | Popup::Confirm { body, .. }) => body.join(" "),
            other => panic!("expected a logout popup, got {other:?}"),
        };
        assert!(
            body.contains("Alice"),
            "the display name still labels the account: {body:?}"
        );
        assert!(
            body.contains("npub1alice"),
            "the npub is shown regardless of the display name: {body:?}"
        );
    }
}

#[test]
fn logout_popup_sanitizes_a_hostile_display_name() {
    // A hostile display name (ANSI/control/format characters) must be
    // terminal-safe in the logout popup body specifically: the dangerous bytes
    // are stripped, the visible text survives, and the npub still identifies the
    // account.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.accounts[0].display_name = Some("Al\u{1b}\u{7}ice\u{202e}".to_owned());

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout arms the popup");

    let body = match &app.popup {
        Some(Popup::Text { body, .. }) => body.join(" "),
        other => panic!("expected a typed-token logout popup, got {other:?}"),
    };
    assert!(
        !body.contains('\u{1b}'),
        "the ANSI escape is stripped: {body:?}"
    );
    assert!(
        !body.contains('\u{7}'),
        "the BEL control byte is stripped: {body:?}"
    );
    assert!(
        !body.contains('\u{202e}'),
        "the BiDi override is stripped: {body:?}"
    );
    assert!(
        body.contains("Alice"),
        "the visible display-name text survives sanitization: {body:?}"
    );
    assert!(
        body.contains("npub1alice"),
        "the npub identifies the account: {body:?}"
    );
}

#[test]
fn logout_slash_command_without_a_selected_account_reports_instead_of_arming() {
    // With no account loaded there is nothing to log out; the command reports on
    // the status line rather than opening a popup with an empty target.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.accounts.clear();

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout with no account is not an error");

    assert!(app.popup.is_none(), "no popup without an account to target");
    assert_eq!(app.status, "no account selected");
}

#[cfg(unix)]
#[test]
fn typing_the_logout_token_runs_wn_logout_and_refreshes() {
    // The whole point of the typed-token confirm: typing the token and pressing
    // Enter runs the real `wn logout <pubkey>` for the selected account, then
    // reloads accounts so the TUI lands on a remaining account rather than the
    // removed one.
    let removed = "aa".repeat(32);
    let remaining = "bb".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) = test_appending_arg_executable(
        dir.path(),
        r#"{"ok":true,"result":{"accounts":[{"account_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","npub":"npub1bob","local_signing":true}]}}"#,
    );
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &removed);
    // No daemon so the refresh does not spawn subscription subprocesses; the flow
    // under test is the command dispatch and account reload.
    app.daemon.running = false;

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout arms the popup");
    type_logout_token(&mut app);
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("Enter on the exact token confirms logout");

    let recorded = std::fs::read_to_string(&args_file).expect("the fake wn ran");
    assert!(
        recorded
            .lines()
            .any(|line| line == format!("--json logout {removed}")),
        "confirming runs `wn logout <selected-account>`; recorded: {recorded:?}"
    );
    assert!(app.popup.is_none(), "the popup closes after submit");
    assert_eq!(
        app.accounts.len(),
        1,
        "accounts reloaded after the wipe: {:?}",
        app.accounts
    );
    assert_eq!(
        app.accounts[0].account_id, remaining,
        "the TUI lands on the remaining account, not the removed one"
    );
    assert!(
        app.status.starts_with("logged out"),
        "status: {}",
        app.status
    );
}

#[cfg(unix)]
#[test]
fn logout_subprocess_failure_surfaces_on_status_without_clobbering_accounts() {
    // A failed `wn logout` must be non-destructive to the TUI's view: the error
    // surfaces on the status line, the popup closes, and the account list is left
    // intact (the account still appears) rather than being cleared as if the wipe
    // had succeeded.
    let account_id = "aa".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) = test_appending_arg_executable(
        dir.path(),
        r#"{"ok":false,"error":{"message":"keychain locked"}}"#,
    );
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout arms the popup");
    type_logout_token(&mut app);
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("Enter on the exact token confirms logout");

    let recorded = std::fs::read_to_string(&args_file).expect("the fake wn ran");
    assert!(
        recorded
            .lines()
            .any(|line| line == format!("--json logout {account_id}")),
        "the wipe was attempted; recorded: {recorded:?}"
    );
    assert!(
        app.popup.is_none(),
        "the popup closes even when the wipe fails"
    );
    assert!(
        app.status.starts_with("error:"),
        "the failure surfaces on the status line: {}",
        app.status
    );
    assert_eq!(
        app.accounts.len(),
        1,
        "a failed wipe does not clobber the account list"
    );
    assert_eq!(
        app.accounts[0].account_id, account_id,
        "the account still appears after a failed wipe"
    );
}

#[cfg(unix)]
#[test]
fn canceling_the_typed_token_logout_with_esc_runs_nothing() {
    // Esc cancels the typed-token confirm with no side effect — even after part
    // of the token was typed: no `wn` process is spawned and the account list is
    // unchanged.
    let account_id = "aa".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) = test_appending_arg_executable(dir.path(), r#"{"ok":true,"result":{}}"#);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout arms the popup");
    for character in "log".chars() {
        app.handle_key(char_key(character))
            .expect("partial token typed");
    }
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("Esc cancels the typed-token popup");

    assert!(app.popup.is_none(), "Esc dismisses the typed-token popup");
    assert!(!args_file.exists(), "canceling never spawns a `wn` process");
    assert_eq!(app.accounts.len(), 1, "the account list is untouched");
    assert_eq!(app.accounts[0].account_id, account_id);
}

#[cfg(unix)]
#[test]
fn public_only_logout_confirms_with_y_enter_and_runs_wn_logout() {
    // A public-only account is re-addable, so it keeps the lighter y/Enter
    // confirm (medium-tier friction is proportional there): `y` runs the real
    // `wn logout <pubkey>`.
    let account_id = "bb".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) =
        test_appending_arg_executable(dir.path(), r#"{"ok":true,"result":{"accounts":[]}}"#);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;
    app.accounts[0].local_signing = false;

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout arms the popup");
    assert!(
        matches!(app.popup, Some(Popup::Confirm { .. })),
        "a public-only account keeps the y/Enter confirm"
    );
    app.handle_key(char_key('y')).expect("y confirms logout");

    let recorded = std::fs::read_to_string(&args_file).expect("the fake wn ran");
    assert!(
        recorded
            .lines()
            .any(|line| line == format!("--json logout {account_id}")),
        "y runs `wn logout <account>`; recorded: {recorded:?}"
    );
    assert!(app.popup.is_none(), "the confirm closes after submit");
}

#[cfg(unix)]
#[test]
fn canceling_public_only_logout_with_n_or_esc_runs_nothing() {
    // The public-only confirm keeps its two cancel keys: both `n` and `Esc`
    // dismiss it with no `wn` process spawned and the account list unchanged.
    let account_id = "bb".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) = test_appending_arg_executable(dir.path(), r#"{"ok":true,"result":{}}"#);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.accounts[0].local_signing = false;

    for cancel in [
        char_key('n'),
        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
    ] {
        app.run_slash_command(SlashCommand::Logout)
            .expect("/logout arms the popup");
        app.handle_key(cancel).expect("cancel key handled");
        assert!(app.popup.is_none(), "cancel dismisses the confirm");
    }

    assert!(!args_file.exists(), "canceling never spawns a `wn` process");
    assert_eq!(app.accounts.len(), 1, "the account list is untouched");
    assert_eq!(app.accounts[0].account_id, account_id);
}

#[test]
fn logout_popup_captures_keys_without_leaking_to_the_composer() {
    // The typed-token popup is modal: characters land in its own token field and
    // never reach the composer draft hidden behind it.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Composer;
    app.input.set_value("draft");

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout arms the popup");
    app.handle_key(char_key('x')).expect("stray key handled");

    match &app.popup {
        Some(Popup::Text { input, .. }) => {
            assert_eq!(
                input.value(),
                "x",
                "the key lands in the popup's own token field"
            );
        }
        other => panic!("expected the typed-token popup to stay open, got {other:?}"),
    }
    assert_eq!(
        app.input.value(),
        "draft",
        "the key does not leak into the composer behind the popup"
    );
}

#[cfg(unix)]
#[test]
fn logging_out_the_last_account_returns_to_the_login_menu_and_clears_state() {
    // When the removed account was the only one, the TUI must not be left pointed
    // at nothing: it clears chat/subscription state and drops to the login menu.
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let (exe, _args_file) =
        test_appending_arg_executable(dir.path(), r#"{"ok":true,"result":{"accounts":[]}}"#);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;
    app.chats = vec![ChatRow {
        group_id: group_id.clone(),
        name: "general".to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    }];
    app.chat_subscription = Some(test_chat_subscription(&account_id, false));
    app.notification_subscription = Some(test_notification_subscription(&account_id));

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout arms the popup");
    type_logout_token(&mut app);
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("Enter on the exact token confirms logout");

    assert!(app.accounts.is_empty(), "the last account is gone");
    assert!(app.chats.is_empty(), "chats cleared");
    assert!(
        app.chat_subscription.is_none(),
        "chat subscription torn down"
    );
    assert!(
        app.notification_subscription.is_none(),
        "notification subscription torn down"
    );
    assert_eq!(
        app.screen,
        Screen::Login(LoginMode::Menu),
        "the TUI drops back to the login menu"
    );
}

#[cfg(unix)]
#[test]
fn double_enter_after_slash_logout_does_not_wipe_a_local_signing_account() {
    // The fixed footgun: `/logout` submitted from the composer used to arm a
    // y/Enter confirm, so Enter-then-Enter (slash submit, then confirm accept)
    // instantly ran the destructive wipe — the identity-destroying action was
    // uniquely reachable by two Enters. For a local-signing account the second
    // Enter must be a no-op that keeps the popup open and spawns no `wn` process.
    let account_id = "aa".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) =
        test_appending_arg_executable(dir.path(), r#"{"ok":true,"result":{"accounts":[]}}"#);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;
    app.focus = Focus::Composer;
    app.input.set_value("/logout");

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("first Enter submits /logout and arms the popup");
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("second Enter is handled");

    assert!(
        app.popup.is_some(),
        "the logout popup stays open after the second Enter"
    );
    assert!(
        !args_file.exists(),
        "Enter-then-Enter never spawns a `wn` process"
    );
    assert_eq!(app.accounts.len(), 1, "the account is untouched");
}

#[cfg(unix)]
#[test]
fn logout_token_mismatch_is_a_noop_that_keeps_the_popup_open() {
    // A local-signing logout requires typing the exact token `logout`. Anything
    // else — a near miss included — keeps the popup open and spawns no `wn`
    // process, so a fat-fingered confirmation never destroys the identity.
    let account_id = "aa".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) =
        test_appending_arg_executable(dir.path(), r#"{"ok":true,"result":{"accounts":[]}}"#);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;

    app.run_slash_command(SlashCommand::Logout)
        .expect("/logout arms the popup");
    for character in "logoutt".chars() {
        app.handle_key(char_key(character))
            .expect("typing the wrong token");
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("Enter on a mismatched token is handled");

    assert!(
        app.popup.is_some(),
        "a mismatched token keeps the popup open"
    );
    assert!(
        !args_file.exists(),
        "a mismatched token spawns no `wn` process"
    );
    assert_eq!(app.accounts.len(), 1, "the account is untouched");
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
        parse_slash_command("/chat mute 1h"),
        Ok(SlashCommand::ChatMute("1h".to_owned()))
    );
    assert_eq!(
        parse_slash_command("/chat unmute"),
        Ok(SlashCommand::ChatUnmute)
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
fn slash_command_parser_handles_image_sends() {
    assert_eq!(
        parse_slash_command("/image /tmp/photo.jpg"),
        Ok(SlashCommand::Image {
            file_path: "/tmp/photo.jpg".to_owned(),
            caption: None,
        })
    );
    assert_eq!(
        parse_slash_command("/image \"/tmp/family photo.jpg\" hello there"),
        Ok(SlashCommand::Image {
            file_path: "/tmp/family photo.jpg".to_owned(),
            caption: Some("hello there".to_owned()),
        })
    );
    assert!(parse_slash_command("/image").is_err());
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
fn diagnostics_panel_lines_show_mls_and_components() {
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

    // The diagnostics panel drops the leading status line (now in the status bar):
    // it starts straight at the MLS summary.
    let rendered = diagnostics_panel_lines(Some(&diagnostics))
        .iter()
        .map(line_text)
        .collect::<Vec<_>>();

    assert_eq!(
        rendered[0],
        "MLS epoch=7 group=aaaaaaa...aaaaaaaa members=3"
    );
    assert_eq!(rendered[1], "components:");
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
        projection: ChatProjection::default(),
    };

    let line = chat_row_line(&chat, false, 3);

    assert_eq!(line_text(&line), "  Project Room (3)");
    assert!(line.spans[0].style.add_modifier.contains(Modifier::BOLD));
    assert!(line.spans[1].style.add_modifier.contains(Modifier::BOLD));
    assert_eq!(line.spans[1].style.fg, Some(Color::Green));
}

#[test]
fn chat_row_line_renders_the_unread_badge_yellow_and_bold() {
    let chat = ChatRow {
        group_id: "group-a".to_owned(),
        name: "Project Room".to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    };

    let line = chat_row_line(&chat, false, 3);

    // The name keeps its own style while the `(N)` badge is a separate yellow
    // bold span (the wn-tui look the spec pins).
    assert_eq!(line_text(&line), "  Project Room (3)");
    let name = &line.spans[1];
    assert_eq!(name.content.as_ref(), "Project Room");
    assert_eq!(name.style.fg, Some(Color::Green));
    assert!(name.style.add_modifier.contains(Modifier::BOLD));
    let badge = &line.spans[2];
    assert_eq!(badge.content.as_ref(), " (3)");
    assert_eq!(badge.style.fg, Some(Color::Yellow));
    assert!(badge.style.add_modifier.contains(Modifier::BOLD));
}

#[test]
fn chat_row_line_selected_badge_takes_the_row_fg_bump() {
    let chat = ChatRow {
        group_id: "group-a".to_owned(),
        name: "Project Room".to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    };

    let line = chat_row_line(&chat, true, 3);

    // The selected row renders black-on-white; the badge takes the same fg bump
    // as the name (`row_label_style`) so it stays readable on the white bg.
    let badge = &line.spans[2];
    assert_eq!(badge.content.as_ref(), " (3)");
    assert_eq!(badge.style.fg, Some(Color::Black));
    assert!(badge.style.add_modifier.contains(Modifier::BOLD));
}

#[test]
fn chat_row_line_read_chat_has_no_badge_span() {
    let chat = ChatRow {
        group_id: "group-a".to_owned(),
        name: "Project Room".to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    };

    let line = chat_row_line(&chat, false, 0);

    assert_eq!(line_text(&line), "  Project Room");
    assert!(
        !line
            .spans
            .iter()
            .any(|span| span.style.fg == Some(Color::Yellow)),
        "a read chat renders no badge span"
    );
}

#[test]
fn chat_label_keeps_unread_count_when_truncated() {
    // The name is truncated to leave room for the whole badge within `max_len`,
    // so the badge always survives truncation intact.
    assert_eq!(
        chat_label("A very long group display name", 12, 18),
        ("A ver... name".to_owned(), Some(" (12)".to_owned()))
    );
    assert_eq!(
        chat_label("ops", 0, 18),
        ("ops".to_owned(), None),
        "a read chat has no badge part"
    );
}

#[test]
fn terminal_safe_text_strips_bidi_and_zero_width_format_characters() {
    assert_eq!(
        terminal_safe_text(
            "safe\u{202a}name\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}\u{200b}\u{200c}\u{200d}\u{200e}\u{200f}\u{feff}done",
        ),
        "safenamedone"
    );
}

#[test]
fn terminal_safe_text_strips_residual_invisible_and_format_spoofing_characters() {
    // Each entry is a residual invisible / format vector that the original
    // hardcoded denylist let through (see #473). All must be stripped, while
    // the surrounding visible "ab" must survive so we are sure we are not
    // simply dropping everything.
    let format_class_cf: &[(char, &str)] = &[
        ('\u{00ad}', "SOFT HYPHEN"),
        ('\u{2061}', "FUNCTION APPLICATION"),
        ('\u{2062}', "INVISIBLE TIMES"),
        ('\u{2063}', "INVISIBLE SEPARATOR"),
        ('\u{2064}', "INVISIBLE PLUS"),
        ('\u{206a}', "INHIBIT SYMMETRIC SWAPPING"),
        ('\u{206f}', "NOMINAL DIGIT SHAPES"),
        ('\u{fff9}', "INTERLINEAR ANNOTATION ANCHOR"),
        ('\u{fffa}', "INTERLINEAR ANNOTATION SEPARATOR"),
        ('\u{fffb}', "INTERLINEAR ANNOTATION TERMINATOR"),
        ('\u{180e}', "MONGOLIAN VOWEL SEPARATOR"),
        ('\u{1d173}', "MUSICAL SYMBOL BEGIN BEAM"),
        ('\u{061c}', "ARABIC LETTER MARK"),
        ('\u{e0001}', "LANGUAGE TAG"),
        ('\u{e0020}', "TAG SPACE"),
        ('\u{e007e}', "TAG TILDE"),
        ('\u{e007f}', "CANCEL TAG"),
    ];
    let invisible_non_cf: &[(char, &str)] = &[
        ('\u{115f}', "HANGUL CHOSEONG FILLER"),
        ('\u{1160}', "HANGUL JUNGSEONG FILLER"),
        ('\u{3164}', "HANGUL FILLER"),
        ('\u{ffa0}', "HALFWIDTH HANGUL FILLER"),
        ('\u{2800}', "BRAILLE PATTERN BLANK"),
    ];

    for (ch, name) in format_class_cf.iter().chain(invisible_non_cf) {
        let input = format!("a{ch}b");
        assert_eq!(
            terminal_safe_text(&input),
            "ab",
            "expected {name} (U+{:04X}) to be stripped",
            *ch as u32
        );
    }
}

#[test]
fn terminal_safe_text_preserves_legitimate_visible_and_combining_text() {
    // Visible scripts, whitespace, and zero-width combining marks (accents,
    // Indic virama, Arabic vowel marks, emoji variation selectors) must survive
    // unchanged so the sanitizer does not mangle real localized text. Combining
    // marks legitimately have zero rendered width, so a naive width-only filter
    // would corrupt them.
    let preserved = [
        "plain ascii",
        "中文 日本語 한국어",
        "café",         // precomposed
        "cafe\u{0301}", // e + COMBINING ACUTE ACCENT
        "नमस्ते",         // Devanagari incl. virama U+094D
        "سَلَام",          // Arabic incl. fatha U+064E
        "❤\u{fe0f}",    // heart + VARIATION SELECTOR-16
        "emoji 😀 ok",
        "a b\u{00a0}c", // NO-BREAK SPACE is visible/whitespace, keep
    ];
    for sample in preserved {
        assert_eq!(
            terminal_safe_text(sample),
            sample,
            "expected {sample:?} to pass through unchanged"
        );
    }
    // Tab is a C0 control and is correctly stripped (prior behavior preserved).
    assert_eq!(
        terminal_safe_text("with\ttab-was-control"),
        "withtab-was-control"
    );
}

#[test]
fn render_lines_strip_terminal_control_sequences_from_untrusted_text() {
    let mut row = timeline_row("01", 0);
    row.from = "alice".to_owned();
    row.from_display_name = Some("ali\u{1b}]0;pwn\u{7}ce".to_owned());
    row.display_text = "hi\u{1b}[2Jbob".to_owned();
    let rendered = timeline_row_lines(&row, None)
        .into_iter()
        .map(|line| line_text(&line))
        .collect::<Vec<_>>();
    assert_eq!(hhmm_body(&rendered[0]), "ali]0;pwnce: hi[2Jbob");

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
        projection: ChatProjection::default(),
    };
    assert_eq!(line_text(&chat_row_line(&chat, false, 0)), "  ops[5m");

    let diagnostics =
        diagnostics_panel_lines(Some(&GroupDiagnostics::unavailable("aa", "bad\u{1b}[31m")));
    assert_eq!(
        line_text(&diagnostics[0]),
        "MLS group=aa unavailable: bad[31m"
    );
}

#[test]
fn image_slash_command_uses_real_media_upload_send_surface() {
    assert_eq!(
        media_upload_send_args(
            "group-a".to_owned(),
            "/tmp/photo.jpg".to_owned(),
            Some("hello image".to_owned()),
        ),
        vec![
            "media",
            "upload",
            "group-a",
            "/tmp/photo.jpg",
            "--send",
            "--message",
            "hello image",
        ]
    );
    assert_eq!(
        media_upload_send_args(
            "group-a".to_owned(),
            "/tmp/photo.jpg".to_owned(),
            Some("   ".to_owned()),
        ),
        vec!["media", "upload", "group-a", "/tmp/photo.jpg", "--send"]
    );
}

#[test]
fn daemon_status_json_becomes_status_text() {
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
        projection: ChatProjection::default(),
    }];
    // Selection now points at a DIFFERENT group than the streamed-into one.
    app.selected_chat = 0;
    app.streaming = Some(StreamComposer {
        stream_id: stream_id.to_owned(),
        group_id: stream_group.to_owned(),
        pending_text: String::new(),
        last_flush: Instant::now(),
    });
    app.input.set_value("hello");

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
    let mut previews = Vec::new();

    apply_subscription_result(
        &mut previews,
        &serde_json::json!({
            "type": "agent_stream_delta",
            "agent_stream_delta": {
                "group_id": group_id,
                "stream_id": stream_id,
                "text": "hello "
            }
        }),
    );
    apply_subscription_result(
        &mut previews,
        &serde_json::json!({
            "type": "agent_stream_delta",
            "agent_stream_delta": {
                "group_id": group_id,
                "stream_id": stream_id,
                "text": "stream"
            }
        }),
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
            projection: ChatProjection::default(),
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
fn subscription_final_message_removes_live_stream_preview() {
    // The plain feed no longer populates the pane (the timeline feed owns it),
    // but it still clears the live stream preview when the agent stream's final
    // row lands so a completed stream stops rendering in the pane's bottom block.
    let mut previews = Vec::new();

    apply_subscription_result(
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
    );
    assert_eq!(previews.len(), 1);
    apply_subscription_result(
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
    );

    assert!(previews.is_empty());
}

#[test]
fn plain_feed_cleans_up_stream_preview_on_agent_final() {
    // Phase 4 retired the plain feed's local unread counting (unread is
    // runtime-backed now). The feed still owns QUIC stream previews: an agent
    // stream's final row clears the live preview, with no message appended.
    // (Retired with the local counting: all_chat_subscription_marks_nonselected_
    // messages_unread, _does_not_count_selected_group_as_unread, and
    // _ignores_initial_replay_for_unread_counts.)
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let stream_id = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let mut previews = vec![LiveStreamPreview {
        group_id: group_id.to_owned(),
        stream_id: stream_id.to_owned(),
        author: "alice".to_owned(),
        status: "streaming".to_owned(),
        text: "partial".to_owned(),
        error: None,
        optimistic: false,
    }];

    apply_subscription_result(
        &mut previews,
        &serde_json::json!({
            "trigger": "AgentStreamFinalized",
            "type": "agent_stream_final",
            "message": {
                "message_id": "final",
                "direction": "received",
                "group_id": group_id,
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

    assert!(previews.is_empty());
}

// Retired in Phase 4: message_subscription_gates_on_loaded_chat_not_highlighted_chat
// asserted the plain feed's local unread counting, which no longer exists — unread
// is runtime-backed. The loaded-vs-highlighted gating that still matters (the
// timeline feed and mark-read target the loaded pane) is covered by the timeline
// and mark-read tests below.

#[test]
fn drain_status_leaves_the_login_prompt_untouched_but_updates_main() {
    // A picker reached via `A` from an active session keeps its background
    // drains running. On the login/account-select screen the status line carries
    // the nsec prompt and picker guidance, so a live drain must apply its state
    // changes without overwriting that prompt.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    let (tx, rx) = mpsc::channel();
    app.message_subscription = Some(MessageSubscription {
        account_id: account_id.clone(),
        child: test_sleep_child(),
        rx,
    });

    app.screen = Screen::Login(LoginMode::NsecEntry);
    let prompt = "enter nsec; Enter submits, Esc cancels".to_owned();
    app.status = prompt.clone();
    tx.send(SubscriptionEvent::Error("relay dropped".to_owned()))
        .expect("send error event");
    assert!(app.drain_message_subscription());
    assert_eq!(
        app.status, prompt,
        "the login prompt survives a background drain"
    );

    // The same event on the main view still surfaces on the status line.
    app.screen = Screen::Main;
    tx.send(SubscriptionEvent::Error("relay dropped".to_owned()))
        .expect("send error event");
    assert!(app.drain_message_subscription());
    assert!(
        app.status.contains("relay dropped"),
        "main-view drains still set status, got: {}",
        app.status
    );
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
fn refresh_accounts_clears_chat_state_when_no_accounts_remain() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"accounts":[]}}"#);
    let mut app = test_tui_app(client, account_id);
    app.chats = vec![ChatRow {
        group_id: group_id.to_owned(),
        name: "general".to_owned(),
        archived: false,
        projection: ChatProjection {
            unread_count: 3,
            has_unread: true,
            ..ChatProjection::default()
        },
    }];
    app.chat_subscription = Some(test_chat_subscription(account_id, false));
    app.message_subscription = Some(test_message_subscription(account_id));
    app.notification_subscription = Some(test_notification_subscription(account_id));
    app.group_diagnostics = Some(GroupDiagnostics::unavailable(group_id, "old"));

    app.refresh_accounts().expect("refresh accounts");

    assert!(app.accounts.is_empty());
    assert!(app.chats.is_empty());
    assert!(app.timeline.is_empty());
    assert!(app.chat_subscription.is_none());
    assert!(app.message_subscription.is_none());
    assert!(app.notification_subscription.is_none());
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
    assert!(app.timeline.is_empty());
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
        projection: ChatProjection::default(),
    }];
    app.messages_account_id = Some(previous_account.to_owned());
    app.messages_group_id = Some(previous_group.to_owned());
    app.chat_subscription = Some(test_chat_subscription(previous_account, false));
    app.message_subscription = Some(test_message_subscription(previous_account));
    app.group_diagnostics = Some(GroupDiagnostics::unavailable(previous_group, "old"));

    app.refresh_chats().expect("refresh chats");

    assert!(app.chats.is_empty());
    assert!(app.timeline.is_empty());
    assert!(app.messages_account_id.is_none());
    assert!(app.messages_group_id.is_none());
    assert!(app.chat_subscription.is_none());
    assert!(app.message_subscription.is_none());
    assert!(app.group_state_subscription.is_none());
    assert!(app.notification_subscription.is_none());
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
fn timeline_subscription_pins_the_initial_page_size() {
    // Without --limit the daemon's default 50-row page transiently clobbers the
    // snapshot's accurate has_more_before; pin it to the TUI page size.
    assert_eq!(
        timeline_subscription_args("group-1"),
        vec![
            "messages".to_owned(),
            "timeline".to_owned(),
            "subscribe".to_owned(),
            "group-1".to_owned(),
            "--limit".to_owned(),
            TUI_TIMELINE_PAGE_SIZE.to_string(),
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
        account_setup_invocation(Some("nsec1secret".to_owned()), None),
        WnInvocation {
            args: vec!["login".to_owned(), "--nsec-stdin".to_owned()],
            stdin: Some("nsec1secret\n".to_owned()),
        }
    );
    assert_eq!(
        account_setup_invocation(Some("npub1bob".to_owned()), None),
        WnInvocation {
            args: vec!["login".to_owned(), "npub1bob".to_owned()],
            stdin: None,
        }
    );
}

#[test]
fn account_setup_invocation_appends_first_run_setup_relay() {
    // The first-run setup relay is appended as the one `--relay` flag account
    // setup accepts (global for create-identity, command-local for login).
    assert_eq!(
        account_setup_invocation(None, Some("wss://relay.example".to_owned())),
        WnInvocation {
            args: vec![
                "create-identity".to_owned(),
                "--relay".to_owned(),
                "wss://relay.example".to_owned(),
            ],
            stdin: None,
        }
    );
    assert_eq!(
        account_setup_invocation(
            Some("nsec1secret".to_owned()),
            Some("wss://relay.example".to_owned())
        ),
        WnInvocation {
            args: vec![
                "login".to_owned(),
                "--nsec-stdin".to_owned(),
                "--relay".to_owned(),
                "wss://relay.example".to_owned(),
            ],
            stdin: Some("nsec1secret\n".to_owned()),
        }
    );
    // A blank relay adds no flag.
    assert_eq!(
        account_setup_invocation(None, Some("  ".to_owned())),
        WnInvocation {
            args: vec!["create-identity".to_owned()],
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
fn message_account_row_uses_loaded_account_not_highlighted_account() {
    // The pane colors a row green when it belongs to the *loaded* account, even
    // when a different account is highlighted in the accounts list. A received
    // row whose sender is the loaded account (alice) must render green; a row
    // from someone else renders cyan.
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

    let mut from_alice = timeline_row("01", 1);
    from_alice.direction = "received".to_owned();
    from_alice.from = alice.to_owned();
    let mut from_bob = timeline_row("02", 2);
    from_bob.direction = "received".to_owned();
    from_bob.from = bob.to_owned();
    from_bob.from_display_name = Some("Bob".to_owned());

    let selected_account = app.message_account_row();
    assert_eq!(
        timeline_row_lines(&from_alice, selected_account)[0].spans[1]
            .style
            .fg,
        Some(Color::Green),
        "a row from the loaded account is colored as self"
    );
    assert_eq!(
        timeline_row_lines(&from_bob, selected_account)[0].spans[1]
            .style
            .fg,
        Some(Color::Cyan),
        "a row from another sender is colored as other"
    );
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

fn char_key(character: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE)
}

/// Type the exact logout confirmation token into an open typed-token popup,
/// keyed off the shared constant so the tests track its value.
fn type_logout_token(app: &mut TuiApp) {
    for character in LOGOUT_CONFIRMATION_TOKEN.chars() {
        app.handle_key(char_key(character))
            .expect("typing the logout token");
    }
}

#[test]
fn leading_question_mark_inserts_into_empty_composer() {
    // Regression for mdk#200: a leading '?' in an empty composer
    // used to toggle help and was swallowed instead of being inserted.
    let mut app = test_tui_app(test_unused_client(), "aa".repeat(32).as_str());
    app.focus = Focus::Composer;
    assert!(app.input.is_empty());
    assert!(app.popup.is_none());

    app.handle_key(char_key('?')).expect("handle '?'");

    assert_eq!(app.input.value(), "?");
    assert!(app.popup.is_none(), "'?' in composer must not open help");

    app.handle_key(char_key('h')).expect("handle 'h'");
    app.handle_key(char_key('i')).expect("handle 'i'");
    assert_eq!(app.input.value(), "?hi");
}

#[test]
fn question_mark_opens_help_popup_outside_composer() {
    // '?' opens the help popup when the composer is not focused; a second key
    // (routed to the modal) dismisses the dismiss-on-any-key card.
    let mut app = test_tui_app(test_unused_client(), "aa".repeat(32).as_str());
    app.focus = Focus::Chats;
    assert!(app.popup.is_none());

    app.handle_key(char_key('?')).expect("handle '?'");
    assert!(
        matches!(app.popup, Some(Popup::Card { .. })),
        "'?' outside composer opens the help card"
    );
    assert!(app.input.is_empty());

    app.handle_key(char_key('?')).expect("handle '?'");
    assert!(
        app.popup.is_none(),
        "a key under the help card dismisses it"
    );
}

#[test]
fn q_under_open_help_dismisses_the_card_without_quitting() {
    // Regression: with the old boolean help overlay, `q` under help quit the
    // app. As a modal card, `q` is captured and dismisses the card instead.
    let mut app = test_tui_app(test_unused_client(), "aa".repeat(32).as_str());
    app.focus = Focus::Chats;
    app.handle_key(char_key('?')).expect("open help");
    assert!(app.popup.is_some());

    app.handle_key(char_key('q')).expect("q under help");

    assert!(app.popup.is_none(), "q dismisses the help card");
    assert!(app.running, "q under help must not quit the app");
}

fn line_text(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>()
}

fn test_tui_app(client: WnClient, account_id: &str) -> TuiApp {
    TuiApp {
        client,
        initial_account: None,
        running: true,
        screen: Screen::Main,
        entered_main: true,
        show_diagnostics: false,
        focus: Focus::Composer,
        accounts: vec![AccountRow {
            account_id: account_id.to_owned(),
            npub: "npub1alice".to_owned(),
            display_name: None,
            local_signing: true,
        }],
        selected_account: 0,
        picker_selection: 0,
        chats: Vec::new(),
        selected_chat: 0,
        messages_account_id: None,
        messages_group_id: None,
        show_archived_chats: false,
        timeline: Vec::new(),
        timeline_scroll: TimelineScroll::default(),
        live_stream_previews: Vec::new(),
        chat_subscription: None,
        message_subscription: None,
        timeline_subscription: None,
        group_state_subscription: None,
        notification_subscription: None,
        pending_chat_relist: false,
        pending_mark_read: false,
        seen_notification_keys: SeenNotificationKeys::new(),
        daemon: DaemonView {
            running: true,
            ..DaemonView::default()
        },
        group_diagnostics: None,
        input: Input::default(),
        streaming: None,
        status: String::new(),
        popup: None,
        group_detail: None,
        user_search: None,
        profile_view: None,
        relay_health: None,
        media: MediaState::new(),
    }
}

fn test_unused_client() -> WnClient {
    WnClient {
        exe: PathBuf::from("unused"),
        home: None,
        socket: None,
        relay: None,
        discovery_relays: Vec::new(),
        default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
    }
}

fn test_json_client(response: &str) -> (tempfile::TempDir, WnClient) {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let exe = test_json_executable(tempdir.path(), response);
    let client = WnClient {
        exe,
        home: None,
        socket: None,
        relay: None,
        discovery_relays: Vec::new(),
        default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
    };
    (tempdir, client)
}

/// A fake `wn` whose `groups invites` calls return `first` on the first call and
/// `rest` afterward, while every other subcommand returns a benign empty result.
/// This lets a test drive the invites picker across an accept/decline where the
/// refreshed list shrinks (the fixed-response fake cannot model that).
#[cfg(unix)]
fn test_invites_seq_client(first: &str, rest: &str) -> (tempfile::TempDir, WnClient) {
    use std::os::unix::fs::PermissionsExt;

    let tempdir = tempfile::tempdir().expect("tempdir");
    let counter = tempdir.path().join("invites-seen");
    let exe = tempdir.path().join("wn-json");
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in\n  *\" invites \"*)\n    if [ -f '{counter}' ]; then\ncat <<'JSON'\n{rest}\nJSON\n    else\n      : > '{counter}'\ncat <<'JSON'\n{first}\nJSON\n    fi\n    ;;\n  *)\ncat <<'JSON'\n{{\"ok\":true,\"result\":{{}}}}\nJSON\n    ;;\nesac\n",
        counter = counter.display(),
    );
    std::fs::write(&exe, script).expect("write fake wn");
    let mut permissions = std::fs::metadata(&exe)
        .expect("fake wn metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&exe, permissions).expect("chmod fake wn");
    let client = WnClient {
        exe,
        home: None,
        socket: None,
        relay: None,
        discovery_relays: Vec::new(),
        default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
    };
    (tempdir, client)
}

#[cfg(unix)]
fn test_json_executable(dir: &std::path::Path, response: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let exe = dir.join("wn-json");
    std::fs::write(&exe, format!("#!/bin/sh\ncat <<'JSON'\n{response}\nJSON\n"))
        .expect("write fake wn");
    let mut permissions = std::fs::metadata(&exe)
        .expect("fake wn metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&exe, permissions).expect("chmod fake wn");
    exe
}

/// A fake `wn` that records its argv (one arg per line) to a sidecar file and
/// then prints `response`, so a test can assert which command was spawned.
/// Returns the executable path and the args-file path.
#[cfg(unix)]
fn test_arg_recording_executable(dir: &std::path::Path, response: &str) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let exe = dir.join("wn-json");
    let args_file = dir.join("recorded-args");
    std::fs::write(
        &exe,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncat <<'JSON'\n{response}\nJSON\n",
            args_file.display()
        ),
    )
    .expect("write fake wn");
    let mut permissions = std::fs::metadata(&exe)
        .expect("fake wn metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&exe, permissions).expect("chmod fake wn");
    (exe, args_file)
}

#[cfg(windows)]
fn test_json_executable(dir: &std::path::Path, response: &str) -> PathBuf {
    let exe = dir.join("wn-json.cmd");
    std::fs::write(&exe, format!("@echo off\r\necho {response}\r\n")).expect("write fake wn");
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
    // Regression for mdk#197: automatic stream-append retries come from
    // tick(), which runs every UI event interval. A failing append must move the
    // retry gate forward so a down daemon/broker does not spawn a blocking `wn`
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
fn streaming_keys_capture_input_before_screen_dispatch() {
    // The streaming-composer check must sit ahead of the screen dispatch (behind
    // only Ctrl-C), so any future Main->Login path with an open stream still
    // routes keys to the stream while tick() keeps flushing, instead of the login
    // handler consuming the key. Constructed by flipping the screen to Login with
    // a live stream.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.streaming = Some(StreamComposer {
        stream_id: "stream-1".to_owned(),
        group_id: "bb".repeat(32),
        pending_text: String::new(),
        last_flush: Instant::now(),
    });

    // Main view: a character queues on the stream composer.
    app.screen = Screen::Main;
    app.handle_key(char_key('x')).expect("char in main");
    assert_eq!(
        app.streaming.as_ref().expect("stream active").pending_text,
        "x"
    );

    // With the screen on the login/account-select flow, an open stream keeps
    // capturing input; the login handler never sees the key.
    app.screen = Screen::Login(LoginMode::AccountSelect);
    app.handle_key(char_key('y'))
        .expect("char while login screen");
    assert_eq!(
        app.streaming.as_ref().expect("stream active").pending_text,
        "xy"
    );
    assert_eq!(
        app.screen,
        Screen::Login(LoginMode::AccountSelect),
        "the login handler never consumed the streaming key"
    );
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
    app.input.set_value("hello");

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
    // fallible `wn stream compose-finish`. On failure it must be restored so
    // the draft text in `self.input` is not silently re-sent as a normal
    // message through the non-streaming Enter path on the next keypress.
    assert!(
        app.streaming.is_some(),
        "composer must be restored after a compose-finish failure so Enter/Esc retries the stream"
    );
    assert_eq!(
        app.input.value(),
        "hello",
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
    app.input.set_value("queued");

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

fn test_notification_subscription(account_id: &str) -> NotificationSubscription {
    let child = test_sleep_child();
    let (_tx, rx) = mpsc::channel();
    NotificationSubscription {
        account_id: account_id.to_owned(),
        child,
        rx,
    }
}

/// A chat row carrying a runtime projection: `unread` unread messages and, when
/// `last_activity` is set, a `last_message` from "Bob" at that timestamp.
fn projected_chat(
    group_id: &str,
    name: &str,
    unread: usize,
    last_activity: Option<u64>,
) -> ChatRow {
    ChatRow {
        group_id: group_id.to_owned(),
        name: name.to_owned(),
        archived: false,
        projection: ChatProjection {
            unread_count: unread,
            has_unread: unread > 0,
            last_message: last_activity.map(|timeline_at| ChatLastMessage {
                sender: Some("bob".to_owned()),
                sender_display_name: Some("Bob".to_owned()),
                plaintext: "hello".to_owned(),
                kind: Some(9),
                timeline_at,
                deleted: false,
            }),
            ..ChatProjection::default()
        },
    }
}

/// A `notifications subscribe` daemon event with the runtime DTO nested under
/// `notification`, matching the real feed's envelope.
fn notification_json(trigger: &str, group_id: &str, notification_key: &str) -> Value {
    serde_json::json!({
        "trigger": "Notification",
        "type": "notification",
        "group_id": group_id,
        "notification_key": notification_key,
        "notification": {
            "trigger": trigger,
            "group_id_hex": group_id,
            "notification_key": notification_key
        }
    })
}

// ── Phase 4 ambient state: projection, previews, ordering, notifications ────

#[test]
fn parse_chat_reads_runtime_projection_fields() {
    let chat = parse_chat(&serde_json::json!({
        "group_id": "aa",
        "profile": {"name": "ops"},
        "archived": false,
        "unread_count": 4,
        "has_unread": true,
        "last_message": {
            "message_id_hex": "m1",
            "sender": "bob_hex",
            "sender_display_name": "Bob",
            "plaintext": "hey there",
            "kind": 9,
            "timeline_at": 1_700_000_050_u64,
            "deleted": false
        },
        "last_read_message_id_hex": "r1",
        "last_read_timeline_at": 1_700_000_000_u64
    }))
    .expect("chat parses");

    assert_eq!(chat.projection.unread_count, 4);
    assert!(chat.projection.has_unread);
    let last = chat.projection.last_message.expect("last message present");
    assert_eq!(last.sender_display_name.as_deref(), Some("Bob"));
    assert_eq!(last.plaintext, "hey there");
    assert_eq!(last.kind, Some(9));
    assert_eq!(last.timeline_at, 1_700_000_050);
    assert!(!last.deleted);
    assert_eq!(
        chat.projection.last_read_message_id_hex.as_deref(),
        Some("r1")
    );
    assert_eq!(chat.projection.last_read_timeline_at, Some(1_700_000_000));
}

#[test]
fn parse_chat_defaults_projection_when_keys_absent() {
    // Tolerant parse: a legacy/partial row (no projection keys) is still a chat.
    let chat = parse_chat(&serde_json::json!({
        "group_id": "aa",
        "profile": {"name": "ops"}
    }))
    .expect("chat parses");

    assert_eq!(chat.projection, ChatProjection::default());
    assert_eq!(chat.projection.unread_count, 0);
    assert!(!chat.projection.has_unread);
    assert!(chat.projection.last_message.is_none());
}

#[test]
fn status_bar_unread_total_sums_runtime_projections() {
    // The status bar's `{u} unread` is the sum of the runtime projection counts —
    // no local counting anywhere.
    let chats = vec![
        projected_chat("aa", "ops", 2, Some(10)),
        projected_chat("bb", "eng", 0, Some(20)),
        projected_chat("cc", "ops2", 5, Some(30)),
    ];
    assert_eq!(total_unread(&chats), 7);
}

#[test]
fn chat_row_badge_and_preview_come_from_the_projection() {
    let chat = projected_chat("aa", "ops", 2, Some(30));

    let line = chat_row_line(&chat, false, chat.projection.unread_count);
    assert_eq!(line_text(&line), "  ops (2)");

    let preview = chat_preview_line(&chat).expect("a chat with a last message has a preview");
    assert_eq!(line_text(&preview), "    Bob: hello");
    assert_eq!(
        preview.spans.last().expect("preview span").style.fg,
        Some(Color::DarkGray)
    );
}

#[test]
fn chat_without_last_message_has_no_preview_line() {
    let chat = projected_chat("aa", "ops", 0, None);
    assert!(chat_preview_line(&chat).is_none());
}

#[test]
fn chat_preview_renders_tombstone_and_group_system_summary() {
    let mut deleted = projected_chat("aa", "ops", 0, Some(30));
    deleted
        .projection
        .last_message
        .as_mut()
        .expect("last message")
        .deleted = true;
    assert_eq!(
        line_text(&chat_preview_line(&deleted).expect("preview")),
        "    message deleted"
    );

    let mut system = projected_chat("bb", "eng", 0, Some(30));
    let last = system
        .projection
        .last_message
        .as_mut()
        .expect("last message");
    last.kind = Some(GROUP_SYSTEM_KIND);
    last.sender_display_name = Some("Alice".to_owned());
    last.plaintext = r#"{"system_type":"member_added","data":{"subject":"carol"}}"#.to_owned();
    assert_eq!(
        line_text(&chat_preview_line(&system).expect("preview")),
        "    Alice added carol"
    );
}

#[test]
fn chats_order_by_last_activity_preserving_selection() {
    let mut chats = vec![
        projected_chat("aa", "old", 0, Some(10)),
        projected_chat("bb", "new", 0, Some(30)),
        projected_chat("cc", "mid", 0, Some(20)),
    ];
    let mut selected = 0; // highlighting "aa"

    resort_chats_preserving_selection(&mut chats, &mut selected);

    assert_eq!(
        chats
            .iter()
            .map(|chat| chat.group_id.as_str())
            .collect::<Vec<_>>(),
        vec!["bb", "cc", "aa"],
        "chats order by last activity, newest first"
    );
    assert_eq!(
        chats[selected].group_id, "aa",
        "the highlight follows its chat across the reorder"
    );
}

#[test]
fn message_less_chats_keep_the_list_order_as_a_stable_fallback() {
    // Equal-activity rows (here: all message-less) keep the order they came in —
    // the documented stable fallback.
    let mut chats = vec![
        projected_chat("aa", "first", 0, None),
        projected_chat("bb", "second", 0, None),
        projected_chat("cc", "third", 0, None),
    ];
    sort_chats_by_activity(&mut chats);
    assert_eq!(
        chats
            .iter()
            .map(|chat| chat.group_id.as_str())
            .collect::<Vec<_>>(),
        vec!["aa", "bb", "cc"]
    );
}

#[test]
fn timeline_chat_list_row_folds_into_the_loaded_chat() {
    let mut chats = vec![
        projected_chat("aa", "ops", 0, Some(10)),
        projected_chat("bb", "eng", 0, Some(20)),
    ];
    let mut selected = 0; // highlighting "aa"
    let event = serde_json::json!({
        "type": "timeline_projection_updated",
        "group_id": "aa",
        "chat_list_row": {
            "unread_count": 3,
            "has_unread": true,
            "last_message": {
                "sender_display_name": "Bob",
                "plaintext": "new here",
                "kind": 9,
                "timeline_at": 30,
                "deleted": false
            }
        }
    });

    let (group_id, projection) = timeline_chat_list_row(&event).expect("chat_list_row present");
    assert!(fold_chat_projection(
        &mut chats,
        &mut selected,
        &group_id,
        projection
    ));

    // aa now has the newest activity (30), so it sorts to the top and the
    // highlight follows it there.
    assert_eq!(chats[0].group_id, "aa");
    assert_eq!(chats[0].projection.unread_count, 3);
    assert_eq!(chats[selected].group_id, "aa");
    assert_eq!(
        chats[1].projection.unread_count, 0,
        "the other chat is untouched"
    );
}

#[test]
fn timeline_chat_list_row_is_none_without_a_projection() {
    let ready = serde_json::json!({"type": "timeline_subscription_ready"});
    assert!(timeline_chat_list_row(&ready).is_none());
}

#[test]
fn chats_feed_default_projection_does_not_clobber_a_live_one() {
    // A transient producer-side projection read failure degrades a chats-feed
    // row to all-default keys. The full-row replace must not wipe a live badge
    // and preview, so an entirely-default incoming projection keeps the
    // existing non-default one.
    let mut chats = vec![projected_chat("aa", "ops", 4, Some(30))];
    let bare = ChatRow {
        group_id: "aa".to_owned(),
        name: "ops".to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    };
    upsert_chat(&mut chats, bare, false);
    assert_eq!(
        chats[0].projection.unread_count, 4,
        "an all-default feed row keeps the existing live badge"
    );
    assert!(
        chats[0].projection.last_message.is_some(),
        "the last-message preview is preserved too"
    );
}

#[test]
fn chats_feed_nonempty_projection_still_replaces() {
    // A legitimate projection (here a read that lowers the badge) is not
    // entirely default, so it still replaces the existing one.
    let mut chats = vec![projected_chat("aa", "ops", 4, Some(30))];
    let read = ChatRow {
        group_id: "aa".to_owned(),
        name: "ops".to_owned(),
        archived: false,
        projection: ChatProjection {
            last_message: Some(ChatLastMessage {
                sender: Some("bob".to_owned()),
                sender_display_name: Some("Bob".to_owned()),
                plaintext: "hello".to_owned(),
                kind: Some(9),
                timeline_at: 40,
                deleted: false,
            }),
            ..ChatProjection::default()
        },
    };
    upsert_chat(&mut chats, read, false);
    assert_eq!(
        chats[0].projection.unread_count, 0,
        "a non-default incoming projection replaces (a real read lowers the badge)"
    );
}

#[test]
fn notifications_for_other_chats_schedule_one_pending_relist() {
    // N distinct NewMessage events for non-loaded chats, drained in one window,
    // set exactly one pending re-list (coalesced by the debounce flag).
    let mut seen = SeenNotificationKeys::new();
    let mut pending = false;
    for key in ["msg:1", "msg:2", "msg:3"] {
        let event = parse_notification_event(&notification_json("NewMessage", "bb", key));
        assert_eq!(
            apply_notification_event(&mut seen, &mut pending, Some("aa"), event),
            NotificationOutcome::ScheduledRelist
        );
    }
    assert!(
        pending,
        "several NewMessage events set the single pending flag"
    );
    assert_eq!(seen.len(), 3);
}

#[test]
fn duplicate_notification_key_does_not_retrigger() {
    let mut seen = SeenNotificationKeys::new();
    let mut pending = false;

    let first = parse_notification_event(&notification_json("NewMessage", "bb", "msg:1"));
    assert_eq!(
        apply_notification_event(&mut seen, &mut pending, Some("aa"), first),
        NotificationOutcome::ScheduledRelist
    );

    pending = false; // as the tick loop would, after performing the re-list
    let duplicate = parse_notification_event(&notification_json("NewMessage", "bb", "msg:1"));
    assert_eq!(
        apply_notification_event(&mut seen, &mut pending, Some("aa"), duplicate),
        NotificationOutcome::Ignored
    );
    assert!(!pending, "a duplicated emission does not re-schedule");
}

#[test]
fn notification_for_the_loaded_chat_is_ignored() {
    // The loaded pane's badge is kept fresh by the timeline feed + mark-read, so
    // its NewMessage notifications never schedule a re-list.
    let mut seen = SeenNotificationKeys::new();
    let mut pending = false;
    let event = parse_notification_event(&notification_json("NewMessage", "aa", "msg:1"));
    assert_eq!(
        apply_notification_event(&mut seen, &mut pending, Some("aa"), event),
        NotificationOutcome::Ignored
    );
    assert!(!pending);
}

#[test]
fn group_invite_notification_surfaces_a_notice() {
    let mut seen = SeenNotificationKeys::new();
    let mut pending = false;
    let event = parse_notification_event(&serde_json::json!({
        "type": "notification",
        "group_id": "bb",
        "notification": {
            "trigger": "GroupInvite",
            "group_id_hex": "bb",
            "group_name": "Secret Room",
            "notification_key": "invite:1"
        }
    }));
    assert_eq!(
        apply_notification_event(&mut seen, &mut pending, Some("aa"), event),
        NotificationOutcome::Invite("invited to Secret Room — press I to view invites".to_owned())
    );
    assert!(!pending, "an invite does not schedule a re-list this phase");
}

#[test]
fn drain_notification_subscription_coalesces_to_one_pending_relist() {
    let account_id = "aa".repeat(32);
    let loaded_group = "aa".repeat(32);
    let other_group = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.messages_group_id = Some(loaded_group);
    let (tx, rx) = mpsc::channel();
    app.notification_subscription = Some(NotificationSubscription {
        account_id: account_id.clone(),
        child: test_sleep_child(),
        rx,
    });
    for key in ["m1", "m2", "m3"] {
        tx.send(SubscriptionEvent::Result(notification_json(
            "NewMessage",
            &other_group,
            key,
        )))
        .expect("send notification event");
    }

    assert!(app.drain_notification_subscription());
    assert!(
        app.pending_chat_relist,
        "several NewMessage events in one drain set exactly one pending re-list"
    );
    assert_eq!(app.seen_notification_keys.len(), 3);
}

#[test]
fn drain_notification_subscription_drops_other_accounts_events() {
    // The runtime-wide feed carries every local account's notifications. An
    // event routed to a different account must change nothing on this one: no
    // notice, no pending re-list, no dedup-key insertion.
    let account_id = "aa".repeat(32);
    let other_account = "cc".repeat(32);
    let other_group = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.messages_group_id = None;
    let (tx, rx) = mpsc::channel();
    app.notification_subscription = Some(NotificationSubscription {
        account_id: account_id.clone(),
        child: test_sleep_child(),
        rx,
    });
    let mut new_message = notification_json("NewMessage", &other_group, "m1");
    new_message["account_id"] = Value::String(other_account.clone());
    tx.send(SubscriptionEvent::Result(new_message))
        .expect("send new-message event");
    let invite = serde_json::json!({
        "type": "notification",
        "account_id": other_account,
        "notification": {
            "trigger": "GroupInvite",
            "group_name": "Secret Room",
            "notification_key": "invite:1"
        }
    });
    tx.send(SubscriptionEvent::Result(invite))
        .expect("send invite event");

    app.drain_notification_subscription();

    assert!(
        !app.pending_chat_relist,
        "another account's message never arms a re-list"
    );
    assert!(
        app.seen_notification_keys.is_empty(),
        "another account's dedup key is never recorded"
    );
    assert_eq!(
        app.status, "",
        "another account's invite surfaces no notice on this account"
    );
}

#[test]
fn seen_notification_keys_are_bounded() {
    // Dedup only needs to cover the recent event window, so the set is capped
    // and evicts oldest-first instead of growing unbounded over a session.
    let mut seen = SeenNotificationKeys::new();
    for i in 0..(TUI_SEEN_NOTIFICATION_KEYS_LIMIT + 50) {
        assert!(
            seen.insert(format!("k{i}")),
            "each distinct key is newly inserted"
        );
    }
    assert_eq!(
        seen.len(),
        TUI_SEEN_NOTIFICATION_KEYS_LIMIT,
        "the dedup set is capped, not unbounded"
    );
    assert!(
        seen.insert("k0".to_owned()),
        "the oldest key aged out, so it is treated as new again"
    );
    let recent = format!("k{}", TUI_SEEN_NOTIFICATION_KEYS_LIMIT + 49);
    assert!(
        !seen.insert(recent),
        "a key inside the recent window is still deduplicated"
    );
}

#[test]
fn tick_performs_the_pending_relist_exactly_once() {
    let account_id = "aa".repeat(32);
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"chats":[]}}"#);
    let mut app = test_tui_app(client, &account_id);
    app.daemon = DaemonView::default(); // no live subscriptions to drain
    app.pending_chat_relist = true;

    let changed = app.tick();

    assert!(changed);
    assert!(
        !app.pending_chat_relist,
        "tick runs the pending re-list once, then clears the debounce flag"
    );
}

#[test]
fn should_mark_loaded_chat_read_only_for_the_loaded_chat_with_unread() {
    let with_unread = ChatProjection {
        unread_count: 2,
        ..ChatProjection::default()
    };
    let read = ChatProjection::default();
    assert!(should_mark_loaded_chat_read(Some("aa"), "aa", &with_unread));
    assert!(
        !should_mark_loaded_chat_read(Some("aa"), "aa", &read),
        "no unread on the loaded chat means nothing to mark"
    );
    assert!(
        !should_mark_loaded_chat_read(Some("aa"), "bb", &with_unread),
        "a non-loaded chat keeps its badge (the ambient path owns it)"
    );
    assert!(
        !should_mark_loaded_chat_read(None, "aa", &with_unread),
        "no loaded chat means nothing to mark"
    );
}

#[test]
fn timeline_fold_arms_a_mark_read_for_the_viewed_chat() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some(group_id.clone());
    app.chats = vec![projected_chat(&group_id, "general", 0, Some(10))];
    app.selected_chat = 0;
    let (tx, rx) = mpsc::channel();
    app.timeline_subscription = Some(TimelineSubscription {
        account_id: account_id.clone(),
        group_id: group_id.clone(),
        child: test_sleep_child(),
        rx,
    });
    // The viewed chat accrues unread while we read it; the timeline feed imports
    // the growing count through its chat_list_row.
    tx.send(SubscriptionEvent::Result(serde_json::json!({
        "type": "timeline_projection_updated",
        "group_id": group_id,
        "chat_list_row": {"unread_count": 3, "has_unread": true},
        "changes": []
    })))
    .expect("send chat_list_row");

    assert!(app.drain_timeline_subscription());
    assert!(
        app.pending_mark_read,
        "importing a nonzero count for the viewed chat schedules a mark-read"
    );
}

#[test]
fn tick_marks_the_viewed_chat_read_once_and_clears_the_badge() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let (_tempdir, client) = test_json_client(
        r#"{"ok":true,"result":{"unread_count":0,"has_unread":false,"last_message":null}}"#,
    );
    let mut app = test_tui_app(client, &account_id);
    app.daemon = DaemonView::default(); // no live subscriptions to drain
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some(group_id.clone());
    app.chats = vec![projected_chat(&group_id, "general", 3, Some(30))];
    app.selected_chat = 0;
    app.pending_mark_read = true;

    assert!(app.tick());
    assert_eq!(
        app.chats[0].projection.unread_count, 0,
        "tick folds the mark-read response and clears the viewed chat's badge"
    );
    assert!(
        !app.pending_mark_read,
        "a successful mark-read clears the flag"
    );

    // The folded projection is now zero, so a second tick re-arms nothing.
    app.tick();
    assert!(!app.pending_mark_read, "no re-arm once the badge is clear");
}

#[test]
fn a_failed_relist_re_arms_for_the_next_tick() {
    let account_id = "aa".repeat(32);
    let (_tempdir, client) = test_json_client(r#"{"ok":false,"error":{"message":"daemon gone"}}"#);
    let mut app = test_tui_app(client, &account_id);
    app.daemon = DaemonView::default(); // no live subscriptions to drain
    app.pending_chat_relist = true;

    app.tick();

    assert!(
        app.pending_chat_relist,
        "a failed re-list re-arms instead of dropping the batch"
    );
    assert!(
        app.status.contains("re-list failed"),
        "the error still surfaces on the status line"
    );
}

#[test]
fn a_failed_mark_read_re_arms_for_the_next_tick() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let (_tempdir, client) = test_json_client(r#"{"ok":false,"error":{"message":"daemon gone"}}"#);
    let mut app = test_tui_app(client, &account_id);
    app.daemon = DaemonView::default();
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some(group_id.clone());
    app.chats = vec![projected_chat(&group_id, "general", 3, Some(30))];
    app.pending_mark_read = true;

    app.tick();

    assert!(
        app.pending_mark_read,
        "a failed mark-read re-arms for the next tick"
    );
    assert!(
        app.status.contains("mark-read failed"),
        "the error still surfaces on the status line"
    );
}

#[test]
fn opening_a_chat_marks_it_read_and_clears_the_badge() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    // The fake returns one response for every call; both `messages timeline list`
    // and `chats mark-read` see the empty-timeline/read projection.
    let (_tempdir, client) = test_json_client(
        r#"{"ok":true,"result":{"messages":[],"has_more_before":false,"unread_count":0,"has_unread":false,"last_message":null}}"#,
    );
    let mut app = test_tui_app(client, &account_id);
    app.daemon = DaemonView::default(); // mark-read is a normal command, daemon or not
    app.chats = vec![ChatRow {
        group_id: group_id.clone(),
        name: "general".to_owned(),
        archived: false,
        projection: ChatProjection {
            unread_count: 5,
            has_unread: true,
            ..ChatProjection::default()
        },
    }];
    app.selected_chat = 0;

    app.refresh_messages().expect("refresh messages");

    assert_eq!(
        app.chats[0].projection.unread_count, 0,
        "opening a chat folds the mark-read response and clears the badge immediately"
    );
}

#[test]
fn mark_read_failure_keeps_the_badge_honest() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let (_tempdir, client) = test_json_client(r#"{"ok":false,"error":{"message":"daemon gone"}}"#);
    let mut app = test_tui_app(client, &account_id);
    app.chats = vec![ChatRow {
        group_id: group_id.clone(),
        name: "general".to_owned(),
        archived: false,
        projection: ChatProjection {
            unread_count: 5,
            has_unread: true,
            ..ChatProjection::default()
        },
    }];
    app.selected_chat = 0;

    let result = app.mark_selected_chat_read(&account_id, &group_id);

    assert!(
        result.is_err(),
        "a failed mark-read is surfaced, not swallowed"
    );
    assert_eq!(
        app.chats[0].projection.unread_count, 5,
        "a failed mark-read never zeroes the badge locally"
    );
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

// ── Phase 1 timeline: rows, fold, scroll, heights, line building ────────

#[test]
fn parse_timeline_row_reads_core_fields() {
    let value = serde_json::json!({
        "message_id": "09be",
        "source_message_id": "5b10",
        "direction": "sent",
        "group_id": "cdaa",
        "from": "5a26",
        "from_display_name": "Witty Gecko",
        "plaintext": "msg-15",
        "kind": 9,
        "timeline_at": 1784070726u64,
        "received_at": 1784070726u64,
        "reply_to_message_id": null,
        "reply_preview": null,
        "media": null,
        "agent_text_stream": null,
        "reactions": { "by_emoji": {}, "user_reactions": [] },
        "deleted": false,
        "deleted_by_message_id": null
    });

    let row = parse_timeline_row(&value).expect("row parses");

    assert_eq!(row.message_id, "09be");
    assert_eq!(row.direction, "sent");
    assert_eq!(row.from, "5a26");
    assert_eq!(row.from_display_name.as_deref(), Some("Witty Gecko"));
    assert_eq!(row.plaintext, "msg-15");
    assert_eq!(row.display_text, "msg-15");
    assert_eq!(row.timeline_at, 1784070726);
    assert_eq!(row.received_at, 1784070726);
    assert!(!row.deleted);
    assert!(row.reactions.is_empty());
    assert!(row.reply.is_none());
    assert!(row.attachments.is_empty());
}

#[test]
fn parse_timeline_row_tallies_reactions_by_emoji_in_deterministic_order() {
    let value = serde_json::json!({
        "message_id": "1",
        "plaintext": "hi",
        "reactions": {
            "by_emoji": {
                "\u{2764}": ["a", "b"],
                "\u{1f44d}": ["1e23"]
            },
            "user_reactions": [{ "emoji": "\u{2764}" }]
        }
    });

    let row = parse_timeline_row(&value).expect("row parses");

    // Deterministic order regardless of JSON object ordering, and count is the
    // reactor-list length.
    assert_eq!(
        row.reactions,
        vec![
            TimelineReaction {
                emoji: "\u{2764}".to_owned(),
                count: 2
            },
            TimelineReaction {
                emoji: "\u{1f44d}".to_owned(),
                count: 1
            },
        ]
    );
}

#[test]
fn parse_timeline_row_reads_hydrated_reply_preview() {
    let value = serde_json::json!({
        "message_id": "2",
        "plaintext": "a reply",
        "reply_to_message_id": "parent-id",
        "reply_preview": {
            "message_id_hex": "parent-id",
            "sender": "Alice",
            "plaintext": "the original",
            "kind": 9,
            "deleted": false
        }
    });

    let reply = parse_timeline_row(&value)
        .expect("row parses")
        .reply
        .expect("reply present");

    assert_eq!(reply.reply_to_message_id, "parent-id");
    let preview = reply.preview.expect("preview hydrated");
    assert_eq!(preview.sender.as_deref(), Some("Alice"));
    assert_eq!(preview.plaintext, "the original");
    assert!(!preview.deleted);
}

#[test]
fn parse_timeline_row_reply_without_preview_keeps_parent_id_only() {
    let value = serde_json::json!({
        "message_id": "3",
        "plaintext": "orphan reply",
        "reply_to_message_id": "unresolved-parent",
        "reply_preview": null
    });

    let reply = parse_timeline_row(&value)
        .expect("row parses")
        .reply
        .expect("reply present");

    assert_eq!(reply.reply_to_message_id, "unresolved-parent");
    assert!(reply.preview.is_none());
}

#[test]
fn parse_timeline_row_reads_media_imeta_mime_and_filename() {
    let value = serde_json::json!({
        "message_id": "4",
        "plaintext": "look",
        "media": {
            "imeta": [
                [
                    "imeta",
                    "v encrypted-media-v1",
                    "locator blossom-v1 https://blossom.example/abc",
                    "ciphertext_sha256 deadbeef",
                    "plaintext_sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "nonce 00112233",
                    "m image/png",
                    "filename pixel.png"
                ],
                [
                    "imeta",
                    "m application/pdf",
                    "filename spec.pdf"
                ]
            ]
        }
    });

    let attachments = parse_timeline_row(&value).expect("row parses").attachments;

    assert_eq!(
        attachments,
        vec![
            TimelineAttachment {
                mime: Some("image/png".to_owned()),
                filename: Some("pixel.png".to_owned()),
                plaintext_hash: Some("aa".repeat(32)),
            },
            TimelineAttachment {
                mime: Some("application/pdf".to_owned()),
                filename: Some("spec.pdf".to_owned()),
                plaintext_hash: None,
            },
        ]
    );
}

/// A malicious member can put anything in the `imeta` `plaintext_sha256` field.
/// The parse boundary is the only place that decides whether a hash is trusted:
/// it must reject any value that is not exactly 64 lowercase hex characters,
/// dropping the attachment to `plaintext_hash: None` (a plain placeholder that
/// never downloads and never reaches the cache path or the `wn media download`
/// argv). Storage always emits lowercase hex (`hex::encode`), so uppercase is
/// not a legitimate hash and is rejected too, rather than normalized.
#[test]
fn parse_timeline_attachment_rejects_unsafe_plaintext_hash() {
    let hostile = [
        "../../../../etc/passwd", // path traversal
        "aa/bb",                  // path separator, right length family
        "nothex_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // non-hex
        "aaaa",                   // too short
        &"aa".repeat(33),         // too long (66 chars)
        &"AA".repeat(32),         // uppercase hex, correct length
    ];
    for value in hostile {
        let row = serde_json::json!({
            "message_id": "m",
            "media": { "imeta": [["imeta", "m image/png", "filename x.png",
                format!("plaintext_sha256 {value}")]] }
        });
        let attachment = &parse_timeline_row(&row).expect("row parses").attachments[0];
        assert_eq!(
            attachment.plaintext_hash, None,
            "unsafe hash {value:?} must be rejected at the parse boundary"
        );
    }

    // A genuine 64-char lowercase-hex hash is accepted unchanged.
    let good = "0123456789abcdef".repeat(4);
    let row = serde_json::json!({
        "message_id": "m",
        "media": { "imeta": [["imeta", "m image/png", "filename x.png",
            format!("plaintext_sha256 {good}")]] }
    });
    let attachment = &parse_timeline_row(&row).expect("row parses").attachments[0];
    assert_eq!(attachment.plaintext_hash, Some(good));
}

#[test]
fn parse_timeline_row_filters_agent_stream_start_marker() {
    let value = serde_json::json!({
        "message_id": "5",
        "plaintext": "{}",
        "agent_text_stream": { "kind": "start", "stream_id": "abc" }
    });
    assert!(parse_timeline_row(&value).is_none());
}

#[test]
fn parse_timeline_row_marks_tombstone() {
    let value = serde_json::json!({
        "message_id": "6",
        "plaintext": "",
        "deleted": true,
        "deleted_by_message_id": "a83f"
    });
    let row = parse_timeline_row(&value).expect("tombstone row is kept");
    assert!(row.deleted);
    assert_eq!(row.plaintext, "");
}

#[test]
fn parse_timeline_row_derives_group_system_and_stream_summaries() {
    let group_system = serde_json::json!({
        "message_id": "7",
        "kind": 1210,
        "from_display_name": "alice",
        "plaintext": "{\"system_type\":\"member_added\",\"data\":{\"subject\":\"bob\"}}"
    });
    assert_eq!(
        parse_timeline_row(&group_system).unwrap().display_text,
        "alice added bob"
    );

    let stream_final = serde_json::json!({
        "message_id": "8",
        "plaintext": "{\"marmot_payload\":\"marmot.agent_text_stream.v1\"}",
        "agent_text_stream": {
            "kind": "final",
            "stream_id": "s1",
            "final_text_or_reference": "hello from the stream"
        }
    });
    assert_eq!(
        parse_timeline_row(&stream_final).unwrap().display_text,
        "hello from the stream"
    );
}

#[test]
fn parse_timeline_event_reads_ready_initial_and_projection() {
    let ready = serde_json::json!({
        "trigger": "TimelineSubscriptionReady",
        "type": "timeline_subscription_ready"
    });
    assert!(matches!(parse_timeline_event(&ready), TimelineEvent::Ready));

    let initial = serde_json::json!({
        "trigger": "InitialTimelinePage",
        "type": "initial_timeline_page",
        "has_more_before": true,
        "messages": [
            { "message_id": "a", "plaintext": "one", "timeline_at": 1 },
            { "message_id": "b", "plaintext": "two", "timeline_at": 2 }
        ]
    });
    match parse_timeline_event(&initial) {
        TimelineEvent::InitialPage {
            rows,
            has_more_before,
        } => {
            assert!(has_more_before);
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0].message_id, "a");
        }
        other => panic!("expected initial page, got {other:?}"),
    }

    let projection = serde_json::json!({
        "trigger": "TimelineProjectionUpdated",
        "type": "timeline_projection_updated",
        "group_id": "cdaa",
        "changes": [
            {
                "type": "upsert",
                "trigger": "NewMessage",
                "message": { "message_id": "c", "plaintext": "three", "timeline_at": 3 }
            },
            { "type": "remove", "message_id": "d", "reason": "expired" }
        ]
    });
    match parse_timeline_event(&projection) {
        TimelineEvent::ProjectionUpdated { group_id, changes } => {
            assert_eq!(group_id, "cdaa");
            assert_eq!(changes.len(), 2);
            assert!(matches!(&changes[0], TimelineChange::Upsert(row) if row.message_id == "c"));
            assert!(
                matches!(&changes[1], TimelineChange::Remove { message_id } if message_id == "d")
            );
        }
        other => panic!("expected projection update, got {other:?}"),
    }

    let unknown = serde_json::json!({ "type": "something_else" });
    assert!(matches!(
        parse_timeline_event(&unknown),
        TimelineEvent::Other
    ));
}

/// Build a minimal timeline row for fold/scroll tests.
fn timeline_row(message_id: &str, timeline_at: u64) -> TimelineRow {
    TimelineRow {
        message_id: message_id.to_owned(),
        direction: "received".to_owned(),
        from: "someone".to_owned(),
        from_display_name: None,
        plaintext: format!("msg {message_id}"),
        display_text: format!("msg {message_id}"),
        timeline_at,
        received_at: timeline_at,
        deleted: false,
        reactions: Vec::new(),
        reply: None,
        attachments: Vec::new(),
    }
}

fn timeline_ids(rows: &[TimelineRow]) -> Vec<&str> {
    rows.iter().map(|row| row.message_id.as_str()).collect()
}

/// The rendered `[HH:MM] ` timestamp is local wall-clock and machine-dependent
/// (`local_hhmm`), so row-content tests assert its fixed 8-column shape and
/// return the text after it instead of a timezone-specific value. The formatting
/// arithmetic is covered deterministically by `format_hhmm_renders_local_offset`.
fn hhmm_body(text: &str) -> String {
    let bytes = text.as_bytes();
    assert!(
        bytes.len() >= 8
            && bytes[0] == b'['
            && bytes[1].is_ascii_digit()
            && bytes[2].is_ascii_digit()
            && bytes[3] == b':'
            && bytes[4].is_ascii_digit()
            && bytes[5].is_ascii_digit()
            && bytes[6] == b']'
            && bytes[7] == b' ',
        "expected a [HH:MM] prefix, got {text:?}"
    );
    text[8..].to_owned()
}

#[test]
fn format_hhmm_renders_local_offset() {
    // 12:34:56 UTC.
    assert_eq!(format_hhmm_with_offset(45_296, 0), "12:34");
    // Same instant five hours west of UTC.
    assert_eq!(format_hhmm_with_offset(45_296, -5 * 3_600), "07:34");
    // Wall-clock wraps around midnight without panicking on the negative.
    assert_eq!(format_hhmm_with_offset(0, -3_600), "23:00");
}

#[test]
fn upsert_timeline_row_keeps_sorted_by_timeline_at_then_id() {
    let mut rows = Vec::new();
    upsert_timeline_row(&mut rows, timeline_row("b", 20));
    upsert_timeline_row(&mut rows, timeline_row("a", 10));
    // Same second: tiebreak by message_id ascending.
    upsert_timeline_row(&mut rows, timeline_row("z", 20));
    upsert_timeline_row(&mut rows, timeline_row("y", 20));

    assert_eq!(timeline_ids(&rows), vec!["a", "b", "y", "z"]);
}

#[test]
fn upsert_timeline_row_is_idempotent_by_message_id() {
    let mut rows = Vec::new();
    upsert_timeline_row(&mut rows, timeline_row("a", 10));
    upsert_timeline_row(&mut rows, timeline_row("b", 20));

    // Re-applying the same row (as duplicated projection events do) must not
    // append a second copy and must leave the list unchanged in effect.
    let before = rows.clone();
    upsert_timeline_row(&mut rows, timeline_row("a", 10));
    upsert_timeline_row(&mut rows, timeline_row("b", 20));

    assert_eq!(rows, before);
    assert_eq!(rows.len(), 2);
}

#[test]
fn upsert_timeline_row_replaces_existing_row_content() {
    let mut rows = vec![timeline_row("a", 10)];
    let mut updated = timeline_row("a", 10);
    updated.reactions = vec![TimelineReaction {
        emoji: "\u{1f44d}".to_owned(),
        count: 1,
    }];
    upsert_timeline_row(&mut rows, updated);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reactions.len(), 1);
}

#[test]
fn apply_timeline_change_reports_insert_update_and_remove() {
    let mut rows = vec![timeline_row("a", 10), timeline_row("c", 30)];

    // New row inserted in sorted position between a and c.
    let outcome = apply_timeline_change(
        &mut rows,
        TimelineChange::Upsert(Box::new(timeline_row("b", 20))),
    );
    assert_eq!(outcome, TimelineFoldOutcome::Inserted(1));
    assert_eq!(timeline_ids(&rows), vec!["a", "b", "c"]);

    // Same id again = update, not a second row (duplicated events).
    let outcome = apply_timeline_change(
        &mut rows,
        TimelineChange::Upsert(Box::new(timeline_row("b", 20))),
    );
    assert_eq!(outcome, TimelineFoldOutcome::Updated(1));
    assert_eq!(rows.len(), 3);

    // Remove drops the row.
    let outcome = apply_timeline_change(
        &mut rows,
        TimelineChange::Remove {
            message_id: "b".to_owned(),
        },
    );
    assert_eq!(outcome, TimelineFoldOutcome::Removed(1));
    assert_eq!(timeline_ids(&rows), vec!["a", "c"]);

    // Removing an unknown id changes nothing.
    let outcome = apply_timeline_change(
        &mut rows,
        TimelineChange::Remove {
            message_id: "zzz".to_owned(),
        },
    );
    assert_eq!(outcome, TimelineFoldOutcome::Unchanged);
    assert_eq!(rows.len(), 2);
}

#[test]
fn oldest_timeline_cursor_reads_first_row() {
    assert!(oldest_timeline_cursor(&[]).is_none());
    let rows = vec![timeline_row("a", 10), timeline_row("b", 20)];
    assert_eq!(
        oldest_timeline_cursor(&rows),
        Some(TimelineCursor {
            timeline_at: 10,
            message_id: "a".to_owned(),
        })
    );
}

#[test]
fn timeline_scroll_default_is_pinned_to_newest() {
    let scroll = TimelineScroll::default();
    assert!(scroll.is_pinned());
    assert_eq!(scroll.offset, 0);
    // With no explicit selection, the newest message is selected.
    assert_eq!(scroll.resolved_selection(4), Some(3));
    assert!(scroll.resolved_selection(0).is_none());
}

#[test]
fn timeline_scroll_stays_pinned_when_message_arrives_at_bottom() {
    let mut scroll = TimelineScroll::default();
    // A new newest row is appended: old len 3 -> new len 4, index 3.
    scroll.on_insert(3, 4);
    assert!(scroll.is_pinned());
    assert_eq!(scroll.offset, 0);
}

#[test]
fn timeline_scroll_holds_position_when_scrolled_up_and_message_arrives() {
    // Reading history, 2 messages up from the bottom.
    let mut scroll = TimelineScroll {
        offset: 2,
        ..TimelineScroll::default()
    };
    // A new newest row is appended (old len 4 -> new len 5, index 4).
    scroll.on_insert(4, 5);
    assert_eq!(scroll.offset, 3, "offset bumps by one so content stays put");
}

#[test]
fn timeline_scroll_prepend_keeps_same_message_selected_and_visible() {
    // Reading the top of a 5-row list.
    let mut scroll = TimelineScroll {
        offset: 4,
        selection: Some(0),
        visible_range: Some((0, 2)),
        ..TimelineScroll::default()
    };

    // Page in 5 older rows at the front.
    scroll.on_prepend(5);

    // The same logical rows stay selected and visible; only their absolute
    // indices shifted by N. Offset counts from the unchanged bottom, so it must
    // NOT move (moving it would jump the view to the newly loaded oldest rows).
    assert_eq!(scroll.selection, Some(5));
    assert_eq!(scroll.visible_range, Some((5, 7)));
    assert_eq!(scroll.offset, 4);
}

#[test]
fn timeline_scroll_prepend_of_nothing_is_a_noop() {
    let mut scroll = TimelineScroll {
        offset: 2,
        selection: Some(1),
        visible_range: Some((0, 3)),
        ..TimelineScroll::default()
    };
    let before = scroll.clone();
    scroll.on_prepend(0);
    assert_eq!(scroll, before);
}

#[test]
fn timeline_scroll_selection_within_viewport_does_not_scroll() {
    let mut scroll = TimelineScroll {
        visible_range: Some((10, 19)),
        ..TimelineScroll::default()
    };
    // Newest (19) selected by default; move up to 18, still on screen.
    scroll.select_up(20);
    assert_eq!(scroll.selection, Some(18));
    assert_eq!(
        scroll.offset, 0,
        "selection inside the viewport scrolls nothing"
    );
}

#[test]
fn timeline_scroll_selection_leaving_top_nudges_offset_up() {
    let mut scroll = TimelineScroll {
        offset: 5,
        selection: Some(10),
        visible_range: Some((10, 19)),
        ..TimelineScroll::default()
    };
    scroll.select_up(30);
    assert_eq!(scroll.selection, Some(9));
    assert_eq!(
        scroll.offset, 6,
        "viewport nudges up by one when selection exits the top"
    );
}

#[test]
fn timeline_scroll_selection_leaving_bottom_nudges_offset_down() {
    let mut scroll = TimelineScroll {
        offset: 5,
        selection: Some(19),
        visible_range: Some((10, 19)),
        ..TimelineScroll::default()
    };
    scroll.select_down(30);
    assert_eq!(scroll.selection, Some(20));
    assert_eq!(
        scroll.offset, 4,
        "viewport nudges down by one when selection exits the bottom"
    );
}

#[test]
fn timeline_scroll_selection_clamps_at_both_ends() {
    let mut scroll = TimelineScroll {
        selection: Some(0),
        ..TimelineScroll::default()
    };
    scroll.select_up(20);
    assert_eq!(scroll.selection, Some(0));
    scroll.selection = Some(19);
    scroll.select_down(20);
    assert_eq!(scroll.selection, Some(19));
}

#[test]
fn timeline_scroll_jump_newest_selects_newest_and_pins() {
    let mut scroll = TimelineScroll {
        offset: 7,
        selection: Some(3),
        ..TimelineScroll::default()
    };
    scroll.jump_newest(20);
    assert_eq!(scroll.offset, 0);
    assert!(scroll.is_pinned());
    assert_eq!(scroll.resolved_selection(20), Some(19));
}

#[test]
fn timeline_scroll_jump_oldest_selects_first_and_scrolls_to_top() {
    let mut scroll = TimelineScroll::default();
    scroll.jump_oldest(20);
    assert_eq!(scroll.selection, Some(0));
    assert_eq!(scroll.offset, 19);
    // Empty list is a no-op.
    let mut empty = TimelineScroll::default();
    empty.jump_oldest(0);
    assert_eq!(empty, TimelineScroll::default());
}

#[test]
fn timeline_scroll_page_up_moves_by_visible_count_and_follows() {
    let mut scroll = TimelineScroll {
        offset: 0,
        selection: Some(50),
        visible_range: Some((45, 54)), // 10 visible messages
        ..TimelineScroll::default()
    };
    scroll.page_up(100);
    assert_eq!(scroll.selection, Some(40), "moved up by the visible count");
    assert_eq!(
        scroll.offset, 5,
        "viewport follows the selection above the top"
    );
}

#[test]
fn timeline_scroll_page_down_moves_by_visible_count() {
    let mut scroll = TimelineScroll {
        offset: 8,
        selection: Some(40),
        visible_range: Some((40, 49)),
        ..TimelineScroll::default()
    };
    scroll.page_down(100);
    assert_eq!(
        scroll.selection,
        Some(50),
        "moved down by the visible count"
    );
    assert!(
        scroll.offset < 8,
        "viewport follows the selection below the bottom"
    );
}

#[test]
fn timeline_scroll_page_clamps_at_edges() {
    let mut scroll = TimelineScroll {
        selection: Some(3),
        visible_range: Some((0, 9)),
        ..TimelineScroll::default()
    };
    scroll.page_up(40);
    assert_eq!(scroll.selection, Some(0));
    scroll.selection = Some(35);
    scroll.page_down(40);
    assert_eq!(scroll.selection, Some(39));
}

#[test]
fn timeline_scroll_records_visible_range_from_the_renderer() {
    let mut scroll = TimelineScroll::default();
    scroll.record_visible_range(3, 9, 20);
    assert_eq!(scroll.visible_range, Some((3, 9)));
    assert_eq!(
        scroll.offset, 0,
        "a small offset with `last` at the anchor is not renormalized"
    );
}

#[test]
fn timeline_scroll_record_visible_range_clamps_a_stale_over_large_offset() {
    // `g` set offset to len-1 (29); the renderer clamped the anchor to 0 and
    // filled forward to `last` = 4. The effective offset is (30-1) - 4 = 25.
    let mut scroll = TimelineScroll {
        offset: 29,
        ..TimelineScroll::default()
    };
    scroll.record_visible_range(0, 4, 30);
    assert_eq!(
        scroll.offset, 25,
        "offset clamps down to the drawn geometry"
    );
    // Idempotent: a second identical frame leaves it put.
    scroll.record_visible_range(0, 4, 30);
    assert_eq!(scroll.offset, 25);
}

#[test]
fn timeline_scroll_requests_older_history_only_at_the_oldest_row() {
    let mut scroll = TimelineScroll {
        has_more_before: true,
        selection: Some(5),
        ..TimelineScroll::default()
    };
    assert!(!scroll.at_oldest(20));
    assert!(!scroll.should_request_older(20), "not at the oldest row");

    scroll.selection = Some(0);
    assert!(scroll.at_oldest(20));
    assert!(
        scroll.should_request_older(20),
        "at oldest with more history"
    );

    scroll.loading_older = true;
    assert!(
        !scroll.should_request_older(20),
        "a page request is already in flight"
    );

    scroll.loading_older = false;
    scroll.has_more_before = false;
    assert!(!scroll.should_request_older(20), "no more history to load");
}

#[test]
fn timeline_scroll_remove_below_selection_shifts_it_down() {
    let mut scroll = TimelineScroll {
        offset: 3,
        selection: Some(10),
        ..TimelineScroll::default()
    };
    // Remove a row older than the selection (index 4 of an old list of 20).
    scroll.on_remove(4, 19);
    assert_eq!(
        scroll.selection,
        Some(9),
        "same message stays selected after older row drops"
    );
    assert_eq!(
        scroll.offset, 3,
        "removing below the anchor does not move the viewport"
    );
}

#[test]
fn timeline_scroll_remove_newer_than_anchor_pulls_offset_down_while_scrolled_up() {
    let mut scroll = TimelineScroll {
        offset: 2,
        selection: Some(1),
        ..TimelineScroll::default()
    };
    // Old list of 10; anchor = 9 - 2 = 7. Remove index 8 (newer than anchor).
    scroll.on_remove(8, 9);
    assert_eq!(scroll.offset, 1, "viewport follows the shrinking bottom");
}

#[test]
fn timeline_scroll_remove_clamps_selection_when_list_empties() {
    let mut scroll = TimelineScroll {
        selection: Some(0),
        ..TimelineScroll::default()
    };
    scroll.on_remove(0, 0);
    assert_eq!(scroll.resolved_selection(0), None);
}

#[test]
fn cap_timeline_scrollback_trims_oldest_only_when_pinned() {
    let mut rows: Vec<TimelineRow> = (0..(TUI_MESSAGE_SCROLLBACK_LIMIT + 5))
        .map(|i| timeline_row(&format!("{i:05}"), i as u64))
        .collect();
    let mut scroll = TimelineScroll {
        selection: Some(rows.len() - 1),
        ..TimelineScroll::default()
    };
    cap_timeline_scrollback(&mut rows, &mut scroll);
    assert_eq!(rows.len(), TUI_MESSAGE_SCROLLBACK_LIMIT);
    assert_eq!(
        rows.first().unwrap().message_id,
        "00005",
        "oldest rows dropped"
    );
    assert_eq!(
        scroll.selection,
        Some(TUI_MESSAGE_SCROLLBACK_LIMIT - 1),
        "selection follows the dropped rows so it stays on the same message"
    );
}

#[test]
fn cap_timeline_scrollback_never_trims_while_scrolled_up() {
    let mut rows: Vec<TimelineRow> = (0..(TUI_MESSAGE_SCROLLBACK_LIMIT + 5))
        .map(|i| timeline_row(&format!("{i:05}"), i as u64))
        .collect();
    let original_len = rows.len();
    let mut scroll = TimelineScroll {
        offset: 3,
        ..TimelineScroll::default()
    };
    cap_timeline_scrollback(&mut rows, &mut scroll);
    assert_eq!(
        rows.len(),
        original_len,
        "capping while scrolled up would fight history paging"
    );
}

#[test]
fn timeline_row_lines_render_timestamp_author_and_content() {
    let mut row = timeline_row("m1", 45296);
    row.from_display_name = Some("Alice".to_owned());
    row.display_text = "hello world".to_owned();

    let lines = timeline_row_lines(&row, None);
    assert_eq!(lines.len(), 1);
    assert_eq!(hhmm_body(&line_text(&lines[0])), "Alice: hello world");
    assert_eq!(
        lines[0].spans[0].style.fg,
        Some(Color::DarkGray),
        "timestamp is dark gray"
    );
    assert_eq!(
        lines[0].spans[1].style.fg,
        Some(Color::Cyan),
        "other author is cyan"
    );
    assert!(
        lines[0].spans[1]
            .style
            .add_modifier
            .contains(Modifier::BOLD)
    );
}

#[test]
fn timeline_row_lines_color_own_messages_green() {
    let mut row = timeline_row("m2", 0);
    row.direction = "sent".to_owned();
    row.from_display_name = Some("Me".to_owned());
    let lines = timeline_row_lines(&row, None);
    assert_eq!(
        lines[0].spans[1].style.fg,
        Some(Color::Green),
        "own author is green"
    );
}

#[test]
fn timeline_row_lines_indent_embedded_newlines_to_the_prefix_width() {
    let mut row = timeline_row("m3", 0);
    row.from_display_name = Some("Al".to_owned());
    row.display_text = "one\ntwo".to_owned();
    let lines = timeline_row_lines(&row, None);
    assert_eq!(lines.len(), 2);
    assert_eq!(hhmm_body(&line_text(&lines[0])), "Al: one");
    // Continuation indents to "[HH:MM] Al: " width (12 columns).
    assert_eq!(line_text(&lines[1]), "            two");
}

#[test]
fn timeline_row_lines_render_reply_context_above_content() {
    let mut row = timeline_row("m", 0);
    row.from_display_name = Some("Bob".to_owned());
    row.display_text = "agreed".to_owned();
    row.reply = Some(TimelineReply {
        reply_to_message_id: "parent".to_owned(),
        preview: Some(TimelineReplyPreview {
            sender: Some("Alice".to_owned()),
            plaintext: "this is a long parent message body over thirty chars".to_owned(),
            deleted: false,
        }),
    });
    let lines = timeline_row_lines(&row, None);
    assert_eq!(
        line_text(&lines[0]),
        "             reply to Alice: \"this is a long parent message ...\""
    );
    assert!(
        lines[0].spans[1]
            .style
            .add_modifier
            .contains(Modifier::ITALIC)
    );
    assert_eq!(lines[0].spans[1].style.fg, Some(Color::DarkGray));
    assert_eq!(hhmm_body(&line_text(&lines[1])), "Bob: agreed");
}

#[test]
fn timeline_row_lines_reply_falls_back_to_shortened_id() {
    let mut row = timeline_row("m", 0);
    row.reply = Some(TimelineReply {
        reply_to_message_id: "0123456789abcdef".to_owned(),
        preview: None,
    });
    let lines = timeline_row_lines(&row, None);
    assert!(line_text(&lines[0]).contains("reply to 0123...bcdef"));
}

#[test]
fn timeline_row_lines_reply_fallback_strips_terminal_controls_from_parent_id() {
    // The parent id is untrusted; both fallback branches (no preview, and a
    // preview whose sender resolves empty) must sanitize it like every sibling
    // path. Controls sit in the surviving prefix/suffix so shortening keeps them.
    let raw_id = "\u{202e}ab\u{7}cdefghij0123456789";

    // Branch 1: no preview at all.
    let mut row = timeline_row("m", 0);
    row.reply = Some(TimelineReply {
        reply_to_message_id: raw_id.to_owned(),
        preview: None,
    });
    let text = line_text(&timeline_row_lines(&row, None)[0]);
    assert!(
        !text.contains('\u{202e}'),
        "bidi override stripped from the no-preview fallback id"
    );
    assert!(
        !text.contains('\u{7}'),
        "control char stripped from the no-preview fallback id"
    );

    // Branch 2: a preview whose sender is absent falls back to the parent id.
    let mut row = timeline_row("m", 0);
    row.reply = Some(TimelineReply {
        reply_to_message_id: raw_id.to_owned(),
        preview: Some(TimelineReplyPreview {
            sender: None,
            plaintext: "hi".to_owned(),
            deleted: false,
        }),
    });
    let text = line_text(&timeline_row_lines(&row, None)[0]);
    assert!(
        !text.contains('\u{202e}'),
        "bidi override stripped from the empty-sender fallback id"
    );
    assert!(
        !text.contains('\u{7}'),
        "control char stripped from the empty-sender fallback id"
    );
}

#[test]
fn timeline_row_lines_render_reactions_below_content() {
    let mut row = timeline_row("m", 0);
    row.reactions = vec![
        TimelineReaction {
            emoji: "\u{1f44d}".to_owned(),
            count: 2,
        },
        TimelineReaction {
            emoji: "\u{2764}".to_owned(),
            count: 1,
        },
    ];
    let lines = timeline_row_lines(&row, None);
    let reactions = lines.last().unwrap();
    assert_eq!(line_text(reactions).trim_start(), "\u{1f44d} 2  \u{2764} 1");
    assert_eq!(reactions.spans[1].style.fg, Some(Color::Yellow));
}

#[test]
fn timeline_row_lines_render_tombstone_for_deleted_rows() {
    let mut row = timeline_row("m", 0);
    row.from_display_name = Some("Al".to_owned());
    row.deleted = true;
    row.plaintext = String::new();
    row.display_text = String::new();
    let lines = timeline_row_lines(&row, None);
    assert_eq!(lines.len(), 1);
    assert_eq!(hhmm_body(&line_text(&lines[0])), "Al: message deleted");
    let tombstone = lines[0].spans.last().unwrap();
    assert!(tombstone.style.add_modifier.contains(Modifier::ITALIC));
    assert_eq!(tombstone.style.fg, Some(Color::DarkGray));
}

#[test]
fn timeline_row_lines_render_attachment_placeholders() {
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![
        TimelineAttachment {
            mime: Some("image/png".to_owned()),
            filename: Some("pixel.png".to_owned()),
            plaintext_hash: Some("cafebabe".to_owned()),
        },
        TimelineAttachment {
            mime: Some("application/pdf".to_owned()),
            filename: Some("spec.pdf".to_owned()),
            plaintext_hash: None,
        },
    ];
    // With an empty (unsupported) media view, an image with a hash still shows the
    // `[img ...]` placeholder — capability detection has not enabled rendering.
    let lines = timeline_row_lines(&row, None);
    assert_eq!(line_text(&lines[1]).trim_start(), "[img pixel.png]");
    assert_eq!(line_text(&lines[2]).trim_start(), "[file spec.pdf]");
}

// ---- Phase 6: inbound media ----

fn image_attachment(hash: &str) -> TimelineAttachment {
    TimelineAttachment {
        mime: Some("image/png".to_owned()),
        filename: Some("pixel.png".to_owned()),
        plaintext_hash: Some(hash.to_owned()),
    }
}

/// A media state with an image-capable (halfblocks) picker and one decoded,
/// ready image, built without a terminal or network via the test hooks.
fn media_with_ready_image(hash: &str) -> MediaState {
    media_ready_image_with_picker(ratatui_image::picker::Picker::halfblocks(), hash)
}

/// As `media_with_ready_image`, but adopting a specific `picker`. Used to prove
/// the inline renderer stays cell-exact even when the terminal reports (or is
/// mis-detected as) a pixel protocol such as iTerm2/Kitty/Sixel.
fn media_ready_image_with_picker(picker: ratatui_image::picker::Picker, hash: &str) -> MediaState {
    let mut media = MediaState::with_test_picker(picker);
    // Larger than the halfblocks font cell (10x20) so it occupies cells, and
    // vertically varied so the encoder emits half-block glyphs (a uniform image
    // collapses each cell to a space).
    let mut buffer = image::RgbImage::new(200, 160);
    for (x, y, pixel) in buffer.enumerate_pixels_mut() {
        *pixel = image::Rgb([(x % 256) as u8, y.wrapping_mul(3) as u8, 200]);
    }
    media.apply_for_test(MediaLoad::Decoded {
        hash: hash.to_owned(),
        image: Box::new(image::DynamicImage::ImageRgb8(buffer)),
    });
    media
}

/// Each terminal row of a full frame render, top to bottom, as a string. Unlike
/// `rendered_buffer` (which flattens the whole grid) this keeps row boundaries so
/// a test can assert *where* content lands — e.g. that an image block never draws
/// onto the following message's row.
fn rendered_rows(app: &mut TuiApp) -> Vec<String> {
    let backend = ratatui::backend::TestBackend::new(100, 30);
    let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
    terminal.draw(|frame| app.render(frame)).expect("draw TUI");
    let buffer = terminal.backend().buffer().clone();
    let area = buffer.area;
    (0..area.height)
        .map(|y| {
            (0..area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect()
}

#[test]
fn media_view_slot_walks_the_placeholder_ladder() {
    let hash = "cafebabe";
    let attachment = image_attachment(hash);
    let mut media = MediaState::with_test_picker(ratatui_image::picker::Picker::halfblocks());

    assert_eq!(
        media.view().slot(&attachment),
        MediaSlot::Placeholder("[img pixel.png]".to_owned())
    );
    media.begin_download(hash.to_owned());
    assert_eq!(
        media.view().slot(&attachment),
        MediaSlot::Placeholder("[downloading pixel.png...]".to_owned())
    );
    media.apply_for_test(MediaLoad::Downloaded {
        hash: hash.to_owned(),
    });
    assert_eq!(
        media.view().slot(&attachment),
        MediaSlot::Placeholder("[loading pixel.png...]".to_owned())
    );
    media.apply_for_test(MediaLoad::Failed {
        hash: hash.to_owned(),
        error: "boom".to_owned(),
    });
    assert_eq!(
        media.view().slot(&attachment),
        MediaSlot::Placeholder("[pixel.png failed: boom]".to_owned())
    );
}

#[test]
fn media_view_slot_ready_image_reserves_a_block() {
    let media = media_with_ready_image("cafebabe");
    assert!(media.is_ready("cafebabe"));
    assert_eq!(
        media.view().slot(&image_attachment("cafebabe")),
        MediaSlot::Image { rows: 8 }
    );
}

#[test]
fn media_view_slot_without_capability_stays_placeholder() {
    // No picker: an image never advances past `[img ...]`; no download is armed.
    let media = MediaState::new();
    assert!(!media.supported());
    assert_eq!(
        media.view().slot(&image_attachment("cafebabe")),
        MediaSlot::Placeholder("[img pixel.png]".to_owned())
    );
}

#[test]
fn media_view_slot_non_image_is_a_file_placeholder() {
    let attachment = TimelineAttachment {
        mime: Some("application/pdf".to_owned()),
        filename: Some("spec.pdf".to_owned()),
        plaintext_hash: Some("cafebabe".to_owned()),
    };
    let media = media_with_ready_image("cafebabe");
    assert_eq!(
        media.view().slot(&attachment),
        MediaSlot::Placeholder("[file spec.pdf]".to_owned())
    );
}

#[test]
fn media_drain_folds_duplicate_decoded_events_idempotently() {
    let mut media = MediaState::with_test_picker(ratatui_image::picker::Picker::halfblocks());
    for _ in 0..2 {
        media.apply_for_test(MediaLoad::Decoded {
            hash: "cafebabe".to_owned(),
            image: Box::new(image::DynamicImage::new_rgb8(2, 2)),
        });
    }
    assert!(media.is_ready("cafebabe"));
}

#[test]
fn media_downloads_are_capped_at_three_in_flight() {
    // Ten images all want to download. The cap keeps at most three workers in
    // flight; the rest are slotted as running downloads complete.
    let hashes: Vec<String> = (0..10).map(|i| format!("hash{i}")).collect();
    let mut media = MediaState::with_test_picker(ratatui_image::picker::Picker::halfblocks());

    for _ in 0..1000 {
        for hash in media.downloads_to_start(&hashes) {
            media.begin_download(hash);
        }
        assert!(
            media.in_flight() <= 3,
            "never more than three downloads run at once"
        );
        if hashes.iter().all(|hash| media.is_ready(hash)) {
            break;
        }
        // A worker completes, freeing one in-flight slot for the next tick.
        if let Some(hash) = hashes
            .iter()
            .find(|hash| media.is_tracked(hash) && !media.is_ready(hash))
        {
            media.apply_for_test(MediaLoad::Decoded {
                hash: hash.clone(),
                image: Box::new(image::DynamicImage::new_rgb8(2, 2)),
            });
        }
    }

    assert!(
        hashes.iter().all(|hash| media.is_ready(hash)),
        "all ten images are eventually tracked as completions arrive"
    );
}

#[test]
fn timeline_row_height_media_reserves_rows_for_a_ready_image() {
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![image_attachment("cafebabe")];

    let placeholder_height = timeline_row_height(&row, None, 80);
    let media = media_with_ready_image("cafebabe");
    let ready_height = timeline_row_height_media(&row, None, 80, media.view());

    // A ready image reserves 8 rows where the placeholder used one line.
    assert_eq!(ready_height, placeholder_height + 7);
}

#[test]
fn timeline_row_image_blocks_locates_the_reserved_block() {
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![image_attachment("cafebabe")];
    let media = media_with_ready_image("cafebabe");

    let blocks = timeline_row_image_blocks(&row, None, 80, media.view());
    assert_eq!(blocks.len(), 1);
    let (hash, offset, rows) = &blocks[0];
    assert_eq!(hash, "cafebabe");
    // One content line above the block, so it starts at row 1 and reserves 8.
    assert_eq!(*offset, 1);
    assert_eq!(*rows, 8);
}

#[test]
fn timeline_row_image_blocks_place_image_before_a_trailing_file_placeholder() {
    // A ready image followed by a non-image attachment: the file placeholder
    // renders *after* the image block, so it must not push the image's offset
    // down. Deriving the offset from the row layout (not by subtracting from the
    // bottom) keeps the drawn image on its reserved blanks.
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![
        image_attachment("cafebabe"),
        TimelineAttachment {
            mime: Some("application/pdf".to_owned()),
            filename: Some("spec.pdf".to_owned()),
            plaintext_hash: None,
        },
    ];
    let media = media_with_ready_image("cafebabe");

    let blocks = timeline_row_image_blocks(&row, None, 80, media.view());
    assert_eq!(blocks.len(), 1);
    let (hash, offset, rows) = &blocks[0];
    assert_eq!(hash, "cafebabe");
    // One content line above the image; the trailing file placeholder sits below
    // the block and must not shift it.
    assert_eq!(*offset, 1);
    assert_eq!(*rows, 8);
}

#[test]
fn ready_image_renders_over_its_placeholder_in_the_message_pane() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Messages;
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![image_attachment("cafebabe")];
    app.timeline = vec![row];
    app.media = media_with_ready_image("cafebabe");

    let rendered = rendered_buffer(&mut app);
    // The halfblocks protocol draws half-block glyphs, and the `[img ...]`
    // placeholder is gone because the image filled its reserved block.
    assert!(
        rendered.contains('▀') || rendered.contains('▄'),
        "expected halfblock image cells"
    );
    assert!(
        !rendered.contains("pixel.png"),
        "the placeholder should be replaced by the image"
    );
}

/// Row index of the first rendered row containing `needle`, or `None`.
fn row_index_containing(rows: &[String], needle: &str) -> Option<usize> {
    rows.iter().position(|row| row.contains(needle))
}

/// Render `app` and return the row index where the second timeline message
/// ("SENTINELREPLY") lands. Used to observe how far the first message's image
/// slot pushes it down — measure (row height) must equal draw (rendered rows).
fn second_message_row(app: &mut TuiApp) -> usize {
    let rows = rendered_rows(app);
    row_index_containing(&rows, "SENTINELREPLY")
        .unwrap_or_else(|| panic!("second message not rendered:\n{}", rows.join("\n")))
}

fn image_row_pair() -> Vec<TimelineRow> {
    let mut first = timeline_row("m0", 0);
    first.from_display_name = Some("Al".to_owned());
    first.display_text = "look".to_owned();
    first.attachments = vec![image_attachment("cafebabe")];
    let mut second = timeline_row("m1", 1);
    second.from_display_name = Some("Bo".to_owned());
    second.display_text = "SENTINELREPLY".to_owned();
    vec![first, second]
}

#[test]
fn ready_image_reserves_exactly_its_block_and_placeholders_reserve_one_row() {
    // measure==draw: the rows a message occupies in the height model must equal
    // the rows it draws. Observe it through where the *next* message lands. Every
    // placeholder ladder state is one row, so the second message sits at the same
    // row; a ready image reserves MEDIA_IMAGE_ROWS, pushing it down by exactly the
    // difference. A block that drew more (or fewer) rows than it measured would
    // move the next message and occlude/leave a gap — the reported symptom.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Messages;
    app.timeline = image_row_pair();

    // `[img ...]` placeholder: capable terminal, image not yet requested.
    app.media = MediaState::with_test_picker(ratatui_image::picker::Picker::halfblocks());
    let img_row = second_message_row(&mut app);

    // `[downloading ...]`
    app.media = MediaState::with_test_picker(ratatui_image::picker::Picker::halfblocks());
    app.media.begin_download("cafebabe".to_owned());
    assert_eq!(
        second_message_row(&mut app),
        img_row,
        "the downloading placeholder is one row, like [img ...]"
    );

    // `[loading ...]`
    app.media = MediaState::with_test_picker(ratatui_image::picker::Picker::halfblocks());
    app.media.begin_download("cafebabe".to_owned());
    app.media.apply_for_test(MediaLoad::Downloaded {
        hash: "cafebabe".to_owned(),
    });
    assert_eq!(
        second_message_row(&mut app),
        img_row,
        "the loading placeholder is one row, like [img ...]"
    );

    // `[... failed: ...]`
    app.media = MediaState::with_test_picker(ratatui_image::picker::Picker::halfblocks());
    app.media.apply_for_test(MediaLoad::Failed {
        hash: "cafebabe".to_owned(),
        error: "boom".to_owned(),
    });
    assert_eq!(
        second_message_row(&mut app),
        img_row,
        "the failed placeholder is one row, like [img ...]"
    );

    // Ready image: reserves MEDIA_IMAGE_ROWS rows where the placeholder used one.
    app.media = media_with_ready_image("cafebabe");
    let ready_row = second_message_row(&mut app);
    assert_eq!(
        ready_row - img_row,
        usize::from(MEDIA_IMAGE_ROWS) - 1,
        "a ready image reserves exactly MEDIA_IMAGE_ROWS rows, pushing the next \
         message down by the block minus the one placeholder row it replaced"
    );
}

#[test]
fn ready_image_never_draws_onto_the_next_message_row() {
    // Symptom 1, cell-exact form: the image must stay inside its reserved block
    // and never draw onto (occlude) the following message's row.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Messages;
    app.timeline = image_row_pair();
    app.media = media_with_ready_image("cafebabe");

    let rows = rendered_rows(&mut app);
    let sentinel_row = row_index_containing(&rows, "SENTINELREPLY")
        .expect("second message must remain visible below the image");
    let last_glyph_row = rows
        .iter()
        .rposition(|row| row.contains('▀') || row.contains('▄'))
        .expect("the ready image must draw halfblock glyphs");
    assert!(
        last_glyph_row < sentinel_row,
        "image glyphs (last at row {last_glyph_row}) must stay above the next \
         message (row {sentinel_row}); an image drawn onto it is the occlusion bug"
    );
}

#[test]
fn inline_images_render_cell_exact_not_a_pixel_protocol() {
    // A terminal that reports (or is mis-detected as) a pixel protocol must not
    // make the inline timeline draw a pixel-protocol image. In a scrolling message
    // list a pixel image (iTerm2/Kitty/Sixel) maps its reserved cell block to
    // pixels via a font size and stores image bytes terminal-side; if the detected
    // font is off it overflows the block (occluding the next message) and cannot be
    // erased on scroll. The renderer must adopt the cell-exact halfblocks protocol
    // regardless of what the terminal reported.
    //
    // Structural guard: the picker here is force-set to a pixel protocol and then
    // handed to `MediaState` through the *same* `adopt_picker` chokepoint the
    // runtime's `detect_capability` uses (via the `with_test_picker` hook, which
    // now just delegates to it). This test therefore fails if anyone removes or
    // bypasses the chokepoint's cell-exact normalization — not merely if a
    // test-only normalization is dropped.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Messages;
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![image_attachment("cafebabe")];
    app.timeline = vec![row];

    // Build the media state the way a pixel-protocol terminal (iTerm2 answers the
    // Kitty query and would be force-set to iTerm2) hands the picker over.
    let mut picker = ratatui_image::picker::Picker::halfblocks();
    picker.set_protocol_type(ratatui_image::picker::ProtocolType::Iterm2);
    app.media = media_ready_image_with_picker(picker, "cafebabe");

    let rendered = rendered_buffer(&mut app);
    // No raw pixel-protocol control sequence may be emitted into a cell: the iTerm2
    // inline-image marker (OSC 1337) is the mechanism that overflows the block.
    assert!(
        !rendered.contains("1337"),
        "an iTerm2 pixel escape must never be drawn inline in the scrolling timeline"
    );
    // The reserved block is filled by cell-exact halfblock glyphs instead.
    assert!(
        rendered.contains('▀') || rendered.contains('▄'),
        "expected a cell-exact halfblock image in the reserved block"
    );
}

#[test]
fn startup_media_sweep_removes_leftover_cache_files_but_keeps_the_dir() {
    // Decrypted-media artifacts are deleted right after decode, so any file still
    // in the cache dir is litter left by a crashed session — decrypted plaintext
    // at rest. The startup sweep must clear those files while leaving the
    // directory itself in place for this session's downloads.
    let home = tempfile::tempdir().expect("tempdir");
    let cache_dir = home.path().join("tui-media-cache");
    std::fs::create_dir_all(&cache_dir).expect("seed cache dir");
    for name in ["deadbeef", "cafebabe", "f00dface"] {
        std::fs::write(cache_dir.join(name), b"decrypted-plaintext").expect("seed leftover");
    }

    let client = WnClient {
        home: Some(home.path().to_path_buf()),
        ..test_unused_client()
    };
    let app = test_tui_app(client, &"aa".repeat(32));
    app.sweep_media_cache();

    assert!(cache_dir.is_dir(), "the sweep keeps the cache directory");
    let remaining: Vec<_> = std::fs::read_dir(&cache_dir)
        .expect("cache dir readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        remaining.is_empty(),
        "the sweep removes every leftover decrypted file; remaining: {remaining:?}"
    );
}

#[cfg(unix)]
#[test]
fn startup_media_sweep_unlinks_symlinks_without_following_them() {
    // The sweep's security contract: a symlink inside the cache dir is removed
    // as a link, and the file it points to — outside the directory — survives.
    let home = tempfile::tempdir().expect("tempdir");
    let cache_dir = home.path().join("tui-media-cache");
    std::fs::create_dir_all(&cache_dir).expect("seed cache dir");
    let sentinel = home.path().join("sentinel-outside-cache");
    std::fs::write(&sentinel, b"must survive").expect("seed sentinel");
    std::os::unix::fs::symlink(&sentinel, cache_dir.join("deadbeef")).expect("seed symlink");

    let client = WnClient {
        home: Some(home.path().to_path_buf()),
        ..test_unused_client()
    };
    let app = test_tui_app(client, &"aa".repeat(32));
    app.sweep_media_cache();

    assert!(
        cache_dir.join("deadbeef").symlink_metadata().is_err(),
        "the sweep unlinks the symlink itself"
    );
    assert!(
        sentinel.exists(),
        "the sweep never follows a link out of the cache dir"
    );
}

#[cfg(unix)]
#[test]
fn startup_media_sweep_refuses_a_symlinked_cache_root() {
    // `read_dir` follows a symlink at the path itself, so a cache root replaced
    // by a symlink would redirect the sweep's unlinks into the target directory
    // (the no-home fallback lives under the shared temp dir, where such a root
    // can be pre-planted). The sweep must refuse a root that is not a real
    // directory.
    let home = tempfile::tempdir().expect("tempdir");
    let target = home.path().join("victim-dir");
    std::fs::create_dir_all(&target).expect("seed target dir");
    std::fs::write(target.join("precious"), b"must survive").expect("seed victim file");
    std::os::unix::fs::symlink(&target, home.path().join("tui-media-cache"))
        .expect("seed symlinked cache root");

    let client = WnClient {
        home: Some(home.path().to_path_buf()),
        ..test_unused_client()
    };
    let app = test_tui_app(client, &"aa".repeat(32));
    app.sweep_media_cache();

    assert!(
        target.join("precious").exists(),
        "a symlinked cache root must never redirect the sweep's unlinks"
    );
}

/// Drive the download worker to completion and return its terminal result,
/// skipping the intermediate `Downloaded` ladder step. The worker removes the
/// on-disk artifact before sending the terminal result, so once this returns the
/// file state is settled and race-free to assert on.
#[cfg(unix)]
fn run_media_worker(exe: &std::path::Path, output_path: PathBuf) -> MediaLoad {
    let (tx, rx) = mpsc::channel();
    spawn_media_download(StdCommand::new(exe), output_path, "deadbeef".to_owned(), tx);
    loop {
        match rx
            .recv_timeout(Duration::from_secs(5))
            .expect("worker result")
        {
            MediaLoad::Downloaded { .. } => continue,
            terminal => return terminal,
        }
    }
}

/// A real, decodable PNG on disk, standing in for the CLI's decrypted write that
/// the worker sees at `--output` after a successful `media download`.
#[cfg(unix)]
fn seed_decodable_image(path: &std::path::Path) {
    let mut buffer = image::RgbImage::new(4, 4);
    for (_, _, pixel) in buffer.enumerate_pixels_mut() {
        *pixel = image::Rgb([10, 20, 30]);
    }
    let mut encoded = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(buffer)
        .write_to(&mut encoded, image::ImageFormat::Png)
        .expect("encode png");
    std::fs::write(path, encoded.into_inner()).expect("seed decrypted file");
}

#[cfg(unix)]
#[test]
fn media_worker_removes_the_decrypted_file_after_a_successful_decode() {
    // The decrypted image is decoded into memory and never read from disk again,
    // so the worker must remove the plaintext artifact once decode succeeds —
    // decrypted media must not linger at rest.
    let dir = tempfile::tempdir().expect("tempdir");
    let wn = test_json_executable(dir.path(), r#"{"ok":true}"#);
    let output_path = dir.path().join("deadbeef");
    seed_decodable_image(&output_path);
    assert!(
        output_path.exists(),
        "the artifact exists before the worker runs"
    );

    let result = run_media_worker(&wn, output_path.clone());

    assert!(
        matches!(result, MediaLoad::Decoded { .. }),
        "a valid image decodes"
    );
    assert!(
        !output_path.exists(),
        "the worker removes the decrypted artifact after a successful decode"
    );
}

#[cfg(unix)]
#[test]
fn media_worker_removes_the_decrypted_file_after_a_failed_decode() {
    // A download that succeeds but yields undecodable bytes still wrote decrypted
    // plaintext to disk; the worker must remove it on the decode-failure path too,
    // not only when decode succeeds.
    let dir = tempfile::tempdir().expect("tempdir");
    let wn = test_json_executable(dir.path(), r#"{"ok":true}"#);
    let output_path = dir.path().join("deadbeef");
    std::fs::write(&output_path, b"decrypted-but-not-an-image").expect("seed decrypted file");

    let result = run_media_worker(&wn, output_path.clone());

    assert!(
        matches!(result, MediaLoad::Failed { .. }),
        "undecodable bytes fail to decode"
    );
    assert!(
        !output_path.exists(),
        "the worker removes the decrypted artifact after a failed decode"
    );
}

#[test]
fn timeline_row_lines_strip_terminal_control_sequences() {
    let mut row = timeline_row("m", 0);
    row.from_display_name = Some("Al\u{202e}ice".to_owned());
    row.display_text = "hi\u{7}there".to_owned();
    let lines = timeline_row_lines(&row, None);
    let text = line_text(&lines[0]);
    assert!(
        !text.contains('\u{202e}'),
        "bidi override stripped from author"
    );
    assert!(
        !text.contains('\u{7}'),
        "control char stripped from content"
    );
    assert_eq!(hhmm_body(&text), "Alice: hithere");
}

#[test]
fn timeline_row_height_counts_content_reactions_reply_and_separator() {
    let mut row = timeline_row("m1", 0);
    row.from_display_name = Some("Al".to_owned());
    row.display_text = "hi".to_owned();
    // one content line + one blank separator row
    assert_eq!(timeline_row_height(&row, None, 80), 2);

    row.reactions = vec![TimelineReaction {
        emoji: "x".to_owned(),
        count: 1,
    }];
    assert_eq!(timeline_row_height(&row, None, 80), 3);

    row.reply = Some(TimelineReply {
        reply_to_message_id: "p".to_owned(),
        preview: None,
    });
    assert_eq!(timeline_row_height(&row, None, 80), 4);
}

#[test]
fn timeline_row_height_accounts_for_wrapping() {
    let mut row = timeline_row("m", 0);
    row.from_display_name = Some("A".to_owned());
    row.display_text = "x".repeat(200);
    assert!(
        timeline_row_height(&row, None, 40) > 3,
        "a 200-char body must wrap to several rows at width 40"
    );
}

#[test]
fn timeline_row_heights_maps_every_row() {
    let rows = vec![timeline_row("a", 0), timeline_row("b", 1)];
    assert_eq!(timeline_row_heights(&rows, None, 80).len(), 2);
}

#[test]
fn timeline_visible_range_pins_newest_at_bottom() {
    let heights = vec![1u16; 20];
    assert_eq!(timeline_visible_range(&heights, 10, 0, 0), Some((10, 19)));
}

#[test]
fn timeline_visible_range_walks_back_from_the_anchor() {
    let heights = vec![1u16; 20];
    // offset 10: anchor = 9, fill backward then render forward through the anchor.
    assert_eq!(timeline_visible_range(&heights, 10, 10, 0), Some((0, 9)));
}

#[test]
fn timeline_visible_range_scroll_to_top_fills_forward_not_blank() {
    let heights = vec![1u16; 20];
    // offset at the max (as `g` sets it) shows the oldest at the top and fills
    // the viewport forward — never a nearly blank pane.
    let (first, last) = timeline_visible_range(&heights, 10, 19, 0).unwrap();
    assert_eq!(first, 0);
    assert!(last >= 9, "viewport filled forward, got last={last}");
}

#[test]
fn timeline_visible_range_shows_oversized_message() {
    let heights = vec![50u16];
    assert_eq!(timeline_visible_range(&heights, 10, 0, 0), Some((0, 0)));
}

#[test]
fn timeline_visible_range_bottom_block_consumes_space_only_at_newest() {
    let heights = vec![1u16; 20];
    // Pinned at newest: a 3-row bottom block (live stream preview) shrinks the
    // message viewport from 10 to 7.
    assert_eq!(timeline_visible_range(&heights, 10, 0, 3), Some((13, 19)));
    // Scrolled up: the anchor is not the newest, so the block is not shown and
    // does not consume viewport space.
    assert_eq!(timeline_visible_range(&heights, 10, 5, 3), Some((5, 14)));
}

#[test]
fn timeline_visible_range_is_empty_without_rows_or_viewport() {
    assert_eq!(timeline_visible_range(&[], 10, 0, 0), None);
    assert_eq!(timeline_visible_range(&[1u16; 5], 0, 0, 0), None);
}

/// Render one frame: compute the visible range with the real height/visibility
/// algorithm, feed it back to the scroll model, and return the visible ids.
fn timeline_frame(
    rows: &[TimelineRow],
    scroll: &mut TimelineScroll,
    width: u16,
    viewport: u16,
) -> Vec<String> {
    let heights = timeline_row_heights(rows, None, width);
    match timeline_visible_range(&heights, viewport, scroll.offset, 0) {
        Some((first, last)) => {
            scroll.record_visible_range(first, last, rows.len());
            rows[first..=last]
                .iter()
                .map(|row| row.message_id.clone())
                .collect()
        }
        None => Vec::new(),
    }
}

fn uniform_row(id: &str, timeline_at: u64) -> TimelineRow {
    let mut row = timeline_row(id, timeline_at);
    row.from_display_name = Some("a".to_owned());
    row.display_text = "x".to_owned();
    row
}

#[test]
fn scrolled_up_view_is_stable_across_arrival_and_history_paging() {
    let (width, viewport) = (80u16, 10u16);
    let mut rows: Vec<TimelineRow> = (10..40)
        .map(|i| uniform_row(&format!("{i:03}"), i))
        .collect();
    let mut scroll = TimelineScroll::default();

    // Scroll to the oldest row, rendering each frame like the real loop.
    timeline_frame(&rows, &mut scroll, width, viewport);
    for _ in 0..rows.len() + 5 {
        scroll.select_up(rows.len());
        timeline_frame(&rows, &mut scroll, width, viewport);
    }
    assert!(scroll.at_oldest(rows.len()));
    let visible_before = timeline_frame(&rows, &mut scroll, width, viewport);
    let selected_before = rows[scroll.resolved_selection(rows.len()).unwrap()]
        .message_id
        .clone();

    // A new message arrives at the bottom while scrolled up: the view must not move.
    let outcome = apply_timeline_change(
        &mut rows,
        TimelineChange::Upsert(Box::new(uniform_row("999", 999))),
    );
    if let TimelineFoldOutcome::Inserted(index) = outcome {
        scroll.on_insert(index, rows.len());
    }
    assert_eq!(
        timeline_frame(&rows, &mut scroll, width, viewport),
        visible_before,
        "an incoming message must not move a scrolled-up reader"
    );

    // Page in 5 older rows at the front: the view still must not move.
    let older: Vec<TimelineRow> = (5..10)
        .map(|i| uniform_row(&format!("{i:03}"), i))
        .collect();
    let paged_in = older.len();
    rows.extend(older);
    sort_timeline_rows(&mut rows);
    scroll.on_prepend(paged_in);
    assert_eq!(
        timeline_frame(&rows, &mut scroll, width, viewport),
        visible_before,
        "history paging must not move the view (offset stays; indices shift)"
    );
    assert_eq!(
        rows[scroll.resolved_selection(rows.len()).unwrap()].message_id,
        selected_before,
        "the same message stays selected across paging"
    );
}

#[test]
fn jump_oldest_then_paging_keeps_the_top_of_history_stable() {
    // `g` (jump_oldest) sets a geometrically over-large offset; the renderer
    // clamps the anchor to 0. If that stale offset survives, a later prepend
    // anchors below the true top and the view jumps. Rendering must renormalize
    // the offset from the drawn geometry so paging keeps the top stable.
    let (width, viewport) = (80u16, 10u16);
    let mut rows: Vec<TimelineRow> = (10..40)
        .map(|i| uniform_row(&format!("{i:03}"), i))
        .collect();
    let mut scroll = TimelineScroll::default();

    // Jump to the oldest row, then render one frame.
    scroll.jump_oldest(rows.len());
    let visible_before = timeline_frame(&rows, &mut scroll, width, viewport);
    assert_eq!(
        visible_before.first().map(String::as_str),
        Some("010"),
        "g shows the oldest row at the top"
    );

    // Page in 5 older rows at the front; the offset stays put (rule 6) and the
    // view must not move.
    let older: Vec<TimelineRow> = (5..10)
        .map(|i| uniform_row(&format!("{i:03}"), i))
        .collect();
    let paged_in = older.len();
    rows.extend(older);
    sort_timeline_rows(&mut rows);
    scroll.on_prepend(paged_in);

    assert_eq!(
        timeline_frame(&rows, &mut scroll, width, viewport),
        visible_before,
        "history paging after `g` must not move the view"
    );
}

#[test]
fn pinned_view_follows_incoming_messages() {
    let (width, viewport) = (80u16, 10u16);
    let mut rows: Vec<TimelineRow> = (0..12)
        .map(|i| uniform_row(&format!("{i:03}"), i))
        .collect();
    let mut scroll = TimelineScroll::default();
    timeline_frame(&rows, &mut scroll, width, viewport);

    let outcome = apply_timeline_change(
        &mut rows,
        TimelineChange::Upsert(Box::new(uniform_row("099", 99))),
    );
    if let TimelineFoldOutcome::Inserted(index) = outcome {
        scroll.on_insert(index, rows.len());
    }
    let visible = timeline_frame(&rows, &mut scroll, width, viewport);
    assert!(scroll.is_pinned());
    assert_eq!(
        visible.last().map(String::as_str),
        Some("099"),
        "pinned view shows the new message"
    );
}

// ── Phase 1 timeline: pane title, event fold, and app wiring ────────────

#[test]
fn timeline_pane_title_reports_offscreen_row_counts() {
    // Everything on screen: the plain title.
    assert_eq!(timeline_pane_title(5, 0, 4), "Messages");
    // Older rows above the view.
    assert_eq!(timeline_pane_title(10, 3, 9), "Messages [3 older]");
    // Newer rows below the view.
    assert_eq!(timeline_pane_title(10, 0, 6), "Messages [3 newer]");
    // Both directions.
    assert_eq!(
        timeline_pane_title(10, 2, 6),
        "Messages [2 older | 3 newer]"
    );
}

#[test]
fn apply_timeline_event_initial_page_sets_rows_and_more_before() {
    let mut rows = Vec::new();
    let mut scroll = TimelineScroll::default();
    apply_timeline_event(
        &mut rows,
        &mut scroll,
        Some("group"),
        TimelineEvent::InitialPage {
            rows: vec![timeline_row("b", 20), timeline_row("a", 10)],
            has_more_before: true,
        },
    );
    assert_eq!(timeline_ids(&rows), vec!["a", "b"], "merged and sorted");
    assert!(scroll.has_more_before);

    // Re-delivering the same page (the feed duplicates events) is a no-op in
    // effect: the fold upserts by id and never appends a second copy.
    let before = rows.clone();
    apply_timeline_event(
        &mut rows,
        &mut scroll,
        Some("group"),
        TimelineEvent::InitialPage {
            rows: vec![timeline_row("b", 20), timeline_row("a", 10)],
            has_more_before: true,
        },
    );
    assert_eq!(rows, before, "duplicated initial page is idempotent by id");
}

#[test]
fn apply_timeline_event_initial_page_compensates_scroll_for_newer_rows() {
    // The snapshot loaded rows 000..029 and the reader scrolled up. The
    // subscription's initial page then carries the same rows plus 3 newer rows
    // that arrived between the snapshot and the subscribe; folding them must
    // drive the scroll model so the row being read stays anchored, exactly like
    // the projection arm.
    let mut rows: Vec<TimelineRow> = (0..30)
        .map(|i| timeline_row(&format!("{i:03}"), i))
        .collect();
    let mut scroll = TimelineScroll {
        offset: 5,
        selection: Some(24),
        visible_range: Some((20, 24)),
        ..TimelineScroll::default()
    };

    let mut page: Vec<TimelineRow> = (0..33)
        .map(|i| timeline_row(&format!("{i:03}"), i))
        .collect();
    // Deliver the page out of order to prove the fold indexes by sorted position.
    page.reverse();

    apply_timeline_event(
        &mut rows,
        &mut scroll,
        Some("group"),
        TimelineEvent::InitialPage {
            rows: page,
            has_more_before: false,
        },
    );

    assert_eq!(rows.len(), 33, "3 newer rows merged in");
    let anchor = (rows.len() - 1) - scroll.offset;
    assert_eq!(
        rows[anchor].message_id, "024",
        "the row being read stays anchored despite the newer rows"
    );
    assert_eq!(scroll.selection, Some(24), "same row stays selected");
}

#[test]
fn apply_timeline_event_projection_folds_and_drives_scroll_for_loaded_group() {
    let mut rows = vec![timeline_row("a", 10), timeline_row("b", 20)];
    let mut scroll = TimelineScroll::default();
    apply_timeline_event(
        &mut rows,
        &mut scroll,
        Some("group"),
        TimelineEvent::ProjectionUpdated {
            group_id: "group".to_owned(),
            changes: vec![TimelineChange::Upsert(Box::new(timeline_row("c", 30)))],
        },
    );
    assert_eq!(timeline_ids(&rows), vec!["a", "b", "c"]);
    assert!(
        scroll.is_pinned(),
        "an arrival while pinned keeps the view pinned"
    );

    // A duplicated projection event (optimistic write plus relay echo) must not
    // append a second copy.
    apply_timeline_event(
        &mut rows,
        &mut scroll,
        Some("group"),
        TimelineEvent::ProjectionUpdated {
            group_id: "group".to_owned(),
            changes: vec![TimelineChange::Upsert(Box::new(timeline_row("c", 30)))],
        },
    );
    assert_eq!(timeline_ids(&rows), vec!["a", "b", "c"], "idempotent by id");

    apply_timeline_event(
        &mut rows,
        &mut scroll,
        Some("group"),
        TimelineEvent::ProjectionUpdated {
            group_id: "group".to_owned(),
            changes: vec![TimelineChange::Remove {
                message_id: "a".to_owned(),
            }],
        },
    );
    assert_eq!(timeline_ids(&rows), vec!["b", "c"]);
}

#[test]
fn apply_timeline_event_ignores_projection_for_other_group() {
    let mut rows = vec![timeline_row("a", 10)];
    let mut scroll = TimelineScroll::default();
    apply_timeline_event(
        &mut rows,
        &mut scroll,
        Some("loaded"),
        TimelineEvent::ProjectionUpdated {
            group_id: "elsewhere".to_owned(),
            changes: vec![TimelineChange::Upsert(Box::new(timeline_row("z", 99)))],
        },
    );
    assert_eq!(
        timeline_ids(&rows),
        vec!["a"],
        "off-group changes are dropped"
    );
}

#[test]
fn send_message_upserts_an_optimistic_timeline_row() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (_tempdir, client) =
        test_json_client(r#"{"ok":true,"result":{"published":1,"message_ids":["m1"]}}"#);
    let mut app = test_tui_app(client, account_id);
    app.messages_account_id = Some(account_id.to_owned());
    app.messages_group_id = Some(group_id.to_owned());

    app.send_message("hello there".to_owned())
        .expect("send message");

    assert_eq!(app.timeline.len(), 1);
    assert_eq!(app.timeline[0].message_id, "m1");
    assert_eq!(app.timeline[0].direction, "sent");
    assert_eq!(app.timeline[0].display_text, "hello there");
    assert!(
        app.timeline_scroll.is_pinned(),
        "an own send keeps the view pinned to the bottom"
    );
}

#[cfg(unix)]
#[test]
fn send_message_uses_the_documented_plural_messages_namespace() {
    // `messages send` is the documented surface; `message send` is a hidden
    // deprecated alias. The message interactions (react/unreact/delete/retry)
    // all spawn the plural form, so send must too, for a consistent surface.
    let account_id = "aa".repeat(32);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) = test_arg_recording_executable(
        tempdir.path(),
        r#"{"ok":true,"result":{"published":1,"message_ids":["m1"]}}"#,
    );
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some("bb".repeat(32));

    app.send_message("hello there".to_owned()).expect("send");

    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    let args: Vec<&str> = recorded.lines().collect();
    let send_index = args
        .iter()
        .position(|arg| *arg == "send")
        .expect("a send subcommand was spawned");
    assert_eq!(
        args[send_index - 1],
        "messages",
        "send must spawn the plural `messages send`, not the singular alias; got {args:?}"
    );
}

#[test]
fn refresh_messages_loads_the_materialized_timeline_page() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (_tempdir, client) = test_json_client(
        r#"{"ok":true,"result":{"messages":[{"message_id":"m1","direction":"received","from":"alice","plaintext":"hello","timeline_at":100,"received_at":100}],"has_more_before":true}}"#,
    );
    let mut app = test_tui_app(client, account_id);
    app.chats = vec![ChatRow {
        group_id: group_id.to_owned(),
        name: "general".to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    }];
    app.selected_chat = 0;

    app.refresh_messages().expect("refresh messages");

    assert_eq!(app.timeline.len(), 1);
    assert_eq!(app.timeline[0].message_id, "m1");
    assert!(app.timeline_scroll.has_more_before);
    assert!(app.timeline_scroll.is_pinned());
    assert_eq!(app.timeline_scroll.selection, None);
    assert_eq!(app.messages_group_id.as_deref(), Some(group_id));
}

#[test]
fn load_older_messages_prepends_a_page_and_updates_the_cursor() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (_tempdir, client) = test_json_client(
        r#"{"ok":true,"result":{"messages":[{"message_id":"old","direction":"received","from":"alice","plaintext":"older","timeline_at":50,"received_at":50}],"has_more_before":false}}"#,
    );
    let mut app = test_tui_app(client, account_id);
    app.messages_account_id = Some(account_id.to_owned());
    app.messages_group_id = Some(group_id.to_owned());
    app.timeline = vec![timeline_row("new", 100)];
    app.timeline_scroll.has_more_before = true;

    app.load_older_messages().expect("load older messages");

    assert_eq!(timeline_ids(&app.timeline), vec!["old", "new"]);
    assert!(
        !app.timeline_scroll.has_more_before,
        "page reported no more"
    );
    assert!(!app.timeline_scroll.loading_older, "in-flight flag cleared");
}

#[test]
fn load_older_messages_clears_loading_flag_on_error() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (_tempdir, client) = test_json_client(r#"{"ok":false,"error":{"message":"backend gone"}}"#);
    let mut app = test_tui_app(client, account_id);
    app.messages_account_id = Some(account_id.to_owned());
    app.messages_group_id = Some(group_id.to_owned());
    app.timeline = vec![timeline_row("new", 100)];
    app.timeline_scroll.has_more_before = true;

    let outcome = app.load_older_messages();

    assert!(
        outcome.is_err(),
        "the backend failure propagates to the caller"
    );
    assert_eq!(app.timeline.len(), 1, "no rows added on failure");
    assert!(
        !app.timeline_scroll.loading_older,
        "the in-flight flag is cleared on the error path so paging is not wedged"
    );
}

#[test]
fn load_older_messages_upserts_overlap_without_duplicating_or_overshifting() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    // The fetched page overlaps the oldest loaded row ("new") and adds one
    // genuinely older row ("old"). An exclusive cursor should not overlap, but if
    // it ever does the merge must stay idempotent: no duplicate, no over-shift.
    let (_tempdir, client) = test_json_client(
        r#"{"ok":true,"result":{"messages":[
            {"message_id":"old","direction":"received","from":"alice","plaintext":"older","timeline_at":50,"received_at":50},
            {"message_id":"new","direction":"received","from":"alice","plaintext":"newer","timeline_at":100,"received_at":100}
        ],"has_more_before":false}}"#,
    );
    let mut app = test_tui_app(client, account_id);
    app.messages_account_id = Some(account_id.to_owned());
    app.messages_group_id = Some(group_id.to_owned());
    app.timeline = vec![timeline_row("new", 100)];
    app.timeline_scroll.has_more_before = true;
    app.timeline_scroll.selection = Some(0);
    app.timeline_scroll.visible_range = Some((0, 0));

    app.load_older_messages().expect("load older messages");

    assert_eq!(
        timeline_ids(&app.timeline),
        vec!["old", "new"],
        "the overlapping row is upserted, not duplicated"
    );
    assert_eq!(
        app.timeline_scroll.selection,
        Some(1),
        "only the one genuinely-new row shifts the selection"
    );
    assert_eq!(app.timeline_scroll.visible_range, Some((1, 1)));
}

#[test]
fn messages_select_up_pages_in_older_history_at_the_oldest_row() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (_tempdir, client) = test_json_client(
        r#"{"ok":true,"result":{"messages":[{"message_id":"old","direction":"received","from":"alice","plaintext":"older","timeline_at":5,"received_at":5}],"has_more_before":false}}"#,
    );
    let mut app = test_tui_app(client, account_id);
    app.focus = Focus::Messages;
    app.messages_account_id = Some(account_id.to_owned());
    app.messages_group_id = Some(group_id.to_owned());
    app.timeline = vec![timeline_row("new", 10)];
    app.timeline_scroll.has_more_before = true;
    app.timeline_scroll.selection = Some(0);

    app.handle_key(char_key('k'))
        .expect("handle 'k' at oldest row");

    assert_eq!(timeline_ids(&app.timeline), vec!["old", "new"]);
    assert!(!app.timeline_scroll.has_more_before);
}

#[test]
fn messages_jump_oldest_pages_in_older_history() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (_tempdir, client) = test_json_client(
        r#"{"ok":true,"result":{"messages":[{"message_id":"old","direction":"received","from":"alice","plaintext":"older","timeline_at":5,"received_at":5}],"has_more_before":false}}"#,
    );
    let mut app = test_tui_app(client, account_id);
    app.focus = Focus::Messages;
    app.messages_account_id = Some(account_id.to_owned());
    app.messages_group_id = Some(group_id.to_owned());
    app.timeline = vec![timeline_row("new", 10)];
    app.timeline_scroll.has_more_before = true;

    // `g` jumps to the oldest loaded row and must fetch older history, like `k`.
    app.handle_key(char_key('g'))
        .expect("handle 'g' jump oldest");

    assert_eq!(timeline_ids(&app.timeline), vec!["old", "new"]);
    assert!(!app.timeline_scroll.has_more_before);
}

#[test]
fn drain_timeline_subscription_applies_events_for_the_loaded_group_only() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let group_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let other_group = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let mut app = test_tui_app(test_unused_client(), account_id);
    app.messages_group_id = Some(group_id.to_owned());
    let (tx, rx) = mpsc::channel();
    app.timeline_subscription = Some(TimelineSubscription {
        account_id: account_id.to_owned(),
        group_id: group_id.to_owned(),
        child: test_sleep_child(),
        rx,
    });

    tx.send(SubscriptionEvent::Result(serde_json::json!({
        "type": "initial_timeline_page",
        "has_more_before": true,
        "messages": [
            { "message_id": "a", "plaintext": "one", "timeline_at": 1 },
            { "message_id": "b", "plaintext": "two", "timeline_at": 2 }
        ]
    })))
    .expect("send initial page");
    assert!(app.drain_timeline_subscription());
    assert_eq!(timeline_ids(&app.timeline), vec!["a", "b"]);
    assert!(app.timeline_scroll.has_more_before);

    tx.send(SubscriptionEvent::Result(serde_json::json!({
        "type": "timeline_projection_updated",
        "group_id": group_id,
        "changes": [
            { "type": "upsert", "message": { "message_id": "c", "plaintext": "three", "timeline_at": 3 } }
        ]
    })))
    .expect("send projection for loaded group");
    assert!(app.drain_timeline_subscription());
    assert_eq!(timeline_ids(&app.timeline), vec!["a", "b", "c"]);

    tx.send(SubscriptionEvent::Result(serde_json::json!({
        "type": "timeline_projection_updated",
        "group_id": other_group,
        "changes": [
            { "type": "upsert", "message": { "message_id": "z", "plaintext": "nope", "timeline_at": 9 } }
        ]
    })))
    .expect("send projection for another group");
    assert!(app.drain_timeline_subscription());
    assert_eq!(
        timeline_ids(&app.timeline),
        vec!["a", "b", "c"],
        "a projection for another group is ignored"
    );
}

#[test]
fn messages_pane_keys_drive_the_selection_and_composer_focus() {
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut app = test_tui_app(test_unused_client(), account_id);
    app.focus = Focus::Messages;
    app.timeline = (0..5).map(|i| timeline_row(&format!("m{i}"), i)).collect();
    // No older history, so navigation never shells out (the client is unused).
    app.timeline_scroll.has_more_before = false;

    assert_eq!(
        app.timeline_scroll.resolved_selection(5),
        Some(4),
        "newest by default"
    );
    app.handle_key(char_key('k')).expect("k");
    assert_eq!(app.timeline_scroll.resolved_selection(5), Some(3));
    app.handle_key(char_key('g')).expect("g");
    assert_eq!(
        app.timeline_scroll.resolved_selection(5),
        Some(0),
        "g jumps to oldest"
    );
    app.handle_key(char_key('j')).expect("j");
    assert_eq!(app.timeline_scroll.resolved_selection(5), Some(1));
    app.handle_key(char_key('G')).expect("G");
    assert_eq!(
        app.timeline_scroll.resolved_selection(5),
        Some(4),
        "G jumps to newest"
    );
    assert!(app.timeline_scroll.is_pinned(), "G pins to the bottom");
    app.handle_key(char_key('i')).expect("i");
    assert_eq!(app.focus, Focus::Composer, "i focuses the composer");
}

#[test]
fn render_messages_wraps_long_lines_so_the_tail_is_visible() {
    // The height model (`timeline_row_height`) measures with wrapping, so the
    // renderer must wrap too or long lines truncate at the pane edge and the
    // reserved-vs-drawn height mismatch breaks bottom-anchoring.
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut app = test_tui_app(test_unused_client(), account_id);
    app.focus = Focus::Messages;
    let mut row = timeline_row("m", 0);
    row.from_display_name = Some("Al".to_owned());
    // ~100 chars, wider than the ~28-column messages pane; the tail only renders
    // if the paragraph wraps.
    row.display_text = format!("{}TAILMARKER", "word ".repeat(19));
    app.timeline = vec![row];

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

    assert!(
        rendered.contains("TAILMARKER"),
        "the wrapped tail of a long message must render, not truncate at the pane edge"
    );
}

// --- Phase 2: the shell (screen model, key routing, status/hints bars) ---

#[test]
fn startup_screen_routes_by_account_count() {
    assert_eq!(startup_screen(0, false), Screen::Login(LoginMode::Menu));
    assert_eq!(startup_screen(1, false), Screen::Main);
    assert_eq!(
        startup_screen(2, false),
        Screen::Login(LoginMode::AccountSelect)
    );
    assert_eq!(
        startup_screen(9, false),
        Screen::Login(LoginMode::AccountSelect)
    );
    // An explicit --account selection enters the main view even with several
    // accounts; a resolved single/none selection is unaffected.
    assert_eq!(startup_screen(2, true), Screen::Main);
    assert_eq!(startup_screen(9, true), Screen::Main);
    assert_eq!(startup_screen(0, true), Screen::Login(LoginMode::Menu));
}

#[test]
fn focus_cycles_the_three_main_panes() {
    assert_eq!(Focus::Chats.next(), Focus::Messages);
    assert_eq!(Focus::Messages.next(), Focus::Composer);
    assert_eq!(Focus::Composer.next(), Focus::Chats);
    assert_eq!(Focus::Chats.previous(), Focus::Composer);
    assert_eq!(Focus::Messages.previous(), Focus::Chats);
    assert_eq!(Focus::Composer.previous(), Focus::Messages);
}

#[test]
fn login_mode_for_accounts_picks_the_launching_screen() {
    assert_eq!(login_mode_for_accounts(0), LoginMode::Menu);
    assert_eq!(login_mode_for_accounts(1), LoginMode::AccountSelect);
    assert_eq!(login_mode_for_accounts(4), LoginMode::AccountSelect);
}

#[test]
fn masked_secret_hides_every_character() {
    assert_eq!(masked_secret(""), "");
    assert_eq!(masked_secret("nsec1abc"), "********");
    // Multi-byte characters each mask to a single `*`.
    assert_eq!(masked_secret("aé😀"), "***");
}

#[test]
fn status_bar_line_assembles_daemon_counts_and_status() {
    assert_eq!(
        status_bar_line("alice", true, 3, 5, "loaded 2 message(s)", 200),
        "alice · daemon on · 3 chats · 5 unread · loaded 2 message(s)"
    );
    assert_eq!(
        status_bar_line("bob", false, 0, 0, "", 200),
        "bob · daemon off · 0 chats · 0 unread · "
    );
    // Narrow widths shorten the assembled line (middle ellipsis keeps head + tail).
    let narrow = status_bar_line("alice", true, 3, 5, "loaded", 20);
    assert!(narrow.chars().count() <= 20, "over width: {narrow:?}");
    assert!(narrow.contains("..."), "expected truncation: {narrow:?}");
}

#[test]
fn status_bar_line_strips_control_sequences_from_untrusted_fields() {
    assert_eq!(
        status_bar_line("al\u{1b}[31mice", true, 1, 0, "ok\u{1b}[2J", 200),
        "al[31mice · daemon on · 1 chats · 0 unread · ok[2J"
    );
}

#[test]
fn hints_line_matches_the_keymap_per_screen_and_focus() {
    assert_eq!(
        hints_line(Screen::Main, Focus::Chats, true),
        "j/k move  Enter open  g detail  s search  p profile  h relays  I invites  A accounts  ? help"
    );
    assert_eq!(
        hints_line(Screen::Profile, Focus::Chats, true),
        "j/k move  Enter edit  f follow  x unfollow  Esc back"
    );
    assert_eq!(
        hints_line(Screen::RelayHealth, Focus::Chats, true),
        "r refresh  j/k scroll  Esc back"
    );
    // The user-search screen's hint is focus-aware (rendered via `user_search_hint`).
    assert_eq!(
        user_search_hint(UserSearchFocus::Query),
        "type query  Enter search  Down results  Esc back"
    );
    assert_eq!(
        user_search_hint(UserSearchFocus::Results),
        "j/k move  Enter profile  c chat  a add  i query  Esc back"
    );
    assert_eq!(
        hints_line(Screen::Main, Focus::Messages, true),
        "j/k select  G/g ends  r react  u unreact  d delete  R reply  i compose"
    );
    assert_eq!(
        hints_line(Screen::GroupDetail, Focus::Chats, true),
        "j/k move  A add  x remove  P promote  R rename  L leave  I invites  ? help  Esc back"
    );
    assert_eq!(
        hints_line(Screen::Main, Focus::Composer, true),
        "Enter send  Ctrl-U clear"
    );
    assert_eq!(
        hints_line(Screen::Login(LoginMode::Menu), Focus::Chats, false),
        "c create identity  l nsec login  q quit"
    );
    // The account picker shows `Esc back` only when a main session exists to
    // return to; at the startup picker `Esc` is inert, so the hint is omitted.
    assert_eq!(
        hints_line(Screen::Login(LoginMode::AccountSelect), Focus::Chats, true),
        "j/k navigate  Enter select  c create  l nsec  Esc back  q quit"
    );
    assert_eq!(
        hints_line(Screen::Login(LoginMode::AccountSelect), Focus::Chats, false),
        "j/k navigate  Enter select  c create  l nsec  q quit"
    );
    assert_eq!(
        hints_line(Screen::Login(LoginMode::NsecEntry), Focus::Chats, false),
        "Enter submit  Esc back"
    );
}

// ---- Phase 5a: popups, group detail, invites ----

#[test]
fn popup_key_text_entry_submits_purpose_and_cancels() {
    let mut rename = Popup::Text {
        purpose: TextPurpose::RenameGroup {
            group_id: "g1".to_owned(),
        },
        title: "Rename Group".to_owned(),
        body: Vec::new(),
        input: Input::default(),
    };
    for character in "ops".chars() {
        assert_eq!(
            popup_key(&mut rename, KeyCode::Char(character)),
            PopupAction::None
        );
    }
    assert_eq!(
        popup_key(&mut rename, KeyCode::Enter),
        PopupAction::Submit(PopupSubmit::RenameGroup {
            group_id: "g1".to_owned(),
            name: "ops".to_owned(),
        })
    );

    let mut add = Popup::Text {
        purpose: TextPurpose::AddMemberByPubkey {
            group_id: "g1".to_owned(),
        },
        title: "Add Member".to_owned(),
        body: Vec::new(),
        input: Input::default(),
    };
    // An empty submit is a no-op; Esc cancels with no side effect.
    assert_eq!(popup_key(&mut add, KeyCode::Enter), PopupAction::None);
    for character in "npub1".chars() {
        popup_key(&mut add, KeyCode::Char(character));
    }
    assert_eq!(
        popup_key(&mut add, KeyCode::Enter),
        PopupAction::Submit(PopupSubmit::AddMember {
            group_id: "g1".to_owned(),
            pubkey: "npub1".to_owned(),
        })
    );
    let mut cancel = Popup::Text {
        purpose: TextPurpose::AddMemberByPubkey {
            group_id: "g1".to_owned(),
        },
        title: "Add Member".to_owned(),
        body: Vec::new(),
        input: Input::default(),
    };
    assert_eq!(popup_key(&mut cancel, KeyCode::Esc), PopupAction::Dismiss);
}

#[test]
fn popup_key_confirm_logout_requires_the_exact_token() {
    // The typed-token confirm submits only when the input is exactly the token.
    // Both an empty submit (the double-Enter case) and any mismatch are no-ops
    // that keep the popup open; Esc always cancels. This is the reducer-level
    // guard behind the local-signing logout.
    let logout = || Popup::Text {
        purpose: TextPurpose::ConfirmLogout {
            account_id: "aa".repeat(32),
            npub: "npub1alice".to_owned(),
        },
        title: "Log Out".to_owned(),
        body: vec!["Log out npub1alice?".to_owned()],
        input: Input::default(),
    };

    // Empty submit: no-op, popup stays open.
    let mut empty = logout();
    assert_eq!(popup_key(&mut empty, KeyCode::Enter), PopupAction::None);

    // A near-miss token: no-op, popup stays open.
    let mut mismatch = logout();
    for character in "logoutt".chars() {
        popup_key(&mut mismatch, KeyCode::Char(character));
    }
    assert_eq!(popup_key(&mut mismatch, KeyCode::Enter), PopupAction::None);

    // The exact token submits the wipe.
    let mut exact = logout();
    for character in LOGOUT_CONFIRMATION_TOKEN.chars() {
        popup_key(&mut exact, KeyCode::Char(character));
    }
    assert_eq!(
        popup_key(&mut exact, KeyCode::Enter),
        PopupAction::Submit(PopupSubmit::Logout {
            account_id: "aa".repeat(32),
            npub: "npub1alice".to_owned(),
        })
    );

    // Esc cancels regardless of typed content.
    let mut cancel = logout();
    assert_eq!(popup_key(&mut cancel, KeyCode::Esc), PopupAction::Dismiss);
}

#[test]
fn popup_key_confirm_accepts_y_or_enter_and_cancels_n_or_esc() {
    let leave = || Popup::Confirm {
        purpose: ConfirmPurpose::LeaveGroup {
            group_id: "g1".to_owned(),
        },
        title: "Leave Group".to_owned(),
        body: Vec::new(),
    };
    let expect = PopupAction::Submit(PopupSubmit::LeaveGroup {
        group_id: "g1".to_owned(),
    });
    assert_eq!(popup_key(&mut leave(), KeyCode::Char('y')), expect);
    assert_eq!(popup_key(&mut leave(), KeyCode::Enter), expect);
    assert_eq!(
        popup_key(&mut leave(), KeyCode::Char('n')),
        PopupAction::Dismiss
    );
    assert_eq!(popup_key(&mut leave(), KeyCode::Esc), PopupAction::Dismiss);
    // A confirm ignores unrelated keys instead of acting on them.
    assert_eq!(
        popup_key(&mut leave(), KeyCode::Char('x')),
        PopupAction::None
    );
}

#[test]
fn popup_key_card_dismisses_on_any_key() {
    for key in [
        KeyCode::Char('q'),
        KeyCode::Char('j'),
        KeyCode::Enter,
        KeyCode::Esc,
    ] {
        assert_eq!(popup_key(&mut Popup::help(), key), PopupAction::Dismiss);
    }
}

#[test]
fn popup_key_invites_picker_navigates_accepts_and_declines() {
    let items = vec![
        PickerItem {
            id: "g1".to_owned(),
            label: "Room A".to_owned(),
        },
        PickerItem {
            id: "g2".to_owned(),
            label: "Room B".to_owned(),
        },
    ];
    let picker = || Popup::Picker {
        purpose: PickerPurpose::Invites,
        title: "Pending Invites".to_owned(),
        items: items.clone(),
        selected: 0,
    };
    let mut accept = picker();
    assert_eq!(popup_key(&mut accept, KeyCode::Down), PopupAction::None);
    assert_eq!(
        popup_key(&mut accept, KeyCode::Char('a')),
        PopupAction::Submit(PopupSubmit::AcceptInvite {
            group_id: "g2".to_owned(),
        })
    );
    let mut decline = picker();
    assert_eq!(
        popup_key(&mut decline, KeyCode::Char('d')),
        PopupAction::Submit(PopupSubmit::DeclineInvite {
            group_id: "g1".to_owned(),
        })
    );
    assert_eq!(popup_key(&mut decline, KeyCode::Esc), PopupAction::Dismiss);
}

#[test]
fn popup_key_group_picker_navigates_and_chains_into_the_add_confirm() {
    let items = vec![
        PickerItem {
            id: "g1".to_owned(),
            label: "Room A".to_owned(),
        },
        PickerItem {
            id: "g2".to_owned(),
            label: "Room B".to_owned(),
        },
    ];
    let picker =
        || Popup::add_user_group_picker("pk".to_owned(), "Alice".to_owned(), items.clone(), 0);

    // j then Enter chains into the add-user confirm for the highlighted chat —
    // the picker chooses the target, the confirm still guards the action.
    let mut choose = picker();
    assert_eq!(
        popup_key(&mut choose, KeyCode::Char('j')),
        PopupAction::None
    );
    let action = popup_key(&mut choose, KeyCode::Enter);
    let PopupAction::Open(Popup::Confirm {
        purpose,
        title,
        body,
    }) = action
    else {
        panic!("Enter must open the add-user confirm, got {action:?}");
    };
    assert_eq!(
        purpose,
        ConfirmPurpose::AddUserToChat {
            group_id: "g2".to_owned(),
            pubkey: "pk".to_owned(),
        }
    );
    assert_eq!(title, "Add to Chat");
    assert_eq!(body, vec!["Add Alice to Room B?".to_owned()]);

    // The invites action keys mean nothing here, and Esc closes the picker.
    let mut dismiss = picker();
    assert_eq!(
        popup_key(&mut dismiss, KeyCode::Char('a')),
        PopupAction::None
    );
    assert_eq!(
        popup_key(&mut dismiss, KeyCode::Char('d')),
        PopupAction::None
    );
    assert_eq!(popup_key(&mut dismiss, KeyCode::Esc), PopupAction::Dismiss);
}

#[test]
fn leave_group_decision_covers_sole_admin_co_admin_and_non_admin() {
    assert_eq!(
        leave_group_decision(true, 1),
        LeaveDecision::Blocked(LEAVE_SOLE_ADMIN_MESSAGE)
    );
    assert_eq!(
        leave_group_decision(true, 3),
        LeaveDecision::Blocked(LEAVE_CO_ADMIN_MESSAGE)
    );
    assert_eq!(leave_group_decision(false, 3), LeaveDecision::Confirm);
    // The exact wn-tui messages, pinned so a reword is a deliberate change.
    assert_eq!(
        LEAVE_SOLE_ADMIN_MESSAGE,
        "You're the only admin. Promote another member to admin before you can leave."
    );
    assert_eq!(
        LEAVE_CO_ADMIN_MESSAGE,
        "You're an admin of this group. Step down as admin before leaving."
    );
}

#[test]
fn build_group_detail_tags_admins_and_self() {
    let members = vec![
        ("aa".to_owned(), "npubself".to_owned()),
        ("bb".to_owned(), "npubbob".to_owned()),
    ];
    let admins = vec!["aa".to_owned()];
    let view = build_group_detail(
        "g1",
        "Ops",
        "desc",
        &members,
        &admins,
        &["wss://relay.example".to_owned()],
        "aa",
    );
    assert!(view.members[0].is_admin && view.members[0].is_self);
    assert!(!view.members[1].is_admin && !view.members[1].is_self);
    assert!(view.account_is_admin);
    assert_eq!(view.admin_count, 1);
    assert_eq!(view.relays, vec!["wss://relay.example".to_owned()]);
}

#[test]
fn group_detail_parsers_read_members_admins_relays_profile_and_invites() {
    let result = serde_json::json!({
        "members": [{"member_id": "aa", "npub": "npuba", "local": true}],
        "admins": [{"admin_id": "aa", "npub": "npuba"}],
        "relays": ["wss://relay.example", ""],
        "profile": {"name": "Ops", "description": "the ops room"},
    });
    assert_eq!(
        parse_group_members(&result),
        vec![("aa".to_owned(), "npuba".to_owned())]
    );
    assert_eq!(parse_group_admins(&result), vec!["aa".to_owned()]);
    // The empty relay string is filtered out.
    assert_eq!(
        parse_group_relays(&result),
        vec!["wss://relay.example".to_owned()]
    );
    assert_eq!(
        parse_group_profile(&result),
        Some(("Ops".to_owned(), "the ops room".to_owned()))
    );

    let invites = serde_json::json!({
        "invites": [
            {"group_id": "g1", "profile": {"name": "Room A"}, "pending_confirmation": true},
            {"group_id": "g2", "profile": {"name": "Room B"}, "pending_confirmation": false},
        ]
    });
    assert_eq!(
        parse_invite_items(&invites),
        vec![PickerItem {
            id: "g1".to_owned(),
            label: "Room A".to_owned(),
        }]
    );
}

#[test]
fn open_group_detail_loads_state_and_esc_returns_to_main() {
    let self_id = "aa".repeat(32);
    let bob_id = "bb".repeat(32);
    let response = format!(
        r#"{{"ok":true,"result":{{"profile":{{"name":"Ops","description":"ops room"}},"members":[{{"member_id":"{self_id}","npub":"npubself"}},{{"member_id":"{bob_id}","npub":"npubbob"}}],"admins":[{{"admin_id":"{self_id}","npub":"npubself"}}],"relays":["wss://relay.example"]}}}}"#
    );
    let (_tempdir, client) = test_json_client(&response);
    let mut app = test_tui_app(client, &self_id);
    app.focus = Focus::Chats;
    app.chats = vec![ChatRow {
        group_id: "cc".repeat(32),
        name: "Ops".to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    }];
    app.selected_chat = 0;

    app.handle_key(char_key('g')).expect("g opens group detail");

    assert_eq!(app.screen, Screen::GroupDetail);
    let view = app.group_detail.as_ref().expect("group detail loaded");
    assert_eq!(view.members.len(), 2);
    assert!(view.account_is_admin);
    assert_eq!(view.admin_count, 1);
    assert!(view.members[0].is_self);

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc leaves group detail");
    assert_eq!(app.screen, Screen::Main);
    assert!(
        app.group_detail.is_none(),
        "group-detail state is dropped on exit"
    );
}

#[test]
fn group_detail_leave_guard_blocks_admins_and_confirms_non_admins() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::GroupDetail;
    app.group_detail = Some(GroupDetailView {
        group_id: "g1".to_owned(),
        name: "Ops".to_owned(),
        description: String::new(),
        members: Vec::new(),
        relays: Vec::new(),
        account_is_admin: true,
        admin_count: 1,
        selected: 0,
    });

    app.handle_key(char_key('L')).expect("L (sole admin)");
    match &app.popup {
        Some(Popup::Card { title, body }) => {
            assert_eq!(title, CANNOT_LEAVE_TITLE);
            assert_eq!(body[0], LEAVE_SOLE_ADMIN_MESSAGE);
        }
        other => panic!("expected sole-admin info card, got {other:?}"),
    }

    app.popup = None;
    app.group_detail.as_mut().unwrap().admin_count = 2;
    app.handle_key(char_key('L')).expect("L (co-admin)");
    match &app.popup {
        Some(Popup::Card { body, .. }) => assert_eq!(body[0], LEAVE_CO_ADMIN_MESSAGE),
        other => panic!("expected co-admin info card, got {other:?}"),
    }

    app.popup = None;
    app.group_detail.as_mut().unwrap().account_is_admin = false;
    app.handle_key(char_key('L')).expect("L (non-admin)");
    assert!(matches!(
        app.popup,
        Some(Popup::Confirm {
            purpose: ConfirmPurpose::LeaveGroup { .. },
            ..
        })
    ));
}

#[test]
fn group_detail_add_and_rename_open_text_popups_with_expected_prefill() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::GroupDetail;
    app.group_detail = Some(GroupDetailView {
        group_id: "g1".to_owned(),
        name: "Ops Room".to_owned(),
        description: String::new(),
        members: vec![GroupMemberRow {
            member_id: "bb".to_owned(),
            npub: "npubbob".to_owned(),
            is_admin: false,
            is_self: false,
        }],
        relays: Vec::new(),
        account_is_admin: false,
        admin_count: 1,
        selected: 0,
    });

    app.handle_key(char_key('A')).expect("A add member");
    match &app.popup {
        Some(Popup::Text { purpose, input, .. }) => {
            assert_eq!(
                *purpose,
                TextPurpose::AddMemberByPubkey {
                    group_id: "g1".to_owned()
                }
            );
            assert!(input.is_empty(), "add-member starts empty");
        }
        other => panic!("expected add-member text popup, got {other:?}"),
    }

    app.popup = None;
    app.handle_key(char_key('R')).expect("R rename");
    match &app.popup {
        Some(Popup::Text { purpose, input, .. }) => {
            assert_eq!(
                *purpose,
                TextPurpose::RenameGroup {
                    group_id: "g1".to_owned()
                }
            );
            assert_eq!(
                input.value(),
                "Ops Room",
                "rename prefills the current name"
            );
        }
        other => panic!("expected rename text popup, got {other:?}"),
    }

    app.popup = None;
    app.handle_key(char_key('P')).expect("P promote");
    assert!(matches!(
        app.popup,
        Some(Popup::Confirm {
            purpose: ConfirmPurpose::PromoteMember { .. },
            ..
        })
    ));
}

#[test]
fn question_mark_in_group_detail_opens_the_help_card() {
    // `?` is bound to the help card on the group-detail screen too, so the same
    // help is reachable there and not only from the main chat list.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::GroupDetail;
    app.group_detail = Some(GroupDetailView {
        group_id: "g1".to_owned(),
        name: "Ops Room".to_owned(),
        description: String::new(),
        members: Vec::new(),
        relays: Vec::new(),
        account_is_admin: false,
        admin_count: 1,
        selected: 0,
    });

    app.handle_key(char_key('?')).expect("? in group detail");

    assert!(
        matches!(app.popup, Some(Popup::Card { .. })),
        "'?' opens the help card on the group-detail screen"
    );
}

#[test]
fn promote_yourself_is_blocked_with_a_status_not_a_confirm() {
    // Mirrors the remove-self guard: you cannot promote yourself, so `P` on your
    // own row sets a status line instead of opening a confirm popup.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::GroupDetail;
    app.group_detail = Some(GroupDetailView {
        group_id: "g1".to_owned(),
        name: "Ops Room".to_owned(),
        description: String::new(),
        members: vec![GroupMemberRow {
            member_id: "aa".to_owned(),
            npub: "npubme".to_owned(),
            is_admin: false,
            is_self: true,
        }],
        relays: Vec::new(),
        account_is_admin: false,
        admin_count: 1,
        selected: 0,
    });

    app.handle_key(char_key('P')).expect("P promote self");

    assert!(
        app.popup.is_none(),
        "promoting yourself opens no confirm popup"
    );
    assert!(
        app.status.contains("promote yourself"),
        "a clear status explains the block, got {}",
        app.status
    );
}

#[test]
fn popup_captures_keys_so_the_screen_behind_it_is_inert() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Chats;
    app.chats = vec![
        ChatRow {
            group_id: "g1".to_owned(),
            name: "one".to_owned(),
            archived: false,
            projection: ChatProjection::default(),
        },
        ChatRow {
            group_id: "g2".to_owned(),
            name: "two".to_owned(),
            archived: false,
            projection: ChatProjection::default(),
        },
    ];
    app.selected_chat = 0;
    app.popup = Some(Popup::help());

    app.handle_key(char_key('j')).expect("j under popup");

    assert_eq!(
        app.selected_chat, 0,
        "the chat list behind the popup does not move"
    );
    assert!(
        app.popup.is_none(),
        "the dismiss-on-any-key card closed instead"
    );
}

#[cfg(unix)]
#[test]
fn invites_picker_accept_closes_the_popup_once_the_last_invite_is_gone() {
    let account_id = "aa".repeat(32);
    let one = r#"{"ok":true,"result":{"invites":[{"group_id":"dddd","profile":{"name":"Invited Room"},"pending_confirmation":true}]}}"#;
    let empty = r#"{"ok":true,"result":{"invites":[]}}"#;
    let (_tempdir, client) = test_invites_seq_client(one, empty);
    let mut app = test_tui_app(client, &account_id);
    app.focus = Focus::Chats;

    app.handle_key(char_key('I')).expect("I opens invites");
    assert!(matches!(app.popup, Some(Popup::Picker { .. })));

    app.handle_key(char_key('a')).expect("accept invite");
    assert!(
        app.popup.is_none(),
        "the picker closes once the refreshed list is empty"
    );
    assert!(
        app.status.contains("accepted invite"),
        "status should confirm the accept, got {}",
        app.status
    );
}

#[cfg(unix)]
#[test]
fn invites_picker_decline_closes_the_popup_once_the_last_invite_is_gone() {
    let account_id = "aa".repeat(32);
    let one = r#"{"ok":true,"result":{"invites":[{"group_id":"dddd","profile":{"name":"Invited Room"},"pending_confirmation":true}]}}"#;
    let empty = r#"{"ok":true,"result":{"invites":[]}}"#;
    let (_tempdir, client) = test_invites_seq_client(one, empty);
    let mut app = test_tui_app(client, &account_id);
    app.focus = Focus::Chats;

    app.handle_key(char_key('I')).expect("I opens invites");
    app.handle_key(char_key('d')).expect("decline invite");

    assert!(app.popup.is_none());
    assert!(
        app.status.contains("declined invite"),
        "status should confirm the decline, got {}",
        app.status
    );
}

#[cfg(unix)]
#[test]
fn invites_picker_stays_open_after_accepting_one_of_several() {
    // Accepting one invite refolds the refreshed list back into the still-open
    // picker instead of closing after a single action.
    let account_id = "aa".repeat(32);
    let two = r#"{"ok":true,"result":{"invites":[{"group_id":"dddd","profile":{"name":"Room D"},"pending_confirmation":true},{"group_id":"eeee","profile":{"name":"Room E"},"pending_confirmation":true}]}}"#;
    let one = r#"{"ok":true,"result":{"invites":[{"group_id":"eeee","profile":{"name":"Room E"},"pending_confirmation":true}]}}"#;
    let (_tempdir, client) = test_invites_seq_client(two, one);
    let mut app = test_tui_app(client, &account_id);
    app.focus = Focus::Chats;

    app.handle_key(char_key('I')).expect("I opens invites");
    match &app.popup {
        Some(Popup::Picker { items, .. }) => assert_eq!(items.len(), 2, "two invites shown"),
        other => panic!("expected the invites picker, got {other:?}"),
    }

    app.handle_key(char_key('a'))
        .expect("accept the first invite");

    match &app.popup {
        Some(Popup::Picker {
            items, selected, ..
        }) => {
            assert_eq!(
                items.len(),
                1,
                "the picker stays open with the remaining invite"
            );
            assert!(*selected < items.len(), "the selection is clamped in range");
        }
        other => panic!("expected the picker to stay open, got {other:?}"),
    }
    assert!(
        app.status.contains("accepted invite"),
        "status confirms the accept, got {}",
        app.status
    );
}

#[cfg(unix)]
#[test]
fn accepting_an_invite_from_group_detail_returns_to_main() {
    // Accepting via `I` from the group-detail screen leaves that (now stale)
    // screen so the refreshed chat list and selection are visible.
    let account_id = "aa".repeat(32);
    let one = r#"{"ok":true,"result":{"invites":[{"group_id":"dddd","profile":{"name":"Invited Room"},"pending_confirmation":true}]}}"#;
    let empty = r#"{"ok":true,"result":{"invites":[]}}"#;
    let (_tempdir, client) = test_invites_seq_client(one, empty);
    let mut app = test_tui_app(client, &account_id);
    app.screen = Screen::GroupDetail;
    app.group_detail = Some(GroupDetailView {
        group_id: "g0".to_owned(),
        name: "Old Room".to_owned(),
        description: String::new(),
        members: Vec::new(),
        relays: Vec::new(),
        account_is_admin: false,
        admin_count: 1,
        selected: 0,
    });

    app.handle_key(char_key('I')).expect("I opens invites");
    app.handle_key(char_key('a')).expect("accept invite");

    assert_eq!(
        app.screen,
        Screen::Main,
        "accepting returns to the main view"
    );
    assert!(
        app.group_detail.is_none(),
        "the stale group-detail view is cleared"
    );
    assert!(app.popup.is_none(), "the sole invite emptied the picker");
}

#[test]
fn empty_invites_shows_an_info_card_not_a_picker() {
    let account_id = "aa".repeat(32);
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"invites":[]}}"#);
    let mut app = test_tui_app(client, &account_id);
    app.focus = Focus::Chats;

    app.handle_key(char_key('I')).expect("I with no invites");

    assert!(matches!(app.popup, Some(Popup::Card { .. })));
}

#[test]
fn popup_overlay_frame_shows_title_body_and_hint() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.popup = Some(Popup::Confirm {
        purpose: ConfirmPurpose::LeaveGroup {
            group_id: "g1".to_owned(),
        },
        title: "Leave Group".to_owned(),
        body: vec!["Leave ops-room?".to_owned()],
    });

    let rendered = rendered_buffer(&mut app);

    assert!(rendered.contains("Leave Group"), "popup title present");
    assert!(rendered.contains("Leave ops-room?"), "popup body present");
    assert!(rendered.contains("[y] yes"), "popup hint present");
}

#[test]
fn group_detail_frame_shows_members_with_badges_and_relays() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::GroupDetail;
    app.group_detail = Some(GroupDetailView {
        group_id: "g1".to_owned(),
        name: "Ops Room".to_owned(),
        description: "the ops".to_owned(),
        members: vec![
            GroupMemberRow {
                member_id: "aa".to_owned(),
                npub: "npubself".to_owned(),
                is_admin: true,
                is_self: true,
            },
            GroupMemberRow {
                member_id: "bb".to_owned(),
                npub: "npubbob".to_owned(),
                is_admin: false,
                is_self: false,
            },
        ],
        relays: vec!["wss://relay.example".to_owned()],
        account_is_admin: true,
        admin_count: 1,
        selected: 0,
    });

    let rendered = rendered_buffer(&mut app);

    assert!(rendered.contains("Ops Room"), "group name present");
    assert!(rendered.contains("npubself"), "member npub present");
    assert!(rendered.contains("[admin]"), "admin badge present");
    assert!(rendered.contains("(you)"), "self badge present");
    assert!(rendered.contains("Relays"), "relay section present");
    assert!(rendered.contains("relay.example"), "relay hint present");
}

#[test]
fn daemon_start_args_forward_first_run_relays() {
    assert_eq!(
        daemon_start_args(&[], &[]),
        vec!["daemon".to_owned(), "start".to_owned()]
    );
    assert_eq!(
        daemon_start_args(
            &["wss://a".to_owned(), "wss://b".to_owned()],
            &["wss://c".to_owned()],
        ),
        vec![
            "daemon".to_owned(),
            "start".to_owned(),
            "--discovery-relays".to_owned(),
            "wss://a,wss://b".to_owned(),
            "--default-account-relays".to_owned(),
            "wss://c".to_owned(),
        ]
    );
}

#[test]
fn account_setup_relay_fills_in_only_without_a_global_relay() {
    let mut client = test_unused_client();
    client.default_account_relays = vec!["wss://default".to_owned()];
    client.discovery_relays = vec!["wss://discovery".to_owned()];
    assert_eq!(
        client.account_setup_relay().as_deref(),
        Some("wss://default")
    );

    // Discovery relay is the fallback when no default account relay is set.
    client.default_account_relays.clear();
    assert_eq!(
        client.account_setup_relay().as_deref(),
        Some("wss://discovery")
    );

    // A global `--relay` already covers setup (`command` appends it), so none here.
    client.relay = Some("wss://global".to_owned());
    assert_eq!(client.account_setup_relay(), None);
}

#[test]
fn slash_command_parser_handles_diagnostics_toggle() {
    assert_eq!(
        parse_slash_command("/diagnostics"),
        Ok(SlashCommand::Diagnostics)
    );
    assert!(parse_slash_command("/diagnostics on").is_err());
}

#[test]
fn diagnostics_slash_command_toggles_the_panel() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    assert!(!app.show_diagnostics);
    app.run_slash_command(SlashCommand::Diagnostics)
        .expect("toggle on");
    assert!(app.show_diagnostics);
    app.run_slash_command(SlashCommand::Diagnostics)
        .expect("toggle off");
    assert!(!app.show_diagnostics);
}

#[test]
fn login_menu_keys_open_nsec_entry_and_quit() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Login(LoginMode::Menu);

    app.handle_key(char_key('l')).expect("l");
    assert_eq!(app.screen, Screen::Login(LoginMode::NsecEntry));

    app.screen = Screen::Login(LoginMode::Menu);
    app.handle_key(char_key('q')).expect("q");
    assert!(!app.running, "q quits from the login menu");
}

#[test]
fn login_create_failure_stays_on_the_login_screen() {
    // The fake exe does not exist, so create fails; the error must surface on the
    // status line without leaving the login screen (errors never tear down).
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Login(LoginMode::Menu);
    app.handle_key(char_key('c')).expect("c");
    assert_eq!(app.screen, Screen::Login(LoginMode::Menu));
    assert!(
        app.status.starts_with("error:"),
        "expected surfaced error, got {}",
        app.status
    );
}

#[test]
fn nsec_entry_accepts_masked_input_and_esc_returns_to_picker() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Login(LoginMode::NsecEntry);
    app.input.clear();
    app.input.set_masked(true);

    for character in "nsec1secret".chars() {
        app.handle_key(char_key(character)).expect("char");
    }
    assert_eq!(app.input.value(), "nsec1secret");
    // The field reuses the composer input's masked mode: it renders `*` per char,
    // never the secret.
    assert_eq!(app.input.display(), "***********");

    app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE))
        .expect("backspace");
    assert_eq!(app.input.value(), "nsec1secre");

    // Esc clears the secret and returns to the picker (one account exists).
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc");
    assert!(app.input.is_empty(), "esc clears the entered secret");
    assert_eq!(app.screen, Screen::Login(LoginMode::AccountSelect));
}

#[test]
fn nsec_entry_esc_returns_to_the_menu_without_accounts() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.accounts.clear();
    app.screen = Screen::Login(LoginMode::NsecEntry);
    app.input.set_value("partial");
    app.input.set_masked(true);
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc");
    assert!(app.input.is_empty());
    assert_eq!(app.screen, Screen::Login(LoginMode::Menu));
}

#[test]
fn nsec_entry_q_is_typed_not_a_quit() {
    // `q` quits only outside the composer with an empty input; during nsec entry
    // it is ordinary input and must append to the masked field, never quit.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Login(LoginMode::NsecEntry);
    app.input.clear();
    app.input.set_masked(true);

    app.handle_key(char_key('q')).expect("q");

    assert_eq!(
        app.input.value(),
        "q",
        "q is entered into the masked nsec field"
    );
    assert!(app.running, "q must not quit during nsec entry");
}

#[test]
fn nsec_entry_empty_submit_reports_and_stays() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Login(LoginMode::NsecEntry);
    app.input.set_value("   ");
    app.input.set_masked(true);
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("enter");
    assert_eq!(app.screen, Screen::Login(LoginMode::NsecEntry));
    assert!(app.input.is_empty(), "the field is cleared on submit");
    assert!(app.status.contains("empty"), "got {}", app.status);
}

#[test]
fn account_picker_esc_discards_navigation_and_keeps_the_active_account() {
    // Regression: picker navigation must not mutate the live selection. Before
    // the fix, `j` moved `selected_account` directly, so `Esc` (which only calls
    // `show_main` with no chat reload) left the status bar and
    // `require_selected_local_account` reporting the highlighted account while
    // the loaded chats/messages still belonged to the active one.
    let alice = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &alice);
    app.accounts.push(AccountRow {
        account_id: "bb".repeat(32),
        npub: "npub1bob".to_owned(),
        display_name: Some("Bob".to_owned()),
        local_signing: true,
    });
    // Alice (index 0) is the active account with her view loaded.
    app.selected_account = 0;
    app.messages_account_id = Some(alice.clone());
    app.screen = Screen::Main;
    app.focus = Focus::Chats;

    // `A` opens the picker from the active session; highlight a *different*
    // account, then cancel with `Esc`.
    app.handle_key(char_key('A')).expect("A");
    assert_eq!(app.screen, Screen::Login(LoginMode::AccountSelect));
    app.handle_key(char_key('j')).expect("j");
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc");

    // Esc discards the highlight: the active account and its loaded view are
    // untouched, so account-scoped commands still run against Alice.
    assert_eq!(app.screen, Screen::Main);
    assert_eq!(app.focus, Focus::Chats);
    assert_eq!(app.selected_account, 0);
    assert_eq!(app.require_selected_local_account().unwrap(), alice);
    assert_eq!(app.messages_account_id.as_deref(), Some(alice.as_str()));
}

#[test]
fn account_picker_enter_commits_the_highlighted_account() {
    let alice = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &alice);
    app.accounts.push(AccountRow {
        account_id: "bb".repeat(32),
        npub: "npub1bob".to_owned(),
        display_name: Some("Bob".to_owned()),
        local_signing: true,
    });
    app.selected_account = 0;
    app.screen = Screen::Main;
    app.focus = Focus::Chats;

    // `A` opens the picker, `j` highlights Bob, `Enter` commits the selection.
    app.handle_key(char_key('A')).expect("A");
    app.handle_key(char_key('j')).expect("j");
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("enter");

    assert_eq!(app.screen, Screen::Main);
    assert_eq!(
        app.selected_account, 1,
        "Enter commits the highlighted account"
    );
}

#[test]
fn account_picker_esc_is_inert_before_main_is_active() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.entered_main = false;
    app.screen = Screen::Login(LoginMode::AccountSelect);
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc");
    assert_eq!(
        app.screen,
        Screen::Login(LoginMode::AccountSelect),
        "no main view to return to yet"
    );
}

#[test]
fn account_picker_l_opens_nsec_entry() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Login(LoginMode::AccountSelect);
    app.handle_key(char_key('l')).expect("l");
    assert_eq!(app.screen, Screen::Login(LoginMode::NsecEntry));
}

#[test]
fn shift_a_reopens_the_account_picker_from_the_chat_list() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Main;
    app.focus = Focus::Chats;
    app.handle_key(char_key('A')).expect("A");
    assert_eq!(app.screen, Screen::Login(LoginMode::AccountSelect));
}

#[test]
fn enter_opens_the_chat_and_focuses_messages() {
    let group_id = "bb".repeat(32);
    let (_tempdir, client) =
        test_json_client(r#"{"ok":true,"result":{"messages":[],"has_more_before":false}}"#);
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.daemon = DaemonView::default();
    app.screen = Screen::Main;
    app.focus = Focus::Chats;
    app.chats = vec![ChatRow {
        group_id: group_id.clone(),
        name: "general".to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    }];
    app.selected_chat = 0;

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("enter");
    assert_eq!(
        app.focus,
        Focus::Messages,
        "opening a chat moves focus to the messages pane"
    );
    assert_eq!(app.messages_group_id.as_deref(), Some(group_id.as_str()));
}

#[test]
fn start_routes_to_login_menu_without_accounts() {
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"accounts":[]}}"#);
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.daemon = DaemonView::default();
    app.start().expect("start");
    assert_eq!(app.screen, Screen::Login(LoginMode::Menu));
    assert!(app.accounts.is_empty());
}

#[test]
fn start_enters_main_with_a_single_account() {
    let account_id = "aa".repeat(32);
    let response = format!(
        r#"{{"ok":true,"result":{{"accounts":[{{"account_id":"{account_id}","npub":"npub1alice","local_signing":true}}]}}}}"#
    );
    let (_tempdir, client) = test_json_client(&response);
    let mut app = test_tui_app(client, &account_id);
    app.daemon = DaemonView::default();
    app.start().expect("start");
    assert_eq!(app.screen, Screen::Main);
    assert_eq!(app.accounts.len(), 1);
}

#[test]
fn start_opens_the_account_picker_with_several_accounts() {
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    let response = format!(
        r#"{{"ok":true,"result":{{"accounts":[{{"account_id":"{a}","npub":"npub1a","local_signing":true}},{{"account_id":"{b}","npub":"npub1b","local_signing":true}}]}}}}"#
    );
    let (_tempdir, client) = test_json_client(&response);
    let mut app = test_tui_app(client, &a);
    app.daemon = DaemonView::default();
    app.entered_main = false;
    app.start().expect("start");
    assert_eq!(app.screen, Screen::Login(LoginMode::AccountSelect));
    assert_eq!(app.accounts.len(), 2);
    assert!(
        !app.entered_main,
        "the startup picker has no active main yet"
    );
}

#[test]
fn start_with_explicit_account_enters_main_with_that_accounts_chats() {
    // `wn tui --account <b>` with several accounts must honor the explicit
    // selection and open the main view directly, not the account picker.
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    let response = format!(
        r#"{{"ok":true,"result":{{"accounts":[{{"account_id":"{a}","npub":"npub1a","local_signing":true}},{{"account_id":"{b}","npub":"npub1b","local_signing":true}}],"chats":[]}}}}"#
    );
    let (_tempdir, client) = test_json_client(&response);
    let mut app = test_tui_app(client, &a);
    app.daemon = DaemonView::default();
    app.initial_account = Some(b.clone());
    app.entered_main = false;

    app.start().expect("start");

    assert_eq!(
        app.screen,
        Screen::Main,
        "an explicit --account skips the picker"
    );
    assert_eq!(
        app.selected_account, 1,
        "the explicitly selected account is active"
    );
    assert_eq!(
        app.messages_account_id.as_deref(),
        Some(b.as_str()),
        "the selected account's chats loaded"
    );
}

fn rendered_buffer(app: &mut TuiApp) -> String {
    let backend = ratatui::backend::TestBackend::new(100, 30);
    let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
    terminal.draw(|frame| app.render(frame)).expect("draw TUI");
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>()
}

#[test]
fn main_frame_shows_chats_and_messages_with_bars_and_toggled_diagnostics() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Chats;
    app.chats = vec![ChatRow {
        group_id: "bb".repeat(32),
        name: "ops-room".to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    }];
    let mut row = timeline_row("m0", 0);
    row.from_display_name = Some("Al".to_owned());
    row.display_text = "hello MESSAGEBODY".to_owned();
    app.timeline = vec![row];
    app.group_diagnostics = Some(GroupDiagnostics::unavailable(&"cc".repeat(32), "loading"));
    app.status = "loaded 1 message(s)".to_owned();

    let rendered = rendered_buffer(&mut app);
    assert!(rendered.contains("Chats"), "chat panel present");
    assert!(rendered.contains("ops-room"), "chat name visible");
    assert!(rendered.contains("MESSAGEBODY"), "message body visible");
    assert!(
        !rendered.contains("Accounts"),
        "the accounts pane is gone from the main view"
    );
    assert!(rendered.contains("g detail"), "chats hints line present");
    assert!(rendered.contains("daemon"), "status bar present");
    assert!(
        !rendered.contains("Diagnostics"),
        "the diagnostics panel is off by default"
    );

    app.show_diagnostics = true;
    let rendered = rendered_buffer(&mut app);
    assert!(
        rendered.contains("Diagnostics"),
        "the diagnostics panel appears after /diagnostics"
    );
    assert!(
        rendered.contains("ops-room"),
        "chats still visible with diagnostics on"
    );
    assert!(
        rendered.contains("MESSAGEBODY"),
        "messages still visible with diagnostics on"
    );
}

#[test]
fn login_menu_frame_shows_options_and_hints() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Login(LoginMode::Menu);
    app.status = "no identities yet".to_owned();

    let rendered = rendered_buffer(&mut app);
    assert!(rendered.contains("White Noise"));
    assert!(rendered.contains("Create a new identity"));
    assert!(rendered.contains("Log in with an nsec"));
    assert!(
        rendered.contains("c create identity"),
        "login hints line present"
    );
}

#[test]
fn nsec_entry_frame_masks_the_secret() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Login(LoginMode::NsecEntry);
    app.input.set_value("nsec1supersecret");
    app.input.set_masked(true);

    let rendered = rendered_buffer(&mut app);
    assert!(
        !rendered.contains("nsec1supersecret"),
        "the secret must never render"
    );
    assert!(
        rendered.contains("****"),
        "the field renders as mask characters"
    );
}

// --- Phase 3: composer input model + editing ---

#[test]
fn input_inserts_deletes_and_moves_across_multibyte_chars() {
    let mut input = Input::default();
    for character in "café".chars() {
        input.insert(character);
    }
    assert_eq!(input.value(), "café");
    assert_eq!(input.cursor(), 4);

    // Backspace removes the multi-byte 'é' as one char.
    input.backspace();
    assert_eq!(input.value(), "caf");
    assert_eq!(input.cursor(), 3);

    // Move left twice and insert mid-string.
    input.left();
    input.left();
    assert_eq!(input.cursor(), 1);
    input.insert('x');
    assert_eq!(input.value(), "cxaf");
    assert_eq!(input.cursor(), 2);

    // Forward-delete removes the char at the cursor ('a').
    input.delete();
    assert_eq!(input.value(), "cxf");
    assert_eq!(input.cursor(), 2);

    // Cursor movement clamps at both ends; deletes at the edges are no-ops.
    input.home();
    assert_eq!(input.cursor(), 0);
    input.left();
    assert_eq!(input.cursor(), 0, "left clamps at the start");
    input.backspace();
    assert_eq!(input.value(), "cxf", "backspace at the start is a no-op");
    input.end();
    assert_eq!(input.cursor(), 3);
    input.right();
    assert_eq!(input.cursor(), 3, "right clamps at the end");
    input.delete();
    assert_eq!(input.value(), "cxf", "delete at the end is a no-op");
}

#[test]
fn input_handles_astral_plane_characters_as_single_stops() {
    let mut input = Input::default();
    input.insert('a');
    input.insert('😀'); // 4-byte UTF-8: one char, one cursor stop
    input.insert('b');
    assert_eq!(input.value(), "a😀b");
    assert_eq!(input.cursor(), 3);

    input.left(); // between 😀 and b
    input.backspace(); // removes 😀 whole, not a broken byte
    assert_eq!(input.value(), "ab");
    assert_eq!(input.cursor(), 1);
}

#[test]
fn input_insert_str_pastes_multibyte_and_multiline_at_the_cursor() {
    let mut input = Input::default();
    input.set_value("ac");
    input.left(); // cursor between 'a' and 'c'
    input.insert_str("b\nx"); // multi-line paste
    assert_eq!(input.value(), "ab\nxc");
    assert_eq!(
        input.cursor(),
        4,
        "cursor advances by the pasted char count"
    );

    // Multi-byte paste advances by char count, not byte count.
    let mut other = Input::default();
    other.insert_str("héllo");
    assert_eq!(other.cursor(), 5);
}

#[test]
fn input_masked_display_hides_the_value_but_preserves_it() {
    let mut input = Input::default();
    input.set_value("nsec1secret");
    assert_eq!(input.display(), "nsec1secret", "plain display by default");

    input.set_masked(true);
    assert_eq!(
        input.display(),
        "***********",
        "masked renders one * per char"
    );
    assert_eq!(
        input.value(),
        "nsec1secret",
        "the value is preserved under the mask"
    );

    // Multi-byte chars each mask to a single *.
    let mut emoji = Input::default();
    emoji.set_value("aé😀");
    emoji.set_masked(true);
    assert_eq!(emoji.display(), "***");
}

#[test]
fn composer_height_grows_with_lines_and_clamps_between_three_and_eight() {
    let mut input = Input::default();
    // A single (empty) line is the 3-row minimum (1 content + 2 borders).
    assert_eq!(composer_height(&input, true, false, 40), 3);

    // More wrapped lines grow the composer.
    input.set_value("a\nb\nc");
    assert_eq!(composer_height(&input, true, false, 40), 5);

    // A long single line wraps by width and grows the composer beyond one row.
    input.set_value("x".repeat(100));
    assert!(
        composer_height(&input, false, false, 40) > 3,
        "a wrapped long line grows the composer past the minimum"
    );

    // Beyond the clamp, height caps at 8.
    input.set_value("a\nb\nc\nd\ne\nf\ng\nh\ni\nj");
    assert_eq!(composer_height(&input, true, false, 40), 8);
}

#[test]
fn composer_grows_with_content_and_renders_the_cursor_cell() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Main;
    app.focus = Focus::Composer;
    // No selected chat row and no timeline selection, so the only black-on-white
    // cell in the frame is the composer's cursor cell.
    app.chats.clear();
    app.timeline.clear();
    app.input.set_value("line one\nline two\nTAILMARKER");

    let backend = ratatui::backend::TestBackend::new(60, 24);
    let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
    terminal.draw(|frame| app.render(frame)).expect("draw TUI");
    let buffer = terminal.backend().buffer().clone();

    let rendered = buffer
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    // A fixed 3-row composer would clip the tail; growth shows every pasted line.
    assert!(
        rendered.contains("TAILMARKER"),
        "the grown composer shows every pasted line"
    );
    // The status bar still renders, so growth stole from the messages row, not the bars.
    assert!(
        rendered.contains("daemon"),
        "the status bar survives composer growth"
    );
    // The focused composer draws a black-on-white cursor cell.
    assert!(
        buffer
            .content()
            .iter()
            .any(|cell| cell.fg == Color::Black && cell.bg == Color::White),
        "the focused composer renders the cursor cell"
    );
}

/// Count the black-on-white cursor cells in a set of composer lines.
fn cursor_cell_contents(lines: &[Line<'static>]) -> Vec<String> {
    lines
        .iter()
        .flat_map(|line| &line.spans)
        .filter(|span| span.style.fg == Some(Color::Black) && span.style.bg == Some(Color::White))
        .map(|span| span.content.to_string())
        .collect()
}

#[test]
fn composer_cursor_cell_renders_at_display_end_when_redaction_shrinks_the_value() {
    // nsec redaction shrinks the display (`/login nsec1…` -> `/login <hidden
    // nsec>`), so the raw cursor at the end of the value lies beyond the display.
    // The cursor must still render exactly one cell, clamped to the display end,
    // instead of vanishing because no display segment holds the raw index.
    let mut input = Input::default();
    input.set_value("/login nsec1supersecretvalue");
    input.end();

    let lines = composer_lines(&input, true, false);
    assert_eq!(
        cursor_cell_contents(&lines),
        vec![" ".to_owned()],
        "exactly one cursor cell renders, a trailing space at the redacted display end"
    );
}

#[test]
fn composer_cursor_keeps_exact_placement_for_unredacted_input() {
    // Normal input (display == value) keeps the cursor on the exact character.
    let mut input = Input::default();
    input.set_value("hello");
    input.home();
    input.right();

    let lines = composer_lines(&input, true, false);
    assert_eq!(
        cursor_cell_contents(&lines),
        vec!["e".to_owned()],
        "the cursor cell sits on the exact char for unredacted input"
    );
}

#[test]
fn nsec_entry_reuses_masked_mode_and_clears_it_on_exit() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.accounts.clear();
    app.screen = Screen::Login(LoginMode::Menu);

    // `l` begins nsec entry with the shared input switched into masked mode.
    app.handle_key(char_key('l')).expect("l");
    assert_eq!(app.screen, Screen::Login(LoginMode::NsecEntry));
    for character in "nsec1secret".chars() {
        app.handle_key(char_key(character)).expect("char");
    }
    assert_eq!(
        app.input.display(),
        "***********",
        "the nsec field reuses the input's masked mode"
    );
    assert_eq!(app.input.value(), "nsec1secret");

    // Leaving nsec entry returns the shared input to plain composer mode.
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc");
    app.input.set_value("hello");
    assert_eq!(
        app.input.display(),
        "hello",
        "the composer input is no longer masked after nsec entry"
    );
}

// --- Phase 3: message interactions ---

#[test]
fn slash_command_parser_handles_message_interactions() {
    assert_eq!(
        parse_slash_command("/react"),
        Ok(SlashCommand::React {
            emoji: "+".to_owned()
        }),
        "a bare /react uses the default + emoji"
    );
    assert_eq!(
        parse_slash_command("/react 🔥"),
        Ok(SlashCommand::React {
            emoji: "🔥".to_owned()
        })
    );
    assert_eq!(parse_slash_command("/unreact"), Ok(SlashCommand::Unreact));
    assert_eq!(parse_slash_command("/delete"), Ok(SlashCommand::Delete));
    assert_eq!(
        parse_slash_command("/retry evt123"),
        Ok(SlashCommand::Retry {
            event_id: "evt123".to_owned()
        })
    );

    // Argument-shape errors surface to the status line instead of panicking.
    assert!(parse_slash_command("/react a b").is_err());
    assert!(parse_slash_command("/unreact x").is_err());
    assert!(parse_slash_command("/delete x").is_err());
    assert!(parse_slash_command("/retry").is_err());
    assert!(parse_slash_command("/retry a b").is_err());
}

#[test]
fn react_content_guard_rejects_typed_prose() {
    // The field defect: `/react ` was prefilled, the user typed a whole message,
    // and the prose published as a NIP-25 reaction. The guard now refuses content
    // that is not a single emoji cluster and teaches the escape hatch on the way
    // out. Prose spans more than one grapheme cluster, or is an all-ASCII token.
    let hint = "reactions are a single emoji (Enter sends the default +); Esc clears";
    for prose in [
        "/react hello world",                              // whitespace between words
        "/react \"hello world\"",                          // quoted -> one whitespaced arg
        "/react hello",                                    // a plain-ASCII word is not an emoji
        "/react 👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍👍", // a wall of emoji is not one reaction
    ] {
        assert_eq!(
            parse_slash_command(prose),
            Err(hint.to_owned()),
            "{prose:?} must be refused with the teaching hint"
        );
    }
}

#[test]
fn react_content_guard_accepts_the_default_and_real_emoji() {
    // The guard must never break the sanctioned reactions: the `+` default and a
    // single emoji, including multi-scalar ZWJ families, skin tones, and flags.
    for (input, emoji) in [
        ("/react", "+"),     // bare -> default +
        ("/react +", "+"),   // the explicit + sentinel
        ("/react 👍", "👍"), // single-scalar emoji
        ("/react 👍🏾", "👍🏾"), // emoji + skin-tone modifier
        ("/react 👨‍👩‍👧‍👦", "👨‍👩‍👧‍👦"), // ZWJ family: many scalars, one emoji
        ("/react 🏳️‍🌈", "🏳️‍🌈"), // rainbow flag: base + VS16 + ZWJ + rainbow
    ] {
        assert_eq!(
            parse_slash_command(input),
            Ok(SlashCommand::React {
                emoji: emoji.to_owned()
            }),
            "{input:?} must be accepted unchanged"
        );
    }
}

#[test]
fn react_content_guard_accepts_counterintuitive_single_graphemes() {
    // Regression pins for the accepted survivors that look like edge cases but are
    // each exactly one non-ASCII grapheme cluster: the NIP-25 `-` downvote, the
    // keycap and copyright emoji (base + variation/keycap scalars), and a lone CJK
    // character (the documented, acceptable ceiling — one cluster, non-ASCII).
    for (input, emoji) in [
        ("/react -", "-"),   // NIP-25 dislike sentinel
        ("/react 1️⃣", "1️⃣"), // keycap: '1' + VS16 + combining enclosing keycap
        ("/react ©️", "©️"), // copyright + VS16
        ("/react 你", "你"), // a single CJK character is one non-ASCII cluster
    ] {
        assert_eq!(
            parse_slash_command(input),
            Ok(SlashCommand::React {
                emoji: emoji.to_owned()
            }),
            "{input:?} is one non-ASCII grapheme cluster and must be accepted"
        );
    }
}

#[test]
fn react_content_guard_rejects_non_latin_and_accented_prose() {
    // The length/ASCII heuristic let short non-Latin and accented prose through:
    // `café`, `你好吗`, and `привет` all published. Real reactions are a single
    // grapheme cluster, so multi-character words are refused whatever their
    // script. `你好吗` is frozen here so this intent cannot silently regress.
    let hint = "reactions are a single emoji (Enter sends the default +); Esc clears";
    for prose in [
        "/react café",   // Latin-1 accented word (4 clusters)
        "/react 你好吗", // CJK prose (3 clusters)
        "/react привет", // Cyrillic word (6 clusters)
        "/react 👍👍",   // a run of emoji is not one reaction
    ] {
        assert_eq!(
            parse_slash_command(prose),
            Err(hint.to_owned()),
            "{prose:?} must be refused: a reaction is one grapheme cluster"
        );
    }
}

#[test]
fn react_content_guard_accepts_the_nip25_downvote_sentinel() {
    // NIP-25 defines `-` as the dislike sentinel, and `messages react` already
    // accepts it. A lone `-` is a single unambiguous token with no typed-prose
    // risk, so the TUI guard must let it through alongside the `+` default.
    assert_eq!(
        parse_slash_command("/react -"),
        Ok(SlashCommand::React {
            emoji: "-".to_owned()
        }),
        "the NIP-25 - downvote sentinel must be accepted"
    );
}

#[test]
fn messages_r_prefills_the_react_command_in_the_composer() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Messages;

    app.handle_key(char_key('r')).expect("r");

    assert_eq!(app.focus, Focus::Composer, "r focuses the composer");
    assert_eq!(
        app.input.value(),
        "/react ",
        "r prefills the react command so Enter sends the default +"
    );
}

#[test]
fn messages_d_prefills_the_delete_command_in_the_composer() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Messages;

    app.handle_key(char_key('d')).expect("d");

    assert_eq!(app.focus, Focus::Composer, "d focuses the composer");
    assert_eq!(
        app.input.value(),
        "/delete",
        "d prefills /delete so Enter is the visible confirmation"
    );
}

#[test]
fn messages_r_preserves_a_composer_draft_and_warns_instead_of_clobbering_it() {
    // A draft typed in the composer survives Tab-cycling to Messages. Pressing
    // `r` there must not silently overwrite it with `/react `; it leaves the
    // draft intact and explains the suppression on the status line.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Messages;
    app.input.set_value("half-written draft");

    app.handle_key(char_key('r')).expect("r");

    assert_eq!(
        app.input.value(),
        "half-written draft",
        "r must not clobber an existing composer draft"
    );
    assert!(
        app.status.contains("draft"),
        "the status line explains why r/d was suppressed, got {}",
        app.status
    );
}

#[test]
fn messages_d_preserves_a_composer_draft_and_warns_instead_of_clobbering_it() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Messages;
    app.input.set_value("half-written draft");

    app.handle_key(char_key('d')).expect("d");

    assert_eq!(
        app.input.value(),
        "half-written draft",
        "d must not clobber an existing composer draft"
    );
    assert!(
        app.status.contains("draft"),
        "the status line explains why r/d was suppressed, got {}",
        app.status
    );
}

#[test]
fn armed_interaction_hint_names_the_action_and_target() {
    // While the composer holds an interaction command, the hint tells the user
    // what Enter will do and to which message — the durable signal the field
    // report was missing. Recomputed from the composer text and selected row.
    let mut row = timeline_row("m0", 0);
    row.from_display_name = Some("Alice".to_owned());
    row.display_text = "hello world".to_owned();

    assert_eq!(
        armed_interaction_hint("/react ", Some(&row)).as_deref(),
        Some("reacting to Alice: \"hello world\" — Enter sends the reaction, Esc clears")
    );
    assert_eq!(
        armed_interaction_hint("/reply ", Some(&row)).as_deref(),
        Some("replying to Alice: \"hello world\" — Enter sends the reply, Esc clears")
    );
    assert_eq!(
        armed_interaction_hint("/delete", Some(&row)).as_deref(),
        Some("deleting Alice: \"hello world\" — Enter deletes, Esc clears")
    );
    // An edited prefill (the trapped scenario: `/react ` then typed prose) stays
    // armed, so the escape-hatch hint persists.
    assert_eq!(
        armed_interaction_hint("/react this is not an emoji", Some(&row)).as_deref(),
        Some("reacting to Alice: \"hello world\" — Enter sends the reaction, Esc clears")
    );
}

#[test]
fn armed_interaction_hint_is_none_for_drafts_and_unrelated_commands() {
    let row = timeline_row("m0", 0);
    // A hand-typed chat draft is not an armed interaction.
    assert_eq!(armed_interaction_hint("hello everyone", Some(&row)), None);
    // An unrelated slash command that merely shares a prefix must not match.
    assert_eq!(armed_interaction_hint("/refresh", Some(&row)), None);
    assert_eq!(armed_interaction_hint("/chat new ops", Some(&row)), None);
    // A word that only starts like a command (no boundary) must not match.
    assert_eq!(armed_interaction_hint("/reactor", Some(&row)), None);
}

#[test]
fn render_hints_shows_the_persistent_armed_interaction_hint() {
    // The armed hint replaces the static keymap in the hints bar while the
    // composer holds an interaction command, so the pending action stays visible
    // even if a later status event fires. Clearing the composer restores the
    // normal keymap.
    let account_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut app = test_tui_app(test_unused_client(), account_id);
    app.focus = Focus::Messages;
    let mut row = timeline_row("m0", 0);
    row.from_display_name = Some("Alice".to_owned());
    row.display_text = "hello world".to_owned();
    app.timeline = vec![row];
    app.input.set_value("/react ");

    let armed = rendered_buffer(&mut app);
    assert!(
        armed.contains("reacting to Alice") && armed.contains("Esc clears"),
        "armed hint must name the action and target, got: {armed:?}"
    );
    assert!(
        !armed.contains("r react  u unreact"),
        "the static messages keymap must be replaced while armed, got: {armed:?}"
    );

    app.input.clear();
    let idle = rendered_buffer(&mut app);
    assert!(
        idle.contains("r react  u unreact"),
        "the static keymap returns once the composer is cleared, got: {idle:?}"
    );
}

#[test]
fn armed_interaction_hint_handles_an_empty_timeline() {
    // Armed with nothing selected (empty timeline): the hint still shows so the
    // escape hatch is visible; the submit path reports "no message selected".
    assert_eq!(
        armed_interaction_hint("/react ", None).as_deref(),
        Some("reacting to the selected message — Enter sends the reaction, Esc clears")
    );
}

#[test]
fn esc_clears_an_armed_interaction_prefill() {
    // Esc is the escape hatch the armed hint advertises. It clears an interaction
    // prefill — pristine or edited — so a user who armed a reaction by accident
    // (the field defect) can back out instead of publishing prose as a reaction.
    for armed in [
        "/react ",
        "/react this is not an emoji",
        "/reply hi",
        "/delete",
    ] {
        let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
        app.focus = Focus::Composer;
        app.input.set_value(armed);

        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("esc");

        assert!(
            app.input.is_empty(),
            "Esc must clear the armed interaction {armed:?}, left {:?}",
            app.input.value()
        );
    }
}

#[test]
fn esc_preserves_a_hand_typed_draft() {
    // Esc must not silently destroy text the user wrote by hand: a chat draft (or
    // any non-interaction slash command) survives Esc, matching the draft
    // protection that keeps r/d/R from clobbering it.
    for draft in ["hello everyone", "/chat new ops"] {
        let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
        app.focus = Focus::Composer;
        app.input.set_value(draft);

        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("esc");

        assert_eq!(
            app.input.value(),
            draft,
            "Esc must preserve a hand-typed draft, not destroy it"
        );
    }
}

#[test]
fn ctrl_u_clears_the_composer_regardless_of_state() {
    // Ctrl-U is the readline kill-line: it empties the composer whatever it holds
    // — a hand-typed draft (which Esc deliberately preserves) or an armed
    // interaction prefill — so the composer hint can honestly name a key that
    // always clears the field.
    for content in ["a half-typed draft", "/chat new ops", "/react ", "/delete"] {
        let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
        app.focus = Focus::Composer;
        app.input.set_value(content);

        app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
            .expect("ctrl-u");

        assert!(
            app.input.is_empty(),
            "Ctrl-U must clear the composer holding {content:?}, left {:?}",
            app.input.value()
        );
    }
}

#[test]
fn armed_hint_and_send_target_resolve_to_the_same_selected_row() {
    // The armed hint names a row and Enter sends to a row: both must be the same
    // row. Arm /react, move the selection off the default newest row, and pin that
    // the hint names the NEW row's sender while the send target
    // (`selected_timeline_message_id`, the resolution the Enter path uses) points
    // at that same row — so the hint can never advertise a different message than
    // the one that gets reacted to.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    let mut oldest = timeline_row("m0", 0);
    oldest.from_display_name = Some("Oldest".to_owned());
    let mut middle = timeline_row("m1", 1);
    middle.from_display_name = Some("Middle".to_owned());
    let mut newest = timeline_row("m2", 2);
    newest.from_display_name = Some("Newest".to_owned());
    app.timeline = vec![oldest, middle, newest];

    // Move the selection off the default newest row, then arm /react via `r`.
    app.focus = Focus::Messages;
    app.handle_key(char_key('k')).expect("select up");
    app.handle_key(char_key('r')).expect("arm react");

    let target = app
        .selected_timeline_message_id()
        .expect("a row is selected");
    assert_eq!(target, "m1", "the send target follows the moved selection");

    let selected = app.selected_timeline_row().expect("a row is selected");
    assert_eq!(
        selected.message_id, target,
        "the hint row and the send target are the same resolution"
    );

    let hint = armed_interaction_hint(app.input.value(), Some(selected))
        .expect("an armed /react shows a hint");
    assert!(
        hint.contains("reacting to Middle") && !hint.contains("Newest"),
        "the armed hint names the selected row's sender, got: {hint:?}"
    );
}

#[test]
fn slash_command_parser_handles_reply() {
    assert_eq!(
        parse_slash_command("/reply hello there"),
        Ok(SlashCommand::Reply {
            text: "hello there".to_owned()
        }),
        "/reply joins the trailing words into the reply text"
    );
    assert_eq!(
        parse_slash_command("/reply \"quoted body\""),
        Ok(SlashCommand::Reply {
            text: "quoted body".to_owned()
        })
    );
    assert!(
        parse_slash_command("/reply").is_err(),
        "a bare /reply has no text to send"
    );
}

#[test]
fn reply_send_args_places_reply_to_flag_before_text() {
    // The CLI send guard treats a `--reply-to` after the text as literal message
    // text and rejects it, so the flag must precede the trailing text.
    let args = reply_send_args("group-hex", "parent-id", "the reply body");
    assert_eq!(
        args,
        vec![
            "messages".to_owned(),
            "send".to_owned(),
            "--group".to_owned(),
            "group-hex".to_owned(),
            "--reply-to".to_owned(),
            "parent-id".to_owned(),
            "the reply body".to_owned(),
        ]
    );
    let flag = args
        .iter()
        .position(|arg| arg == "--reply-to")
        .expect("flag");
    let text = args
        .iter()
        .position(|arg| arg == "the reply body")
        .expect("text");
    assert!(flag < text, "--reply-to must come before the trailing text");
}

#[test]
fn messages_r_capital_prefills_reply_and_names_the_target_on_the_status_line() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Messages;
    let mut row = timeline_row("m0", 0);
    row.from_display_name = Some("Alice".to_owned());
    row.display_text = "hello world".to_owned();
    app.timeline = vec![row];

    app.handle_key(char_key('R')).expect("R");

    assert_eq!(app.focus, Focus::Composer, "R focuses the composer");
    assert_eq!(
        app.input.value(),
        "/reply ",
        "R prefills the reply command so typing then Enter sends"
    );
    assert_eq!(
        app.status, "replying to Alice: \"hello world\"",
        "R names the reply target on the status line"
    );
}

#[test]
fn messages_r_capital_preserves_a_composer_draft_and_warns_instead_of_clobbering_it() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Messages;
    app.input.set_value("half-written draft");
    app.timeline = vec![timeline_row("m0", 0)];

    app.handle_key(char_key('R')).expect("R");

    assert_eq!(
        app.input.value(),
        "half-written draft",
        "R must not clobber an existing composer draft"
    );
    assert!(
        app.status.contains("draft"),
        "the status line explains why R was suppressed, got {}",
        app.status
    );
}

#[test]
fn reply_without_a_selected_message_errors_at_submit() {
    // The target resolves at submit; an empty pane surfaces the same clear error
    // the other interactions use, before any subprocess runs.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.messages_account_id = Some("aa".repeat(32));
    app.messages_group_id = Some("bb".repeat(32));

    let error = app
        .send_reply("no target".to_owned())
        .expect_err("a reply with nothing selected is rejected");
    assert!(
        matches!(error, TuiError::Cli(message) if message.contains("no message selected")),
        "expected a no-message-selected error"
    );
}

#[test]
fn reply_target_status_clips_long_text_and_strips_terminal_controls() {
    let mut row = timeline_row("m0", 0);
    row.from_display_name = Some("Bob".to_owned());
    row.display_text = "0123456789012345678901234567890123".to_owned();
    assert_eq!(
        reply_target_status(&row),
        "replying to Bob: \"012345678901234567890123456789...\"",
        "the preview clips at 30 chars with an ellipsis"
    );

    row.from_display_name = Some("a\u{1b}\u{7}\u{202e}b".to_owned());
    row.display_text = "safe".to_owned();
    assert_eq!(
        reply_target_status(&row),
        "replying to ab: \"safe\"",
        "terminal control sequences are stripped from the target preview"
    );
}

#[test]
fn message_accelerator_under_open_help_dismisses_the_card_and_does_not_act() {
    // The help card is a modal: a message-accelerator key (`u`) under it is
    // captured by the popup and dismisses the card instead of unreacting.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Messages;
    app.popup = Some(Popup::help());
    app.messages_account_id = Some("aa".repeat(32));
    app.messages_group_id = Some("bb".repeat(32));

    app.handle_key(char_key('u')).expect("u");

    assert!(app.popup.is_none(), "u under the help card dismisses it");
}

#[test]
fn messages_u_unreacts_immediately_without_prefilling_or_reloading() {
    let account_id = "aa".repeat(32);
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"published":true}}"#);
    let mut app = test_tui_app(client, &account_id);
    app.focus = Focus::Messages;
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some("bb".repeat(32));
    app.timeline = vec![timeline_row("m0", 0)];

    app.handle_key(char_key('u')).expect("u");

    assert_eq!(
        app.focus,
        Focus::Messages,
        "u acts immediately; it never focuses the composer"
    );
    assert!(app.input.is_empty(), "u does not prefill the composer");
    assert_eq!(app.status, "removed reaction");
    assert_eq!(
        app.timeline.len(),
        1,
        "no list reload on interaction success"
    );
}

#[test]
fn messages_u_without_a_selected_message_surfaces_a_status_error() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Messages;
    // A resolvable group but an empty pane: nothing to unreact.
    app.messages_account_id = Some("aa".repeat(32));
    app.messages_group_id = Some("bb".repeat(32));

    app.handle_key(char_key('u')).expect("u");

    assert_eq!(app.focus, Focus::Messages, "u never prefills the composer");
    assert!(app.input.is_empty());
    assert!(
        app.status.contains("no message selected"),
        "got {}",
        app.status
    );
}

#[test]
fn delete_rejects_foreign_messages_before_shelling_out() {
    // The row's `direction` makes the ownership check trivial, so a clear
    // status-line error fires early instead of a CLI rejection. The client is
    // unused: the early return means no subprocess runs.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.messages_account_id = Some("aa".repeat(32));
    app.messages_group_id = Some("bb".repeat(32));
    let mut foreign = timeline_row("m0", 0);
    foreign.direction = "received".to_owned();
    app.timeline = vec![foreign];

    let error = app
        .delete_selected_message()
        .expect_err("foreign delete is rejected");
    assert!(
        matches!(error, TuiError::Cli(message) if message.contains("your own")),
        "expected an own-messages-only error"
    );
}

#[test]
fn delete_allows_own_message_arriving_via_the_received_path() {
    // Ownership must match render ownership: the renderer colors a row as yours
    // when `timeline_row_is_self` holds, which also matches `from` against the
    // loaded account id/npub/label. Your own message can arrive on the received
    // path (a second device, a re-sync echo, projection upserts overwriting
    // `direction`); it renders as yours and must therefore delete as yours,
    // even though `direction` is not "sent".
    let account_id = "aa".repeat(32);
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"published":true}}"#);
    let mut app = test_tui_app(client, &account_id);
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some("bb".repeat(32));
    let mut own_via_received = timeline_row("m0", 0);
    own_via_received.direction = "received".to_owned();
    own_via_received.from = account_id.clone();
    app.timeline = vec![own_via_received];

    app.delete_selected_message()
        .expect("an own message on the received path renders as yours and is deletable");
    assert_eq!(app.status, "deleted message");
}

#[test]
fn own_message_interactions_do_not_reload_the_timeline() {
    let account_id = "aa".repeat(32);
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"published":true}}"#);
    let mut app = test_tui_app(client, &account_id);
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some("bb".repeat(32));
    let mut own = timeline_row("m0", 0);
    own.direction = "sent".to_owned();
    app.timeline = vec![own];

    app.react_to_selected_message("+".to_owned())
        .expect("react");
    assert_eq!(app.status, "reacted +");
    assert_eq!(app.timeline.len(), 1, "react does not reload the list");

    app.delete_selected_message().expect("delete own");
    assert_eq!(app.status, "deleted message");
    assert_eq!(
        app.timeline.len(),
        1,
        "delete does not reload the list; the projection tombstones the row"
    );
}

#[test]
fn reaction_projection_updates_the_selected_row_without_reloading() {
    let mut rows = vec![timeline_row("m0", 0), timeline_row("m1", 1)];
    let mut scroll = TimelineScroll {
        selection: Some(1),
        ..TimelineScroll::default()
    };
    let before_len = rows.len();

    // A ReactionAdded projection change arrives as an upsert of the same row with
    // the reaction already folded in (Phase 1 machinery). It updates in place.
    let mut reacted = timeline_row("m1", 1);
    reacted.reactions = vec![TimelineReaction {
        emoji: "+".to_owned(),
        count: 1,
    }];
    apply_timeline_event(
        &mut rows,
        &mut scroll,
        Some("g"),
        TimelineEvent::ProjectionUpdated {
            group_id: "g".to_owned(),
            changes: vec![TimelineChange::Upsert(Box::new(reacted))],
        },
    );

    assert_eq!(
        rows.len(),
        before_len,
        "no row appended: the fold is a reload-free upsert"
    );
    assert_eq!(
        scroll.resolved_selection(rows.len()),
        Some(1),
        "the selection stays on the same row"
    );
    let selected = &rows[scroll.resolved_selection(rows.len()).unwrap()];
    assert_eq!(selected.message_id, "m1");
    assert_eq!(
        selected.reactions,
        vec![TimelineReaction {
            emoji: "+".to_owned(),
            count: 1,
        }],
        "the selected row shows the folded reaction without a list reload"
    );
}

// --- Phase 3: bracketed-paste routing ---

#[test]
fn handle_paste_inserts_at_the_composer_cursor_and_normalizes_newlines() {
    // A paste lands as literal characters at the cursor, with CRLF and lone CR
    // normalized to `\n` so multi-line content keeps its line breaks without
    // firing a send per line.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Main;
    app.focus = Focus::Composer;
    app.input.set_value("ac");
    app.input.left(); // cursor between 'a' and 'c'

    app.handle_paste("X\r\nY\rZ".to_owned());

    assert_eq!(
        app.input.value(),
        "aX\nY\nZc",
        "paste inserts at the cursor with CRLF and lone CR normalized to \\n"
    );
    assert_eq!(
        app.input.cursor(),
        6,
        "the cursor advances past the pasted text"
    );
}

#[test]
fn handle_paste_into_masked_nsec_entry_appends_and_stays_masked() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Login(LoginMode::NsecEntry);
    app.input.set_masked(true);

    app.handle_paste("nsec1pasted".to_owned());

    assert_eq!(
        app.input.value(),
        "nsec1pasted",
        "paste fills the nsec field"
    );
    assert_eq!(
        app.input.display(),
        "***********",
        "the pasted nsec stays masked and never renders"
    );
}

#[test]
fn handle_paste_while_streaming_appends_to_pending_text_and_updates_status() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.streaming = Some(StreamComposer {
        stream_id: "s1".to_owned(),
        group_id: "bb".repeat(32),
        pending_text: "typed".to_owned(),
        last_flush: Instant::now(),
    });

    app.handle_paste("PASTED".to_owned());

    let streaming = app.streaming.as_ref().expect("still streaming after paste");
    assert_eq!(
        streaming.pending_text, "typedPASTED",
        "paste appends to the stream's pending text"
    );
    assert_eq!(
        app.status, "queued 11 byte(s) on s1",
        "paste updates the status line the same way typed chars do"
    );
    assert_eq!(
        app.input.value(),
        "PASTED",
        "paste is also mirrored into the composer buffer"
    );
}

#[test]
fn handle_paste_is_ignored_on_the_login_menu_and_when_messages_focused() {
    // The login menu accepts single-key choices, not text; paste is a no-op.
    let mut menu = test_tui_app(test_unused_client(), &"aa".repeat(32));
    menu.screen = Screen::Login(LoginMode::Menu);
    menu.handle_paste("ignored".to_owned());
    assert!(menu.input.is_empty(), "paste is ignored on the login menu");

    // The messages pane is not a text input; paste there is a no-op too.
    let mut messages = test_tui_app(test_unused_client(), &"aa".repeat(32));
    messages.screen = Screen::Main;
    messages.focus = Focus::Messages;
    messages.handle_paste("ignored".to_owned());
    assert!(
        messages.input.is_empty(),
        "paste is ignored when the messages pane is focused"
    );
}

#[test]
fn handle_paste_into_a_text_popup_lands_in_its_input_not_the_composer() {
    // Pasting an npub into the Add Member text popup fills the popup's input,
    // never the composer hidden behind it.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Main;
    app.focus = Focus::Composer;
    app.popup = Some(Popup::Text {
        purpose: TextPurpose::AddMemberByPubkey {
            group_id: "g1".to_owned(),
        },
        title: "Add Member".to_owned(),
        body: Vec::new(),
        input: Input::default(),
    });

    app.handle_paste("npub1pasted".to_owned());

    match &app.popup {
        Some(Popup::Text { input, .. }) => {
            assert_eq!(input.value(), "npub1pasted", "paste fills the popup input");
        }
        other => panic!("expected the text popup to stay open, got {other:?}"),
    }
    assert!(
        app.input.is_empty(),
        "the composer behind the popup stays untouched"
    );
}

#[test]
fn handle_paste_under_a_card_leaves_the_composer_untouched() {
    // A dismiss-on-any-key card has no text field; a paste under it is swallowed
    // and must not leak into the composer hidden behind it.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Main;
    app.focus = Focus::Composer;
    app.input.set_value("draft");
    app.popup = Some(Popup::help());

    app.handle_paste("leaked".to_owned());

    assert_eq!(
        app.input.value(),
        "draft",
        "paste does not leak into the composer behind the card"
    );
    assert!(
        matches!(app.popup, Some(Popup::Card { .. })),
        "the card stays open"
    );
}

#[test]
fn composer_min_and_max_height_coexist_with_the_diagnostics_panel() {
    // With the diagnostics panel toggled on, the composer still clamps to its
    // 3..=8 range and the diagnostics panel plus the hints and status bars all
    // keep rendering at both extremes (growth steals from the messages row only).
    let render_with = |value: &str, expected_composer_rows: u16| {
        let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
        app.screen = Screen::Main;
        app.focus = Focus::Composer;
        app.show_diagnostics = true;
        app.group_diagnostics = None; // renders "MLS no group selected"
        app.chats.clear();
        app.timeline.clear();
        app.input.set_value(value);

        assert_eq!(
            composer_height(&app.input, true, false, 60 - 2),
            expected_composer_rows,
            "composer clamps to {expected_composer_rows} rows"
        );

        let backend = ratatui::backend::TestBackend::new(60, 30);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
        terminal.draw(|frame| app.render(frame)).expect("draw TUI");
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(
            rendered.contains("Diagnostics"),
            "the diagnostics panel renders at composer height {expected_composer_rows}"
        );
        assert!(
            rendered.contains("MLS no group selected"),
            "the diagnostics content renders alongside the composer"
        );
        assert!(
            rendered.contains("daemon"),
            "the status bar survives at composer height {expected_composer_rows}"
        );
    };

    render_with("", 3);
    render_with("a\nb\nc\nd\ne\nf\ng\nh\ni\nj", 8);
}

// ---- Phase 5b: user search, profile, and relay health screens ----

/// A fake `wn` that appends each invocation's argv (space-joined, one line per
/// call) to a sidecar file, so a test can assert a multi-call flow's commands.
#[cfg(unix)]
fn test_appending_arg_executable(dir: &std::path::Path, response: &str) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let exe = dir.join("wn-json");
    let args_file = dir.join("recorded-args");
    std::fs::write(
        &exe,
        format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\ncat <<'JSON'\n{response}\nJSON\n",
            args_file.display()
        ),
    )
    .expect("write fake wn");
    let mut permissions = std::fs::metadata(&exe)
        .expect("fake wn metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&exe, permissions).expect("chmod fake wn");
    (exe, args_file)
}

#[test]
fn user_search_opens_from_s_and_esc_returns_to_main() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Chats;
    // `s` opens the search screen without shelling out (there is no query to run).
    app.handle_key(char_key('s')).expect("s opens user search");
    assert_eq!(app.screen, Screen::UserSearch);
    assert!(app.user_search.is_some());
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc leaves user search");
    assert_eq!(app.screen, Screen::Main);
    assert!(app.user_search.is_none(), "search state dropped on exit");
}

#[test]
fn profile_opens_from_p_and_esc_returns_to_main() {
    let (_dir, client) = test_json_client(
        r#"{"ok":true,"result":{"npub":"npub1self","profile":{"name":"Al","display_name":"Alice"},"follows":[{"npub":"npub1bob"}]}}"#,
    );
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.focus = Focus::Chats;
    app.handle_key(char_key('p')).expect("p opens profile");
    assert_eq!(app.screen, Screen::Profile);
    let view = app.profile_view.as_ref().expect("profile loaded");
    assert_eq!(view.field_value(ProfileField::Name), Some("Al"));
    assert_eq!(view.field_value(ProfileField::DisplayName), Some("Alice"));
    assert_eq!(view.follows, vec!["npub1bob".to_owned()]);
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc leaves profile");
    assert_eq!(app.screen, Screen::Main);
    assert!(app.profile_view.is_none());
}

#[test]
fn relay_health_opens_from_h_and_esc_returns_to_main() {
    let (_dir, client) =
        test_json_client(r#"{"ok":true,"result":{"health":{"total_relays":2,"connected":2}}}"#);
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.focus = Focus::Chats;
    app.handle_key(char_key('h')).expect("h opens relay health");
    assert_eq!(app.screen, Screen::RelayHealth);
    let view = app.relay_health.as_ref().expect("relay health loaded");
    assert_eq!(view.data.total_relays, 2);
    assert_eq!(view.data.connected, 2);
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc leaves relay health");
    assert_eq!(app.screen, Screen::Main);
    assert!(app.relay_health.is_none());
}

#[test]
fn parse_user_search_results_reads_profile_and_match_attribution() {
    let result = serde_json::json!({
        "users": [
            {"account_id_hex": "aa", "npub": "npubaa", "radius": 1, "matched_field": "name", "match_quality": "prefix", "profile": {"display_name": "Alice"}},
            {"account_id_hex": "bb", "npub": "npubbb", "radius": 2, "matched_field": "npub", "match_quality": "contains"},
        ]
    });
    let rows = parse_user_search_results(&result);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].display_label(), "Alice");
    assert_eq!(rows[0].matched_field, "name");
    assert_eq!(rows[0].match_quality, "prefix");
    assert_eq!(rows[0].radius, 1);
    // No display name/name falls back to a shortened npub.
    assert_eq!(rows[1].display_label(), shorten("npubbb", 16));
}

#[test]
fn user_search_runs_query_and_navigates_results() {
    let (_dir, client) = test_json_client(
        r#"{"ok":true,"result":{"users":[{"account_id_hex":"aa","npub":"npubaa","radius":0,"matched_field":"name","match_quality":"exact","profile":{"display_name":"Alice"}},{"account_id_hex":"bb","npub":"npubbb","radius":1,"matched_field":"npub","match_quality":"prefix"}]}}"#,
    );
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.open_user_search(None);
    // Query focus: typed characters edit the query (j/k are literal text here).
    for character in "ali".chars() {
        app.handle_key(char_key(character)).expect("type query");
    }
    assert_eq!(app.user_search.as_ref().unwrap().query.value(), "ali");
    // Enter runs the one-shot search and moves focus into the results.
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("run search");
    {
        let view = app.user_search.as_ref().expect("search view");
        assert_eq!(view.results.len(), 2);
        assert_eq!(view.focus, UserSearchFocus::Results);
        assert_eq!(view.selected, 0);
    }
    // Results focus: j/k navigate; k at the top returns to the query.
    app.handle_key(char_key('j')).expect("j down");
    assert_eq!(app.user_search.as_ref().unwrap().selected, 1);
    app.handle_key(char_key('k')).expect("k up");
    assert_eq!(app.user_search.as_ref().unwrap().selected, 0);
    app.handle_key(char_key('k')).expect("k to query");
    assert_eq!(
        app.user_search.as_ref().unwrap().focus,
        UserSearchFocus::Query
    );
}

#[test]
fn slash_users_query_runs_the_search_immediately() {
    let (_dir, client) = test_json_client(
        r#"{"ok":true,"result":{"users":[{"account_id_hex":"aa","npub":"npubaa","radius":0,"matched_field":"name","match_quality":"exact"}]}}"#,
    );
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.open_user_search(Some("alice".to_owned()));
    let view = app.user_search.as_ref().expect("search view");
    assert_eq!(view.query.value(), "alice");
    assert_eq!(view.results.len(), 1);
    assert_eq!(view.focus, UserSearchFocus::Results);
}

#[test]
fn user_search_add_is_guarded_when_there_are_no_chats() {
    let mut app = user_search_app_with_selected_result(test_unused_client());
    assert!(app.chats.is_empty());

    // No chats at all: the add action is guarded to a status notice, no popup.
    app.handle_key(char_key('a')).expect("a guarded");
    assert!(app.popup.is_none(), "no popup without any chat");
    assert!(
        app.status.contains("no chats"),
        "status explains the guard: {}",
        app.status
    );
}

#[test]
fn user_search_add_preselects_the_open_chat_in_the_picker() {
    let mut app = user_search_app_with_selected_result(test_unused_client());
    app.chats = vec![
        ChatRow {
            group_id: "g1".to_owned(),
            name: "Room One".to_owned(),
            ..ChatRow::default()
        },
        ChatRow {
            group_id: "g2".to_owned(),
            name: "Room Two".to_owned(),
            ..ChatRow::default()
        },
    ];
    app.messages_group_id = Some("g2".to_owned());

    app.handle_key(char_key('a')).expect("a opens the picker");

    let Some(Popup::Picker { selected, .. }) = &app.popup else {
        panic!("a must open the group picker, got {:?}", app.popup);
    };
    assert_eq!(*selected, 1, "the open chat is preselected");
}

#[test]
fn parse_profile_view_reads_fields_and_follows() {
    let show = serde_json::json!({
        "npub": "npub1self",
        "profile": {"name": "al", "display_name": "Alice", "about": "hi", "picture": "https://x/y.png"}
    });
    let follows = serde_json::json!({"follows": [{"npub": "npub1bob"}, {"npub": "npub1carol"}]});
    let view = parse_profile_view(&show, &follows);
    assert_eq!(view.npub, "npub1self");
    assert_eq!(view.field_value(ProfileField::DisplayName), Some("Alice"));
    // Picture URLs are stored (and rendered) as literal text, never fetched.
    assert_eq!(
        view.field_value(ProfileField::Picture),
        Some("https://x/y.png")
    );
    assert_eq!(view.field_value(ProfileField::Nip05), None);
    assert_eq!(
        view.follows,
        vec!["npub1bob".to_owned(), "npub1carol".to_owned()]
    );
    // A single cursor spans the six fields then the follows.
    assert_eq!(view.row_count(), 6 + 2);
    assert_eq!(
        view.selected_target(),
        Some(ProfileTarget::Field(ProfileField::Name))
    );
}

#[cfg(unix)]
#[test]
fn profile_edit_publishes_only_the_selected_field() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) =
        test_appending_arg_executable(tempdir.path(), r#"{"ok":true,"result":{}}"#);
    let client = WnClient {
        exe,
        home: None,
        socket: None,
        relay: None,
        discovery_relays: Vec::new(),
        default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
    };
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.screen = Screen::Profile;
    let mut view = ProfileView {
        npub: "npub1self".to_owned(),
        ..ProfileView::default()
    };
    view.fields[1] = Some("Al".to_owned()); // display_name
    view.selected = 1;
    app.profile_view = Some(view);

    // Enter opens the edit popup for the selected field, prefilled.
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("open edit popup");
    assert!(matches!(
        app.popup,
        Some(Popup::Text {
            purpose: TextPurpose::EditProfileField {
                field: ProfileField::DisplayName
            },
            ..
        })
    ));
    // Enter submits the prefilled value, publishing only --display-name.
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("submit edit");

    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    assert!(
        recorded
            .lines()
            .any(|line| line.contains("profile update --display-name Al")),
        "expected a single-field update argv, got:\n{recorded}"
    );
    assert!(
        !recorded.contains("--about") && !recorded.contains("--picture"),
        "only the changed field is published:\n{recorded}"
    );
}

#[test]
fn parse_relay_health_reads_counters_histograms_and_per_relay() {
    let snapshot = serde_json::json!({
        "metrics": {"active_accounts": 1, "inbound_events_seen": 10, "inbound_events_delivered": 9, "publish_attempts": 4, "publish_successes": 3},
        "delivery_spread": {
            "observed": 5, "corroborated": 3, "single_source": 2,
            "spread": {"buckets": [{"upper_bound_ms": 50, "count": 3}, {"upper_bound_ms": 200, "count": 1}], "overflow_count": 0},
            "per_relay": [{"relay_index": 0, "delivered_first": 3, "delivered_later": 1}]
        },
        "sync": {
            "tracked_subscriptions": 2, "synced_subscriptions": 2,
            "first_event": {"buckets": [{"upper_bound_ms": 100, "count": 4}], "overflow_count": 0},
            "eose": {"buckets": [{"upper_bound_ms": 300, "count": 2}], "overflow_count": 0},
            "per_relay": [{"relay_index": 0, "first_event": {"buckets": [{"upper_bound_ms": 100, "count": 2}], "overflow_count": 0}, "eose": {"buckets": [{"upper_bound_ms": 300, "count": 1}], "overflow_count": 0}}]
        },
        "health": {"sdk_backed": true, "total_relays": 3, "connected": 2, "connecting": 0, "disconnected": 1, "connection_attempts": 5, "connection_successes": 4}
    });
    let data = parse_relay_health(&snapshot, true);
    assert_eq!(data.inbound_seen, 10);
    assert_eq!(data.total_relays, 3);
    assert_eq!(data.connected, 2);
    assert_eq!(data.observed, 5);
    assert_eq!(data.spread_samples, 4);
    // p50 of 4 samples: ceil(0.5*4)=2 falls in the first (<=50ms) bucket.
    assert_eq!(data.spread_p50, "50ms");
    // p99 of 4: ceil(0.99*4)=4 reaches the second (<=200ms) bucket.
    assert_eq!(data.spread_p99, "200ms");
    assert_eq!(data.first_event_p50, "100ms");
    assert_eq!(data.eose_p50, "300ms");
    assert_eq!(data.per_relay.len(), 1);
    assert_eq!(data.per_relay[0].relay_index, 0);
    assert_eq!(data.per_relay[0].first_deliverer, "75%"); // 3/(3+1)
    assert_eq!(data.per_relay[0].first_event_p50, "100ms");
}

#[test]
fn histogram_percentile_label_is_honest_about_empty_and_overflow() {
    let empty = serde_json::json!({"buckets": [], "overflow_count": 0});
    assert_eq!(histogram_percentile_label(&empty, 0.5), "n/a");
    // A distribution dominated by the overflow region is wider than measured.
    let overflowing =
        serde_json::json!({"buckets": [{"upper_bound_ms": 100, "count": 1}], "overflow_count": 9});
    assert_eq!(histogram_percentile_label(&overflowing, 0.99), ">100ms");
}

#[test]
fn relay_health_render_never_shows_relay_urls() {
    // Relay URLs injected into unexpected fields must never reach the rendered
    // output (decision 3: redacted rows, opaque indices, no URLs).
    let snapshot = serde_json::json!({
        "metrics": {"active_accounts": 1, "relay_url": "wss://leak.example"},
        "delivery_spread": {
            "observed": 2, "url": "ws://leak.two",
            "spread": {"buckets": [{"upper_bound_ms": 50, "count": 2}], "overflow_count": 0},
            "per_relay": [{"relay_index": 0, "relay_url": "wss://leak.three", "delivered_first": 2, "delivered_later": 0}]
        },
        "sync": {"per_relay": [{"relay_index": 0, "endpoint": "wss://leak.four", "first_event": {"buckets": [], "overflow_count": 0}, "eose": {"buckets": [], "overflow_count": 0}}]},
        "health": {"total_relays": 1, "url": "wss://leak.five"}
    });
    let data = parse_relay_health(&snapshot, false);
    let rendered = relay_health_lines(&data)
        .iter()
        .flat_map(|line| line.spans.iter().map(|span| span.content.to_string()))
        .collect::<String>();
    assert!(!rendered.contains("ws://"), "no ws:// urls in:\n{rendered}");
    assert!(
        !rendered.contains("wss://"),
        "no wss:// urls in:\n{rendered}"
    );
    assert!(
        rendered.contains("relay#0"),
        "per-relay row keyed by opaque index:\n{rendered}"
    );
}

#[test]
fn user_search_frame_shows_query_and_results() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::UserSearch;
    let mut view = UserSearchView {
        results: vec![UserSearchResultRow {
            pubkey: "aa".to_owned(),
            npub: "npubALICE".to_owned(),
            display_name: Some("Alice".to_owned()),
            matched_field: "name".to_owned(),
            match_quality: "prefix".to_owned(),
            radius: 1,
        }],
        focus: UserSearchFocus::Results,
        ..UserSearchView::default()
    };
    view.query.set_value("alice");
    app.user_search = Some(view);

    let rendered = rendered_buffer(&mut app);
    assert!(rendered.contains("User Search"), "screen title present");
    assert!(rendered.contains("alice"), "query text present");
    assert!(rendered.contains("Alice"), "result label present");
    assert!(rendered.contains("prefix"), "match quality present");
    assert!(rendered.contains("radius 1"), "radius present");
}

#[test]
fn profile_frame_shows_fields_and_follows() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Profile;
    let mut view = ProfileView {
        npub: "npubSELF".to_owned(),
        follows: vec!["npubBOB".to_owned()],
        ..ProfileView::default()
    };
    view.fields[1] = Some("Alice".to_owned());
    app.profile_view = Some(view);

    let rendered = rendered_buffer(&mut app);
    assert!(rendered.contains("Profile"), "screen title present");
    assert!(rendered.contains("display name"), "field label present");
    assert!(rendered.contains("Alice"), "field value present");
    assert!(rendered.contains("Fields"), "fields section present");
    assert!(rendered.contains("Follows"), "follows section present");
    assert!(rendered.contains("npubBOB"), "follow present");
    assert!(rendered.contains("(unset)"), "unset field rendered");
}

#[test]
fn relay_health_frame_shows_redacted_summary_without_urls() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::RelayHealth;
    let data = parse_relay_health(
        &serde_json::json!({
            "health": {"total_relays": 2, "connected": 2},
            "delivery_spread": {"per_relay": [{"relay_index": 0, "delivered_first": 1, "delivered_later": 0}], "spread": {"buckets": [], "overflow_count": 0}}
        }),
        true,
    );
    app.relay_health = Some(RelayHealthView { data, scroll: 0 });

    let rendered = rendered_buffer(&mut app);
    assert!(rendered.contains("Relay Health"), "screen title present");
    assert!(rendered.contains("health:"), "health summary present");
    assert!(
        rendered.contains("relay#0"),
        "per-relay opaque index present"
    );
    assert!(
        !rendered.contains("ws://") && !rendered.contains("wss://"),
        "no relay urls in the frame:\n{rendered}"
    );
}

#[test]
fn slash_command_parser_handles_users_search() {
    assert_eq!(
        parse_slash_command("/users"),
        Ok(SlashCommand::UsersSearch { query: None })
    );
    assert_eq!(
        parse_slash_command("/users alice smith"),
        Ok(SlashCommand::UsersSearch {
            query: Some("alice smith".to_owned())
        })
    );
}

#[test]
fn help_card_documents_the_new_screens() {
    let help = help_card_lines().join("\n");
    assert!(help.contains("s search"), "help mentions user search");
    assert!(help.contains("p profile"), "help mentions profile");
    assert!(help.contains("h relays"), "help mentions relay health");
    assert!(help.contains("/users"), "help mentions the /users command");
}

#[test]
fn logout_is_discoverable_in_help_and_suggestions() {
    let help = help_card_lines().join("\n");
    assert!(help.contains("/logout"), "help card lists /logout");
    assert!(
        slash_command_suggestions("/logout")
            .iter()
            .any(|suggestion| suggestion.usage == "/logout"),
        "slash suggestions offer /logout"
    );
}

#[cfg(unix)]
#[test]
fn follows_child_invocation_borrows_the_setup_relay_only_without_a_global_relay() {
    // `follows add`/`profile update` require a relay; without a launch-time global
    // `--relay` the TUI lends the first configured setup relay so the child does not
    // hard-fail. `--relay` is a global clap flag, so a command-local position lands
    // in the same slot the handler reads, and it is never appended twice.
    let account_id = "aa".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) = test_arg_recording_executable(dir.path(), r#"{"ok":true,"result":{}}"#);
    let mut client = WnClient {
        exe,
        home: None,
        socket: None,
        relay: None,
        discovery_relays: vec!["wss://discovery".to_owned()],
        default_account_relays: vec!["wss://default".to_owned()],
        secret_store: None,
        keychain_service: None,
    };
    let mut app = test_tui_app(client.clone(), &account_id);
    app.follow_user("npub1bob").expect("follow");
    let args: Vec<String> = std::fs::read_to_string(&args_file)
        .expect("args file")
        .lines()
        .map(str::to_owned)
        .collect();
    assert!(
        args.windows(2)
            .any(|window| window == ["--relay", "wss://default"]),
        "follows add borrows the default account relay: {args:?}"
    );

    // No relay configured at all: nothing is fabricated, so the child still reaches
    // the CLI's clear MissingRelay error naming the setup flags.
    client.discovery_relays.clear();
    client.default_account_relays.clear();
    let mut app = test_tui_app(client, &account_id);
    app.follow_user("npub1bob").expect("follow");
    let recorded = std::fs::read_to_string(&args_file).expect("args file");
    assert!(
        !recorded.lines().any(|line| line == "--relay"),
        "no relay is invented when none is configured: {recorded:?}"
    );
}

#[test]
fn relay_health_scroll_clamps_to_content_height() {
    let snapshot = serde_json::json!({
        "metrics": {"active_accounts": 1, "inbound_events_seen": 10, "inbound_events_delivered": 9},
        "delivery_spread": {
            "observed": 5, "corroborated": 3, "single_source": 2,
            "per_relay": [{"relay_index": 0, "delivered_first": 3, "delivered_later": 1}]
        },
        "sync": {"tracked_subscriptions": 2, "synced_subscriptions": 2, "per_relay": [{"relay_index": 0}]},
        "health": {"sdk_backed": true, "total_relays": 3, "connected": 2, "connecting": 0, "disconnected": 1}
    });
    let data = parse_relay_health(&snapshot, true);
    let max_scroll = relay_health_lines(&data).len().saturating_sub(1) as u16;
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.relay_health = Some(RelayHealthView { data, scroll: 0 });
    app.screen = Screen::RelayHealth;

    // PageDown far past the end parks at the last content line, never beyond.
    for _ in 0..64 {
        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE))
            .expect("page down");
    }
    assert_eq!(app.relay_health.as_ref().unwrap().scroll, max_scroll);
    // Scrolling back up still works from the clamped position.
    app.handle_key(char_key('k')).expect("k up");
    assert_eq!(
        app.relay_health.as_ref().unwrap().scroll,
        max_scroll.saturating_sub(1)
    );
}

fn user_search_app_with_selected_result(client: WnClient) -> TuiApp {
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.user_search = Some(UserSearchView {
        results: vec![UserSearchResultRow {
            pubkey: "bb".to_owned(),
            npub: "npubbb".to_owned(),
            display_name: Some("Bob".to_owned()),
            matched_field: "name".to_owned(),
            match_quality: "exact".to_owned(),
            radius: 0,
        }],
        focus: UserSearchFocus::Results,
        ..UserSearchView::default()
    });
    app.screen = Screen::UserSearch;
    app
}

#[test]
fn user_search_add_opens_the_group_picker_over_the_chats_list() {
    let mut app = user_search_app_with_selected_result(test_unused_client());
    app.chats = vec![
        ChatRow {
            group_id: "g1".to_owned(),
            name: "Room One".to_owned(),
            ..ChatRow::default()
        },
        ChatRow {
            group_id: "g2".to_owned(),
            name: "Room Two".to_owned(),
            ..ChatRow::default()
        },
    ];

    app.handle_key(char_key('a')).expect("a opens the picker");

    let Some(Popup::Picker {
        purpose: PickerPurpose::Groups { pubkey, label },
        items,
        selected,
        ..
    }) = &app.popup
    else {
        panic!("a must open the group picker, got {:?}", app.popup);
    };
    assert_eq!(pubkey, "bb", "the picker carries the found user");
    assert_eq!(label, "Bob");
    assert_eq!(
        items
            .iter()
            .map(|item| (item.id.as_str(), item.label.as_str()))
            .collect::<Vec<_>>(),
        vec![("g1", "Room One"), ("g2", "Room Two")],
        "one row per chat, in the chats-list order already in state"
    );
    assert_eq!(*selected, 0, "no open chat: the first row is preselected");
}

#[test]
fn new_chat_from_search_navigates_into_the_created_chat() {
    let (_dir, client) = test_json_client(
        r#"{"ok":true,"result":{"group_id":"abcd","chats":[{"group_id":"abcd","profile":{"name":"New Room"}}]}}"#,
    );
    let mut app = user_search_app_with_selected_result(client);
    app.handle_key(char_key('c'))
        .expect("c opens new-chat popup");
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("submit new chat");
    assert_eq!(app.screen, Screen::Main, "leaves search for the main view");
    assert!(app.user_search.is_none(), "the search view is cleared");
    assert_eq!(
        app.selected_chat_row().map(|chat| chat.group_id.as_str()),
        Some("abcd"),
        "the new chat is selected"
    );
}

#[test]
fn add_to_open_chat_from_search_navigates_into_that_chat() {
    let (_dir, client) = test_json_client(r#"{"ok":true,"result":{}}"#);
    let mut app = user_search_app_with_selected_result(client);
    app.chats = vec![
        ChatRow {
            group_id: "other".to_owned(),
            name: "Other".to_owned(),
            ..ChatRow::default()
        },
        ChatRow {
            group_id: "g1".to_owned(),
            name: "Open Room".to_owned(),
            ..ChatRow::default()
        },
    ];
    app.messages_group_id = Some("g1".to_owned());
    app.handle_key(char_key('a')).expect("a opens the picker");
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("Enter picks the preselected open chat");
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("confirm add to chat");
    assert_eq!(app.screen, Screen::Main, "leaves search for the main view");
    assert!(app.user_search.is_none(), "the search view is cleared");
    assert_eq!(
        app.selected_chat_row().map(|chat| chat.group_id.as_str()),
        Some("g1"),
        "the affected chat is selected"
    );
}

#[cfg(unix)]
#[test]
fn add_to_a_picker_chosen_chat_from_search_confirms_and_navigates_into_it() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) =
        test_appending_arg_executable(tempdir.path(), r#"{"ok":true,"result":{}}"#);
    let client = WnClient {
        exe,
        home: None,
        socket: None,
        relay: None,
        discovery_relays: Vec::new(),
        default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
    };
    let mut app = user_search_app_with_selected_result(client);
    app.chats = vec![
        ChatRow {
            group_id: "other".to_owned(),
            name: "Other".to_owned(),
            ..ChatRow::default()
        },
        ChatRow {
            group_id: "g1".to_owned(),
            name: "Open Room".to_owned(),
            ..ChatRow::default()
        },
    ];
    app.messages_group_id = Some("g1".to_owned());

    // k moves off the preselected open chat; Enter reaches the confirm for the
    // chosen group, not the open one.
    app.handle_key(char_key('a')).expect("a opens the picker");
    app.handle_key(char_key('k')).expect("k moves up");
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("Enter picks the highlighted chat");
    let Some(Popup::Confirm {
        purpose: ConfirmPurpose::AddUserToChat { group_id, pubkey },
        ..
    }) = &app.popup
    else {
        panic!("Enter must open the add-user confirm, got {:?}", app.popup);
    };
    assert_eq!(group_id, "other", "the confirm targets the chosen group");
    assert_eq!(pubkey, "bb");

    // The confirm still guards the action; y runs the real add and navigates.
    app.handle_key(char_key('y')).expect("y confirms the add");
    assert_eq!(app.screen, Screen::Main, "leaves search for the main view");
    assert!(app.user_search.is_none(), "the search view is cleared");
    assert_eq!(
        app.selected_chat_row().map(|chat| chat.group_id.as_str()),
        Some("other"),
        "the chosen chat is selected"
    );
    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    assert!(
        recorded.contains("groups add-members other bb"),
        "the confirm submit runs the real add against the chosen group: {recorded}"
    );
}

#[test]
fn group_picker_esc_closes_with_zero_side_effects() {
    let mut app = user_search_app_with_selected_result(test_unused_client());
    app.chats = vec![ChatRow {
        group_id: "g1".to_owned(),
        name: "Room One".to_owned(),
        ..ChatRow::default()
    }];
    app.status = "before".to_owned();

    // One consistent rule: the picker opens whenever any chat exists, even for
    // a single chat (no direct-to-confirm special case).
    app.handle_key(char_key('a')).expect("a opens the picker");
    assert!(
        matches!(
            app.popup,
            Some(Popup::Picker {
                purpose: PickerPurpose::Groups { .. },
                ..
            })
        ),
        "a single chat still goes through the picker"
    );
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("Esc closes the picker");

    assert!(app.popup.is_none(), "the picker is closed");
    assert_eq!(app.status, "before", "no status change");
    assert_eq!(app.screen, Screen::UserSearch, "still on the search screen");
    assert!(app.user_search.is_some(), "the search view is intact");
    assert_eq!(app.chats.len(), 1, "chats untouched");
    assert_eq!(app.selected_chat, 0, "selection untouched");
}
