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
    assert_eq!(summary, "aaaa...aaaaa added someone");
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
    for input in ["/login \"nsec1synthetic\"", "/login 'nsec1synthetic'"] {
        assert_eq!(
            parse_slash_command(input),
            Ok(SlashCommand::AccountImportSecret(
                "nsec1synthetic".to_owned()
            ))
        );
    }
    // Padding inside quotes must not route secret material through public argv.
    assert_eq!(
        parse_slash_command("/login \" nsec1synthetic\""),
        Ok(SlashCommand::AccountImportSecret(
            " nsec1synthetic".to_owned()
        ))
    );
    assert_eq!(
        parse_slash_command("/login \" npub1synthetic \""),
        Ok(SlashCommand::AccountAddPublic(
            " npub1synthetic ".to_owned()
        ))
    );
    for input in [
        "/login \" nsec1synthetic",
        "/login \"nsec1synthetic",
        "/login 'nsec1synthetic",
        "/login nsec1synthetic \"",
        "/login npub1public 'NSEC1synthetic",
    ] {
        assert_eq!(
            parse_slash_command(input),
            Err("unterminated quoted string".to_owned())
        );
    }
    assert!(parse_slash_command("/account create").is_err());
}

#[test]
fn slash_command_parser_classifies_uppercase_nsec_as_secret() {
    assert_eq!(
        parse_slash_command("/login NSEC1SECRET"),
        Ok(SlashCommand::AccountImportSecret("NSEC1SECRET".to_owned()))
    );
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
fn public_only_logout_confirms_with_y_and_runs_wn_logout() {
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

#[cfg(unix)]
#[test]
fn logout_success_then_refresh_failure_reports_logout_not_error() {
    // The wipe is irreversible and succeeds; only the follow-up account-list
    // reload fails. The status must report the logout as done and point at
    // `/refresh`, never masking a completed wipe behind `error:` while the
    // removed account lingers on screen.
    let account_id = "aa".repeat(32);
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = dir.path().join("wn-json");
    let script = "#!/bin/sh\ncase \" $* \" in\n  *\" account list \"*)\ncat <<'JSON'\n{\"ok\":false,\"error\":{\"message\":\"relays unreachable\"}}\nJSON\n    ;;\n  *)\ncat <<'JSON'\n{\"ok\":true,\"result\":{}}\nJSON\n    ;;\nesac\n";
    write_fake_wn(&exe, script);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;

    app.logout_account(&account_id, "npub1alice")
        .expect("a refresh failure after a successful wipe must not propagate");

    assert!(
        app.status.contains("logged out"),
        "the completed wipe is reported: {:?}",
        app.status
    );
    assert!(
        app.status.contains("/refresh"),
        "the status points at /refresh to retry the reload: {:?}",
        app.status
    );
    assert!(
        !app.status.starts_with("error:"),
        "a completed wipe is never reported as an error: {:?}",
        app.status
    );
}

#[cfg(unix)]
#[test]
fn logout_success_with_successful_refresh_reports_only_the_logout() {
    // The happy path is unchanged: a clean logout + reload reports just the
    // logged-out account, with no reload-failure suffix.
    let account_id = "aa".repeat(32);
    let (_tempdir, client) = test_json_client(r#"{"ok":true,"result":{"accounts":[]}}"#);
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;

    app.logout_account(&account_id, "npub1alice")
        .expect("a clean logout succeeds");

    assert_eq!(app.status, "logged out npub1alice");
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
    const IMAGE_KEY_HEX: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const UPLOAD_KEY_HEX: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    let diagnostics = parse_group_diagnostics(&serde_json::json!({
        "group": {
            "group_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "profile": {
                "component_id": 32769,
                "component": "marmot.group.profile.v1",
                "data_hex": "010203"
            },
            "image": {
                "component_id": 32770,
                "component": "marmot.group.blossom.image.v1",
                "data_hex": format!("00{IMAGE_KEY_HEX}{UPLOAD_KEY_HEX}")
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

    let debug_rendered = format!("{diagnostics:?}");
    assert!(!debug_rendered.contains(IMAGE_KEY_HEX));
    assert!(!debug_rendered.contains(UPLOAD_KEY_HEX));
    assert!(!debug_rendered.contains("010203"));
    assert!(!debug_rendered.contains("aabbcc"));
    assert!(!debug_rendered.contains("ffee"));

    // The diagnostics panel drops the leading status line (now in the status bar):
    // it starts straight at the MLS summary.
    let rendered = diagnostics_panel_lines(Some(&diagnostics))
        .iter()
        .map(line_text)
        .collect::<Vec<_>>();

    let rendered_joined = rendered.join("\n");
    assert!(!rendered_joined.contains(IMAGE_KEY_HEX));
    assert!(!rendered_joined.contains(UPLOAD_KEY_HEX));
    assert!(!rendered_joined.contains("010203"));
    assert!(!rendered_joined.contains("aabbcc"));
    assert!(!rendered_joined.contains("ffee"));

    assert_eq!(
        rendered[0],
        "MLS epoch=7 group=aaaaaaa...aaaaaaaa members=3"
    );
    assert_eq!(rendered[1], "components:");
    assert!(
        rendered
            .iter()
            .any(|line| line == "marmot.group.profile.v1 id=32769")
    );
    assert!(
        rendered
            .iter()
            .any(|line| line == "marmot.group.blossom.image.v1 id=32770")
    );
    assert!(
        rendered
            .iter()
            .any(|line| line == "marmot.group.admin-policy.v1 id=32771")
    );
    assert!(
        rendered
            .iter()
            .any(|line| line == "marmot.group.agent-text-stream.quic.v1 id=32774")
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
    // Chat-list labels are cyan (chrome), reserving green strictly for self.
    assert_eq!(line.spans[1].style.fg, Some(Color::Cyan));
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
    assert_eq!(name.style.fg, Some(Color::Cyan));
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
    assert_eq!(
        daemon_status_sentence(&parse_daemon_view(
            &serde_json::json!({"running": true, "starting": true})
        )),
        "daemon starting"
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
        flushed_bytes: 0,
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

    assert!(
        stream_preview_lines(&DaemonView::default(), &previews, Some(group_id)).is_empty(),
        "an empty local preview is hidden independently of daemon watches"
    );
    assert!(
        stream_preview_lines(&daemon, &[], Some(group_id)).is_empty(),
        "a completed daemon watch is hidden without a local preview shadowing it"
    );
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
    // #2955: masking must work before an opening quote has been closed.
    // These sentinel values are deliberately not valid credentials.
    for input in [
        "/login \" nsec1synthetic",
        "/login '\tNsEc1synthetic",
        "/login \" \nNSEC1synthetic",
        "/login \" nsec1synthetic\"",
        "/login ' nsec1synthetic '",
        "/login \"nsec1synthetic",
        "/login 'nsec1synthetic",
        " /\tlogin  \"NsEc1synthetic",
        "/login nsec1synthetic \"",
        "/login npub1public 'NSEC1synthetic",
        "/\"login\" 'nsec1synthetic",
        "/login \"nsec1synthetic\"",
        "/login 'nsec1synthetic'",
        "/login nsec1secret",
    ] {
        assert_eq!(composer_display_text(input), "/login <hidden nsec>");
    }
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
    for input in [
        "ordinary message",
        "a message mentioning nsec1synthetic",
        "/login \"npub1public",
        "/login 'npub1public",
        "/login \" npub1public",
        "/login '\tnpub1public",
        "/login \" npub1public \"",
        "/login npub1public \"",
        "/login \"npub1public\"",
        "/login 'npub1public'",
        "/login \"",
        "/login '",
    ] {
        assert_eq!(composer_display_text(input), input);
    }
}

#[test]
fn composer_redacts_uppercase_nsec_import() {
    assert_eq!(
        composer_display_text("/login NSEC1SECRET"),
        "/login <hidden nsec>"
    );
}

#[test]
fn account_setup_invocation_pipes_nsec_imports_to_stdin() {
    for identity in [" nsec1synthetic", "\tNsEc1synthetic \n"] {
        assert_eq!(
            account_setup_invocation(Some(identity.to_owned()), None),
            WnInvocation {
                args: vec!["login".to_owned(), "--nsec-stdin".to_owned()],
                stdin: Some(format!("{identity}\n")),
            }
        );
    }
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
fn subscription_parser_accepts_daemon_stream_frames() {
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
    let effects = EffectRunner::spawn(client.clone());
    TuiApp {
        client,
        effects,
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
        // Matches refresh_chats after a successful empty snapshot for this account.
        chats_account_id: Some(account_id.to_owned()),
        selected_chat: 0,
        messages_account_id: None,
        messages_group_id: None,
        show_archived_chats: false,
        timeline: Vec::new(),
        timeline_scroll: TimelineScroll::default(),
        live_stream_previews: Vec::new(),
        // The empty account fixture already owns its account-wide resources.
        stream_previews_account_id: Some(account_id.to_owned()),
        chat_subscription: None,
        message_subscription: None,
        timeline_subscription: None,
        group_state_subscription: None,
        notification_subscription: None,
        pending_chat_relist: false,
        pending_mark_read: false,
        loading_chat: None,
        timeline_load_generation: 0,
        searching_users: None,
        searching_messages: None,
        loading_group_detail: None,
        loading_invites: false,
        flick_countdown: None,
        seen_notification_keys: SeenNotificationKeys::new(),
        daemon: DaemonView {
            running: true,
            ..DaemonView::default()
        },
        group_diagnostics: None,
        input: Input::default(),
        streaming: None,
        status: String::new(),
        status_ownership: StatusOwnership::default(),
        flick_status_owner: None,
        stream_status_owner: None,
        daemon_start_status_owner: None,
        popup: None,
        pending_full_repaint: false,
        group_detail: None,
        user_search: None,
        message_search: None,
        profile_view: None,
        relay_health: None,
        media: MediaState::new(),
        daemon_autostart: None,
    }
}

/// Fence work already queued on the real FIFO worker before inspecting a fake
/// child's recorder. Do not fold the marker: it must not change UI state.
fn finish_queued_effects(app: &mut TuiApp) {
    const MARKER: &str = "test-fifo-completion-marker";
    app.enqueue_effect(Effect::MarkRead {
        account: "aa".repeat(32),
        group: MARKER.to_owned(),
    });
    loop {
        let done = app
            .effects
            .recv_timeout(Duration::from_secs(5))
            .expect("FIFO completion marker");
        if matches!(&done.effect, Effect::MarkRead { group, .. } if group == MARKER) {
            assert!(done.result.is_ok(), "the marker child completed");
            return;
        }
        app.apply_effect_done(done);
    }
}

/// A fake child reports entry, then blocks on a FIFO until the test releases it.
/// The readiness poll observes produced state; its deadline only bounds hangs.
#[cfg(unix)]
struct TestCommandGate {
    entered: PathBuf,
    release_path: PathBuf,
    release: std::fs::File,
    released: bool,
}

#[cfg(unix)]
impl TestCommandGate {
    fn new(dir: &std::path::Path) -> Self {
        let entered = dir.join("entered");
        let release_path = dir.join("release");
        assert!(
            StdCommand::new("mkfifo")
                .arg(&release_path)
                .status()
                .expect("mkfifo")
                .success()
        );
        let release = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&release_path)
            .expect("open release FIFO");
        Self {
            entered,
            release_path,
            release,
            released: false,
        }
    }

    fn script(&self) -> String {
        format!(
            "printf entered > '{}'\nIFS= read -r released < '{}'\n",
            self.entered.display(),
            self.release_path.display()
        )
    }

    fn wait_until_entered(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.entered.exists() {
            assert!(Instant::now() < deadline, "the gated child never entered");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn release(&mut self) {
        if !self.released {
            self.release
                .write_all(b"release\n")
                .expect("release fake child");
            self.released = true;
        }
    }
}

#[cfg(unix)]
impl Drop for TestCommandGate {
    fn drop(&mut self) {
        self.release();
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

/// Write an executable fake `wn` script to `exe` without this process ever
/// holding a write handle to the file it will later exec.
///
/// The test harness runs many write-then-exec fakes across threads at once. On
/// Linux, if any thread has a file open for writing when another thread forks
/// (which every subprocess spawn does under the hood), the forked child
/// inherits that writable descriptor; an `execve` of the same file then fails
/// with `ETXTBSY` ("text file busy") until the descriptor closes. Writing the
/// body from a short-lived child shell keeps the writable descriptor out of
/// this process's table entirely, so no spawn here can inherit it and the race
/// cannot occur. `chmod` is path-based and opens nothing, so it stays in-process.
#[cfg(unix)]
fn write_fake_wn(exe: &std::path::Path, script: &str) {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    // `cat > "$1"` opens `exe` for writing inside the child shell, never here.
    let mut writer = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"cat > "$1""#)
        .arg("write_fake_wn") // $0: a label for diagnostics only
        .arg(exe) // $1: the destination path
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("spawn fake wn writer");
    writer
        .stdin
        .take()
        .expect("fake wn writer stdin")
        .write_all(script.as_bytes())
        .expect("write fake wn body");
    assert!(
        writer.wait().expect("await fake wn writer").success(),
        "fake wn writer exited non-zero"
    );

    let mut permissions = std::fs::metadata(exe)
        .expect("fake wn metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(exe, permissions).expect("chmod fake wn");
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
    let tempdir = tempfile::tempdir().expect("tempdir");
    let counter = tempdir.path().join("invites-seen");
    let exe = tempdir.path().join("wn-json");
    let script = format!(
        "#!/bin/sh\ncase \" $* \" in\n  *\" invites \"*)\n    if [ -f '{counter}' ]; then\ncat <<'JSON'\n{rest}\nJSON\n    else\n      : > '{counter}'\ncat <<'JSON'\n{first}\nJSON\n    fi\n    ;;\n  *)\ncat <<'JSON'\n{{\"ok\":true,\"result\":{{}}}}\nJSON\n    ;;\nesac\n",
        counter = counter.display(),
    );
    write_fake_wn(&exe, &script);
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
    let exe = dir.join("wn-json");
    write_fake_wn(
        &exe,
        &format!("#!/bin/sh\ncat <<'JSON'\n{response}\nJSON\n"),
    );
    exe
}

/// A fake `wn` that records its argv (one arg per line) to a sidecar file and
/// then prints `response`, so a test can assert which command was spawned.
/// Returns the executable path and the args-file path.
///
/// Every invocation truncates and rewrites the recorder, so read it only at a
/// point where the invocation under test is the last to have run. Beware
/// actions whose fold spawns follow-up `wn` children (the daemon-adopt path
/// re-ensures the live subscriptions): read the recorder before such a fold,
/// or the children rewrite it out from under the assertion. For a flow that
/// must observe several sequential calls, use `test_appending_arg_executable`.
#[cfg(unix)]
fn test_arg_recording_executable(dir: &std::path::Path, response: &str) -> (PathBuf, PathBuf) {
    let exe = dir.join("wn-json");
    let args_file = dir.join("recorded-args");
    write_fake_wn(
        &exe,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncat <<'JSON'\n{response}\nJSON\n",
            args_file.display()
        ),
    );
    (exe, args_file)
}

/// A fake `wn` whose behavior is the literal `#!/bin/sh` script `body`, so a test
/// can vary the response by subcommand (a `case " $* " in ... esac`) or add a
/// `sleep` to model a slow call. Returns the tempdir (keep it alive) and a client
/// pointed at the script.
#[cfg(unix)]
fn test_scripted_client(body: &str) -> (tempfile::TempDir, WnClient) {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let exe = tempdir.path().join("wn-json");
    write_fake_wn(&exe, &format!("#!/bin/sh\n{body}"));
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    (tempdir, client)
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

#[cfg(unix)]
fn stream_recording_executable(dir: &std::path::Path, response: &str) -> (PathBuf, PathBuf) {
    let exe = dir.join("wn-stream");
    let calls = dir.join("calls");
    std::fs::create_dir(&calls).unwrap();
    write_fake_wn(
        &exe,
        &format!(
            "#!/bin/sh\nset -e\nn=0\nwhile ! mkdir '{}/'$n 2>/dev/null; do [ -d '{}' ] || exit 1; n=$((n + 1)); done\nprintf '%s\\n' \"$@\" > '{}/'$n/args.tmp\nmv '{}/'$n/args.tmp '{}/'$n/args\ncat <<'JSON'\n{response}\nJSON\n",
            calls.display(),
            calls.display(),
            calls.display(),
            calls.display(),
            calls.display(),
        ),
    );
    (exe, calls)
}

#[cfg(unix)]
fn stream_recorded_calls(dir: &std::path::Path) -> Vec<Vec<String>> {
    let mut calls = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let order = entry
                .file_name()
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let args = std::fs::read_to_string(entry.path().join("args"))
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            (order, args)
        })
        .collect::<Vec<_>>();
    calls.sort_by_key(|(order, _)| *order);
    calls.into_iter().map(|(_, args)| args).collect()
}

#[cfg(unix)]
#[test]
fn stream_slash_controls_forward_options_and_report_the_command_reply() {
    let account = "aa".repeat(32);
    let group = "cc".repeat(16);
    let stream = "bb".repeat(32);
    let digest = "ee".repeat(32);
    for (input, command, selected_owner, status) in [
        (
            format!("/stream start --stream-id {stream} --quic-candidate quic://127.0.0.1:4451"),
            vec![
                "stream".into(),
                "start".into(),
                group.clone(),
                "--stream-id".into(),
                stream.clone(),
                "--quic-candidate".into(),
                "quic://127.0.0.1:4451".into(),
            ],
            true,
            "started stream ddddddd...dddddddd; published=2",
        ),
        (
            format!("/stream watch --stream-id {stream} --insecure-local"),
            vec![
                "stream".into(),
                "watch".into(),
                group.clone(),
                "--background".into(),
                "--stream-id".into(),
                stream.clone(),
                "--insecure-local".into(),
            ],
            true,
            "watching stream returned-watch",
        ),
        (
            format!("/stream finish {stream} {digest} 2 finished text"),
            vec![
                "stream".into(),
                "finish".into(),
                group.clone(),
                "--stream-id".into(),
                stream.clone(),
                "--transcript-hash".into(),
                digest.clone(),
                "--chunk-count".into(),
                "2".into(),
                "finished text".into(),
            ],
            true,
            "finished stream bbbbbbb...bbbbbbbb; published=2",
        ),
        (
            format!("/stream verify {stream} {digest} 2"),
            vec![
                "stream".into(),
                "verify".into(),
                group.clone(),
                "--stream-id".into(),
                stream.clone(),
                "--transcript-hash".into(),
                digest.clone(),
                "--chunk-count".into(),
                "2".into(),
            ],
            true,
            "stream bbbbbbb...bbbbbbbb verified=true",
        ),
        (
            format!("/stream verify {stream} {digest}"),
            vec![
                "stream".into(),
                "verify".into(),
                group.clone(),
                "--stream-id".into(),
                stream.clone(),
                "--transcript-hash".into(),
                digest.clone(),
            ],
            true,
            "stream bbbbbbb...bbbbbbbb verified=true",
        ),
        (
            "/stream status".to_owned(),
            vec!["daemon".into(), "status".into()],
            false,
            "streams: running=1 completed=0 failed=0 latest=bbbbbbb...bbbbbbbb",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let response = serde_json::json!({"ok":true,"result":{
            "stream_id":"dd".repeat(32),"published":2,"watch_id":"returned-watch",
            "verified":true,"running":!selected_owner,"messages":[],"has_more_before":false,
            "stream_watches":if selected_owner {serde_json::json!([])} else {serde_json::json!([
                {"watch_id":"returned-watch","group_id":group,"stream_id":stream,"status":"running"}
            ])}
        }})
        .to_string();
        let (exe, args) = stream_recording_executable(dir.path(), &response);
        let mut app = test_tui_app(
            WnClient {
                exe,
                ..test_unused_client()
            },
            &account,
        );
        app.daemon.running = false;
        app.chats = vec![flick_chat(&group, "Selected room")];
        app.messages_account_id = Some("ff".repeat(32));
        app.messages_group_id = Some("ff".repeat(16));
        if !selected_owner {
            // Global daemon status is also available to a public-only account
            // with no chat; it must not acquire account-specific subscriptions.
            app.accounts[0].local_signing = false;
            app.chats.clear();
            app.messages_account_id = None;
            app.messages_group_id = None;
        }
        app.input.set_value(&input);
        app.submit_input().expect("dispatch stream control");
        assert_eq!(app.status, status, "{input}");
        assert!(app.input.is_empty());
        finish_queued_effects(&mut app);
        // Timeline folding queues diagnostics and mark-read behind the first
        // marker. Fence those children before reading or removing their files.
        finish_queued_effects(&mut app);
        let recorded = stream_recorded_calls(&args);
        let mut expected: Vec<String> = vec!["--json".into()];
        if selected_owner {
            expected.extend(["--account".into(), account.clone()]);
        }
        expected.extend(command);
        assert_eq!(recorded[0], expected, "{input}");
    }
}

#[cfg(unix)]
#[test]
fn stream_composition_adopts_the_returned_id_and_finishes_or_cancels_typed_text() {
    let account = "aa".repeat(32);
    let group = "cc".repeat(16);
    let requested_stream = "bb".repeat(32);
    let returned_stream = "dd".repeat(32);
    for finish in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let response = serde_json::json!({"ok":true,"result":{
            "stream_id":returned_stream,"chunk_count":7,"running":false,
            "messages":[],"has_more_before":false
        }})
        .to_string();
        let (exe, args) = stream_recording_executable(dir.path(), &response);
        let mut app = test_tui_app(
            WnClient {
                exe,
                ..test_unused_client()
            },
            &account,
        );
        app.daemon.running = false;
        app.chats = vec![flick_chat(&group, "Selected room")];
        app.input.set_value(format!("/stream --stream-id {requested_stream} --quic-candidate quic://127.0.0.1:4451 --quic-candidate quic://192.0.2.1:4451"));
        app.submit_input().expect("open stream composer");
        assert_eq!(
            app.status,
            "now streaming ddddddd...dddddddd; type text and press Enter to finish"
        );
        assert!(app.input.is_empty());
        finish_queued_effects(&mut app);
        finish_queued_effects(&mut app);
        for ch in "hello world".chars() {
            app.handle_key(char_key(ch)).unwrap();
        }
        let pending = app.streaming.as_ref().unwrap();
        assert_eq!(
            (
                &pending.stream_id,
                &pending.group_id,
                pending.pending_text.as_str()
            ),
            (&returned_stream, &group, "hello world")
        );
        assert_eq!(app.live_stream_previews[0].text, "hello world");
        let due = pending.last_flush + STREAM_APPEND_FLUSH_INTERVAL + Duration::from_millis(1);
        assert!(app.flush_stream_append_if_due(due).expect("flush text"));
        assert_eq!(app.streaming.as_ref().unwrap().pending_text, "");
        assert_eq!(app.streaming.as_ref().unwrap().flushed_bytes, 11);
        assert_eq!(app.status, "streaming 11 bytes on ddddddd...dddddddd");
        app.handle_key(KeyEvent::new(
            if finish { KeyCode::Enter } else { KeyCode::Esc },
            KeyModifiers::NONE,
        ))
        .unwrap();
        assert!(app.streaming.is_none());
        assert!(app.input.is_empty());
        assert!(app.live_stream_previews.is_empty());
        assert_eq!(
            app.status,
            if finish {
                "finished stream ddddddd...dddddddd chunks=7"
            } else {
                "cancelled stream ddddddd...dddddddd"
            }
        );
        finish_queued_effects(&mut app);
        finish_queued_effects(&mut app);
        let calls = stream_recorded_calls(&args)
            .into_iter()
            .filter(|args| args.iter().any(|arg| arg == "stream"))
            .collect::<Vec<_>>();
        let prefix = vec!["--json".to_owned(), "--account".to_owned(), account.clone()];
        let mut expected = vec![
            vec![
                "stream".into(),
                "compose-open".into(),
                group.clone(),
                "--insecure-local".into(),
                "--stream-id".into(),
                requested_stream.clone(),
                "--quic-candidate".into(),
                "quic://127.0.0.1:4451".into(),
                "--quic-candidate".into(),
                "quic://192.0.2.1:4451".into(),
            ],
            vec![
                "stream".into(),
                "compose-append".into(),
                "--stream-id".into(),
                returned_stream.clone(),
                "hello world".into(),
            ],
            vec![
                "stream".into(),
                if finish {
                    "compose-finish"
                } else {
                    "compose-cancel"
                }
                .into(),
                "--stream-id".into(),
                returned_stream.clone(),
            ],
        ];
        for call in &mut expected {
            call.splice(0..0, prefix.clone());
        }
        assert_eq!(calls, expected);
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
        flushed_bytes: 0,
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

    #[cfg(unix)]
    {
        let dir = tempfile::tempdir().unwrap();
        let (exe, args) = test_appending_arg_executable(dir.path(), r#"{"ok":true,"result":{}}"#);
        app.client.exe = exe;
        assert!(
            app.flush_stream_append_if_due(retry_gate + STREAM_APPEND_FLUSH_INTERVAL)
                .unwrap()
        );
        let streaming = app.streaming.as_ref().unwrap();
        assert_eq!(streaming.pending_text, "");
        assert_eq!(streaming.flushed_bytes, 6);
        assert_eq!(app.status, "streaming 6 bytes on stream-197");
        let recorded = std::fs::read_to_string(args).unwrap();
        let requested = recorded.lines().next().unwrap();
        assert!(requested.ends_with("stream compose-append --stream-id stream-197 queued"));
        assert!(requested.contains(&format!("--account {account_id}")));
    }
    // Automatic retry feedback remains owned by typed text across retries;
    // a newer editing instruction revokes feedback without discarding the flush.
    let (_retry_dir, retry_client) =
        test_json_client(r#"{"ok":false,"error":{"message":"retry offline"}}"#);
    app.client = retry_client;
    app.handle_streaming_key(char_key('x')).unwrap();
    app.streaming.as_mut().unwrap().last_flush = Instant::now() - STREAM_APPEND_FLUSH_INTERVAL;
    app.tick();
    assert_eq!(app.status, "stream append failed: retry offline");
    let (_again_dir, again_client) =
        test_json_client(r#"{"ok":false,"error":{"message":"still offline"}}"#);
    app.client = again_client;
    app.streaming.as_mut().unwrap().last_flush = Instant::now() - STREAM_APPEND_FLUSH_INTERVAL;
    app.tick();
    assert_eq!(app.status, "stream append failed: still offline");
    app.handle_streaming_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE))
        .unwrap();
    let (_ready_dir, ready_client) = test_json_client(r#"{"ok":true,"result":{}}"#);
    app.client = ready_client;
    app.streaming.as_mut().unwrap().last_flush = Instant::now() - STREAM_APPEND_FLUSH_INTERVAL;
    app.tick();
    assert_eq!(
        app.status,
        "stream editing is append-only in this preview; Esc cancels"
    );
    assert!(app.streaming.as_ref().unwrap().pending_text.is_empty());
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
        flushed_bytes: 0,
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
        flushed_bytes: 0,
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
        flushed_bytes: 0,
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
            activity_sort_at: last_activity.unwrap_or(0),
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
fn message_less_chats_tie_break_on_group_id() {
    // Equal `activity_sort_at` rows follow storage: ascending `group_id_hex`.
    let mut chats = vec![
        projected_chat("cc", "third", 0, None),
        projected_chat("aa", "first", 0, None),
        projected_chat("bb", "second", 0, None),
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
fn all_pruned_chat_orders_by_durable_activity_sort_at() {
    // Storage keeps a nonzero `activity_sort_at` after secure prune even when
    // `last_message` is null; the TUI must not sink the row to the bottom.
    let mut chats = vec![
        projected_chat("bb", "recent-preview", 0, Some(10)),
        ChatRow {
            group_id: "aa".to_owned(),
            name: "pruned".to_owned(),
            archived: false,
            projection: ChatProjection {
                activity_sort_at: 30,
                ..ChatProjection::default()
            },
        },
    ];
    sort_chats_by_activity(&mut chats);
    assert_eq!(
        chats
            .iter()
            .map(|chat| chat.group_id.as_str())
            .collect::<Vec<_>>(),
        vec!["aa", "bb"],
        "durable activity_sort_at beats a younger preview-only row"
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
            "activity_sort_at": 30,
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
    for projection in [
        serde_json::json!({"type": "timeline_projection_updated", "group_id": "aa"}),
        serde_json::json!({
            "type": "timeline_projection_updated", "group_id": "aa", "chat_list_row": null
        }),
    ] {
        assert!(
            timeline_chat_list_row(&projection).is_none(),
            "{projection}"
        );
    }
    let valid = serde_json::json!({
        "type": "timeline_projection_updated", "group_id": "aa",
        "chat_list_row": {"unread_count": 3, "has_unread": true}
    });
    let (group, projection) = timeline_chat_list_row(&valid).expect("projection present");
    assert_eq!(group, "aa");
    assert_eq!(projection.unread_count, 3);
    assert!(projection.has_unread);
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
fn a_notification_armed_relist_runs_off_loop_and_preserves_selection() {
    let account_id = "aa".repeat(32);
    let group_a = "aa".repeat(32);
    let group_b = "bb".repeat(32);
    // The re-read returns B as the most-active chat (a reorder): B first, A last.
    // `activity_sort_at` is the durable ordering anchor the fold sorts by — a
    // `last_message.timeline_at` alone leaves both rows at activity 0, where the
    // ascending group-id tie-break would keep A first and the reorder never happens.
    let response = format!(
        r#"{{"ok":true,"result":{{"chats":[{{"group_id":"{group_b}","profile":{{"name":"b"}},"activity_sort_at":200,"last_message":{{"timeline_at":200,"plaintext":"hi","sender":"x"}}}},{{"group_id":"{group_a}","profile":{{"name":"a"}},"activity_sort_at":100,"last_message":{{"timeline_at":100,"plaintext":"yo","sender":"x"}}}}]}}}}"#
    );
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) = test_appending_arg_executable(tempdir.path(), &response);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon = DaemonView::default(); // no live subscriptions to drain
    // A notification can arm the re-list before the chat feed has populated.
    assert!(
        app.chats.is_empty(),
        "an empty list must still be refreshed"
    );
    app.pending_chat_relist = true;

    // tick queues the re-list off the event loop (it never runs `chats list` on the
    // key-handling thread) and clears the debounce.
    assert!(app.tick());
    assert!(
        !app.pending_chat_relist,
        "the debounce clears when the re-list is queued"
    );

    // Before the result is folded, the chat feed can populate and A can be
    // selected. The late re-list must preserve that selection while reordering.
    app.chats = vec![
        projected_chat(&group_a, "a", 0, Some(100)),
        projected_chat(&group_b, "b", 1, Some(50)),
    ];
    app.selected_chat = 0;
    app.settle_effects(1);
    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    assert!(
        recorded.contains("chats list"),
        "the re-read ran through the effect worker: {recorded:?}"
    );
    assert_eq!(
        app.selected_chat_row().map(|chat| chat.group_id.as_str()),
        Some(group_a.as_str()),
        "the background reorder keeps the highlight on the chat the user selected"
    );
    assert_eq!(
        app.selected_chat, 1,
        "A is now second after B out-ranked it"
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

    assert!(app.tick(), "tick queues the mark-read off-loop");
    assert!(!app.pending_mark_read, "a queued mark-read clears the flag");
    app.settle_effects(1);
    assert_eq!(
        app.chats[0].projection.unread_count, 0,
        "folding the mark-read response clears the viewed chat's badge"
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

    // tick queues the re-list off-loop and clears the debounce; the failure lands
    // when the worker's result folds.
    app.tick();
    assert!(!app.pending_chat_relist, "the debounce clears on queue");
    app.settle_effects(1);

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
    // A real feed result is folded before the queued child's completion. Its
    // idle notice must not revoke that child's background error eligibility.
    let (tx, rx) = mpsc::channel();
    app.chat_subscription = Some(ChatSubscription {
        account_id: account_id.clone(),
        include_archived: false,
        child: test_sleep_child(),
        rx,
    });
    tx.send(SubscriptionEvent::Result(
        serde_json::json!({"type":"chat","chat":{
            "group_id":group_id,"profile":{"name":"renamed while marking read"},"unread_count":3
        }}),
    ))
    .unwrap();
    assert!(app.drain_chat_subscription());
    assert_eq!(app.chats[0].name, "renamed while marking read");
    assert_eq!(app.status, "live chat update: chats=1");
    // The mark-read runs off-loop; folding its failed result re-arms the flag.
    app.settle_effects(1);

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
    // The load runs off-loop and, with no daemon, queues diagnostics and a
    // mark-read; folding all three clears the badge.
    app.settle_effects(3);

    assert_eq!(
        app.chats[0].projection.unread_count, 0,
        "opening a chat folds the mark-read response and clears the badge"
    );
}

#[test]
fn mark_read_completions_keep_account_projections_and_pane_retries_separate() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let group = "cc".repeat(32);
    for list_owner in [&account_b, &account_a] {
        for pane_account in [&account_b, &account_a] {
            for pane_group in [group.as_str(), "dddddddddddddddddddddddddddddddd"] {
                for fails in [false, true] {
                    let mut app = test_tui_app(test_unused_client(), &account_a);
                    app.accounts.push(AccountRow {
                        account_id: account_b.clone(),
                        npub: "npub1bob".to_owned(),
                        display_name: None,
                        local_signing: true,
                    });
                    app.selected_account = usize::from(list_owner == &account_b);
                    app.messages_account_id = Some(pane_account.clone());
                    app.messages_group_id = Some(pane_group.to_owned());
                    // Establish ownership through the real full-result writer,
                    // then move selection away without changing the loaded rows.
                    app.apply_effect_done(EffectDone {
                        status_owner: Some(app.status_ownership.revision),
                        effect: Effect::Relist {
                            account: list_owner.clone(),
                            include_archived: false,
                        },
                        result: Ok(vec![serde_json::json!({"chats":[{"group_id":group,
                            "profile":{"name":"general"},"unread_count":5,"has_unread":true}]})]),
                    });
                    app.selected_account = 1 - app.selected_account;
                    app.status = "current context".to_owned();
                    app.apply_effect_done(EffectDone {
                        status_owner: Some(app.status_ownership.revision),
                        effect: Effect::MarkRead {
                            account: account_a.clone(),
                            group: group.clone(),
                        },
                        result: if fails {
                            Err("read failed".to_owned())
                        } else {
                            Ok(vec![
                                serde_json::json!({"unread_count":0,"has_unread":false}),
                            ])
                        },
                    });
                    let same_account = list_owner == &account_a;
                    assert_eq!(
                        app.chats[0].projection.unread_count,
                        if same_account && !fails { 0 } else { 5 },
                        "only the owning account's chat list receives the projection"
                    );
                    let retry = pane_account == &account_a && pane_group == group && fails;
                    assert_eq!(
                        app.pending_mark_read, retry,
                        "an old failure must not schedule a read in the new pane"
                    );
                    assert_eq!(
                        app.status,
                        if retry {
                            "mark-read failed: read failed"
                        } else {
                            "current context"
                        }
                    );
                }
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn mark_read_completion_does_not_cross_a_successful_then_failed_account_switch() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let group = "cc".repeat(32);
    let b_list = serde_json::json!({"ok":true,"result":{"chats":[{
        "group_id":group,"profile":{"name":"B's loaded chat"},
        "unread_count":5,"has_unread":true,"activity_sort_at":20,
        "last_message":{"sender":"B sender","plaintext":"B preview","timeline_at":20}
    }]}});
    let (_dir, client) = test_scripted_client(&format!(
        "case \" $* \" in\n\
         *' --account {account_a} chats mark-read {group} '*)\n\
         printf '%s\\n' '{{\"ok\":true,\"result\":{{\"unread_count\":0,\"has_unread\":false,\"last_message\":null}}}}'\n;;\n\
         *' --account {account_b} chats list '*)\n\
         cat <<'JSON'\n{b_list}\nJSON\n;;\n\
         *' --account {account_a} chats list '*)\n\
         printf '%s\\n' '{{\"ok\":false,\"error\":{{\"message\":\"A refresh failed\"}}}}'\n;;\n\
         *)\n\
         printf '%s\\n' '{{\"ok\":true,\"result\":{{\"messages\":[],\"has_more_before\":false}}}}'\n;;\nesac\n"
    ));
    let mut app = test_tui_app(client, &account_a);
    app.daemon.running = false;
    app.accounts.push(AccountRow {
        account_id: account_b.clone(),
        npub: "npub1bob".to_owned(),
        display_name: None,
        local_signing: true,
    });
    app.messages_account_id = Some(account_a.clone());
    app.messages_group_id = Some(group.clone());
    app.chats = vec![projected_chat(&group, "A's loaded chat", 2, Some(10))];
    app.pending_mark_read = true;
    assert!(app.tick(), "the production tick queues A's mark-read");
    assert!(!app.pending_mark_read);

    // B's real refresh installs a list carrying B-only fixture provenance.
    // Its timeline load is queued behind the pending A read, respecting FIFO.
    app.select_account_by_selector(&account_b)
        .expect("B refresh succeeds");
    assert_eq!(app.chats.len(), 1);
    assert_eq!(app.chats[0].name, "B's loaded chat");
    assert_eq!(app.chats[0].projection.unread_count, 5);
    let b_chats = app.chats.clone();

    let error = app
        .select_account_by_selector(&account_a)
        .expect_err("A refresh fails");
    assert_eq!(error.to_string(), "A refresh failed");
    assert_eq!(app.selected_account_row().unwrap().account_id, account_a);
    assert_eq!(
        app.chats, b_chats,
        "the failed refresh retains B's loaded list"
    );
    assert!(
        app.messages_account_id.is_none(),
        "opening B cleared A's pane before the failed return"
    );

    let done = app
        .effects
        .recv_timeout(Duration::from_secs(5))
        .expect("A read completed");
    assert!(
        matches!(&done.effect, Effect::MarkRead {account, group: target}
        if account == &account_a && target == &group)
    );
    app.apply_effect_done(done);

    assert_eq!(
        app.chats, b_chats,
        "A's completion must not rewrite B's loaded projection"
    );
}

// Both lists use the same group, but only B's foreground fetch succeeds.
// A failed return to A changes the highlight without changing B's real data.
#[cfg(unix)]
fn chat_list_b_after_failed_return_to_a(pane_is_b: bool) -> (tempfile::TempDir, TuiApp) {
    chat_list_b_after_failed_return_to_a_with_daemon(pane_is_b, false)
}

#[cfg(unix)]
fn chat_list_b_after_failed_return_to_a_with_daemon(
    pane_is_b: bool,
    daemon_running: bool,
) -> (tempfile::TempDir, TuiApp) {
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    let group = "cc".repeat(32);
    let response = serde_json::json!({"ok":true,"result":{"chats":[{
        "group_id":group,"profile":{"name":"B list"},"unread_count":7,"has_unread":true,
        "activity_sort_at":30,"last_message":{"plaintext":"B preview","timeline_at":30}
    }]}});
    let (dir, client) = test_scripted_client(&format!(
        "case \" $* \" in\n\
         *' --account {b} chats list '*)\ncat <<'JSON'\n{response}\nJSON\n;;\n\
         *' --account {a} chats list '*)\n\
         printf '%s\\n' '{{\"ok\":false,\"error\":{{\"message\":\"A refresh failed\"}}}}'\n;;\n\
         *' --account {a} chats subscribe '*)\n\
         printf '%s\\n' '{{\"ok\":true,\"result\":{{\"type\":\"chat\",\"chat\":{{\"group_id\":\"{group}\",\"profile\":{{\"name\":\"A live update\"}},\"unread_count\":9,\"has_unread\":true}}}}}}'\n\
         exec sleep 60\n;;\n\
         *' subscribe '*|*' subscribe-archived '*|*' subscribe-state '*)\n\
         exec sleep 60\n;;\n\
         *)\nprintf '%s\\n' '{{\"ok\":true,\"result\":{{\"messages\":[],\"has_more_before\":false}}}}'\n;;\nesac\n"
    ));
    let mut app = test_tui_app(client, &a);
    app.daemon.running = daemon_running;
    app.accounts.push(AccountRow {
        account_id: b.clone(),
        npub: "npub1bob".to_owned(),
        display_name: None,
        local_signing: true,
    });
    app.messages_account_id = Some(a.clone());
    app.messages_group_id = Some(group.clone());
    app.timeline = vec![timeline_row("original", 1)];
    if pane_is_b {
        app.select_account_by_selector(&b)
            .expect("B list actually loads");
    } else {
        // A background list recovery adopts B's rows without replacing A's
        // loaded pane. Foreground switching now correctly clears A's pane.
        app.selected_account = 1;
        app.enqueue_effect(Effect::Relist {
            account: b.clone(),
            include_archived: false,
        });
        app.settle_effects(1);
    }
    assert_eq!(app.chats[0].name, "B list");
    assert_eq!(app.chats[0].projection.unread_count, 7);
    assert_eq!(app.chats_account_id.as_deref(), Some(b.as_str()));
    if pane_is_b {
        app.settle_effects(1);
    }
    let error = app
        .select_account_by_selector(&a)
        .expect_err("A list fetch fails");
    assert_eq!(error.to_string(), "A refresh failed");
    assert_eq!(app.selected_account_row().unwrap().account_id, a);
    assert_eq!(app.chats[0].name, "B list");
    assert_eq!(app.chats[0].projection.unread_count, 7);
    assert_eq!(
        app.chats_account_id.as_deref(),
        Some(b.as_str()),
        "failed A fetch preserves B owner"
    );
    assert_eq!(
        app.messages_account_id.as_deref(),
        Some(if pane_is_b { b.as_str() } else { a.as_str() })
    );
    (dir, app)
}

#[cfg(unix)]
#[test]
fn relist_recovery_realigns_the_live_account_feeds() {
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    let group = "cc".repeat(32);
    let (_dir, mut app) = chat_list_b_after_failed_return_to_a_with_daemon(true, true);
    assert_eq!(app.chat_subscription.as_ref().unwrap().account_id, b);
    assert_eq!(
        app.notification_subscription.as_ref().unwrap().account_id,
        b
    );
    app.timeline = vec![
        timeline_row("B's previous message", 1),
        timeline_row("B's retained message", 2),
    ];
    app.timeline_scroll.offset = 1;
    app.timeline_scroll.selection = Some(0);
    let timeline = app.timeline.clone();
    let scroll = app.timeline_scroll.clone();
    let timeline_child = app.timeline_subscription.as_ref().unwrap().child.id();
    let message_child = app.message_subscription.as_ref().unwrap().child.id();
    let group_child = app.group_state_subscription.as_ref().unwrap().child.id();
    app.status = "draft saved".to_owned();

    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::Relist {
            account: a.clone(),
            include_archived: false,
        },
        result: Ok(vec![serde_json::json!({"chats":[{
            "group_id":group,"profile":{"name":"A recovered list"},"unread_count":5
        }]})]),
    });

    assert_eq!(app.chats_account_id.as_deref(), Some(a.as_str()));
    assert_eq!(app.chats[0].name, "A recovered list");
    assert_eq!(
        (
            app.chat_subscription
                .as_ref()
                .map(|feed| feed.account_id.as_str()),
            app.notification_subscription
                .as_ref()
                .map(|feed| feed.account_id.as_str()),
        ),
        (Some(a.as_str()), Some(a.as_str())),
        "an accepted complete list must recover both account-wide feeds"
    );
    // The relist itself must preserve the pane and all of its live children.
    // Draining a later chat event has its own existing subscription policy.
    assert_eq!(app.messages_account_id.as_deref(), Some(b.as_str()));
    assert_eq!(app.messages_group_id.as_deref(), Some(group.as_str()));
    assert_eq!(app.timeline, timeline);
    assert_eq!(app.timeline_scroll, scroll);
    assert_eq!(
        app.timeline_subscription.as_ref().unwrap().child.id(),
        timeline_child
    );
    assert_eq!(
        app.message_subscription.as_ref().unwrap().child.id(),
        message_child
    );
    assert_eq!(
        app.group_state_subscription.as_ref().unwrap().child.id(),
        group_child
    );
    assert_eq!(
        app.status, "draft saved",
        "successful ambient repair stays quiet"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.chats[0].name != "A live update" {
        assert!(
            Instant::now() < deadline,
            "A's new chat feed must deliver its update"
        );
        app.drain_chat_subscription();
        thread::yield_now();
    }
    assert_eq!(app.chats[0].projection.unread_count, 9);
    assert!(
        app.chat_subscription
            .as_mut()
            .unwrap()
            .child
            .try_wait()
            .unwrap()
            .is_none()
    );
    assert!(
        app.notification_subscription
            .as_mut()
            .unwrap()
            .child
            .try_wait()
            .unwrap()
            .is_none()
    );
    let chat_child = app.chat_subscription.as_ref().unwrap().child.id();
    let notification_child = app.notification_subscription.as_ref().unwrap().child.id();
    let current_message_child = app.message_subscription.as_ref().unwrap().child.id();
    let current_group_child = app.group_state_subscription.as_ref().unwrap().child.id();
    app.status = "draft saved".to_owned();
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::Relist {
            account: a,
            include_archived: false,
        },
        result: Ok(vec![serde_json::json!({"chats":[{
            "group_id":group,"profile":{"name":"A same-account snapshot"},"unread_count":4
        }]})]),
    });
    assert_eq!(app.chats[0].name, "A same-account snapshot");
    assert_eq!(
        app.chat_subscription.as_ref().unwrap().child.id(),
        chat_child
    );
    assert_eq!(
        app.notification_subscription.as_ref().unwrap().child.id(),
        notification_child
    );
    assert_eq!(app.messages_account_id.as_deref(), Some(b.as_str()));
    assert_eq!(app.messages_group_id.as_deref(), Some(group.as_str()));
    assert_eq!(app.timeline, timeline);
    assert_eq!(app.timeline_scroll, scroll);
    assert_eq!(
        app.timeline_subscription.as_ref().unwrap().child.id(),
        timeline_child
    );
    assert_eq!(
        app.message_subscription.as_ref().unwrap().child.id(),
        current_message_child
    );
    assert_eq!(
        app.group_state_subscription.as_ref().unwrap().child.id(),
        current_group_child
    );
    assert_eq!(
        app.status, "draft saved",
        "successful ambient repair stays quiet"
    );

    // A's real recovered chat feed has adopted A's account-wide stream source,
    // while the retained pane deliberately still belongs to B.
    let foreground_account = app.selected_account_row().unwrap().account_id.clone();
    let (tx, rx) = mpsc::channel();
    app.message_subscription = Some(MessageSubscription {
        account_id: foreground_account.clone(),
        child: test_sleep_child(),
        rx,
    });
    tx.send(SubscriptionEvent::Result(serde_json::json!({
        "type":"agent_stream_delta","agent_stream_delta":{
            "group_id":group,"stream_id":"ff".repeat(32),"text":"foreground account preview"
        }
    })))
    .unwrap();
    assert!(app.drain_message_subscription());
    app.focus = Focus::Messages;
    app.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE))
        .unwrap();
    assert!(app.timeline_scroll.is_pinned());
    assert_eq!(app.messages_account_id.as_deref(), Some(b.as_str()));
    assert!(
        !rendered_buffer(&mut app).contains("foreground account preview"),
        "A's account-wide preview cannot render inside B's retained pane"
    );
    app.refresh_messages().expect("open the recovered A chat");
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadTimeline {
            account: foreground_account.clone(),
            group,
            generation: app.timeline_load_generation,
        },
        result: Ok(vec![serde_json::json!({"messages":[{
            "message_id":"A recovered row","direction":"received","from":"peer",
            "plaintext":"A recovered timeline","timeline_at":3,"received_at":3
        }]})]),
    });
    assert_eq!(
        app.messages_account_id.as_deref(),
        Some(foreground_account.as_str())
    );
    assert!(
        rendered_buffer(&mut app).contains("foreground account preview"),
        "the same observed preview remains visible in its own account's pane"
    );
}

#[cfg(unix)]
#[test]
fn relist_feed_spawn_failure_preserves_the_matching_feed_and_can_recover() {
    let a = "aa".repeat(32);
    let group = "cc".repeat(32);
    for fail_chat in [false, true] {
        for login in [false, true] {
            let (dir, mut app) = chat_list_b_after_failed_return_to_a_with_daemon(true, true);
            let survivor = if fail_chat {
                app.ensure_notification_subscription(&a)
                    .expect("matching notification feed");
                app.notification_subscription.as_ref().unwrap().child.id()
            } else {
                app.ensure_chat_subscription(&a)
                    .expect("matching chat feed");
                app.chat_subscription.as_ref().unwrap().child.id()
            };
            let client = app.client.clone();
            app.client.exe = dir.path().join("missing-wn");
            if login {
                app.screen = Screen::Login(LoginMode::NsecEntry);
            }
            app.set_status(if login {
                "current prompt".to_owned()
            } else {
                String::new()
            });
            app.apply_effect_done(EffectDone {
                status_owner: Some(app.status_ownership.revision),
                effect: Effect::Relist {
                    account: a.clone(),
                    include_archived: false,
                },
                result: Ok(vec![serde_json::json!({"chats":[{"group_id":group}]})]),
            });
            assert_eq!(app.chats_account_id.as_deref(), Some(a.as_str()));
            let status_prefix = if fail_chat {
                assert!(
                    app.chat_subscription.is_none(),
                    "a failed spawn drops the stale feed"
                );
                assert_eq!(
                    app.notification_subscription.as_ref().unwrap().child.id(),
                    survivor
                );
                "chat subscription failed: "
            } else {
                assert!(
                    app.notification_subscription.is_none(),
                    "a failed spawn drops the stale filter"
                );
                assert_eq!(app.chat_subscription.as_ref().unwrap().child.id(), survivor);
                "notification subscription failed: "
            };
            if login {
                assert_eq!(
                    app.status, "current prompt",
                    "background failure preserves login guidance"
                );
            } else {
                assert!(
                    app.status.starts_with(status_prefix),
                    "actual subscription failure: {}",
                    app.status
                );
            }
            app.client = client;
            app.apply_effect_done(EffectDone {
                status_owner: Some(app.status_ownership.revision),
                effect: Effect::Relist {
                    account: a.clone(),
                    include_archived: false,
                },
                result: Ok(vec![serde_json::json!({"chats":[{"group_id":group}]})]),
            });
            assert_eq!(app.chat_subscription.as_ref().unwrap().account_id, a);
            assert_eq!(
                app.notification_subscription.as_ref().unwrap().account_id,
                a
            );
            let retained = if fail_chat {
                app.notification_subscription.as_ref().unwrap().child.id()
            } else {
                app.chat_subscription.as_ref().unwrap().child.id()
            };
            assert_eq!(
                retained, survivor,
                "retry leaves the already matching feed in place"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn relist_feed_recovery_respects_daemon_and_local_signing_lifecycle() {
    let a = "aa".repeat(32);
    let group = "cc".repeat(32);
    for public_only in [false, true] {
        let (_dir, mut app) = chat_list_b_after_failed_return_to_a_with_daemon(true, true);
        if public_only {
            app.accounts[0].local_signing = false;
            app.refresh_chats()
                .expect("public-only refresh clears stale state");
        } else {
            app.stop_daemon()
                .expect("stop the daemon through its command owner");
        }
        let status = app.status.clone();
        app.apply_effect_done(EffectDone {
            status_owner: Some(app.status_ownership.revision),
            effect: Effect::Relist {
                account: a.clone(),
                include_archived: false,
            },
            result: Ok(vec![serde_json::json!({"chats":[{"group_id":group}]})]),
        });
        assert!(app.chat_subscription.is_none());
        assert!(app.notification_subscription.is_none());
        assert_eq!(app.status, status);
        if public_only {
            assert!(
                app.chats.is_empty(),
                "a late local result cannot repopulate public-only state"
            );
            assert!(app.chats_account_id.is_none());
        } else {
            assert_eq!(app.chats_account_id.as_deref(), Some(a.as_str()));
        }
    }
}

#[cfg(unix)]
#[test]
fn chat_feed_mutations_follow_loaded_data_owner_after_a_failed_account_switch() {
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    let group = "cc".repeat(32);
    for producer in [&a, &b] {
        let (_dir, mut app) = chat_list_b_after_failed_return_to_a(false);
        let original = app.chats.clone();
        let (tx, rx) = mpsc::channel();
        app.chat_subscription = Some(ChatSubscription {
            account_id: producer.clone(),
            include_archived: false,
            child: test_sleep_child(),
            rx,
        });
        tx.send(SubscriptionEvent::Result(serde_json::json!({"type":"chat","chat":{
            "group_id":group,"profile":{"name":"incoming"},"unread_count":1,
            "has_unread":true,"activity_sort_at":40,"last_message":{"plaintext":"incoming preview","timeline_at":40}
        }}))).expect("external chat update");
        assert!(app.drain_chat_subscription());
        if producer == &b {
            assert_eq!(app.chats[0].name, "incoming");
            assert_eq!(app.chats[0].projection.unread_count, 1);
        } else {
            assert_eq!(
                app.chats, original,
                "A feed must not merge into B's retained list"
            );
        }
        // Newer foreground feedback survives errors, while lifecycle cleanup
        // and idle error reporting remain independent of the retained line.
        let foreground = app.status.clone();
        tx.send(SubscriptionEvent::Error("older feed error".to_owned()))
            .unwrap();
        assert!(app.drain_chat_subscription());
        assert_eq!(app.status, foreground);
        app.set_status(String::new());
        tx.send(SubscriptionEvent::Error("feed offline".to_owned()))
            .expect("error");
        tx.send(SubscriptionEvent::Ended).expect("end");
        assert!(app.drain_chat_subscription());
        assert_eq!(app.status, "chat subscription failed: feed offline");
        assert!(app.chat_subscription.is_none());
    }
}

#[cfg(unix)]
#[test]
fn timeline_feed_scopes_list_projection_independently_of_its_loaded_pane() {
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    let group = "cc".repeat(32);
    for producer in [&a, &b] {
        let (_dir, mut app) = chat_list_b_after_failed_return_to_a(producer == &b);
        let original = app.chats.clone();
        let (tx, rx) = mpsc::channel();
        app.timeline_subscription = Some(TimelineSubscription {
            account_id: producer.clone(),
            group_id: group.clone(),
            child: test_sleep_child(),
            rx,
        });
        tx.send(SubscriptionEvent::Result(serde_json::json!({
            "type":"timeline_projection_updated","group_id":group,
            "chat_list_row":{"unread_count":1,"has_unread":true,"activity_sort_at":40},
            "changes":[{"type":"upsert","message":{"message_id":"incoming","direction":"received",
                "from":"sender","plaintext":"pane update","timeline_at":2,"received_at":2}}]
        })))
        .expect("external timeline update");
        assert!(app.drain_timeline_subscription());
        assert!(
            timeline_ids(&app.timeline).contains(&"incoming"),
            "the owning pane still receives its row"
        );
        assert!(
            app.pending_mark_read,
            "reading the owning pane still schedules its read marker"
        );
        if producer == &b {
            assert_eq!(app.chats[0].projection.unread_count, 1);
        } else {
            assert_eq!(
                app.chats, original,
                "A timeline must not rewrite B list projection"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn complete_relist_replaces_and_reowns_a_retained_other_account_list() {
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    let group = "cc".repeat(32);
    let (_dir, mut app) = chat_list_b_after_failed_return_to_a(false);
    let retained = app.chats.clone();
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::Relist {
            account: a.clone(),
            include_archived: false,
        },
        result: Err("relist failed".to_owned()),
    });
    assert_eq!(app.chats, retained);
    assert_eq!(app.chats_account_id.as_deref(), Some(b.as_str()));
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::Relist {
            account: a.clone(),
            include_archived: false,
        },
        result: Ok(vec![
            serde_json::json!({"chats":[{"group_id":group,"profile":{"name":"A relist"},
            "unread_count":5,"has_unread":true}]}),
        ]),
    });
    assert_eq!(app.chats[0].name, "A relist");
    assert_eq!(app.chats_account_id.as_deref(), Some(a.as_str()));
    for (producer, expected) in [(b, 5), (a, 0)] {
        app.apply_effect_done(EffectDone {
            status_owner: Some(app.status_ownership.revision),
            effect: Effect::MarkRead {
                account: producer,
                group: group.clone(),
            },
            result: Ok(vec![
                serde_json::json!({"unread_count":0,"has_unread":false}),
            ]),
        });
        assert_eq!(
            app.chats[0].projection.unread_count, expected,
            "incremental admission follows the full replacement's producer"
        );
    }
}

#[cfg(unix)]
#[test]
fn complete_relist_can_recover_an_initial_failed_load_without_an_owner() {
    use clap::Parser;
    let a = "aa".repeat(32);
    let group = "cc".repeat(32);
    let response = serde_json::json!({"ok":true,"result":{
        "accounts":[{"account_id":a,"npub":"npub1alice","local_signing":true}],
        "chats":[{"group_id":group,"profile":{"name":"initial retry"},"unread_count":5,"has_unread":true}]
    }}).to_string();
    let (_good_dir, client) = test_json_client(&response);
    let mut app = TuiApp::new(Cli::parse_from(["wn", "tui"])).expect("real empty constructor");
    app.client = client.clone();
    app.effects = EffectRunner::spawn(client.clone());
    app.load_accounts().expect("actual account list");
    assert!(app.chats_account_id.is_none());
    let (_bad_dir, failure) =
        test_json_client(r#"{"ok":false,"error":{"message":"initial list failed"}}"#);
    app.client = failure;
    assert_eq!(
        app.refresh_chats()
            .expect_err("initial load fails")
            .to_string(),
        "initial list failed"
    );
    assert!(app.chats.is_empty());
    assert!(app.chats_account_id.is_none());
    app.client = client;
    app.pending_chat_relist = true;
    assert!(
        app.tick(),
        "a selected-account retry is eligible without a loaded owner"
    );
    assert!(!app.pending_chat_relist);
    app.settle_effects(1);
    assert_eq!(app.chats[0].name, "initial retry");
    assert_eq!(app.chats_account_id.as_deref(), Some(a.as_str()));
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::MarkRead { account: a, group },
        result: Ok(vec![
            serde_json::json!({"unread_count":0,"has_unread":false}),
        ]),
    });
    assert_eq!(app.chats[0].projection.unread_count, 0);
}

#[cfg(unix)]
#[test]
fn chat_list_owner_clears_with_account_removal_or_public_only_refresh() {
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    for public_only in [false, true] {
        let (_dir, mut app) = chat_list_b_after_failed_return_to_a(false);
        let accounts = if public_only {
            serde_json::json!([{"account_id":a,"npub":"npub1alice","local_signing":false}])
        } else {
            serde_json::json!([])
        };
        let response = serde_json::json!({"ok":true,"result":{"accounts":accounts}}).to_string();
        let (_accounts_dir, client) = test_json_client(&response);
        app.client = client;
        app.load_accounts().expect("actual changed account list");
        if public_only {
            assert_eq!(
                app.chats_account_id.as_deref(),
                Some(b.as_str()),
                "account discovery alone does not reown retained rows"
            );
            app.refresh_chats()
                .expect("public-only account clears chat state");
        } else {
            assert!(app.accounts.is_empty());
            app.refresh_chats()
                .expect("no selection keeps chat state clear");
        }
        assert!(app.chats.is_empty());
        assert!(app.chats_account_id.is_none());
        assert!(app.messages_account_id.is_none());
        assert!(app.chat_subscription.is_none());
    }
}

#[cfg(unix)]
#[test]
fn a_search_completion_settles_after_its_chat_feed_removes_the_loaded_pane() {
    let a = "aa".repeat(32);
    let group = "cc".repeat(32);
    let (_dir, mut app) = chat_list_b_after_failed_return_to_a(false);
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::Relist {
            account: a.clone(),
            include_archived: false,
        },
        result: Ok(vec![
            serde_json::json!({"chats":[{"group_id":group,"profile":{"name":"A list"}}]}),
        ]),
    });
    app.open_message_search(Some("hello".to_owned()))
        .expect("search the loaded A pane");
    let (tx, rx) = mpsc::channel();
    app.chat_subscription = Some(ChatSubscription {
        account_id: a,
        include_archived: false,
        child: test_sleep_child(),
        rx,
    });
    tx.send(SubscriptionEvent::Result(
        serde_json::json!({"type":"chat","chat":{
            "group_id":group,"profile":{"name":"A list"},"archived":true
        }}),
    ))
    .expect("the owning chat becomes hidden");
    assert!(app.drain_chat_subscription());
    assert!(app.messages_group_id.is_none());
    assert_eq!(
        app.status, "searching...",
        "search screen suppresses ambient feed status"
    );
    // The real A search completes against the now-removed pane. The background
    // B list was already folded by the fixture; no other effect is outstanding.
    app.settle_effects(1);
    assert!(app.searching_messages.is_none());
    assert_eq!(app.status, "");
    assert!(!rendered_buffer(&mut app).contains("searching..."));
}

#[test]
fn group_diagnostic_completions_belong_to_the_loaded_account_and_group() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let group = "cc".repeat(32);
    for (pane_account, pane_group, applies) in [
        (account_b.as_str(), group.as_str(), false),
        (
            account_a.as_str(),
            "dddddddddddddddddddddddddddddddd",
            false,
        ),
        (account_a.as_str(), group.as_str(), true),
    ] {
        for fails in [false, true] {
            let mut app = test_tui_app(test_unused_client(), &account_b);
            app.accounts.push(AccountRow {
                account_id: account_a.clone(),
                npub: "npub1alice".to_owned(),
                display_name: None,
                local_signing: true,
            });
            app.messages_account_id = Some(pane_account.to_owned());
            app.messages_group_id = Some(pane_group.to_owned());
            let previous = GroupDiagnostics::unavailable(pane_group, "current diagnostics");
            app.group_diagnostics = Some(previous.clone());
            app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
                effect: Effect::GroupDiagnostics { account: account_a.clone(), group: group.clone() },
                result: if fails { Err("diagnostics failed".to_owned()) } else {
                    Ok(vec![serde_json::json!({"group":{"group_id":group},"mls":{"epoch":7,"member_count":2}})])
                },
            });
            let actual = app.group_diagnostics.as_ref().expect("diagnostics");
            if !applies {
                assert_eq!(actual, &previous);
            } else if fails {
                assert_eq!(actual.error.as_deref(), Some("diagnostics failed"));
            } else {
                assert_eq!(actual.epoch, Some(7));
            }
        }
    }
}

#[test]
fn group_detail_completions_do_not_replace_a_new_accounts_same_group_view() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let group = "cc".repeat(32);
    for selected in [&account_b, &account_a] {
        for fails in [false, true] {
            let mut app = test_tui_app(test_unused_client(), selected);
            app.screen = Screen::GroupDetail;
            app.loading_group_detail = Some(group.clone());
            app.status = LOADING_GROUP_DETAIL_STATUS.to_owned();
            app.apply_effect_done(EffectDone {
                status_owner: Some(app.status_ownership.revision),
                effect: Effect::LoadGroupDetail {
                    account: account_a.clone(),
                    group: group.clone(),
                },
                result: if fails {
                    Err("detail failed".to_owned())
                } else {
                    Ok(vec![
                        serde_json::json!({"members":[{"member_id":account_a,"npub":"npubself"}]}),
                        serde_json::json!({"admins":[]}),
                        serde_json::json!({"relays":[]}),
                        serde_json::json!({"profile":{"name":"Account A detail"}}),
                    ])
                },
            });
            if selected == &account_b {
                assert!(app.group_detail.is_none());
                assert_eq!(app.status, LOADING_GROUP_DETAIL_STATUS);
                assert_eq!(app.loading_group_detail.as_deref(), Some(group.as_str()));
            } else if fails {
                assert_eq!(app.status, "error: detail failed");
            } else {
                assert_eq!(
                    app.group_detail.as_ref().expect("detail").name,
                    "Account A detail"
                );
            }
        }
    }
}

#[test]
fn user_search_completions_preserve_a_new_accounts_identical_query() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    for selected in [&account_b, &account_a] {
        for fails in [false, true] {
            let mut app = test_tui_app(test_unused_client(), selected);
            app.open_user_search(Some("alice".to_owned()));
            app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
                effect: Effect::UserSearch { account: account_a.clone(), query: "alice".to_owned() },
                result: if fails { Err("search failed".to_owned()) } else { Ok(vec![
                    serde_json::json!({"users":[{"account_id_hex":"dd","npub":"npubdd","radius":1,"matched_field":"name","match_quality":"exact"}]}),
                    serde_json::json!({"follows":[{"account_id":"dd"}]}),
                ]) },
            });
            let view = app.user_search.as_ref().expect("search view");
            if selected == &account_b {
                assert!(view.results.is_empty());
                assert_eq!(app.status, "searching...");
                assert_eq!(app.searching_users.as_deref(), Some("alice"));
            } else {
                assert!(app.searching_users.is_none());
                if fails {
                    assert_eq!(app.status, "error: search failed");
                } else {
                    assert_eq!(view.results.len(), 1);
                    assert!(view.results[0].following);
                }
            }
        }
    }
}

#[test]
fn message_search_completions_preserve_a_new_panes_identical_query() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let group = "cc".repeat(32);
    for (pane_account, pane_group, applies) in [
        (account_b.as_str(), group.as_str(), false),
        (
            account_a.as_str(),
            "dddddddddddddddddddddddddddddddd",
            false,
        ),
        (account_a.as_str(), group.as_str(), true),
    ] {
        for fails in [false, true] {
            // Selection may differ from the loaded pane after a failed refresh;
            // message search deliberately resolves its account from that pane.
            let mut app = test_tui_app(test_unused_client(), &account_b);
            app.accounts.push(AccountRow {
                account_id: account_a.clone(),
                npub: "npub1alice".to_owned(),
                display_name: None,
                local_signing: true,
            });
            app.messages_account_id = Some(pane_account.to_owned());
            app.messages_group_id = Some(pane_group.to_owned());
            app.open_message_search(Some("hello".to_owned()))
                .expect("open search");
            app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
                effect: Effect::MessageSearch { account: account_a.clone(), group: group.clone(), query: "hello".to_owned() },
                result: if fails { Err("search failed".to_owned()) } else {
                    Ok(vec![serde_json::json!({"messages":[{"message_id":"hit","direction":"received","from":"d","plaintext":"hello","timeline_at":1,"received_at":1}],"has_more_before":true})])
                },
            });
            let view = app.message_search.as_ref().expect("search view");
            if !applies {
                assert!(view.results.is_empty());
                assert_eq!(app.status, "searching...");
                assert_eq!(
                    app.searching_messages
                        .as_ref()
                        .map(|(_, _, query)| query.as_str()),
                    Some("hello")
                );
            } else {
                assert!(app.searching_messages.is_none());
                if fails {
                    assert_eq!(app.status, "error: search failed");
                } else {
                    assert_eq!(view.results[0].message_id, "hit");
                    assert!(view.truncated);
                }
            }
        }
    }
}

#[test]
fn a_message_search_settles_its_own_request_when_the_loaded_pane_changes() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let group = "cc".repeat(32);
    for fails in [false, true] {
        let mut app = test_tui_app(test_unused_client(), &account_a);
        app.daemon.running = false;
        app.accounts.push(AccountRow {
            account_id: account_b.clone(),
            npub: "npub1bob".to_owned(),
            display_name: None,
            local_signing: true,
        });
        app.messages_account_id = Some(account_a.clone());
        app.messages_group_id = Some(group.clone());
        app.open_message_search(Some("hello".to_owned()))
            .expect("search A pane");
        app.selected_account = 1;
        app.chats = vec![projected_chat(&group, "general", 0, Some(10))];
        app.begin_timeline_load(account_b.clone(), group.clone());
        // A's search completes first in the worker's FIFO, after opening B
        // cleared the pane but before B's timeline has loaded.
        assert!(app.messages_account_id.is_none());
        // Unlike the replacement-query table, no B search has been submitted.
        let current_status = app.status.clone();
        assert!(rendered_buffer(&mut app).contains("searching..."));
        app.apply_effect_done(EffectDone {
            status_owner: Some(app.status_ownership.revision),
            effect: Effect::MessageSearch {
                account: account_a.clone(),
                group: group.clone(),
                query: "hello".to_owned(),
            },
            result: if fails {
                Err("old search failed".to_owned())
            } else {
                Ok(vec![
                    serde_json::json!({"messages":[],"has_more_before":false}),
                ])
            },
        });
        assert!(
            app.message_search
                .as_ref()
                .expect("view")
                .results
                .is_empty()
        );
        assert!(
            app.searching_messages.is_none(),
            "the completed request owns this pending anchor"
        );
        assert_eq!(
            app.status, current_status,
            "the pane load owns the current status"
        );
        assert!(
            !rendered_buffer(&mut app).contains("searching..."),
            "completed work cannot leave the search spinner stranded"
        );
        app.apply_effect_done(EffectDone {
            status_owner: Some(app.status_ownership.revision),
            effect: Effect::LoadTimeline {
                account: account_b.clone(),
                group: group.clone(),
                generation: app.timeline_load_generation,
            },
            result: Ok(vec![
                serde_json::json!({"messages":[],"has_more_before":false}),
            ]),
        });
        assert_eq!(app.messages_account_id.as_deref(), Some(account_b.as_str()));
    }
}

#[test]
fn mark_read_failure_keeps_the_badge_honest() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    // Both production enqueue paths capture the loaded pane's account/group:
    // tick reads these fields, and fold_load_timeline sets them before enqueue.
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some(group_id.clone());
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

    // A failed mark-read folds honestly: it never zeroes the badge locally and
    // re-arms so the next tick retries.
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::MarkRead {
            account: account_id,
            group: group_id,
        },
        result: Err("daemon gone".to_owned()),
    });

    assert_eq!(
        app.chats[0].projection.unread_count, 5,
        "a failed mark-read never zeroes the badge locally"
    );
    assert!(
        app.pending_mark_read,
        "a failed mark-read re-arms for the next tick"
    );
    assert!(
        app.status.contains("mark-read failed"),
        "the error still surfaces on the status line: {}",
        app.status
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
    assert_eq!(
        scroll.selection, None,
        "removing the last row resets selection"
    );
    assert_eq!(scroll.resolved_selection(0), None);
    scroll.on_insert(0, 1);
    assert_eq!(scroll.resolved_selection(1), Some(0));
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

/// As `media_ready_image_with_picker`, but with a source large enough (in
/// halfblock cells, font 10x20) that `Resize::Fit` must downscale it *differently*
/// for the small inline block than for the full-size popup. A small source fits
/// without upscaling and renders at one natural size in both, which would mask
/// both a reused-protocol re-resize (item 1) and whether the popup card itself
/// drew anything (item 2). 700x560 is ~70x28 cells: taller than the 8-row inline
/// block and the ~21-row popup, so both downscale it and the popup image fills its
/// card with glyphs.
fn media_ready_large_varied_image(picker: ratatui_image::picker::Picker, hash: &str) -> MediaState {
    let mut media = MediaState::with_test_picker(picker);
    let mut buffer = image::RgbImage::new(700, 560);
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
    let tx = media.begin_download("cafebabe".to_owned());
    for _ in 0..2 {
        tx.send(MediaLoad::Decoded {
            hash: "cafebabe".to_owned(),
            image: Box::new(image::DynamicImage::new_rgb8(2, 2)),
        })
        .expect("decoded result");
    }
    assert!(media.drain(), "the real worker channel is folded");
    assert!(media.is_ready("cafebabe"));
    assert!(media.protocol_mut("cafebabe").is_some());
    // Filling the remaining viewer slots must not evict the duplicated hash:
    // replaying a decode refreshes that image without consuming a second slot.
    for index in 1..MEDIA_VIEWER_RETAINED_IMAGES {
        tx.send(MediaLoad::Decoded {
            hash: format!("other-{index}"),
            image: Box::new(image::DynamicImage::new_rgb8(2, 2)),
        })
        .expect("another decoded result");
    }
    assert!(media.drain());
    assert!(media.build_viewer_protocol("cafebabe"));
    assert!(!media.drain(), "an empty drain does not dirty the frame");
}

#[cfg(unix)]
#[test]
fn media_scheduler_uses_the_loaded_owner_and_real_worker_slots() {
    let dir = tempfile::tempdir().unwrap();
    let hashes = [
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32),
        "44".repeat(32),
    ];
    let account = "aa".repeat(32);
    let group = "bb".repeat(16);
    let args = dir.path().join("args");
    let png = dir.path().join("source.png");
    seed_decodable_image(&png);
    let mut gates = Vec::new();
    for index in 0..4 {
        let gate_dir = dir.path().join(format!("gate-{index}"));
        std::fs::create_dir(&gate_dir).unwrap();
        gates.push(TestCommandGate::new(&gate_dir));
    }
    let exe = dir.path().join("wn-media");
    let mut script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in\n",
        args.display()
    );
    for (hash, gate) in hashes.iter().zip(&gates) {
        // A duplicate-worker fault must not leave two readers waiting on one
        // release. Only its first child enters the explicit gate.
        script.push_str(&format!(
            "*{hash}*)\nif mkdir '{}' 2>/dev/null; then\n{}fi\n;;\n",
            dir.path().join(format!("gated-{hash}")).display(),
            gate.script()
        ));
    }
    script.push_str(&format!("esac\nwhile [ \"$1\" != --output ]; do shift; done\nshift\ncp '{}' \"$1\"\nprintf '%s\\n' '{{\"ok\":true,\"result\":{{}}}}'\n", png.display()));
    write_fake_wn(&exe, &script);
    let mut app = test_tui_app(
        WnClient {
            exe,
            home: Some(dir.path().join("home")),
            secret_store: Some(SecretStoreKind::File),
            ..test_unused_client()
        },
        &"cc".repeat(32),
    );
    app.daemon.running = false;
    app.chats = vec![flick_chat(&"dd".repeat(16), "Selected other room")];
    app.messages_account_id = Some(account.clone());
    app.messages_group_id = Some(group.clone());
    let mut row = timeline_row("image-row", 1);
    row.attachments = vec![
        image_attachment(&hashes[0]),
        image_attachment(&hashes[0]),
        image_attachment(&hashes[1]),
        image_attachment(&hashes[2]),
        image_attachment(&hashes[3]),
        TimelineAttachment {
            mime: Some("application/pdf".into()),
            filename: Some("file.pdf".into()),
            plaintext_hash: Some("55".repeat(32)),
        },
    ];
    app.timeline = vec![row];
    assert!(
        !app.ensure_media_downloads(),
        "a terminal without image support does not schedule children"
    );
    app.media = MediaState::with_test_picker(ratatui_image::picker::Picker::halfblocks());
    assert!(app.ensure_media_downloads());
    for gate in &gates[..3] {
        gate.wait_until_entered();
    }
    assert_eq!(app.media.in_flight(), 3);
    assert!(
        !app.ensure_media_downloads(),
        "a repeated tick cannot exceed the occupied slots"
    );
    let recorded = std::fs::read_to_string(&args).unwrap();
    assert_eq!(recorded.lines().count(), 3);
    for (index, gate) in gates[..3].iter_mut().enumerate() {
        assert!(recorded.lines().any(|line| line.contains(&hashes[index])));
        gate.release();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !hashes[..3].iter().all(|hash| app.media.is_ready(hash)) {
        app.media.drain();
        assert!(
            Instant::now() < deadline,
            "first three produced image results never settled"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        app.ensure_media_downloads(),
        "a completed worker admits the remaining image"
    );
    gates[3].wait_until_entered();
    gates[3].release();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !app.media.is_ready(&hashes[3]) {
        app.media.drain();
        assert!(
            Instant::now() < deadline,
            "fourth produced image result never settled"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert!(!app.ensure_media_downloads());
    let recorded = std::fs::read_to_string(args).unwrap();
    let cache = dir.path().join("home/tui-media-cache");
    let mut actual = recorded.lines().map(str::to_owned).collect::<Vec<_>>();
    actual.sort();
    let mut expected = hashes.iter().map(|hash| format!("--json --home {} --secret-store file --account {account} media download {group} {hash} --output {}", dir.path().join("home").display(), cache.join(hash).display())).collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected);
    assert_eq!(app.media.in_flight(), 0);
    assert_eq!(
        std::fs::read_dir(cache).unwrap().count(),
        0,
        "decoded plaintext artifacts are removed before results settle"
    );
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
fn media_images_downscale_with_a_smoothing_filter_not_nearest() {
    // Sparse nearest-neighbor samples alias this high-frequency image to black
    // or white. A smoothing filter preserves its average brightness in the
    // actual halfblock cells the production widget draws.
    // Match the halfblock picker's 10x20 font aspect so both half-cells sample
    // image pixels rather than the background padding of an aspect-fit image.
    let checker = image::RgbImage::from_fn(80, 160, |x, y| {
        let value = if (x + y) % 2 == 0 { 0 } else { 255 };
        image::Rgb([value; 3])
    });
    let mut protocol = ratatui_image::picker::Picker::halfblocks()
        .new_resize_protocol(image::DynamicImage::ImageRgb8(checker));
    let area = Rect::new(0, 0, 1, 1);
    let mut buffer = ratatui::buffer::Buffer::empty(area);
    ratatui::widgets::StatefulWidget::render(
        media_image_widget(),
        area,
        &mut buffer,
        &mut protocol,
    );
    let cell = &buffer[(0, 0)];
    // Equal upper/lower pixels legitimately render as a colored space; its
    // foreground is invisible, so only the background is part of that sample.
    let visible_colors = if cell.symbol() == " " {
        vec![cell.bg]
    } else {
        vec![cell.fg, cell.bg]
    };
    for color in visible_colors {
        let Color::Rgb(red, green, blue) = color else {
            panic!("expected sampled RGB pixels, got {color:?}");
        };
        assert!(
            (80..=180).contains(&red),
            "checkerboard average was lost: {color:?}"
        );
        assert_eq!((red, red), (green, blue));
    }
}

#[test]
fn oversized_decodes_are_capped_to_the_screen_bound_preserving_aspect() {
    // A decoded image is kept in memory for the rest of the session (the inline
    // protocol retains it, and pixel-capable terminals retain a viewer copy), so
    // an unbounded camera photo would cost its full pixel area forever. Anything
    // beyond the largest plausible terminal display area is downscaled at decode
    // time; smaller images pass through untouched.
    let huge = image::DynamicImage::new_rgb8(2103, 1402);
    let capped = cap_decoded_image(huge);
    assert_eq!(
        (capped.width(), capped.height()),
        (2100, 1400),
        "a 3:2 photo larger than the cap lands exactly on the cap box"
    );

    let portrait = image::DynamicImage::new_rgb8(467, 1401);
    let capped = cap_decoded_image(portrait);
    assert!(
        capped.width() <= 2100 && capped.height() <= 1400,
        "portrait images fit inside the cap box too, got {}x{}",
        capped.width(),
        capped.height()
    );
    assert_eq!(
        (capped.width() as f64 / capped.height() as f64 * 3.0).round(),
        1.0,
        "the 1:3 portrait aspect survives the cap"
    );

    let small = image::DynamicImage::new_rgb8(800, 600);
    let untouched = cap_decoded_image(small);
    assert_eq!(
        (untouched.width(), untouched.height()),
        (800, 600),
        "images already inside the cap are never resized (Fit would upscale)"
    );
}

#[cfg(unix)]
#[test]
fn media_worker_delivers_oversized_images_already_capped() {
    // The cap must run on the worker thread (off the 50ms event loop) before the
    // decoded image is delivered, so no oversized pixel buffer ever crosses the
    // channel or reaches the reducer.
    let dir = tempfile::tempdir().expect("tempdir");
    let wn = test_json_executable(dir.path(), r#"{"ok":true}"#);
    let output_path = dir.path().join("deadbeef");
    let mut encoded = std::io::Cursor::new(Vec::new());
    // Wider than the cap box but with a small pixel area, so the unoptimized
    // test-build decode+resize stays well inside the worker harness timeout.
    image::DynamicImage::new_rgb8(2150, 200)
        .write_to(&mut encoded, image::ImageFormat::Png)
        .expect("encode png");
    std::fs::write(&output_path, encoded.into_inner()).expect("seed decrypted file");

    let result = run_media_worker(&wn, output_path);

    match result {
        MediaLoad::Decoded { image, .. } => {
            assert!(
                image.width() <= 2100 && image.height() <= 1400,
                "the worker caps before delivery, got {}x{}",
                image.width(),
                image.height()
            );
        }
        _ => panic!("a valid image decodes"),
    }
}

#[test]
fn pixel_capable_terminal_builds_a_native_viewer_protocol_on_demand() {
    // On a terminal whose startup query reported a pixel protocol, the inline
    // timeline stays cell-exact halfblocks (the adopt chokepoint), but the
    // full-size viewer popup can draw the real image: the queried pixel
    // capability is remembered, decoded pixels are retained in memory, and a
    // native-protocol instance is built on demand when the viewer opens.
    let mut picker = ratatui_image::picker::Picker::halfblocks();
    picker.set_protocol_type(ratatui_image::picker::ProtocolType::Kitty);
    let mut media = media_ready_image_with_picker(picker, "cafebabe");

    assert!(
        media.build_viewer_protocol("cafebabe"),
        "a pixel-capable terminal builds a native viewer protocol"
    );
    let protocol = media
        .viewer_protocol_mut("cafebabe")
        .expect("the built viewer protocol is drawable");
    assert!(
        matches!(
            protocol.protocol_type(),
            ratatui_image::protocol::StatefulProtocolType::Kitty(_)
        ),
        "the viewer draws the terminal's native pixel protocol, not halfblocks"
    );
}

#[test]
fn halfblock_only_terminal_builds_a_dedicated_halfblock_viewer_protocol() {
    // Terminals whose query reported no pixel protocol still get a *dedicated*
    // popup protocol — a fresh cell-exact halfblock instance built from the
    // retained pixels — rather than reusing the shared inline protocol. It is a
    // distinct instance, so drawing it at popup size never re-resizes the inline
    // block's protocol.
    let mut media = media_with_ready_image("cafebabe");
    assert!(
        media.build_viewer_protocol("cafebabe"),
        "a halfblock-only terminal builds its own dedicated popup protocol"
    );
    let protocol = media
        .viewer_protocol_mut("cafebabe")
        .expect("the dedicated halfblock viewer protocol is drawable");
    assert!(
        matches!(
            protocol.protocol_type(),
            ratatui_image::protocol::StatefulProtocolType::Halfblocks(_)
        ),
        "the dedicated fallback popup protocol stays cell-exact halfblocks"
    );
}

#[test]
fn iterm2_session_viewer_protocol_is_iterm2_even_when_queried_as_kitty() {
    // iTerm2 answers the startup capability query kitty-style and is misdetected
    // as Kitty — the original reason inline rendering forces halfblocks. iTerm2's
    // kitty-graphics support is not the real thing, so inside an iTerm2 session
    // the viewer must use iTerm2's own inline-image protocol.
    let mut picker = ratatui_image::picker::Picker::halfblocks();
    picker.set_protocol_type(ratatui_image::picker::ProtocolType::Kitty);
    let mut media = MediaState::with_test_picker_in_iterm2_session(picker);
    media.apply_for_test(MediaLoad::Decoded {
        hash: "cafebabe".to_owned(),
        image: Box::new(image::DynamicImage::new_rgb8(40, 40)),
    });

    assert!(media.build_viewer_protocol("cafebabe"));
    let protocol = media
        .viewer_protocol_mut("cafebabe")
        .expect("viewer protocol built");
    assert!(
        matches!(
            protocol.protocol_type(),
            ratatui_image::protocol::StatefulProtocolType::ITerm2(_)
        ),
        "an iTerm2 session viewer draws OSC 1337, not misdetected kitty graphics"
    );
}

#[test]
fn viewer_retention_evicts_oldest_and_falls_back_to_the_halfblock_popup() {
    // Retained viewer pixels are bounded: decoding one image past the cap
    // evicts the oldest. The evicted image's viewer degrades honestly — no
    // native protocol, so the popup draws the shared halfblock protocol — while
    // the newest images keep their crisp native viewer. Re-decoding a hash must
    // refresh in place, not double-count it toward the cap.
    let mut picker = ratatui_image::picker::Picker::halfblocks();
    picker.set_protocol_type(ratatui_image::picker::ProtocolType::Kitty);
    let mut media = MediaState::with_test_picker(picker);
    let decode = |media: &mut MediaState, hash: &str| {
        media.apply_for_test(MediaLoad::Decoded {
            hash: hash.to_owned(),
            image: Box::new(image::DynamicImage::new_rgb8(4, 4)),
        });
    };

    for hash in ["h1", "h2", "h3", "h4"] {
        decode(&mut media, hash);
    }
    decode(&mut media, "h2"); // refresh, not a new retention slot
    assert!(
        media.build_viewer_protocol("h1"),
        "a duplicate decode must not evict anything"
    );

    decode(&mut media, "h5"); // one past the cap of 4: h1 is evicted
    assert!(
        !media.build_viewer_protocol("h1"),
        "the oldest image is evicted and its viewer falls back to halfblocks"
    );
    assert!(media.is_ready("h1"), "the inline halfblock render survives");
    for hash in ["h2", "h3", "h4", "h5"] {
        assert!(
            media.build_viewer_protocol(hash),
            "{hash} stays retained for the native viewer"
        );
    }
}

/// A pixel-capable (iTerm2 session, kitty-misdetected) media state with one
/// decoded, ready image, mirroring `media_with_ready_image` for the viewer path.
fn iterm2_media_with_ready_image(hash: &str) -> MediaState {
    let mut picker = ratatui_image::picker::Picker::halfblocks();
    picker.set_protocol_type(ratatui_image::picker::ProtocolType::Kitty);
    let mut media = MediaState::with_test_picker_in_iterm2_session(picker);
    media.apply_for_test(MediaLoad::Decoded {
        hash: hash.to_owned(),
        image: Box::new(image::DynamicImage::new_rgb8(40, 40)),
    });
    media
}

#[test]
fn o_opens_a_native_pixel_viewer_on_a_pixel_capable_terminal() {
    // On a terminal with a real pixel protocol, `o` shows the actual image: the
    // viewer popup draws a native-protocol instance (here iTerm2's OSC 1337
    // inline image) instead of the low-resolution halfblock cells. The inline
    // timeline behind it stays cell-exact (pinned elsewhere).
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Messages;
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![image_attachment("cafebabe")];
    app.timeline = vec![row];
    app.media = iterm2_media_with_ready_image("cafebabe");

    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE))
        .expect("open viewer");

    assert!(
        matches!(app.popup, Some(Popup::Image { .. })),
        "o opens the image viewer popup"
    );
    assert!(
        app.media.viewer_protocol_mut("cafebabe").is_some(),
        "opening the viewer builds the native protocol on demand"
    );
    let rendered = rendered_buffer(&mut app);
    assert!(
        rendered.contains("1337"),
        "the viewer popup draws the terminal's native pixel protocol"
    );
}

#[test]
fn o_falls_back_to_the_halfblock_viewer_without_a_pixel_protocol() {
    // Halfblock-only terminal: `o` opens the viewer popup, which draws its own
    // dedicated cell-exact halfblock protocol — never a pixel escape.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Messages;
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![image_attachment("cafebabe")];
    app.timeline = vec![row];
    app.media = media_with_ready_image("cafebabe");

    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE))
        .expect("open viewer");

    assert!(
        matches!(app.popup, Some(Popup::Image { .. })),
        "o opens the image viewer popup"
    );
    assert!(
        app.media.viewer_protocol_mut("cafebabe").is_some(),
        "the popup builds its own dedicated halfblock protocol, not the inline one"
    );
    let rendered = rendered_buffer(&mut app);
    assert!(
        !rendered.contains("1337"),
        "the fallback viewer never emits a pixel escape"
    );
    assert!(
        rendered.contains('▀') || rendered.contains('▄'),
        "the fallback viewer draws cell-exact halfblocks"
    );
}

#[test]
fn o_on_an_evicted_image_renders_the_halfblock_fallback_on_a_pixel_terminal() {
    // review finding 6, driven end to end: on a pixel-capable terminal, opening
    // `o` on an image whose retained viewer pixels were evicted (older than the
    // retention cap) must still open the viewer and render — degrading honestly to
    // the cell-exact halfblock protocol, never a pixel escape and never a blank
    // card. The evicted image's pixels survive only inside the inline protocol, so
    // that is what the popup draws as a last resort.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Messages;
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![image_attachment("h1")];
    app.timeline = vec![row];

    // Pixel-capable terminal (kitty). Decode h1 first as a large varied image so
    // its inline halfblock protocol fills the popup card with glyphs; then four
    // more decodes push h1 out of the bounded viewer-pixel retention (cap 4,
    // oldest evicted first).
    let mut picker = ratatui_image::picker::Picker::halfblocks();
    picker.set_protocol_type(ratatui_image::picker::ProtocolType::Kitty);
    app.media = media_ready_large_varied_image(picker, "h1");
    for hash in ["h2", "h3", "h4", "h5"] {
        app.media.apply_for_test(MediaLoad::Decoded {
            hash: hash.to_owned(),
            image: Box::new(image::DynamicImage::new_rgb8(4, 4)),
        });
    }
    assert!(
        app.media.is_ready("h1"),
        "h1's inline render survives eviction"
    );

    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE))
        .expect("open viewer");
    assert!(
        matches!(app.popup, Some(Popup::Image { .. })),
        "o opens the viewer even for an evicted image"
    );
    assert!(
        app.media.viewer_protocol_mut("h1").is_none(),
        "the evicted image has no dedicated protocol — its pixels were evicted"
    );

    // On a 100x30 frame the popup card spans rows 3..27; its image area is rows
    // 4..24. The inline preview behind it lives in the top ~9 rows, and the
    // popup's `Clear` wipes everything under the card. So a halfblock glyph in the
    // popup's interior band (rows 12..20) can only come from the popup drawing the
    // image itself — not from the inline preview bleeding through the margins.
    let rows = rendered_rows(&mut app);
    let popup_interior = rows[12..=20].join("");
    assert!(
        popup_interior.contains('▀') || popup_interior.contains('▄'),
        "the evicted fallback draws the cell-exact halfblock image inside the popup card:\n{}",
        rows.join("\n")
    );
    assert!(
        !rows.join("").contains("1337"),
        "the evicted fallback never emits a pixel escape, even on a pixel terminal"
    );
}

#[test]
fn the_fallback_viewer_popup_does_not_re_resize_the_shared_inline_protocol() {
    // The inline timeline draws `protocols[hash]` sized to its small reserved
    // block. The viewer popup must draw its OWN dedicated protocol, never that
    // shared inline one: reusing it would resize the inline protocol from its
    // block size up to the ~80% popup area every frame, and the next inline frame
    // would resize it straight back — two full Lanczos3 passes of a large source
    // per frame, continuous jank while the popup is open.
    //
    // Observe it honestly through the protocol's own encode signal: after the
    // inline block has encoded at its block size, opening and rendering the popup
    // must not trigger a fresh resize/encode of the inline protocol.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Messages;
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![image_attachment("cafebabe")];
    app.timeline = vec![row];
    // Halfblock-only terminal: the popup fallback used to reuse the inline
    // protocol here, so this is the case that thrashed. The source is large so it
    // is downscaled to different sizes for the 8-row inline block and the ~21-row
    // popup — a reused protocol would actually re-encode between them.
    app.media =
        media_ready_large_varied_image(ratatui_image::picker::Picker::halfblocks(), "cafebabe");

    // First frame: the inline block encodes the shared protocol at its block size.
    // Drain that encode result so a later `Some` means a *new* encode was forced.
    let _ = rendered_buffer(&mut app);
    let _ = app
        .media
        .protocol_mut("cafebabe")
        .expect("the inline protocol exists after the first frame")
        .last_encoding_result();

    // Open the viewer popup and render it over the still-visible timeline.
    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE))
        .expect("open viewer");
    assert!(
        matches!(app.popup, Some(Popup::Image { .. })),
        "o opens the viewer popup"
    );
    let _ = rendered_buffer(&mut app);

    assert!(
        app.media
            .protocol_mut("cafebabe")
            .expect("the inline protocol still exists")
            .last_encoding_result()
            .is_none(),
        "the open viewer popup must not re-resize the shared inline protocol"
    );
}

#[test]
fn closing_the_image_viewer_forces_a_full_repaint_and_drops_the_native_protocol() {
    // A pixel-protocol image lives terminal-side, out of reach of ratatui's
    // cell diff (iTerm2 in particular does not self-erase when its cells are
    // overwritten), so dismissing the viewer must schedule a full terminal
    // clear+repaint — `run()` consumes this flag before the next draw — and
    // drop the on-demand native protocol.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Messages;
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![image_attachment("cafebabe")];
    app.timeline = vec![row];
    app.media = iterm2_media_with_ready_image("cafebabe");

    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE))
        .expect("open viewer");
    assert!(
        !app.pending_full_repaint,
        "opening the viewer needs no full repaint"
    );

    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE))
        .expect("dismiss viewer");

    assert!(app.popup.is_none(), "any key dismisses the viewer");
    assert!(
        app.pending_full_repaint,
        "closing the viewer schedules the full clear+repaint"
    );
    assert!(
        app.media.viewer_protocol_mut("cafebabe").is_none(),
        "closing the viewer drops the native protocol"
    );
}

#[test]
fn every_popup_close_arm_forces_a_full_repaint() {
    // All popup teardown funnels through the three non-`None` arms of
    // `handle_popup_key` (dismiss, submit, open-next). The full repaint is
    // uniform across them — a modal close is rare and a full repaint cheap, so
    // no arm needs to know whether the popup it tears down drew a pixel image.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;

    // Dismiss: Esc on the help card.
    app.popup = Some(Popup::help());
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("dismiss help");
    assert!(app.popup.is_none());
    assert!(app.pending_full_repaint, "dismiss forces a full repaint");

    // Submit: Enter on a confirm popup (the CLI call fails onto the status
    // line; the popup still closes).
    app.pending_full_repaint = false;
    app.popup = Some(Popup::confirm_add_user_to_chat("gid", "chat", "pk", "user"));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("submit confirm");
    assert!(app.popup.is_none());
    assert!(app.pending_full_repaint, "submit forces a full repaint");

    // Open-next: Enter on the add-user group picker replaces it with the
    // confirm popup; the picker it tears down gets the same uniform treatment.
    app.pending_full_repaint = false;
    app.popup = Some(Popup::add_user_group_picker(
        "pk".to_owned(),
        "user".to_owned(),
        vec![PickerItem {
            id: "gid".to_owned(),
            label: "chat".to_owned(),
        }],
        0,
    ));
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("advance picker");
    assert!(
        matches!(app.popup, Some(Popup::Confirm { .. })),
        "the picker advances to the confirm popup"
    );
    assert!(
        app.pending_full_repaint,
        "replacing a popup forces a full repaint too"
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

#[cfg(unix)]
#[test]
fn viewer_retention_keeps_pixels_in_memory_only_never_on_disk() {
    // The decrypted download artifact is removed right after decode (the
    // security fix); the viewer's retained pixels must not undo that by
    // parking plaintext back on disk. Drive the real worker end-to-end into a
    // pixel-capable media state, build the native viewer protocol, and verify
    // the cache directory holds nothing — the viewer draws from memory alone.
    let dir = tempfile::tempdir().expect("tempdir");
    let wn = test_json_executable(dir.path(), r#"{"ok":true}"#);
    let cache_dir = dir.path().join("media-cache");
    std::fs::create_dir_all(&cache_dir).expect("cache dir");
    let output_path = cache_dir.join("deadbeef");
    seed_decodable_image(&output_path);

    let result = run_media_worker(&wn, output_path.clone());

    let mut picker = ratatui_image::picker::Picker::halfblocks();
    picker.set_protocol_type(ratatui_image::picker::ProtocolType::Kitty);
    let mut media = MediaState::with_test_picker(picker);
    media.apply_for_test(result);
    assert!(
        media.is_ready("deadbeef"),
        "the image decoded and folded in"
    );
    assert!(
        media.build_viewer_protocol("deadbeef"),
        "the native viewer builds from retained in-memory pixels"
    );

    assert!(
        !output_path.exists(),
        "the decrypted artifact is still removed after decode"
    );
    let leftover: Vec<_> = std::fs::read_dir(&cache_dir)
        .expect("cache dir readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(
        leftover.is_empty(),
        "viewer retention writes nothing to disk; found {leftover:?}"
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
    let mut short = timeline_row("a", 0);
    short.from_display_name = Some("A".to_owned());
    short.display_text = "hi".to_owned();
    let mut wrapped_reply = short.clone();
    wrapped_reply.message_id = "b".to_owned();
    wrapped_reply.display_text = "x".repeat(200);
    wrapped_reply.reply = Some(TimelineReply {
        reply_to_message_id: "parent".to_owned(),
        preview: None,
    });
    assert_eq!(
        timeline_row_heights_media(&[short, wrapped_reply], None, 40, MediaView::default()),
        vec![2, 8],
        "each row keeps its own wrapped/reply height and source order"
    );
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
    // Everything on screen: just the base title.
    assert_eq!(timeline_pane_title("Ops", 5, 0, 4), "Ops");
    // Older rows above the view.
    assert_eq!(timeline_pane_title("Ops", 10, 3, 9), "Ops [3 older]");
    // Newer rows below the view.
    assert_eq!(timeline_pane_title("Ops", 10, 0, 6), "Ops [3 newer]");
    // Both directions.
    assert_eq!(
        timeline_pane_title("Ops", 10, 2, 6),
        "Ops [2 older | 3 newer]"
    );
    // With no loaded chat the base falls back to the plain "Messages".
    assert_eq!(timeline_pane_title("Messages", 5, 0, 4), "Messages");
}

#[test]
fn messages_pane_title_names_the_loaded_chat_not_the_highlighted_one() {
    let account_id = "aa".repeat(32);
    let group_b = "bb".repeat(32);
    let group_c = "cc".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.daemon.running = false;
    app.chats = vec![
        projected_chat(&group_b, "BravoRoom", 0, Some(200)),
        projected_chat(&group_c, "CharlieRoom", 0, Some(100)),
    ];
    // The pane shows B (opened or a settled preview), while the highlight has since
    // moved to C. The title tracks the loaded pane (WYSIWYG), not the selection.
    app.selected_chat = 1;
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some(group_b.clone());
    app.timeline = vec![timeline_row("m1", 200)];

    // Row 0 is the top border of both panes; the only text there is the two pane
    // titles ("Chats" left, the messages title right). Chat names appear as list
    // items on later rows, so the loaded chat's name on row 0 can only be the
    // messages-pane title.
    let rows = rendered_rows(&mut app);
    assert!(
        rows[0].contains("BravoRoom"),
        "the messages pane title names the loaded chat, got: {:?}",
        rows[0]
    );
    assert!(
        !rows[0].contains("CharlieRoom"),
        "the title does not name the merely-highlighted chat, got: {:?}",
        rows[0]
    );
}

#[test]
fn messages_pane_title_falls_back_to_messages_with_no_loaded_chat() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.daemon.running = false;
    // No chat loaded into the pane.
    app.messages_group_id = None;

    let rows = rendered_rows(&mut app);
    assert!(
        rows[0].contains("Messages"),
        "with nothing loaded the pane title is the plain \"Messages\", got: {:?}",
        rows[0]
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
fn completed_sends_only_insert_into_the_originating_account_and_group() {
    // #2956: both accounts can belong to the same MLS group. Resolve the real
    // send/reply while A owns the pane, then deliver its synthetic completion
    // after the pane has moved. The action captures A before navigation clears
    // its pane; the actual worker establishes B's replacement pane below.
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let group = "cc".repeat(32);
    let dir = tempfile::tempdir().expect("recorder directory");
    let response = r#"{"ok":true,"result":{"messages":[],"has_more_before":false}}"#;
    #[cfg(unix)]
    let (exe, args_file) = {
        let exe = dir.path().join("wn-json");
        let args_file = dir.path().join("recorded-args");
        // One immutable fake for the table; shell builtins avoid an extra child
        // per fixed JSON response. No case rewrites an executable another uses.
        write_fake_wn(
            &exe,
            &format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\nprintf '%s\\n' '{}'\n",
                args_file.display(),
                response
            ),
        );
        (exe, args_file)
    };
    #[cfg(windows)]
    let (exe, args_file) = test_appending_arg_executable(dir.path(), response);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    for reply in [false, true] {
        for completion in ["without-id", "with-id", "error"] {
            for (selected_account, selected_group, selection_matches) in [
                (1, group.as_str(), false),
                (0, "dddddddddddddddddddddddddddddddd", false),
                (0, group.as_str(), true),
            ] {
                for (pane_account, pane_group, same_pane) in [
                    (Some(account_b.as_str()), Some(group.as_str()), false),
                    (
                        Some(account_a.as_str()),
                        Some("dddddddddddddddddddddddddddddddd"),
                        false,
                    ),
                    (None, None, false),
                    (Some(account_a.as_str()), Some(group.as_str()), true),
                ] {
                    // The previous case crossed its child-completion fence,
                    // including any work enqueued by a legitimate reload.
                    std::fs::write(&args_file, "").expect("reset fenced per-case recorder");
                    let mut app = test_tui_app(client.clone(), &account_a);
                    app.accounts.push(AccountRow {
                        account_id: account_b.clone(),
                        npub: "npub1bob".to_owned(),
                        display_name: None,
                        local_signing: true,
                    });
                    app.messages_account_id = Some(account_a.clone());
                    app.messages_group_id = Some(group.clone());
                    app.timeline = vec![timeline_row("parent", 5)];
                    app.daemon.running = false;
                    let effect = if reply {
                        app.resolve_reply("hello".to_owned()).expect("reply for A")
                    } else {
                        app.resolve_send_message("hello".to_owned())
                            .expect("send for A")
                    };
                    let switches_account = pane_account == Some(account_b.as_str());
                    if switches_account {
                        app.selected_account = 1;
                        app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
                            effect: Effect::Relist { account: account_b.clone(), include_archived: false },
                            result: Ok(vec![serde_json::json!({"chats":[{"group_id":group,"profile":{"name":"general"}}]})]),
                        });
                        app.begin_timeline_load(account_b.clone(), group.clone());
                        assert!(app.messages_account_id.is_none());
                    }
                    if switches_account {
                        let done = app
                            .effects
                            .recv_timeout(Duration::from_secs(5))
                            .expect("B timeline completed on the actual worker");
                        assert!(
                            matches!(&done.effect, Effect::LoadTimeline {account, group: target, ..}
                            if account == &account_b && target == &group)
                        );
                        app.apply_effect_done(done);
                        assert_eq!(app.messages_account_id.as_deref(), Some(account_b.as_str()));
                        assert_eq!(app.messages_group_id.as_deref(), Some(group.as_str()));
                    }
                    // A failed account refresh can leave A's pane under selection B.
                    // ID rows belong to the pane; a no-ID reload must also respect
                    // the user's currently selected account/chat.
                    app.selected_account = selected_account;
                    if !switches_account {
                        app.messages_account_id = pane_account.map(str::to_owned);
                        app.messages_group_id = pane_group.map(str::to_owned);
                    }
                    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
                        effect: Effect::Relist { account: app.selected_account_row().unwrap().account_id.clone(), include_archived: false },
                        result: Ok(vec![serde_json::json!({"chats":[{"group_id":selected_group,"profile":{"name":"general"}}]})]),
                    });
                    if !switches_account {
                        app.timeline.clear();
                    }
                    let previous_len = app.timeline.len();

                    app.apply_effect_done(EffectDone {
                        status_owner: Some(app.status_ownership.revision),
                        effect,
                        result: match completion {
                            "with-id" => Ok(vec![
                                serde_json::json!({"published": 1, "message_ids": ["sent"]}),
                            ]),
                            "without-id" => Ok(vec![serde_json::json!({"published": 1})]),
                            _ => Err("send failed".to_owned()),
                        },
                    });

                    // Observe the completion itself before the FIFO fence folds
                    // any eligible follow-up load; the recorder then proves its
                    // presence or absence without a timing window.
                    let loading_on_completion = app.loading_chat.clone();
                    let completion_status = app.status.clone();
                    finish_queued_effects(&mut app);
                    let recorded =
                        std::fs::read_to_string(&args_file).expect("fenced command recorder");
                    let expected_loads = usize::from(switches_account)
                        + usize::from(same_pane && selection_matches && completion == "without-id");
                    assert_eq!(
                        recorded
                            .lines()
                            .filter(|line| line.contains("messages timeline list"))
                            .count(),
                        expected_loads,
                        "only the eligible no-ID completion may add a timeline load: {recorded}"
                    );
                    let inserts = same_pane && completion == "with-id";
                    assert_eq!(
                        app.timeline.len(),
                        previous_len + usize::from(inserts),
                        "reply={reply}, completion={completion}, pane_account={pane_account:?}, pane_group={pane_group:?}"
                    );
                    assert_eq!(
                        loading_on_completion
                            .as_ref()
                            .map(|(account, group, _)| (account.as_str(), group.as_str())),
                        (same_pane && selection_matches && completion == "without-id")
                            .then_some((account_a.as_str(), group.as_str())),
                        "only a matching-pane no-ID completion may reload the timeline"
                    );
                    assert_eq!(
                        completion_status,
                        if completion == "error" {
                            "error: send failed"
                        } else if reply {
                            "sent reply; published=1"
                        } else {
                            "sent message; published=1"
                        },
                        "completed mutation outcomes remain visible after navigation"
                    );
                    if same_pane && selection_matches && completion == "without-id" {
                        finish_queued_effects(&mut app);
                    }
                    if inserts {
                        let row = &app.timeline[0];
                        assert_eq!(row.message_id, "sent");
                        assert_eq!(row.from, account_a);
                        assert_eq!(row.display_text, "hello");
                        assert_eq!(
                            row.reply
                                .as_ref()
                                .map(|reply| reply.reply_to_message_id.as_str()),
                            reply.then_some("parent")
                        );
                    }
                }
            }
        }
    }
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
    // The send runs off-loop; folding it inserts the optimistic row.
    app.settle_effects(1);

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
    // The worker runs the send off-loop; wait for it before reading the argv.
    app.settle_effects(1);

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
    // The load runs off-loop; folding it populates the pane.
    app.settle_effects(1);

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
    assert_eq!(app.status, "loaded 1 older message(s)");
    let (tx, rx) = mpsc::channel();
    app.chat_subscription = Some(ChatSubscription {
        account_id: account_id.to_owned(),
        include_archived: false,
        child: test_sleep_child(),
        rx,
    });
    tx.send(SubscriptionEvent::Error("history feed offline".to_owned()))
        .unwrap();
    assert!(app.drain_chat_subscription());
    assert_eq!(
        app.status, "chat subscription failed: history feed offline",
        "ordinary history completion leaves idle feedback"
    );
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
fn ctrl_u_in_messages_focus_does_not_unreact() {
    // Ctrl-U is the composer kill-line, never the Messages `u` (unreact)
    // accelerator. The accelerator must fire only on a plain `u`, so Ctrl-U in
    // the Messages pane is a no-op: it queues no `messages unreact` subprocess
    // and leaves the status line untouched. A selected row is present so a fired
    // unreact WOULD resolve and set "removing reaction..." — proving the no-op is
    // real, not merely an unresolved-selection error.
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.focus = Focus::Messages;
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some(group_id);
    app.timeline = vec![timeline_row("m1", 1)];
    assert!(app.status.is_empty(), "precondition: status starts empty");

    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
        .expect("Ctrl-U handled");

    assert!(
        app.status.is_empty(),
        "Ctrl-U in Messages must not fire unreact; status: {:?}",
        app.status
    );
}

#[test]
fn ctrl_q_does_not_quit() {
    // `q` quits only as a bare accelerator. Ctrl-Q is a chord that must not fall
    // through the modifier-insensitive `q` arm and tear down the session.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Chats;
    assert!(app.input.is_empty(), "precondition: composer empty");

    app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL))
        .expect("Ctrl-Q handled");

    assert!(app.running, "Ctrl-Q must not quit the app");
}

#[test]
fn composer_ctrl_u_clears_the_input() {
    // Ctrl-U in the composer is the readline kill-line and clears the field —
    // the guard on the Messages accelerators must not shadow it.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Composer;
    app.input.set_value("/react 🔥");

    app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL))
        .expect("Ctrl-U handled");

    assert!(app.input.is_empty(), "Ctrl-U clears the composer");
}

#[test]
fn plain_q_quits() {
    // The plain-keypress guard tolerates Shift/no-modifier: a bare `q` outside
    // the composer still quits.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Chats;

    app.handle_key(char_key('q')).expect("q handled");

    assert!(!app.running, "a bare q quits the app");
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

#[test]
fn messages_pane_shows_loading_while_an_open_chat_load_is_in_flight() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.focus = Focus::Messages;
    // An open-chat load is in flight and the pane has not yet folded any rows.
    app.timeline_load_generation = 1;
    app.loading_chat = Some((
        account_id.clone(),
        "bb".repeat(32),
        app.timeline_load_generation,
    ));
    assert!(app.timeline.is_empty());

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
        rendered.contains("loading messages..."),
        "an in-flight load shows honest feedback in the pane, not an empty notice"
    );
    assert!(
        !rendered.contains("no messages yet"),
        "'no messages yet' is only shown once the load settles empty"
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
fn status_bar_line_assembles_account_counts_and_status() {
    let line = status_bar_line(
        None,
        Some("npub1alice"),
        true,
        3,
        5,
        "loaded 2 message(s)",
        200,
    );
    let text = line_text(&line);
    assert!(text.contains("npub1alice"), "account: {text:?}");
    assert!(text.contains("3 chats"), "chats: {text:?}");
    assert!(text.contains("5 unread"), "unread: {text:?}");
    assert!(text.contains("loaded 2 message(s)"), "status: {text:?}");
    // A width that fits the fixed segments but not the whole status truncates
    // the status segment (trailing ellipsis) so the assembled line fits.
    let narrow = status_bar_line(None, Some("npub1a"), true, 3, 0, "loaded slowly now", 30);
    let narrow_text = line_text(&narrow);
    assert!(
        narrow_text.chars().count() <= 30,
        "over width: {narrow_text:?}"
    );
    assert!(
        narrow_text.contains("..."),
        "expected truncation: {narrow_text:?}"
    );
    // A width too small for any status drops the segment rather than overflowing.
    let tiny = status_bar_line(None, Some("npub1a"), true, 3, 0, "loaded", 20);
    assert!(
        !line_text(&tiny).contains("loaded"),
        "dropped: {:?}",
        line_text(&tiny)
    );
}

#[test]
fn status_bar_line_dot_reflects_daemon_state() {
    fn dot(line: &Line<'_>) -> (String, Option<Color>) {
        let span = line
            .spans
            .iter()
            .find(|s| s.content == "●" || s.content == "○")
            .expect("dot span");
        (span.content.to_string(), span.style.fg)
    }
    let on = status_bar_line(None, Some("npub1a"), true, 0, 0, "", 200);
    assert_eq!(dot(&on), ("●".to_owned(), Some(Color::Green)));
    let off = status_bar_line(None, Some("npub1a"), false, 0, 0, "", 200);
    assert_eq!(dot(&off), ("○".to_owned(), Some(Color::Red)));
}

#[test]
fn status_bar_line_hides_zero_unread_and_shows_nonzero_yellow() {
    let zero = status_bar_line(None, Some("npub1a"), true, 3, 0, "", 200);
    assert!(
        !line_text(&zero).contains("unread"),
        "zero hidden: {:?}",
        line_text(&zero)
    );
    let some = status_bar_line(None, Some("npub1a"), true, 3, 7, "", 200);
    let badge = some
        .spans
        .iter()
        .find(|s| s.content.contains("unread"))
        .expect("unread badge");
    assert_eq!(badge.content.as_ref(), "7 unread");
    assert_eq!(badge.style.fg, Some(Color::Yellow));
}

#[test]
fn status_bar_line_shows_display_name_distinct_from_npub() {
    let line = status_bar_line(Some("Alice"), Some("npub1alice"), true, 0, 0, "", 200);
    let text = line_text(&line);
    assert!(text.contains("Alice"), "name: {text:?}");
    assert!(text.contains("npub1alice"), "npub: {text:?}");
    // The npub segment is styled gray, distinct from the name.
    let npub_span = line
        .spans
        .iter()
        .find(|s| s.content.contains("npub1alice"))
        .expect("npub span");
    assert_eq!(npub_span.style.fg, Some(Color::Gray));
}

#[test]
fn status_bar_line_strips_control_sequences_from_untrusted_fields() {
    let line = status_bar_line(
        None,
        Some("al\u{1b}[31mice"),
        true,
        1,
        0,
        "ok\u{1b}[2J",
        200,
    );
    let text = line_text(&line);
    assert!(text.contains("al[31mice"), "account stripped: {text:?}");
    assert!(text.contains("ok[2J"), "status stripped: {text:?}");
    assert!(!text.contains('\u{1b}'), "no escape: {text:?}");
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
    // The user-search screen's hint is focus- and purpose-aware (rendered via
    // `user_search_hint`).
    assert_eq!(
        user_search_hint(UserSearchFocus::Query, &UserSearchPurpose::Browse),
        "type query  Enter search  Down results  Esc back"
    );
    assert_eq!(
        user_search_hint(UserSearchFocus::Results, &UserSearchPurpose::Browse),
        "j/k move  Enter profile  f follow  x unfollow  c chat  a add  i query  Esc back"
    );
    assert_eq!(
        hints_line(Screen::Main, Focus::Messages, true),
        "j/k select  G/g ends  r react  u unreact  d delete  R reply  i compose"
    );
    assert_eq!(
        hints_line(Screen::GroupDetail, Focus::Chats, true),
        "j/k move  a search+add  A add  x remove  P promote  R rename  L leave  I invites  ? help  Esc back"
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
        true,
    );
    assert!(view.members[0].is_admin && view.members[0].is_self);
    assert!(!view.members[1].is_admin && !view.members[1].is_self);
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
    // The four-call load runs off-loop; folding it populates the view.
    app.settle_effects(1);

    let view = app.group_detail.as_ref().expect("group detail loaded");
    assert_eq!(view.members.len(), 2);
    assert!(view.members[0].is_self && view.members[0].is_admin);

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc leaves group detail");
    assert_eq!(app.screen, Screen::Main);
    assert!(
        app.group_detail.is_none(),
        "group-detail state is dropped on exit"
    );
}

#[test]
fn removed_device_with_sibling_admin_on_roster_is_not_self_or_admin() {
    // This device was removed, but another device of the account keeps it on
    // the roster as the sole admin. The detail view must not read that entry
    // as this device: no "(you)" row, even though the account has an admin badge.
    let self_id = "aa".repeat(32);
    let bob_id = "bb".repeat(32);
    let response = format!(
        r#"{{"ok":true,"result":{{"profile":{{"name":"Ops","description":"ops room"}},"self_membership":"removed","members":[{{"member_id":"{self_id}","npub":"npubself"}},{{"member_id":"{bob_id}","npub":"npubbob"}}],"admins":[{{"admin_id":"{self_id}","npub":"npubself"}}],"relays":["wss://relay.example"]}}}}"#
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
    app.settle_effects(1);

    let view = app.group_detail.as_ref().expect("group detail loaded");
    assert!(view.members.iter().all(|member| !member.is_self));
    assert!(
        view.members[0].is_admin,
        "the account is still listed as admin"
    );

    app.handle_key(char_key('L'))
        .expect("L on a removed device");
    assert!(matches!(
        app.popup,
        Some(Popup::Confirm {
            purpose: ConfirmPurpose::LeaveGroup { .. },
            ..
        })
    ));
}

#[test]
fn self_membership_absent_from_group_show_reads_as_member() {
    assert!(parse_self_is_member(&serde_json::json!({})));
    assert!(parse_self_is_member(
        &serde_json::json!({"self_membership": "member"})
    ));
    assert!(!parse_self_is_member(
        &serde_json::json!({"self_membership": "removed"})
    ));
    assert!(!parse_self_is_member(
        &serde_json::json!({"self_membership": "left"})
    ));
}

#[test]
fn group_detail_leave_confirms_before_the_authoritative_command() {
    let self_id = "aa".repeat(32);
    let peer_id = "bb".repeat(32);
    let members = vec![
        (self_id.clone(), "npubself".to_owned()),
        (peer_id.clone(), "npubpeer".to_owned()),
    ];
    // Core owns demotion and last-admin refusal; eligible admins and ordinary
    // members must both reach the authoritative command after confirmation.
    for is_admin in [true, false] {
        for local_signing in [true, false] {
            let dir = tempfile::tempdir().expect("tempdir");
            let (exe, args_file) = test_appending_arg_executable(
                dir.path(),
                r#"{"ok":true,"result":{"published":3}}"#,
            );
            let mut app = test_tui_app(
                WnClient {
                    exe,
                    ..test_unused_client()
                },
                &self_id,
            );
            app.daemon.running = false;
            app.accounts[0].local_signing = local_signing;
            app.accounts.insert(
                0,
                AccountRow {
                    account_id: "cc".repeat(32),
                    npub: "npubother".into(),
                    display_name: None,
                    local_signing: true,
                },
            );
            app.selected_account = 1;
            app.chats = vec![flick_chat("other-group", "Other")];
            app.screen = Screen::GroupDetail;
            let admins = if is_admin {
                vec![self_id.clone(), peer_id.clone()]
            } else {
                vec![peer_id.clone()]
            };
            let view = build_group_detail("g1", "Ops", "", &members, &admins, &[], &self_id, true);
            let self_row = view
                .members
                .iter()
                .find(|member| member.is_self)
                .expect("self row");
            assert_eq!(self_row.member_id, self_id);
            assert_eq!(self_row.is_admin, is_admin);
            app.group_detail = Some(view);
            app.handle_key(char_key('L'))
                .expect("L opens Leave confirmation");
            assert!(matches!(
                &app.popup,
                Some(Popup::Confirm { purpose: ConfirmPurpose::LeaveGroup { group_id }, .. }) if group_id == "g1"
            ));
            app.handle_key(char_key('n')).expect("cancel leave");
            assert!(app.popup.is_none());
            assert!(
                !args_file.exists(),
                "cancel leaves native membership untouched"
            );
            app.handle_key(char_key('L')).expect("reopen leave");
            app.handle_key(char_key('y')).expect("confirm leave");
            if !local_signing {
                assert_eq!(
                    app.status,
                    "error: selected account is public-only and cannot sign"
                );
                assert!(
                    !args_file.exists(),
                    "public-only account must not spawn a mutation"
                );
                continue;
            }
            assert_eq!(app.status, "left group; published=3");
            assert_eq!(app.screen, Screen::Main);
            assert!(app.group_detail.is_none());
            let recorded = std::fs::read_to_string(&args_file).expect("recorded calls");
            assert_eq!(
                recorded.lines().next().map(str::trim_end),
                Some(format!("--json --account {self_id} groups leave g1").as_str())
            );
        }
    }
}

/// A group-detail view with two members, for the search-and-add flow.
fn app_on_group_detail(client: WnClient) -> TuiApp {
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.screen = Screen::GroupDetail;
    app.group_detail = Some(GroupDetailView {
        group_id: "g1".to_owned(),
        name: "Ops Room".to_owned(),
        description: String::new(),
        members: vec![GroupMemberRow {
            member_id: "aa".to_owned(),
            npub: "npubself".to_owned(),
            is_admin: true,
            is_self: true,
        }],
        relays: Vec::new(),
        selected: 0,
    });
    app
}

#[test]
fn a_on_group_detail_opens_a_user_search_aimed_at_that_group() {
    let mut app = app_on_group_detail(test_unused_client());

    app.handle_key(char_key('a')).expect("a on group detail");

    assert_eq!(app.screen, Screen::UserSearch);
    assert_eq!(
        app.user_search.as_ref().map(|view| view.purpose.clone()),
        Some(UserSearchPurpose::AddToGroup {
            group_id: "g1".to_owned(),
            group_name: "Ops Room".to_owned(),
        }),
        "the search knows the group it was opened to add to"
    );
}

/// A result row for the search-and-add flow.
fn search_result_row(npub: &str, label: &str) -> UserSearchResultRow {
    UserSearchResultRow {
        pubkey: "bb".repeat(32),
        npub: npub.to_owned(),
        display_name: Some(label.to_owned()),
        matched_field: "name".to_owned(),
        match_quality: "exact".to_owned(),
        radius: 1,
        following: false,
    }
}

#[test]
fn a_on_a_result_confirms_against_the_group_the_search_was_opened_for() {
    let mut app = app_on_group_detail(test_unused_client());
    app.handle_key(char_key('a')).expect("a on group detail");
    app.user_search.as_mut().expect("search view").results =
        vec![search_result_row("npubbob", "Bob")];
    app.user_search.as_mut().expect("search view").focus = UserSearchFocus::Results;

    app.handle_key(char_key('a')).expect("a on the result");

    // Straight to the confirm: the target group is already known, so the chat
    // picker that the browse flow needs would be a dead step here.
    match &app.popup {
        Some(Popup::Confirm {
            purpose: ConfirmPurpose::AddUserToChat { group_id, pubkey },
            body,
            ..
        }) => {
            assert_eq!(group_id, "g1");
            assert_eq!(pubkey, &"bb".repeat(32));
            assert!(
                body[0].contains("Bob") && body[0].contains("Ops Room"),
                "the confirm names the user and the group; got: {body:?}"
            );
        }
        other => panic!("expected the add-to-group confirm, got {other:?}"),
    }
}

#[test]
fn a_group_aimed_search_hint_names_the_group_and_the_help_card_names_the_key() {
    let purpose = UserSearchPurpose::AddToGroup {
        group_id: "g1".to_owned(),
        group_name: "Ops Room".to_owned(),
    };
    let hint = user_search_hint(UserSearchFocus::Results, &purpose);
    assert!(
        hint.contains("a add to Ops Room"),
        "the aimed search names its target, since `a` no longer asks; got: {hint}"
    );
    let help = help_card_lines().join("\n");
    assert!(
        help.contains("a search for a member to add"),
        "the help card names the group-detail search key; got:\n{help}"
    );
}

#[test]
fn a_group_name_cannot_fabricate_a_keycap_in_the_search_hint() {
    // `keymap_hint_spans` splits hint segments on a double space and boxes a
    // leading key-shaped token, so an unsanitized name could paint a convincing
    // fake `Esc` keycap into the hint line.
    let purpose = UserSearchPurpose::AddToGroup {
        group_id: "g1".to_owned(),
        group_name: "Ops  Esc quit".to_owned(),
    };
    let hint = user_search_hint(UserSearchFocus::Results, &purpose);
    assert!(
        hint.contains("a add to Ops Esc quit"),
        "the name stays one segment; got: {hint}"
    );
    let keycaps = keymap_hint_spans(&hint)
        .into_iter()
        .filter(|span| span.content.as_ref() == " Esc ")
        .count();
    assert_eq!(keycaps, 1, "only the real `Esc back` renders as a keycap");
}

#[test]
fn esc_from_a_group_aimed_search_returns_to_the_group_not_the_main_view() {
    let mut app = app_on_group_detail(test_unused_client());
    app.handle_key(char_key('a')).expect("a on group detail");

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("Esc from the search");

    assert_eq!(
        app.screen,
        Screen::GroupDetail,
        "back where `a` was pressed"
    );
    assert!(app.user_search.is_none(), "the search view is cleared");
    assert!(
        app.group_detail.is_some(),
        "the group-detail view was kept, so the return needs no reload to render"
    );
}

#[test]
fn a_failing_return_from_a_group_aimed_search_reports_and_keeps_the_session_up() {
    // The return schedules a group-detail refresh, whose account precondition can
    // fail. A key handler reports such a failure on the status line; propagating it
    // would exit `run()` and end the whole session over a recoverable error.
    let mut app = app_on_group_detail(test_unused_client());
    app.handle_key(char_key('a')).expect("a on group detail");
    // A public-only account cannot sign, so `require_selected_local_account` — the
    // refresh's precondition — fails.
    app.accounts[0].local_signing = false;

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("Esc reports the failure instead of tearing down the session");

    assert!(
        app.status.starts_with("error:"),
        "the failure reaches the status line; got: {:?}",
        app.status
    );
    // The navigation the user asked for still applied: only the refresh failed, and
    // the cached group-detail view is what renders.
    assert_eq!(app.screen, Screen::GroupDetail);
    assert!(app.user_search.is_none(), "the search view is cleared");
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

    #[cfg(unix)]
    for (key, pasted, arguments, acknowledgement) in [
        (
            'R',
            " Renamed",
            &["groups", "rename", "g1", "Ops Room Renamed"][..],
            "renamed group; published=3",
        ),
        (
            'A',
            "npubpasted",
            &["groups", "add-members", "g1", "npubpasted"][..],
            "added member(s); published=3",
        ),
        (
            'x',
            "",
            &["groups", "remove-members", "g1", "npubchosen"][..],
            "removed member(s); published=3",
        ),
        (
            'P',
            "",
            &["groups", "promote", "g1", "npubchosen"][..],
            "promoted admin; published=3",
        ),
    ] {
        for local_signing in [true, false] {
            let dir = tempfile::tempdir().expect("tempdir");
            let exe = dir.path().join("wn-json");
            let args_file = dir.path().join("recorded-args");
            let response = r#"{"ok":true,"result":{"published":3}}"#;
            // NULs separate arguments; an empty record separates calls. This
            // keeps multiword names observable as one argument.
            write_fake_wn(
                &exe,
                &format!(
                    "#!/bin/sh\nset -eu\nprintf '%s\\0' \"$@\" >> '{}'\nprintf '\\0' >> '{}'\ncat <<'JSON'\n{response}\nJSON\n",
                    args_file.display(),
                    args_file.display(),
                ),
            );
            let account = "aa".repeat(32);
            let mut app = test_tui_app(
                WnClient {
                    exe,
                    ..test_unused_client()
                },
                &account,
            );
            app.daemon.running = false;
            app.accounts[0].local_signing = local_signing;
            app.accounts.insert(
                0,
                AccountRow {
                    account_id: "bb".repeat(32),
                    npub: "npubother".into(),
                    display_name: None,
                    local_signing: true,
                },
            );
            app.selected_account = 1;
            app.chats = vec![flick_chat("other-group", "Other")];
            app.screen = Screen::GroupDetail;
            app.group_detail = Some(GroupDetailView {
                group_id: "g1".into(),
                name: "Ops Room".into(),
                description: String::new(),
                members: vec![
                    GroupMemberRow {
                        member_id: account.clone(),
                        npub: "npubself".into(),
                        is_admin: true,
                        is_self: true,
                    },
                    GroupMemberRow {
                        member_id: "cc".repeat(32),
                        npub: "npubchosen".into(),
                        is_admin: false,
                        is_self: false,
                    },
                ],
                relays: Vec::new(),
                selected: 1,
            });
            app.handle_key(char_key(key)).expect("open action popup");
            app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                .expect("cancel");
            assert!(app.popup.is_none());
            assert!(!args_file.exists(), "cancel must not invoke a command");
            app.handle_key(char_key(key)).expect("reopen action popup");
            if !pasted.is_empty() {
                app.handle_paste(pasted.to_owned());
            }
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .expect("submit");
            assert!(app.popup.is_none());
            if !local_signing {
                assert_eq!(
                    app.status,
                    "error: selected account is public-only and cannot sign"
                );
                assert!(
                    !args_file.exists(),
                    "a public-only account cannot spawn the mutation"
                );
                continue;
            }
            assert_eq!(app.status, acknowledgement);
            assert_eq!(app.loading_group_detail.as_deref(), Some("g1"));
            finish_queued_effects(&mut app);
            let recorded = std::fs::read_to_string(&args_file).expect("recorded calls");
            let primary: Vec<_> = recorded.split("\0\0").next().unwrap().split('\0').collect();
            let mut expected = vec!["--json", "--account", account.as_str()];
            expected.extend_from_slice(arguments);
            assert_eq!(primary, expected);
        }
    }

    // These are local UI refusals. Native authorization remains in the CLI/core.
    let view = app.group_detail.as_mut().expect("existing detail view");
    view.members[0].is_self = true;
    app.popup = None;
    app.handle_key(char_key('x')).expect("remove self refusal");
    assert!(app.popup.is_none());
    assert_eq!(app.status, "cannot remove yourself; press L to leave");
    let member = &mut app.group_detail.as_mut().unwrap().members[0];
    member.is_self = false;
    member.is_admin = true;
    app.handle_key(char_key('P'))
        .expect("existing admin refusal");
    assert!(app.popup.is_none());
    assert_eq!(app.status, "member is already an admin");
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
    app.settle_effects(1);
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
    app.settle_effects(1);
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
    app.settle_effects(1);
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
        selected: 0,
    });

    app.handle_key(char_key('I')).expect("I opens invites");
    app.settle_effects(1);
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
    app.settle_effects(1);

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
fn group_detail_pane_scrolls_the_selected_member_into_view() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::GroupDetail;
    // A member list far taller than the pane, with the selection at the bottom.
    let mut members: Vec<GroupMemberRow> = (0..40)
        .map(|index| GroupMemberRow {
            member_id: format!("id{index:02}"),
            npub: format!("npubmember{index:02}"),
            is_admin: false,
            is_self: false,
        })
        .collect();
    members[39].npub = "npubLASTMEMBER".to_owned();
    let selected = members.len() - 1;
    app.group_detail = Some(GroupDetailView {
        group_id: "g1".to_owned(),
        name: "Ops Room".to_owned(),
        description: "the ops".to_owned(),
        members,
        relays: vec!["wss://relay.example".to_owned()],
        selected,
    });

    let rendered = rendered_buffer(&mut app);
    assert!(
        rendered.contains("npubLASTMEMBER"),
        "the selected member renders inside the pane"
    );
}

#[test]
fn group_detail_reveals_the_relay_section_at_the_end_of_a_long_member_list() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::GroupDetail;
    // The relay hints sit *after* the member list, so with more members than the
    // pane can hold they scroll off the bottom. Nothing scrolls the pane
    // independently of the selection, so reaching the end of the list has to be
    // what brings the tail into view.
    let members: Vec<GroupMemberRow> = (0..40)
        .map(|index| GroupMemberRow {
            member_id: format!("id{index:02}"),
            npub: format!("npubmember{index:02}"),
            is_admin: false,
            is_self: false,
        })
        .collect();
    let selected = members.len() - 1;
    app.group_detail = Some(GroupDetailView {
        group_id: "g1".to_owned(),
        name: "Ops Room".to_owned(),
        description: "the ops".to_owned(),
        members,
        relays: vec![
            "wss://first.example".to_owned(),
            "wss://middle.example".to_owned(),
            "wss://last.example".to_owned(),
        ],
        selected,
    });

    let rendered = rendered_buffer(&mut app);
    assert!(
        rendered.contains("first.example") && rendered.contains("last.example"),
        "the whole relay section is reachable once the selection reaches the last member"
    );
    assert!(
        rendered.contains("npubmember39"),
        "and the selected member is still on screen with it"
    );
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
fn account_picker_renders_without_panic_in_a_tiny_terminal() {
    // Regression: with the account picker open, a terminal of height <= 3 shrinks
    // the login body below the popup's 4-row floor. `rows.clamp(4, body.height)`
    // panicked ("min > max") because the requested floor exceeded the available
    // height. The rect must instead be built with a plain `max(4)` floor and left
    // to `centered_cell_rect` to clamp down to the body.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.accounts.push(AccountRow {
        account_id: "bb".repeat(32),
        npub: "npub1bob".to_owned(),
        display_name: None,
        local_signing: false,
    });
    app.screen = Screen::Login(LoginMode::AccountSelect);

    let backend = ratatui::backend::TestBackend::new(50, 3);
    let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| app.render(frame))
        .expect("account picker must render without panicking in a 3-row terminal");
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
        "opening a chat moves focus to the messages pane immediately"
    );
    // The timeline load runs off-loop; folding it settles the pane target.
    app.settle_effects(1);
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
fn account_picker_scrolls_the_selected_account_into_view() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Login(LoginMode::AccountSelect);
    // More accounts than the picker card can show, with the selection last.
    app.accounts = (0..40)
        .map(|index| AccountRow {
            account_id: format!("{index:064}"),
            npub: format!("npubaccount{index:02}"),
            display_name: Some(if index == 39 {
                "LASTACCOUNT".to_owned()
            } else {
                format!("account{index:02}")
            }),
            local_signing: true,
        })
        .collect();
    app.picker_selection = app.accounts.len() - 1;

    let rendered = rendered_buffer(&mut app);
    assert!(
        rendered.contains("LASTACCOUNT"),
        "the highlighted account renders inside the picker card"
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
    use clap::Parser;
    let cli = Cli::try_parse_from(["wn", "--account", b.as_str(), "tui"])
        .expect("parse explicit startup account");
    let mut app = TuiApp::new(cli).expect("construct TUI");
    // Keep constructor-owned startup choices; replace only the child boundary.
    app.client.exe = client.exe;
    app.effects = EffectRunner::spawn(app.client.clone());

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
    // The keymap hint renders keycaps (boxed keys) + dim labels; the `detail`
    // label sits after the boxed `g` keycap.
    assert!(rendered.contains("detail"), "chats hints line present");
    assert!(
        rendered.contains("loaded 1 message(s)"),
        "status bar shows the latest status segment"
    );
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
        rendered.contains("create identity"),
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
        rendered.contains('●'),
        "the status bar (connection dot) survives composer growth"
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
fn keymap_hint_spans_box_keys_and_dim_labels() {
    let spans = keymap_hint_spans("j/k move  Enter open");
    // The keycap for `j/k`: white bold text on a dark-gray block, padded. White-on-
    // dark-gray reads clearly on dark themes where black-on-dark-gray washed out.
    let keycap = spans
        .iter()
        .find(|s| s.content.contains("j/k"))
        .expect("j/k keycap");
    assert_eq!(keycap.content.as_ref(), " j/k ");
    assert_eq!(keycap.style.fg, Some(Color::White));
    assert_eq!(keycap.style.bg, Some(Color::DarkGray));
    assert!(keycap.style.add_modifier.contains(Modifier::BOLD));
    // The label after it is dim, no keycap background.
    let label = spans
        .iter()
        .find(|s| s.content.contains("move"))
        .expect("move label");
    assert_eq!(label.style.fg, Some(Color::DarkGray));
    assert_eq!(label.style.bg, None);
    // `Enter` is boxed like any other key.
    assert!(
        spans
            .iter()
            .any(|s| s.content.as_ref() == " Enter " && s.style.bg == Some(Color::DarkGray)),
        "Enter keycap present"
    );
}

#[test]
fn keymap_hint_spans_leave_prose_leading_segment_unboxed() {
    // `type query` is prose, not a key press — its first token must not be boxed.
    let spans = keymap_hint_spans("type query  Enter search");
    assert!(
        !spans.iter().any(|s| s.content.as_ref() == " type "),
        "the prose word `type` is not rendered as a keycap"
    );
    // The real key `Enter` is still boxed.
    assert!(
        spans
            .iter()
            .any(|s| s.content.as_ref() == " Enter " && s.style.bg == Some(Color::DarkGray)),
        "Enter keycap present"
    );
}

#[test]
fn armed_hint_spans_box_only_enter_and_esc() {
    let spans = armed_hint_spans("reacting to Alice — Enter sends the reaction, Esc clears");
    let boxed = spans
        .iter()
        .filter(|s| s.style.bg == Some(Color::DarkGray))
        .map(|s| s.content.trim().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(boxed, vec!["Enter".to_owned(), "Esc".to_owned()]);
    // The prose target still renders (dim), preserving the whole hint text.
    let text = spans.iter().map(|s| s.content.as_ref()).collect::<String>();
    assert!(text.contains("Alice"), "target preserved: {text:?}");
}

#[test]
fn popup_hint_spans_color_bracket_keys_cyan_and_desc_gray() {
    let spans = popup_hint_spans("[Enter] submit  [Esc] cancel");
    let key = spans
        .iter()
        .find(|s| s.content.contains("[Enter]"))
        .expect("[Enter] span");
    assert_eq!(key.style.fg, Some(Color::Cyan));
    let desc = spans
        .iter()
        .find(|s| s.content.contains("submit"))
        .expect("submit desc");
    assert_eq!(desc.style.fg, Some(Color::DarkGray));
}

#[test]
fn empty_messages_notice_distinguishes_loading_no_chat_and_empty_chat() {
    // In-flight load: yellow, regardless of whether a chat is already loaded.
    assert_eq!(
        empty_messages_notice(true, false),
        ("loading messages...", Color::Yellow)
    );
    assert_eq!(
        empty_messages_notice(true, true),
        ("loading messages...", Color::Yellow)
    );
    // Settled, no chat loaded into the pane: the pick-a-chat prompt (dark gray).
    assert_eq!(
        empty_messages_notice(false, false),
        ("select a chat to start messaging", Color::DarkGray)
    );
    // Settled, a chat is loaded but has no messages: genuinely empty (dark gray).
    assert_eq!(
        empty_messages_notice(false, true),
        ("no messages yet", Color::DarkGray)
    );
}

#[test]
fn messages_pane_renders_the_three_empty_states() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;

    // Loading a chat's timeline off the event loop.
    app.timeline_load_generation = 1;
    app.loading_chat = Some((
        account_id.clone(),
        "gg".repeat(32),
        app.timeline_load_generation,
    ));
    assert!(rendered_buffer(&mut app).contains("loading messages..."));

    // Settled, no chat loaded.
    app.loading_chat = None;
    app.messages_group_id = None;
    assert!(rendered_buffer(&mut app).contains("select a chat to start messaging"));

    // Settled, a chat loaded but empty.
    app.messages_group_id = Some("gg".repeat(32));
    assert!(rendered_buffer(&mut app).contains("no messages yet"));

    // Chats pane empty state.
    assert!(rendered_buffer(&mut app).contains("no chats yet"));
}

#[test]
fn popup_rect_sizes_a_short_confirm_to_content_and_centers() {
    let popup = Popup::Confirm {
        purpose: ConfirmPurpose::LeaveGroup {
            group_id: "gg".repeat(32),
        },
        title: "Leave Group".to_owned(),
        body: vec!["Leave ops-room?".to_owned()],
    };
    let area = Rect::new(0, 0, 100, 30);
    let rect = popup_rect(&popup, area);
    // Content-sized: 55 wide, snug height for one body line (not 70% of screen).
    assert_eq!(rect.width, 55, "confirm width");
    assert_eq!(
        rect.height, 5,
        "confirm height = body(1) + blank + hint + borders"
    );
    // Centered exactly.
    assert_eq!(rect.x, (100 - 55) / 2);
    assert_eq!(rect.y, (30 - 5) / 2);
}

#[test]
fn popup_rect_clamps_to_a_small_area() {
    let popup = Popup::info("Info", "hello");
    let area = Rect::new(0, 0, 20, 4);
    let rect = popup_rect(&popup, area);
    assert!(rect.width <= 20, "width clamps: {}", rect.width);
    assert!(rect.height <= 4, "height clamps: {}", rect.height);
}

#[test]
fn picker_popup_scrolls_the_selected_row_into_view() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Main;
    // More rows than the screen can hold, so the popup clamps to the area and
    // the highlighted row falls outside the drawn body without a scroll offset.
    let items: Vec<PickerItem> = (0..40)
        .map(|index| PickerItem {
            id: format!("id{index:02}"),
            label: if index == 39 {
                "LASTCHOICE".to_owned()
            } else {
                format!("choice{index:02}")
            },
        })
        .collect();
    let selected = items.len() - 1;
    app.popup = Some(Popup::Picker {
        purpose: PickerPurpose::Invites,
        title: "Pending Invites".to_owned(),
        items,
        selected,
    });

    let rendered = rendered_buffer(&mut app);
    assert!(
        rendered.contains("LASTCHOICE"),
        "the selected picker row renders inside the popup"
    );
}

#[test]
fn popup_body_lines_color_confirm_yellow_and_logout_red() {
    let confirm = Popup::Confirm {
        purpose: ConfirmPurpose::LeaveGroup {
            group_id: "gg".repeat(32),
        },
        title: "Leave Group".to_owned(),
        body: vec!["Leave ops-room?".to_owned()],
    };
    let lines = popup_body_lines(&confirm).lines;
    assert_eq!(
        lines[0].spans[0].style.fg,
        Some(Color::Yellow),
        "confirm body yellow"
    );

    let logout = Popup::Text {
        purpose: TextPurpose::ConfirmLogout {
            account_id: "aa".repeat(32),
            npub: "npub1a".to_owned(),
        },
        title: "Log out".to_owned(),
        body: vec!["This permanently destroys the signing key.".to_owned()],
        input: Input::default(),
    };
    let lines = popup_body_lines(&logout).lines;
    assert_eq!(
        lines[0].spans[0].style.fg,
        Some(Color::Red),
        "logout danger body red"
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
    // The armed hint boxes `Enter`/`Esc` as keycaps, so the surrounding words are
    // separate spans; assert on the prose fragments rather than exact spacing.
    assert!(
        armed.contains("reacting to Alice") && armed.contains("clears"),
        "armed hint must name the action and target, got: {armed:?}"
    );
    assert!(
        !armed.contains("unreact"),
        "the static messages keymap must be replaced while armed, got: {armed:?}"
    );

    app.input.clear();
    let idle = rendered_buffer(&mut app);
    assert!(
        idle.contains("unreact"),
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
fn sidebar_width_shrinks_on_narrow_terminals() {
    // 5c: fixed 36 on a wide terminal, but never more than a third of the width so
    // a narrow terminal gives the conversation more room.
    assert_eq!(sidebar_width(120), 36, "wide: capped at 36");
    assert_eq!(sidebar_width(108), 36, "108/3 == 36, still 36");
    assert_eq!(sidebar_width(90), 30, "narrow: a third of 90");
    assert_eq!(sidebar_width(30), 10, "very narrow: a third of 30");
}

#[test]
fn esc_moves_focus_back_spatially_on_main() {
    // 5a: Esc is spatial back on Main — Composer -> Messages -> Chats -> (no-op).
    // A hand-typed draft is never destroyed; only the focus changes.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Main;
    app.focus = Focus::Composer;
    app.input.set_value("draft in progress");

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc");
    assert_eq!(app.focus, Focus::Messages, "Composer -> Messages");
    assert_eq!(app.input.value(), "draft in progress", "draft preserved");

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc");
    assert_eq!(app.focus, Focus::Chats, "Messages -> Chats");

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc");
    assert_eq!(app.focus, Focus::Chats, "Chats -> no-op");
    assert_eq!(
        app.input.value(),
        "draft in progress",
        "draft still preserved"
    );
}

/// Whether the rendered frame has any cell holding `ch` with the DarkGray
/// selection-highlight background (used to detect the messages-pane row
/// highlight, which only the message body carries).
fn cell_with_char_has_darkgray_bg(app: &mut TuiApp, ch: char) -> bool {
    let backend = ratatui::backend::TestBackend::new(100, 30);
    let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");
    terminal.draw(|frame| app.render(frame)).expect("draw TUI");
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .any(|cell| cell.symbol() == ch.to_string() && cell.bg == Color::DarkGray)
}

#[test]
fn messages_highlight_renders_only_when_messages_focused() {
    // 5b: the messages-pane row highlight is gated on focus, so a chat previewed
    // while focus stays on the list (flick-through) shows no stray highlight.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.messages_group_id = Some("gg".repeat(32));
    let mut row = timeline_row("m0", 0);
    row.display_text = "ZEBRAMSG".to_owned();
    app.timeline = vec![row];

    app.focus = Focus::Messages;
    assert!(
        cell_with_char_has_darkgray_bg(&mut app, 'Z'),
        "the selected row is highlighted when the messages pane is focused"
    );

    app.focus = Focus::Chats;
    assert!(
        !cell_with_char_has_darkgray_bg(&mut app, 'Z'),
        "no highlight on the message row when focus is elsewhere"
    );
}

#[test]
fn messages_highlight_stays_while_an_interaction_is_armed() {
    // Arming r/d/R moves focus to the composer, but the highlighted row is the
    // exact target of the pending action — it must keep its highlight while armed
    // so the user can see what they are about to react to / delete / reply to.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.messages_group_id = Some("gg".repeat(32));
    let mut row = timeline_row("m0", 0);
    row.display_text = "ZEBRAMSG".to_owned();
    app.timeline = vec![row];

    // `r` arms /react from the messages pane and moves focus to the composer.
    app.focus = Focus::Messages;
    app.handle_key(char_key('r')).expect("r arms /react");
    assert_eq!(app.focus, Focus::Composer, "r moves focus to the composer");
    assert!(
        is_armed_interaction(app.input.value()),
        "r leaves an armed /react in the composer, got {:?}",
        app.input.value()
    );
    assert!(
        cell_with_char_has_darkgray_bg(&mut app, 'Z'),
        "the target row stays highlighted while an interaction is armed"
    );

    // Companion: focus on the chat list with nothing armed keeps the highlight
    // hidden, so flick-through browsing shows no stray highlight.
    app.input.clear();
    app.focus = Focus::Chats;
    assert!(
        !cell_with_char_has_darkgray_bg(&mut app, 'Z'),
        "no highlight when focus is elsewhere and nothing is armed"
    );
}

#[test]
fn a_leading_space_before_a_command_is_still_armed_and_esc_clears_it() {
    // `parse_slash_command` trims, so a hand-typed leading space (" /react x")
    // still submits as a reaction. The armed hint and the Esc escape hatch share
    // `armed_interaction`, so they must agree with what submits: the hint shows
    // and Esc clears the prefill rather than leaving the user with an invisible
    // armed command.
    assert!(
        armed_interaction_hint(" /react x", None).is_some(),
        "a leading space before /react is still an armed interaction"
    );

    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Composer;
    app.input.set_value(" /react x");

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc");

    assert!(
        app.input.is_empty(),
        "Esc clears the armed interaction even with a leading space, left {:?}",
        app.input.value()
    );
}

#[test]
fn a_leading_space_before_plain_text_is_not_armed_and_esc_preserves_it() {
    // Trimming for command detection must not turn leading-space plain text into
    // an armed command: " hello" is a hand-typed draft, so it shows no armed hint
    // and Esc preserves it (the draft-protection rule).
    assert_eq!(
        armed_interaction_hint(" hello", None),
        None,
        "leading-space plain text is not an armed interaction"
    );

    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.focus = Focus::Composer;
    app.input.set_value(" hello");

    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
        .expect("esc");

    assert_eq!(
        app.input.value(),
        " hello",
        "Esc preserves a hand-typed draft with a leading space"
    );
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
    app.timeline = vec![timeline_row("m0", 0)];
    app.status = "reading".to_owned();
    app.input.set_value("draft");

    app.handle_key(char_key('u')).expect("u");

    assert!(app.popup.is_none(), "u under the help card dismisses it");
    assert_eq!(app.status, "reading", "the underlying unreact never runs");
    assert_eq!(app.input.value(), "draft");
    assert_eq!(app.focus, Focus::Messages);
    assert_eq!(app.timeline[0].message_id, "m0");
}

#[test]
fn messages_u_unreacts_immediately_without_prefilling_or_reloading() {
    let account_id = "aa".repeat(32);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) =
        test_appending_arg_executable(tempdir.path(), r#"{"ok":true,"result":{"published":true}}"#);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;
    app.focus = Focus::Messages;
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some("bb".repeat(32));
    app.timeline = vec![timeline_row("m0", 0)];

    assert!(app.chats.is_empty(), "dispatch needs only the loaded pane");
    app.handle_key(char_key('u')).expect("u");

    assert_eq!(
        app.focus,
        Focus::Messages,
        "u acts immediately; it never focuses the composer"
    );
    assert!(app.input.is_empty(), "u does not prefill the composer");
    assert_eq!(
        app.status, "removing reaction...",
        "the subprocess runs off-loop; the in-flight status is honest"
    );

    // A chat-feed update may arrive while the action is in flight. At fold
    // time, a mistaken reload must have a real selected chat to target.
    app.chats = vec![flick_chat(&"bb".repeat(32), "loaded")];
    app.settle_effects(1);
    assert_eq!(app.status, "removed reaction");
    assert_eq!(
        app.timeline.len(),
        1,
        "no list reload on interaction success"
    );
    finish_queued_effects(&mut app);
    let recorded = std::fs::read_to_string(args_file).expect("recorded args");
    assert!(!recorded.contains("timeline list"), "{recorded}");
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
    assert_eq!(app.status, "deleting...", "in-flight feedback");
    app.settle_effects(1);
    assert_eq!(app.status, "deleted message");
}

#[test]
fn own_message_interactions_do_not_reload_the_timeline() {
    let account_id = "aa".repeat(32);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) =
        test_appending_arg_executable(tempdir.path(), r#"{"ok":true,"result":{"published":true}}"#);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;
    app.chats = vec![flick_chat(&"bb".repeat(32), "loaded")];
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some("bb".repeat(32));
    let mut own = timeline_row("m0", 0);
    own.direction = "sent".to_owned();
    app.timeline = vec![own];

    app.react_to_selected_message("+".to_owned())
        .expect("react");
    app.settle_effects(1);
    assert_eq!(app.status, "reacted +");
    assert_eq!(app.timeline.len(), 1, "react does not reload the list");
    finish_queued_effects(&mut app);
    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    assert!(!recorded.contains("timeline list"), "{recorded}");

    app.delete_selected_message().expect("delete own");
    app.settle_effects(1);
    assert_eq!(app.status, "deleted message");
    assert_eq!(
        app.timeline.len(),
        1,
        "delete does not reload the list; the projection tombstones the row"
    );
    finish_queued_effects(&mut app);
    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    assert!(!recorded.contains("timeline list"), "{recorded}");
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
        flushed_bytes: 0,
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
fn handle_paste_fills_the_message_search_query_only_while_it_has_focus() {
    // Typing edits the message-search query, so pasting one must too — otherwise
    // the most natural way to search for a phrase you already have on the
    // clipboard silently does nothing. The focus gate is what is under test: once
    // the hits take focus the query is no longer accepting characters.
    let mut app = app_with_open_chat(test_unused_client(), &[("m1", "the deploy is green")]);
    app.open_message_search(None).expect("open search");

    app.handle_paste("deploy".to_owned());
    assert_eq!(
        app.message_search.as_ref().expect("view").query.value(),
        "deploy",
        "paste fills the query the same way typing does"
    );

    app.message_search.as_mut().expect("view").focus = MessageSearchFocus::Results;
    app.handle_paste(" ignored".to_owned());
    assert_eq!(
        app.message_search.as_ref().expect("view").query.value(),
        "deploy",
        "paste is ignored once the hits have focus"
    );
    assert!(
        app.input.is_empty(),
        "and never leaks into the composer behind the screen"
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
            rendered.contains('●'),
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
    let exe = dir.join("wn-json");
    let args_file = dir.join("recorded-args");
    write_fake_wn(
        &exe,
        &format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\ncat <<'JSON'\n{response}\nJSON\n",
            args_file.display()
        ),
    );
    (exe, args_file)
}

#[cfg(windows)]
fn test_appending_arg_executable(dir: &std::path::Path, response: &str) -> (PathBuf, PathBuf) {
    let exe = dir.join("wn-json.cmd");
    let args_file = dir.join("recorded-args");
    std::fs::write(
        &exe,
        format!(
            "@echo off\r\necho %* >> \"{}\"\r\necho {response}\r\n",
            args_file.display()
        ),
    )
    .expect("write fake wn");
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
    // Enter runs the one-shot search off-loop; folding it moves focus into the
    // results.
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("run search");
    app.settle_effects(1);
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

/// A timeline-row JSON object in the shape `messages timeline search` returns,
/// which is the same page shape `messages timeline list` returns.
fn timeline_hit_json(message_id: &str, from: &str, text: &str, timeline_at: u64) -> String {
    format!(
        r#"{{"message_id":"{message_id}","direction":"received","from":"{from}","from_display_name":"{from}","plaintext":"{text}","timeline_at":{timeline_at},"received_at":{timeline_at},"deleted":false}}"#
    )
}

/// An app with one chat open and its timeline loaded, ready to search.
fn app_with_open_chat(client: WnClient, rows: &[(&str, &str)]) -> TuiApp {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(client, &account_id);
    app.chats = vec![ChatRow {
        group_id: "g1".to_owned(),
        name: "Ops Room".to_owned(),
        ..ChatRow::default()
    }];
    app.selected_chat = 0;
    app.messages_account_id = Some(account_id);
    app.messages_group_id = Some("g1".to_owned());
    app.timeline = rows
        .iter()
        .enumerate()
        .map(|(index, (message_id, text))| {
            parse_timeline_row(
                &serde_json::from_str::<serde_json::Value>(&timeline_hit_json(
                    message_id,
                    "bob",
                    text,
                    1_700_000_000 + index as u64,
                ))
                .expect("row json"),
            )
            .expect("row parses")
        })
        .collect();
    app
}

#[test]
fn slash_search_runs_a_message_search_over_the_open_chat() {
    let (_dir, client) = test_json_client(&format!(
        r#"{{"ok":true,"result":{{"messages":[{}],"has_more_before":false,"has_more_after":false,"query":"deploy"}}}}"#,
        timeline_hit_json("m2", "bob", "the deploy is green", 1_700_000_001)
    ));
    let mut app = app_with_open_chat(client, &[("m1", "morning"), ("m2", "the deploy is green")]);

    app.run_slash_command(parse_slash_command("/search deploy").expect("parses"))
        .expect("slash search");
    app.settle_effects(1);

    assert_eq!(app.screen, Screen::MessageSearch);
    let view = app.message_search.as_ref().expect("search view");
    assert_eq!(view.query.value(), "deploy");
    assert_eq!(view.results.len(), 1, "the hit folds in as a timeline row");
    assert_eq!(view.results[0].message_id, "m2");
    assert_eq!(view.results[0].plaintext, "the deploy is green");
}

#[cfg(unix)]
#[test]
fn message_search_runs_against_the_loaded_account_not_the_highlighted_one() {
    // A failed `refresh_chats` commits the newly highlighted account while the
    // pane keeps showing the previous account's chat. Search is a pane operation
    // like send/reply/react/delete, so it must follow the pane: keying it on the
    // highlight searches a database that does not hold the searched chat and
    // reports a confident zero hits.
    let loaded_account = "aa".repeat(32);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) = test_arg_recording_executable(
        tempdir.path(),
        r#"{"ok":true,"result":{"messages":[],"has_more_before":false,"has_more_after":false,"query":"deploy"}}"#,
    );
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = app_with_open_chat(client, &[("m1", "the deploy is green")]);
    app.accounts.push(AccountRow {
        account_id: "bb".repeat(32),
        npub: "npub1bob".to_owned(),
        display_name: Some("Bob".to_owned()),
        local_signing: true,
    });
    app.selected_account = 1;

    app.open_message_search(Some("deploy".to_owned()))
        .expect("open search");
    app.settle_effects(1);

    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    let args: Vec<&str> = recorded.lines().collect();
    let account = args
        .iter()
        .position(|arg| *arg == "--account")
        .map(|index| args[index + 1])
        .expect("the search spawns an --account-scoped child");
    assert_eq!(
        account, loaded_account,
        "the search follows the loaded pane, not the highlighted row; got: {args:?}"
    );
}

#[test]
fn message_search_navigates_hits_and_returns_to_the_query() {
    let (_dir, client) = test_json_client(&format!(
        r#"{{"ok":true,"result":{{"messages":[{},{}]}}}}"#,
        timeline_hit_json("m1", "bob", "deploy one", 1_700_000_000),
        timeline_hit_json("m2", "bob", "deploy two", 1_700_000_001)
    ));
    let mut app = app_with_open_chat(client, &[("m1", "deploy one"), ("m2", "deploy two")]);
    app.open_message_search(None).expect("open search");
    // Query focus: typed characters edit the query, so j/k are literal text here.
    for character in "dej".chars() {
        app.handle_key(char_key(character)).expect("type query");
    }
    assert_eq!(app.message_search.as_ref().unwrap().query.value(), "dej");
    app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE))
        .expect("fix the query");
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("run search");
    app.settle_effects(1);

    // Newest first, so the later message leads.
    {
        let view = app.message_search.as_ref().expect("view");
        assert_eq!(view.results.len(), 2);
        assert_eq!(view.results[0].message_id, "m2");
        assert_eq!(view.selected, 0);
    }
    app.handle_key(char_key('j')).expect("j down");
    assert_eq!(app.message_search.as_ref().unwrap().selected, 1);
    app.handle_key(char_key('k')).expect("k up");
    assert_eq!(app.message_search.as_ref().unwrap().selected, 0);
    app.handle_key(char_key('k')).expect("k to query");
    assert_eq!(
        app.message_search.as_ref().unwrap().focus,
        MessageSearchFocus::Query,
        "k at the top returns to the query"
    );
}

/// `TUI_MESSAGE_SEARCH_LIMIT` hits, so a fixture can pair a page of exactly the
/// limit with either answer to "were hits dropped".
fn limit_sized_hit_page() -> String {
    (0..TUI_MESSAGE_SEARCH_LIMIT)
        .map(|index| {
            timeline_hit_json(
                &format!("m{index}"),
                "bob",
                "deploy",
                1_700_000_000 + index as u64,
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Open the message-search screen over a canned page and settle its one effect.
fn settled_message_search(response: &str) -> (tempfile::TempDir, TuiApp) {
    let (dir, client) = test_json_client(response);
    let mut app = app_with_open_chat(client, &[("m0", "deploy")]);
    app.open_message_search(Some("deploy".to_owned()))
        .expect("open search");
    app.settle_effects(1);
    (dir, app)
}

#[test]
fn a_message_search_with_hits_beyond_the_page_reports_a_partial_count() {
    // Hits remain past the page, and the screen is a scan-and-pick list with no
    // paging. Reporting the page size as an exact count would read as "these are
    // all of them" and hide the need to refine the query.
    let hits = limit_sized_hit_page();
    let (_dir, app) = settled_message_search(&format!(
        r#"{{"ok":true,"result":{{"messages":[{hits}],"has_more_before":true}}}}"#
    ));

    let view = app.message_search.as_ref().expect("view");
    assert_eq!(view.results.len(), TUI_MESSAGE_SEARCH_LIMIT);
    assert_eq!(
        view.match_count_label(),
        format!("{TUI_MESSAGE_SEARCH_LIMIT}+"),
        "a page with more behind it is labelled as a lower bound, not an exact count"
    );
    assert!(
        app.status.contains(&format!("{TUI_MESSAGE_SEARCH_LIMIT}+")),
        "the status says the count is partial; got: {:?}",
        app.status
    );
    assert!(
        app.status.contains("refine"),
        "the status points at the action that fixes it; got: {:?}",
        app.status
    );
}

#[test]
fn a_message_search_page_of_exactly_the_limit_with_nothing_behind_it_is_exact() {
    // The count alone cannot tell this page from the one above it, which is why
    // the answer comes from the response rather than from `hits.len()`.
    let hits = limit_sized_hit_page();
    let (_dir, app) = settled_message_search(&format!(
        r#"{{"ok":true,"result":{{"messages":[{hits}],"has_more_before":false}}}}"#
    ));

    let view = app.message_search.as_ref().expect("view");
    assert_eq!(
        view.match_count_label(),
        TUI_MESSAGE_SEARCH_LIMIT.to_string(),
        "a page that happens to be limit-sized is still an exact count"
    );
    assert!(
        !app.status.contains('+') && !app.status.contains("refine"),
        "so nothing asks the reader to refine a complete answer; got: {:?}",
        app.status
    );
}

#[test]
fn a_short_message_search_page_with_hits_behind_it_reports_a_partial_count() {
    // The mirror image: fewer hits than the limit, but the backend says more
    // remain, so the count is a lower bound. Only the response can say this.
    let hits = (0..3)
        .map(|index| {
            timeline_hit_json(
                &format!("m{index}"),
                "bob",
                "deploy",
                1_700_000_000 + index as u64,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let (_dir, app) = settled_message_search(&format!(
        r#"{{"ok":true,"result":{{"messages":[{hits}],"has_more_before":true}}}}"#
    ));

    assert_eq!(
        app.message_search
            .as_ref()
            .expect("view")
            .match_count_label(),
        "3+",
        "truncation follows the response, not the hit count"
    );
}

#[test]
fn a_short_message_search_page_reports_an_exact_count() {
    let (_dir, client) = test_json_client(&format!(
        r#"{{"ok":true,"result":{{"messages":[{}]}}}}"#,
        timeline_hit_json("m1", "bob", "deploy one", 1_700_000_000)
    ));
    let mut app = app_with_open_chat(client, &[("m1", "deploy one")]);
    app.open_message_search(Some("deploy".to_owned()))
        .expect("open search");
    app.settle_effects(1);

    assert_eq!(
        app.message_search
            .as_ref()
            .expect("view")
            .match_count_label(),
        "1",
        "an unfilled page is an exact count"
    );
    assert!(
        !app.status.contains('+'),
        "no partial marker on an exact count; got: {:?}",
        app.status
    );
}

/// A message search for `deploy` with its one-hit page still outstanding. A test
/// that wants the settled screen adds a `settle_effects(1)`; one that types
/// during the flight does not.
fn message_search_in_flight() -> (tempfile::TempDir, TuiApp) {
    let (dir, client) = test_json_client(&format!(
        r#"{{"ok":true,"result":{{"messages":[{}]}}}}"#,
        timeline_hit_json("m1", "bob", "the deploy is green", 1_700_000_000)
    ));
    let mut app = app_with_open_chat(client, &[("m1", "the deploy is green")]);
    app.open_message_search(Some("deploy".to_owned()))
        .expect("open search");
    (dir, app)
}

#[test]
fn editing_a_settled_message_search_query_drops_the_hits_it_answered() {
    let (_dir, mut app) = message_search_in_flight();
    app.settle_effects(1);
    app.handle_key(char_key('i')).expect("back to the query");

    for character in "ment".chars() {
        app.handle_key(char_key(character)).expect("append");
    }

    let view = app.message_search.as_ref().expect("view");
    assert_eq!(view.query.value(), "deployment");
    assert!(
        view.results.is_empty(),
        "hits for `deploy` do not sit under the query `deployment`"
    );
    assert_eq!(view.selected, 0, "nor does a selection into them");
    assert!(!view.truncated, "nor the old page's truncation");
    assert!(
        app.status.is_empty(),
        "nor a count describing the old query; got: {:?}",
        app.status
    );

    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE))
        .expect("down");
    assert_eq!(
        app.message_search.as_ref().expect("view").focus,
        MessageSearchFocus::Query,
        "there is no list to step into"
    );
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("enter");
    assert_eq!(
        app.searching_messages
            .as_ref()
            .map(|(_, _, query)| query.as_str()),
        Some("deployment"),
        "and Enter runs the query the screen shows"
    );
}

#[test]
fn moving_the_message_search_cursor_keeps_a_settled_hit_list() {
    let (_dir, mut app) = message_search_in_flight();
    app.settle_effects(1);
    let count = app.status.clone();
    app.handle_key(char_key('i')).expect("back to the query");

    // `Home` then `Backspace`, and `End` then `Delete`, are the keys that mutate on
    // any other cursor position and change nothing here. Invalidating on the key
    // rather than on the text would throw the hits away on both.
    for code in [
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Home,
        KeyCode::Backspace,
        KeyCode::End,
        KeyCode::Delete,
    ] {
        app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
            .expect("cursor key");
    }

    let view = app.message_search.as_ref().expect("view");
    assert_eq!(view.query.value(), "deploy", "the text is untouched");
    assert_eq!(view.results.len(), 1, "so the hits stay");
    assert_eq!(app.status, count, "and so does the count");
}

#[test]
fn editing_the_query_drops_an_in_flight_message_search_page() {
    let (_dir, mut app) = message_search_in_flight();
    assert_eq!(
        app.searching_messages
            .as_ref()
            .map(|(_, _, query)| query.as_str()),
        Some("deploy")
    );

    for character in "ment".chars() {
        app.handle_key(char_key(character)).expect("append");
    }
    app.settle_effects(1);

    let view = app.message_search.as_ref().expect("view");
    assert!(
        view.results.is_empty(),
        "the page for `deploy` does not land under `deployment`"
    );
    assert_eq!(
        view.focus,
        MessageSearchFocus::Query,
        "and a landing page cannot yank focus out of the query mid-word"
    );
}

#[test]
fn pasting_into_the_message_search_query_invalidates_like_typing() {
    let (_dir, mut app) = message_search_in_flight();
    app.settle_effects(1);
    app.handle_key(char_key('i')).expect("back to the query");

    app.handle_paste("ment".to_owned());

    let view = app.message_search.as_ref().expect("view");
    assert_eq!(view.query.value(), "deployment");
    assert!(view.results.is_empty(), "a paste is an edit like any other");
}

#[test]
fn a_stale_message_search_result_for_a_superseded_query_is_dropped() {
    let (_dir, mut app) = message_search_in_flight();
    // Supersede the first query the way a user does — by editing and re-running it
    // — rather than by assigning the anchor. The anchor comparison in the fold is
    // only worth anything if an edit actually moves the anchor.
    for character in "ment".chars() {
        app.handle_key(char_key(character)).expect("append");
    }
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("run the new query");
    // Effects run in order, so this is the first search's page landing second.
    app.settle_effects(1);

    assert!(
        app.message_search
            .as_ref()
            .expect("view")
            .results
            .is_empty(),
        "the superseded query's page does not repopulate the list"
    );
    assert_eq!(
        app.searching_messages
            .as_ref()
            .map(|(_, _, query)| query.as_str()),
        Some("deployment"),
        "and the outstanding query is left alone"
    );
}

#[test]
fn message_search_targets_the_loaded_chat_not_the_highlighted_row() {
    let (_dir, client) = test_json_client(r#"{"ok":true,"result":{"messages":[]}}"#);
    let mut app = app_with_open_chat(client, &[("m1", "morning")]);
    // Flicking the chat list moves the highlight ahead of the pane, which keeps
    // showing `g1` until the debounced preview lands. A search keyed on the
    // highlight would return `g2` hits the jump could only refuse.
    app.chats.push(ChatRow {
        group_id: "g2".to_owned(),
        name: "Other Room".to_owned(),
        ..ChatRow::default()
    });
    app.selected_chat = 1;

    app.open_message_search(None).expect("open search");

    assert_eq!(
        app.message_search.as_ref().expect("view").group_id,
        "g1",
        "the search follows the pane, not the highlight"
    );
}

#[test]
fn message_search_without_a_loaded_chat_reports_instead_of_opening() {
    let (_dir, client) = test_json_client(r#"{"ok":true,"result":{"messages":[]}}"#);
    let mut app = test_tui_app(client, &"aa".repeat(32));

    let error = app
        .open_message_search(Some("deploy".to_owned()))
        .expect_err("no chat is loaded");

    assert!(
        error.to_string().contains("open a chat first"),
        "says what to do; got: {error}"
    );
    assert!(app.message_search.is_none(), "no empty screen is opened");
    assert_eq!(app.screen, Screen::Main, "and the screen does not change");
}

#[test]
fn message_search_frame_shows_matches_and_strips_control_sequences() {
    let (_dir, client) = test_json_client(&format!(
        r#"{{"ok":true,"result":{{"messages":[{}],"has_more_before":false,"has_more_after":false}}}}"#,
        // An escape sequence in the message body and in the sender's display name:
        // both are relay-supplied text rendering into a pane.
        "{\"message_id\":\"m9\",\"direction\":\"received\",\"from\":\"bob\",\"from_display_name\":\"ev\\u001b[31mil\",\"plaintext\":\"deploy is \\u001b[2Jgreen\",\"timeline_at\":1700000000,\"received_at\":1700000000,\"deleted\":false}"
    ));
    let mut app = app_with_open_chat(client, &[("m9", "deploy is green")]);
    app.open_message_search(Some("deploy".to_owned()))
        .expect("open search");
    app.settle_effects(1);

    let rendered = rendered_buffer(&mut app);
    assert!(rendered.contains("Message Search"), "screen title present");
    assert!(
        rendered.contains("Ops Room"),
        "names the chat being searched"
    );
    assert!(rendered.contains("Matches (1)"), "match count present");
    assert!(rendered.contains("deploy is"), "hit text rendered");

    // Assert the escape stripping on the built lines, not on the rendered buffer:
    // ratatui drops a zero-width ESC while writing cells whatever we hand it, so a
    // buffer-level assertion passes even with the sanitizer removed and would be
    // no guard at all for invariant 7.
    let view = app.message_search.as_ref().expect("search view");
    let body = message_search_lines(view, app.selected_account_row(), false)
        .lines
        .iter()
        .flat_map(|line| line.spans.iter().map(|span| span.content.to_string()))
        .collect::<String>();
    assert!(
        !body.contains('\u{1b}'),
        "no escape reaches a rendered span; got: {body:?}"
    );
    assert!(
        body.contains("deploy is [2Jgreen") && body.contains("ev[31mil"),
        "the surrounding text survives the strip; got: {body:?}"
    );
}

#[test]
fn the_message_search_key_is_named_in_the_palette_hints_and_help() {
    let palette = SLASH_COMMAND_SUGGESTIONS
        .iter()
        .map(|entry| entry.usage)
        .collect::<Vec<_>>();
    assert!(
        palette.contains(&"/search [query]"),
        "the command palette offers the message search; got: {palette:?}"
    );
    assert!(
        message_search_hint(MessageSearchFocus::Results).contains("Enter jump to message"),
        "the results hint names what Enter does"
    );
    let help = help_card_lines().join("\n");
    assert!(
        help.contains("/search"),
        "the help card names the message search; got:\n{help}"
    );
}

#[test]
fn enter_on_a_hit_jumps_the_messages_pane_to_that_message() {
    let (_dir, client) = test_json_client(&format!(
        r#"{{"ok":true,"result":{{"messages":[{}],"has_more_before":false,"has_more_after":false}}}}"#,
        timeline_hit_json("m1", "bob", "the deploy is green", 1_700_000_000)
    ));
    // Four loaded rows with the hit oldest, so a jump has to move the selection
    // and the offset off the newest row it defaults to.
    let mut app = app_with_open_chat(
        client,
        &[
            ("m1", "the deploy is green"),
            ("m2", "second"),
            ("m3", "third"),
            ("m4", "fourth"),
        ],
    );
    app.open_message_search(Some("deploy".to_owned()))
        .expect("open search");
    app.settle_effects(1);
    assert_eq!(
        app.message_search.as_ref().expect("view").focus,
        MessageSearchFocus::Results,
        "landing hits move focus into them"
    );

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("jump to the hit");

    assert_eq!(app.screen, Screen::Main, "returns to the conversation");
    assert_eq!(app.focus, Focus::Messages, "with the messages pane focused");
    assert!(app.message_search.is_none(), "the search view is cleared");
    assert_eq!(
        app.timeline_scroll.resolved_selection(app.timeline.len()),
        Some(0),
        "the hit is the selected message"
    );
    assert_eq!(
        app.timeline_scroll.offset, 3,
        "and the viewport is anchored on it, not on the newest row"
    );
}

#[test]
fn enter_on_a_hit_outside_the_loaded_history_explains_instead_of_moving() {
    let (_dir, client) = test_json_client(&format!(
        r#"{{"ok":true,"result":{{"messages":[{}],"has_more_before":true,"has_more_after":false}}}}"#,
        timeline_hit_json("ancient", "bob", "the deploy is green", 1_600_000_000)
    ));
    // The hit is not among the loaded rows: the timeline is one contiguous run
    // ending at the newest message and cannot represent a hole, so the jump must
    // decline rather than move the viewport somewhere misleading.
    let mut app = app_with_open_chat(client, &[("m1", "morning"), ("m2", "second")]);
    app.open_message_search(Some("deploy".to_owned()))
        .expect("open search");
    app.settle_effects(1);
    let offset_before = app.timeline_scroll.offset;

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("attempt the jump");

    assert_eq!(
        app.screen,
        Screen::MessageSearch,
        "the search screen stays open so the reader keeps the result list"
    );
    assert_eq!(
        app.timeline_scroll.offset, offset_before,
        "the viewport does not move"
    );
    assert!(
        app.status.contains("older than the loaded history"),
        "the status says why, and what to do about it; got: {}",
        app.status
    );
}

#[test]
fn slash_users_query_runs_the_search_immediately() {
    let (_dir, client) = test_json_client(
        r#"{"ok":true,"result":{"users":[{"account_id_hex":"aa","npub":"npubaa","radius":0,"matched_field":"name","match_quality":"exact"}]}}"#,
    );
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.open_user_search(Some("alice".to_owned()));
    // The search runs off-loop; folding it populates the results.
    app.settle_effects(1);
    let view = app.user_search.as_ref().expect("search view");
    assert_eq!(view.query.value(), "alice");
    assert_eq!(view.results.len(), 1);
    assert_eq!(view.focus, UserSearchFocus::Results);
}

fn flick_chat(group_id: &str, name: &str) -> ChatRow {
    ChatRow {
        group_id: group_id.to_owned(),
        name: name.to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    }
}

#[test]
fn flick_j_schedules_a_debounced_preview_and_fires_after_the_quiet_window() {
    let account_id = "aa".repeat(32);
    let group_b = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.daemon.running = false;
    app.focus = Focus::Chats;
    app.chats = vec![flick_chat(&"aa".repeat(32), "a"), flick_chat(&group_b, "b")];
    app.selected_chat = 0;

    app.handle_key(char_key('j'))
        .expect("j highlights the next chat");
    assert_eq!(app.selected_chat, 1, "highlight moved");
    assert_eq!(
        app.flick_countdown,
        Some(FLICK_PREVIEW_DEBOUNCE_TICKS),
        "a preview is scheduled but not fired"
    );
    assert_eq!(app.focus, Focus::Chats, "focus stays on the chat list");
    assert!(app.loading_chat.is_none(), "nothing loads yet");

    // Not enough quiet ticks yet.
    for _ in 0..(FLICK_PREVIEW_DEBOUNCE_TICKS - 1) {
        app.tick();
    }
    assert!(
        app.loading_chat.is_none(),
        "the debounce has not elapsed; no preview load"
    );

    // The tick that reaches zero fires the preview for the highlighted chat.
    app.tick();
    assert_eq!(app.flick_countdown, None, "the countdown cleared");
    assert_eq!(
        app.loading_chat
            .as_ref()
            .map(|(_, group, _)| group.as_str()),
        Some(group_b.as_str()),
        "the highlighted chat's timeline load fired"
    );
    assert_eq!(app.focus, Focus::Chats, "focus never left the chat list");
}

#[test]
fn flick_preview_does_not_fire_after_leaving_the_main_view() {
    let account_id = "aa".repeat(32);
    let group_b = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.daemon.running = false;
    app.focus = Focus::Chats;
    app.chats = vec![flick_chat(&"aa".repeat(32), "a"), flick_chat(&group_b, "b")];
    app.selected_chat = 0;

    app.handle_key(char_key('j')).expect("j");
    assert_eq!(app.flick_countdown, Some(FLICK_PREVIEW_DEBOUNCE_TICKS));

    // The user immediately opens the user-search screen.
    app.open_user_search(None);
    assert_eq!(app.screen, Screen::UserSearch);
    assert_eq!(app.status, "user search");

    for _ in 0..FLICK_PREVIEW_DEBOUNCE_TICKS {
        app.tick();
    }
    assert!(
        app.loading_chat.is_none(),
        "flick preview fired while on the user-search screen"
    );
}

#[test]
fn flick_preview_does_not_fire_behind_an_open_popup() {
    let account_id = "aa".repeat(32);
    let group_b = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.daemon.running = false;
    app.focus = Focus::Chats;
    app.chats = vec![flick_chat(&"aa".repeat(32), "a"), flick_chat(&group_b, "b")];
    app.selected_chat = 0;

    app.handle_key(char_key('j')).expect("j");
    assert_eq!(app.flick_countdown, Some(FLICK_PREVIEW_DEBOUNCE_TICKS));

    // `?` opens the help card over the still-focused chat list (Screen::Main,
    // Focus::Chats). The countdown keeps running behind the modal.
    app.handle_key(char_key('?')).expect("?");
    assert!(app.popup.is_some());
    assert_eq!(app.screen, Screen::Main);
    assert_eq!(app.focus, Focus::Chats);

    for _ in 0..FLICK_PREVIEW_DEBOUNCE_TICKS {
        app.tick();
    }
    assert!(
        app.loading_chat.is_none(),
        "flick preview fired behind the help popup, reloading the pane and \
         marking a chat read behind the modal"
    );
}

#[cfg(unix)]
#[test]
fn rapid_flick_coalesces_to_one_load_of_the_final_selection() {
    let account_id = "aa".repeat(32);
    let group_a = "aa".repeat(32);
    let group_b = "bb".repeat(32);
    let group_c = "cc".repeat(32);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) =
        test_appending_arg_executable(tempdir.path(), r#"{"ok":true,"result":{}}"#);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;
    app.focus = Focus::Chats;
    app.chats = vec![
        flick_chat(&group_a, "a"),
        flick_chat(&group_b, "b"),
        flick_chat(&group_c, "c"),
    ];
    app.selected_chat = 0;

    // Race through the list with no quiet ticks between presses: j (->b), j
    // (->c), k (->b). The countdown resets on every move, so nothing fires yet.
    app.handle_key(char_key('j')).expect("j");
    app.handle_key(char_key('j')).expect("j");
    app.handle_key(char_key('k')).expect("k");
    assert_eq!(app.selected_chat, 1, "settled on the middle chat");
    assert!(app.loading_chat.is_none(), "no premature load mid-race");

    // Let the movement quiet: exactly one preview fires, for the final selection.
    for _ in 0..FLICK_PREVIEW_DEBOUNCE_TICKS {
        app.tick();
    }
    assert_eq!(
        app.loading_chat
            .as_ref()
            .map(|(_, group, _)| group.as_str()),
        Some(group_b.as_str())
    );
    app.settle_effects(1);
    finish_queued_effects(&mut app);

    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    let timeline_loads: Vec<&str> = recorded
        .lines()
        .filter(|line| line.contains("timeline list"))
        .collect();
    assert_eq!(
        timeline_loads.len(),
        1,
        "rapid flicks coalesce to exactly one timeline load: {recorded:?}"
    );
    assert!(
        timeline_loads[0].contains(&group_b),
        "the single load targets the final selection (b): {:?}",
        timeline_loads[0]
    );
}

#[cfg(unix)]
#[test]
fn enter_after_a_settled_same_chat_preview_is_a_focus_move_only() {
    let account_id = "aa".repeat(32);
    let group_a = "aa".repeat(32);
    let group_b = "bb".repeat(32);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) = test_appending_arg_executable(
        tempdir.path(),
        r#"{"ok":true,"result":{"messages":[],"has_more_before":false}}"#,
    );
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = test_tui_app(client, &account_id);
    app.daemon.running = false;
    app.focus = Focus::Chats;
    app.chats = vec![flick_chat(&group_a, "a"), flick_chat(&group_b, "b")];
    app.selected_chat = 0;

    // Flick to B and let the preview fire and settle onto the pane.
    app.handle_key(char_key('j')).expect("j to b");
    for _ in 0..FLICK_PREVIEW_DEBOUNCE_TICKS {
        app.tick();
    }
    assert_eq!(
        app.loading_chat
            .as_ref()
            .map(|(_, group, _)| group.as_str()),
        Some(group_b.as_str())
    );
    app.settle_effects(1); // fold the flick preview load
    assert_eq!(app.messages_group_id.as_deref(), Some(group_b.as_str()));
    assert!(app.loading_chat.is_none(), "the preview settled");

    // Enter on the already-loaded, settled chat is a focus move only: it must not
    // re-enqueue a redundant timeline load (nor a second mark-read).
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("enter");
    assert_eq!(
        app.focus,
        Focus::Messages,
        "Enter still moves focus to the message pane"
    );
    assert!(
        app.loading_chat.is_none(),
        "Enter on a settled same-chat preview enqueues no reload"
    );
    finish_queued_effects(&mut app);

    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    let timeline_loads: Vec<&str> = recorded
        .lines()
        .filter(|line| line.contains("timeline list"))
        .collect();
    assert_eq!(
        timeline_loads.len(),
        1,
        "flick-then-open loads B exactly once, not twice: {recorded:?}"
    );

    let other_account = "dd".repeat(32);
    app.accounts.push(AccountRow {
        account_id: other_account.clone(),
        npub: "npub1other".into(),
        display_name: None,
        local_signing: true,
    });
    app.selected_account = 1;
    app.focus = Focus::Chats;
    app.activate_focus()
        .expect("open the same group as another account");
    assert_eq!(
        app.loading_chat
            .as_ref()
            .map(|(account, group, _)| (account, group)),
        Some((&other_account, &group_b))
    );
    assert!(app.timeline.is_empty());
    app.settle_effects(1);
    finish_queued_effects(&mut app);
    assert_eq!(
        app.messages_account_id.as_deref(),
        Some(other_account.as_str())
    );

    app.selected_account = 0;
    app.focus = Focus::Chats;
    app.flick_countdown = Some(1);
    app.tick();
    assert_eq!(
        app.loading_chat
            .as_ref()
            .map(|(account, group, _)| (account, group)),
        Some((&account_id, &group_b))
    );
    app.settle_effects(1);
    finish_queued_effects(&mut app);
    let recorded = std::fs::read_to_string(&args_file).expect("fenced cross-account args");
    let timeline_loads: Vec<_> = recorded
        .lines()
        .filter(|line| line.contains("timeline list"))
        .collect();
    assert_eq!(timeline_loads.len(), 3);
    assert!(timeline_loads[1].contains(&format!("--account {other_account}")));
    assert!(timeline_loads[2].contains(&format!("--account {account_id}")));
}

#[test]
fn enter_supersedes_a_pending_flick_preview() {
    let account_id = "aa".repeat(32);
    let group_b = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.daemon.running = false;
    app.focus = Focus::Chats;
    app.chats = vec![flick_chat(&"aa".repeat(32), "a"), flick_chat(&group_b, "b")];
    app.selected_chat = 0;

    app.handle_key(char_key('j'))
        .expect("j schedules a preview");
    assert!(app.flick_countdown.is_some());

    // Enter opens the chat immediately and cancels the pending preview.
    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("enter");
    assert_eq!(
        app.flick_countdown, None,
        "the pending preview is cancelled"
    );
    assert_eq!(app.focus, Focus::Messages, "Enter moves focus to messages");
    assert_eq!(
        app.loading_chat
            .as_ref()
            .map(|(_, group, _)| group.as_str()),
        Some(group_b.as_str())
    );
}

#[test]
fn group_detail_load_maps_to_the_four_groups_calls_in_order() {
    let effect = Effect::LoadGroupDetail {
        account: "aa".repeat(32),
        group: "gg".to_owned(),
    };
    let calls = effect.calls();
    assert_eq!(
        calls,
        ["members", "admins", "relays", "show"].map(|subcommand| WnCall {
            account: Some("aa".repeat(32)),
            args: vec!["groups".to_owned(), subcommand.to_owned(), "gg".to_owned()],
        }),
        "group detail reads members, admins, relays, then show — the fold's slice order"
    );
}

#[test]
fn a_stale_group_detail_load_after_leaving_is_dropped() {
    let self_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &self_id);
    // The user opened a group detail, then left before it landed.
    app.screen = Screen::Main;
    app.loading_group_detail = None;

    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadGroupDetail {
            account: self_id.clone(),
            group: "cc".repeat(32),
        },
        result: Ok(vec![
            serde_json::json!({"members": [{"member_id": self_id, "npub": "npubself"}]}),
            serde_json::json!({"admins": []}),
            serde_json::json!({"relays": []}),
            serde_json::json!({"profile": {"name": "Ops"}}),
        ]),
    });
    assert!(
        app.group_detail.is_none(),
        "a group-detail result after leaving never repopulates the view"
    );
}

#[test]
fn open_group_detail_reports_loading_then_settles_on_fold() {
    let self_id = "aa".repeat(32);
    let group_id = "cc".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &self_id);
    app.focus = Focus::Chats;
    app.chats = vec![projected_chat(&group_id, "Ops", 0, Some(10))];
    app.selected_chat = 0;

    app.open_group_detail().expect("open group detail");
    assert_eq!(
        app.status, "loading group detail...",
        "honest in-flight feedback while the four-call load runs off-loop"
    );
    assert_eq!(app.screen, Screen::GroupDetail);

    // Folding the completed load clears the in-flight status.
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadGroupDetail {
            account: self_id.clone(),
            group: group_id.clone(),
        },
        result: Ok(vec![
            serde_json::json!({"members": [{"member_id": self_id, "npub": "npubself"}]}),
            serde_json::json!({"admins": []}),
            serde_json::json!({"relays": []}),
            serde_json::json!({"profile": {"name": "Ops"}}),
        ]),
    });
    assert_ne!(
        app.status, "loading group detail...",
        "the in-flight status is cleared once the load lands"
    );
    assert!(app.group_detail.is_some(), "the view populated");
}

#[test]
fn invites_load_reports_loading_then_opens_the_picker() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);

    app.open_invites().expect("kickoff");
    assert_eq!(
        app.status, "loading invites...",
        "honest in-flight feedback"
    );
    assert!(app.loading_invites, "a load is in flight");
    assert!(
        app.popup.is_none(),
        "the picker opens only when the list lands"
    );

    // A second press while one is in flight does not double-queue.
    app.open_invites().expect("no double-queue");

    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadInvites {
            account: account_id,
        },
        result: Ok(vec![serde_json::json!({
            "invites": [{"group_id": "cc", "profile": {"name": "Ops"}, "pending_confirmation": true}]
        })]),
    });
    assert!(!app.loading_invites, "the load settled");
    assert!(
        matches!(
            app.popup,
            Some(Popup::Picker {
                purpose: PickerPurpose::Invites,
                ..
            })
        ),
        "the invites picker opened"
    );
}

#[test]
fn a_stale_invites_result_for_a_switched_account_is_dropped() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_a);
    app.accounts = vec![
        AccountRow {
            account_id: account_a.clone(),
            npub: "npuba".to_owned(),
            display_name: None,
            local_signing: true,
        },
        AccountRow {
            account_id: account_b.clone(),
            npub: "npubb".to_owned(),
            display_name: None,
            local_signing: true,
        },
    ];
    // A is selected and started an invites load; the user then switched to B
    // before it landed.
    app.selected_account = 0;
    app.loading_invites = true;
    app.selected_account = 1;

    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadInvites {
            account: account_a.clone(),
        },
        result: Ok(vec![serde_json::json!({
            "invites": [{"group_id": "cc", "profile": {"name": "Ops"}, "pending_confirmation": true}]
        })]),
    });

    assert!(
        app.popup.is_none(),
        "an invites list for a since-switched account never opens a picker of the wrong account's invites"
    );
    assert!(
        !app.loading_invites,
        "the stale load clears the in-flight guard so a fresh open can proceed"
    );
}

#[test]
fn an_invites_fold_over_an_image_popup_reopens_through_the_close_funnel() {
    // I from the chat list queues the invites load; the user Tabs to the pane
    // and opens an image message. On a pixel terminal the viewer writes the
    // image terminal-side, out of ratatui's cell-diff reach. When the invites
    // result lands, replacing the popup by direct assignment would leave the
    // pixel image on screen and the decoded viewer copy alive. The fold must
    // funnel through close_popup: schedule the full clear+repaint and drop the
    // native protocol before opening the picker.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Main;
    app.focus = Focus::Messages;
    let mut row = timeline_row("m", 0);
    row.display_text = "look".to_owned();
    row.attachments = vec![image_attachment("cafebabe")];
    app.timeline = vec![row];
    app.media = iterm2_media_with_ready_image("cafebabe");

    app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE))
        .expect("open viewer");
    assert!(matches!(app.popup, Some(Popup::Image { .. })));
    assert!(app.media.viewer_protocol_mut("cafebabe").is_some());
    assert!(!app.pending_full_repaint);

    // The invites load (queued before the image was opened) now lands.
    app.loading_invites = true;
    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadInvites {
            account: account_id,
        },
        result: Ok(vec![serde_json::json!({
            "invites": [{"group_id": "cc", "profile": {"name": "Ops"}, "pending_confirmation": true}]
        })]),
    });

    assert!(
        matches!(
            app.popup,
            Some(Popup::Picker {
                purpose: PickerPurpose::Invites,
                ..
            })
        ),
        "the invites picker replaced the image popup"
    );
    assert!(
        app.pending_full_repaint,
        "replacing the image popup must schedule the full clear+repaint"
    );
    assert!(
        app.media.viewer_protocol_mut("cafebabe").is_none(),
        "replacing the image popup must drop the terminal-side viewer protocol"
    );
}

#[test]
fn an_invites_fold_while_on_the_profile_screen_does_not_open_the_picker() {
    // I queues the invites load from the chat list; p then opens Profile before
    // the result lands. The picker is reachable only from Main and group detail,
    // so a late fold must drop rather than pop over an unrelated screen.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::Profile;
    app.loading_invites = true;

    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadInvites {
            account: account_id,
        },
        result: Ok(vec![serde_json::json!({
            "invites": [{"group_id": "cc", "profile": {"name": "Ops"}, "pending_confirmation": true}]
        })]),
    });

    assert!(
        app.popup.is_none(),
        "the invites picker popped over the profile screen"
    );
    assert!(
        !app.loading_invites,
        "the dropped load clears the in-flight guard"
    );
}

#[test]
fn user_search_maps_to_the_users_search_argv_plus_a_follows_snapshot() {
    // The second call is the local `follows list` directory read — one cheap
    // call that lets every result row render an accurate follow badge, instead
    // of a `follows check` per row.
    let effect = Effect::UserSearch {
        account: "aa".repeat(32),
        query: "alice".to_owned(),
    };
    assert_eq!(
        effect.calls(),
        vec![
            WnCall {
                account: Some("aa".repeat(32)),
                args: vec!["users".to_owned(), "search".to_owned(), "alice".to_owned()],
            },
            WnCall {
                account: Some("aa".repeat(32)),
                args: vec!["follows".to_owned(), "list".to_owned()],
            },
        ]
    );
}

#[test]
fn a_user_search_fold_badges_the_rows_the_account_already_follows() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::UserSearch;
    app.user_search = Some(UserSearchView::default());
    app.searching_users = Some("ali".to_owned());

    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::UserSearch {
            account: account_id,
            query: "ali".to_owned(),
        },
        result: Ok(vec![
            serde_json::json!({
                "users": [
                    {"account_id_hex": "bb".repeat(32), "npub": "npubbb", "radius": 1,
                     "matched_field": "name", "match_quality": "prefix",
                     "profile": {"display_name": "Alice"}},
                    {"account_id_hex": "cc".repeat(32), "npub": "npubcc", "radius": 2,
                     "matched_field": "name", "match_quality": "prefix",
                     "profile": {"display_name": "Alina"}},
                ]
            }),
            serde_json::json!({
                "follows": [{"account_id": "bb".repeat(32), "npub": "npubbb"}]
            }),
        ]),
    });

    let view = app.user_search.as_ref().expect("search view");
    assert!(
        view.results[0].following,
        "the followed result is badged from the snapshot"
    );
    assert!(
        !view.results[1].following,
        "an unfollowed result carries no badge"
    );

    let rendered = user_search_lines(view, false)
        .lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        rendered.contains("[following]"),
        "the badge renders on the followed row; got:\n{rendered}"
    );
    assert_eq!(
        rendered.matches("[following]").count(),
        1,
        "only the followed row is badged; got:\n{rendered}"
    );
}

#[test]
fn user_search_pane_scrolls_the_whole_selected_row_into_view() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::UserSearch;
    // Two lines per result, so a result list far taller than the pane needs the
    // attribution line visible too — not just the label the marker sits on.
    let results: Vec<UserSearchResultRow> = (0..30)
        .map(|index| UserSearchResultRow {
            pubkey: format!("{index:064}"),
            npub: format!("npubresult{index:02}"),
            display_name: Some(if index == 29 {
                "LASTRESULT".to_owned()
            } else {
                format!("result{index:02}")
            }),
            matched_field: if index == 29 { "nip05" } else { "name" }.to_owned(),
            match_quality: "prefix".to_owned(),
            radius: 2,
            following: false,
        })
        .collect();
    let selected = results.len() - 1;
    app.user_search = Some(UserSearchView {
        results,
        selected,
        focus: UserSearchFocus::Results,
        ..UserSearchView::default()
    });

    let rendered = rendered_buffer(&mut app);
    assert!(
        rendered.contains("LASTRESULT"),
        "the selected result renders inside the pane"
    );
    assert!(
        rendered.contains("nip05 · prefix · radius 2"),
        "the selected result's attribution line renders with it"
    );
}

#[cfg(unix)]
#[test]
fn a_failing_follows_snapshot_still_folds_the_search_results_without_badges() {
    // The badge read is the effect's second call and is best-effort: a
    // `follows list` failure that lands *after* a successful `users search`
    // must still surface the results (with no badges), never discard the whole
    // search as an error the way the old first-error short-circuit did.
    let account_id = "aa".repeat(32);
    let (_tempdir, client) = test_scripted_client(
        "case \" $* \" in\n\
         *' follows list '*)\n\
         cat <<'JSON'\n{\"ok\":false,\"error\":{\"message\":\"relay unreachable\"}}\nJSON\n;;\n\
         *' users search '*)\n\
         cat <<'JSON'\n{\"ok\":true,\"result\":{\"users\":[\
         {\"account_id_hex\":\"bb\",\"npub\":\"npubbb\",\"radius\":1,\"matched_field\":\"name\",\"match_quality\":\"prefix\",\"profile\":{\"display_name\":\"Alice\"}},\
         {\"account_id_hex\":\"cc\",\"npub\":\"npubcc\",\"radius\":2,\"matched_field\":\"name\",\"match_quality\":\"prefix\",\"profile\":{\"display_name\":\"Alina\"}}\
         ]}}\nJSON\n;;\n\
         *)\ncat <<'JSON'\n{\"ok\":true,\"result\":{}}\nJSON\n;;\nesac\n",
    );
    let mut app = test_tui_app(client, &account_id);

    app.open_user_search(Some("ali".to_owned()));
    app.settle_effects(1);

    let view = app.user_search.as_ref().expect("search view");
    assert_eq!(view.results.len(), 2, "both search results still fold in");
    assert!(
        view.results.iter().all(|row| !row.following),
        "a failed follows snapshot leaves every row unbadged"
    );
    assert_eq!(
        app.status, "found 2 user(s)",
        "the search succeeds; the best-effort badge failure is not surfaced as an error"
    );
}

#[cfg(unix)]
#[test]
fn a_failing_user_search_call_still_reports_as_an_error() {
    // The search itself is the required first call: its failure must still land
    // on the status line as an error (the best-effort tolerance covers only the
    // trailing badge read).
    let account_id = "aa".repeat(32);
    let (_tempdir, client) = test_scripted_client(
        "case \" $* \" in\n\
         *' users search '*)\n\
         cat <<'JSON'\n{\"ok\":false,\"error\":{\"message\":\"directory offline\"}}\nJSON\n;;\n\
         *)\ncat <<'JSON'\n{\"ok\":true,\"result\":{}}\nJSON\n;;\nesac\n",
    );
    let mut app = test_tui_app(client, &account_id);

    app.open_user_search(Some("ali".to_owned()));
    app.settle_effects(1);

    assert_eq!(app.status, "error: directory offline");
    assert!(
        app.user_search
            .as_ref()
            .expect("search view")
            .results
            .is_empty(),
        "a failed search folds no results"
    );
}

#[cfg(unix)]
#[test]
fn a_re_search_after_following_badges_the_row_from_the_follows_snapshot() {
    // Following a result (`f`) badges its row directly; a fresh re-search rebuilds
    // the result rows from scratch, so their badge can only come from the
    // `follows list` snapshot the search takes. This proves that snapshot reflects
    // the just-made follow end to end. The fake `follows list` returns the user
    // only once `follows add` has run (a marker beside the script), so the first
    // search shows no badge and the re-search does.
    let account_id = "aa".repeat(32);
    let (_tempdir, client) = test_scripted_client(
        "marker=\"$(dirname \"$0\")/followed\"\n\
         case \" $* \" in\n\
         *' follows add '*)\n\
         : > \"$marker\"\n\
         cat <<'JSON'\n{\"ok\":true,\"result\":{\"follows\":[{\"account_id\":\"bb\",\"npub\":\"npubbb\"}]}}\nJSON\n;;\n\
         *' follows list '*)\n\
         if [ -f \"$marker\" ]; then\n\
         cat <<'JSON'\n{\"ok\":true,\"result\":{\"follows\":[{\"account_id\":\"bb\",\"npub\":\"npubbb\"}]}}\nJSON\n\
         else\n\
         cat <<'JSON'\n{\"ok\":true,\"result\":{\"follows\":[]}}\nJSON\n\
         fi\n;;\n\
         *' users search '*)\n\
         cat <<'JSON'\n{\"ok\":true,\"result\":{\"users\":[\
         {\"account_id_hex\":\"bb\",\"npub\":\"npubbb\",\"radius\":1,\"matched_field\":\"name\",\"match_quality\":\"prefix\",\"profile\":{\"display_name\":\"Bob\"}}\
         ]}}\nJSON\n;;\n\
         *)\ncat <<'JSON'\n{\"ok\":true,\"result\":{}}\nJSON\n;;\nesac\n",
    );
    let mut app = test_tui_app(client, &account_id);

    app.open_user_search(Some("bob".to_owned()));
    app.settle_effects(1);
    assert!(
        !app.user_search.as_ref().expect("search view").results[0].following,
        "before following, the snapshot has no follow so the row is unbadged"
    );

    app.handle_key(char_key('f'))
        .expect("f follows the highlighted result");
    app.settle_effects(1);

    // Re-run the same query: the results are rebuilt from scratch, so the badge
    // below can only have come from the refreshed follows snapshot.
    app.run_user_search().expect("re-search");
    app.settle_effects(1);
    assert!(
        app.user_search.as_ref().expect("search view").results[0].following,
        "the re-search badges the row from the follows snapshot that now lists the user"
    );
}

/// A user search for `bob` with its one-result page still outstanding, the
/// user-search mirror of [`message_search_in_flight`].
fn user_search_in_flight() -> (tempfile::TempDir, TuiApp) {
    let (dir, client) = test_json_client(
        r#"{"ok":true,"result":{"users":[{"account_id_hex":"bb","npub":"npubbb","radius":1,"matched_field":"name","match_quality":"prefix","profile":{"display_name":"Bob"}}]}}"#,
    );
    let mut app = test_tui_app(client, &"aa".repeat(32));
    app.open_user_search(Some("bob".to_owned()));
    (dir, app)
}

#[test]
fn editing_a_settled_user_search_query_drops_the_results_it_answered() {
    // It matters more here than on message search: the results-focus keys publish
    // follows (`f`/`x`) and open chat popups (`c`/`a`), so a row left under a query
    // it does not answer is not just misread, it is acted on.
    let (_dir, mut app) = user_search_in_flight();
    app.settle_effects(1);
    assert_eq!(app.user_search.as_ref().expect("view").results.len(), 1);
    app.handle_key(char_key('i')).expect("back to the query");

    for character in "by".chars() {
        app.handle_key(char_key(character)).expect("append");
    }

    let view = app.user_search.as_ref().expect("view");
    assert_eq!(view.query.value(), "bobby");
    assert!(
        view.results.is_empty(),
        "results for `bob` do not sit under the query `bobby`"
    );
    assert_eq!(view.selected, 0, "nor does a selection into them");
    assert!(
        app.status.is_empty(),
        "nor a count describing the old query; got: {:?}",
        app.status
    );

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("enter");
    assert_eq!(
        app.searching_users.as_deref(),
        Some("bobby"),
        "and Enter runs the query the screen shows"
    );
}

#[test]
fn moving_the_user_search_cursor_keeps_a_settled_result_list() {
    let (_dir, mut app) = user_search_in_flight();
    app.settle_effects(1);
    let count = app.status.clone();
    app.handle_key(char_key('i')).expect("back to the query");

    for code in [
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Home,
        KeyCode::Backspace,
        KeyCode::End,
        KeyCode::Delete,
    ] {
        app.handle_key(KeyEvent::new(code, KeyModifiers::NONE))
            .expect("cursor key");
    }

    let view = app.user_search.as_ref().expect("view");
    assert_eq!(view.query.value(), "bob", "the text is untouched");
    assert_eq!(view.results.len(), 1, "so the results stay");
    assert_eq!(app.status, count, "and so does the count");
}

#[test]
fn editing_the_query_drops_an_in_flight_user_search_page() {
    let (_dir, mut app) = user_search_in_flight();
    assert_eq!(app.searching_users.as_deref(), Some("bob"));

    for character in "by".chars() {
        app.handle_key(char_key(character)).expect("append");
    }
    app.settle_effects(1);

    let view = app.user_search.as_ref().expect("view");
    assert!(
        view.results.is_empty(),
        "the page for `bob` does not land under `bobby`"
    );
    assert_eq!(
        view.focus,
        UserSearchFocus::Query,
        "and a landing page cannot yank focus out of the query mid-word"
    );
}

#[test]
fn pasting_into_the_user_search_query_invalidates_like_typing() {
    let (_dir, mut app) = user_search_in_flight();
    app.settle_effects(1);
    app.handle_key(char_key('i')).expect("back to the query");

    app.handle_paste("by".to_owned());

    let view = app.user_search.as_ref().expect("view");
    assert_eq!(view.query.value(), "bobby");
    assert!(view.results.is_empty(), "a paste is an edit like any other");
}

#[test]
fn a_stale_user_search_result_for_a_superseded_query_is_dropped() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::UserSearch;
    let mut view = UserSearchView::default();
    view.query.set_value("bob".to_owned());
    app.user_search = Some(view);
    // The pending search is for "bob"; an "alice" result is a superseded query.
    app.searching_users = Some("bob".to_owned());

    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
        effect: Effect::UserSearch {
            account: account_id,
            query: "alice".to_owned(),
        },
        result: Ok(vec![serde_json::json!({
            "users": [{"account_id_hex":"aa","npub":"npubaa","radius":0,"matched_field":"name","match_quality":"exact"}]
        })]),
    });

    assert!(
        app.user_search.as_ref().unwrap().results.is_empty(),
        "the superseded query's results never land"
    );
    assert_eq!(
        app.searching_users.as_deref(),
        Some("bob"),
        "the pending search anchor is untouched by a stale result"
    );
}

#[test]
fn leaving_a_search_in_flight_drops_a_late_result_from_the_reopened_screen() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    // A search for "alice" is in flight on the search screen.
    app.screen = Screen::UserSearch;
    let mut view = UserSearchView::default();
    view.query.set_value("alice".to_owned());
    app.user_search = Some(view);
    app.searching_users = Some("alice".to_owned());
    app.status = "searching...".to_owned();

    // The user leaves before it lands: the pending-search anchor is cleared so a
    // late fold cannot pass the tag guard against a freshly reopened screen.
    app.leave_screen();
    assert!(
        app.searching_users.is_none(),
        "leaving clears the in-flight search anchor"
    );

    // The user reopens a fresh search screen without running a new query.
    app.open_user_search(None);
    assert!(app.user_search.as_ref().unwrap().results.is_empty());

    // The abandoned "alice" search now completes; its result must not land in the
    // fresh screen.
    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
        effect: Effect::UserSearch {
            account: account_id,
            query: "alice".to_owned(),
        },
        result: Ok(vec![serde_json::json!({
            "users": [{"account_id_hex":"aa","npub":"npubaa","radius":0,"matched_field":"name","match_quality":"exact"}]
        })]),
    });
    assert!(
        app.user_search.as_ref().unwrap().results.is_empty(),
        "a search abandoned by leaving never repopulates a freshly reopened screen"
    );
}

#[test]
fn leaving_a_search_in_flight_clears_the_searching_status() {
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.screen = Screen::UserSearch;
    let mut view = UserSearchView::default();
    view.query.set_value("alice".to_owned());
    app.user_search = Some(view);
    app.searching_users = Some("alice".to_owned());
    app.status = "searching...".to_owned();

    app.leave_screen();

    assert!(
        app.status.is_empty(),
        "the stranded \"searching...\" status is cleared when leaving mid-search, got {:?}",
        app.status
    );
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
    for (index, field, flag, value, acknowledgement) in [
        (0, ProfileField::Name, "--name", "Alice", "updated name"),
        (
            1,
            ProfileField::DisplayName,
            "--display-name",
            "Al",
            "updated display name",
        ),
        (
            2,
            ProfileField::About,
            "--about",
            "ships tools",
            "updated about",
        ),
        (
            3,
            ProfileField::Picture,
            "--picture",
            "https://example.test/avatar.png",
            "updated picture",
        ),
        (
            4,
            ProfileField::Nip05,
            "--nip05",
            "alice@example.test",
            "updated nip05",
        ),
        (
            5,
            ProfileField::Lud16,
            "--lud16",
            "tips@example.test",
            "updated lud16",
        ),
    ] {
        for local_signing in [true, false] {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let exe = tempdir.path().join("wn-json");
            let args_file = tempdir.path().join("recorded-args");
            let response = r#"{"ok":true,"result":{}}"#;
            write_fake_wn(
                &exe,
                &format!(
                    "#!/bin/sh\nset -eu\nprintf '%s\\0' \"$@\" >> '{}'\nprintf '\\0' >> '{}'\ncat <<'JSON'\n{response}\nJSON\n",
                    args_file.display(),
                    args_file.display(),
                ),
            );
            let account = "aa".repeat(32);
            let mut app = test_tui_app(
                WnClient {
                    exe,
                    ..test_unused_client()
                },
                &account,
            );
            app.daemon.running = false;
            app.accounts[0].local_signing = local_signing;
            app.accounts.insert(
                0,
                AccountRow {
                    account_id: "bb".repeat(32),
                    npub: "npubother".into(),
                    display_name: None,
                    local_signing: true,
                },
            );
            app.selected_account = 1;
            app.screen = Screen::Profile;
            let mut view = ProfileView {
                npub: "npub1self".into(),
                ..ProfileView::default()
            };
            view.fields = [
                "stored-name",
                "stored-display",
                "stored-about",
                "stored-picture",
                "stored-nip05",
                "stored-lud16",
            ]
            .map(|value| Some(value.to_owned()));
            view.fields[index] = Some(value.to_owned());
            view.selected = index;
            app.profile_view = Some(view);
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .expect("open edit");
            assert!(matches!(
                &app.popup,
                Some(Popup::Text { purpose: TextPurpose::EditProfileField { field: selected }, input, .. })
                    if *selected == field && input.value() == value
            ));
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .expect("submit edit");
            if !local_signing {
                assert_eq!(
                    app.status,
                    "error: selected account is public-only and cannot sign"
                );
                assert!(
                    !args_file.exists(),
                    "public-only account must not spawn a mutation"
                );
                continue;
            }
            assert_eq!(app.status, acknowledgement);
            let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
            let updates: Vec<Vec<_>> = recorded
                .split("\0\0")
                .filter(|call| !call.is_empty())
                .map(|call| call.split('\0').collect::<Vec<_>>())
                .filter(|call| call.get(3) == Some(&"profile") && call.get(4) == Some(&"update"))
                .collect();
            assert_eq!(
                updates,
                [vec![
                    "--json",
                    "--account",
                    account.as_str(),
                    "profile",
                    "update",
                    flag,
                    value
                ]]
            );
        }
    }
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
        "health": {
            "sdk_backed": true,
            "total_relays": 3,
            "connected": 2,
            "connecting": 0,
            "disconnected": 1,
            "connection_attempts": 5,
            "connection_successes": 4,
            "notification_forwarder_running": true,
            "notification_forwarder_restarts": 2,
            "notification_forwarder_lag_incidents": 1,
            "notification_forwarder_lagged_notifications": 17,
            "notification_forwarder_panics": 1,
            "notification_forwarder_unexpected_exits": 1
        }
    });
    let data = parse_relay_health(&snapshot, true);
    assert_eq!(data.inbound_seen, 10);
    assert_eq!(data.total_relays, 3);
    assert_eq!(data.connected, 2);
    assert!(data.notification_forwarder_running);
    assert_eq!(data.notification_forwarder_restarts, 2);
    assert_eq!(data.notification_forwarder_lag_incidents, 1);
    assert_eq!(data.notification_forwarder_lagged_notifications, 17);
    assert_eq!(data.notification_forwarder_panics, 1);
    assert_eq!(data.notification_forwarder_unexpected_exits, 1);
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
            following: false,
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
fn profile_pane_scrolls_the_selected_follow_into_view() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.screen = Screen::Profile;
    // A follow list far taller than the pane, with the selection at the bottom.
    let mut follows: Vec<String> = (0..60)
        .map(|index| format!("npubfollow{index:02}"))
        .collect();
    follows[59] = "npubLASTFOLLOW".to_owned();
    let mut view = ProfileView {
        npub: "npubSELF".to_owned(),
        follows,
        ..ProfileView::default()
    };
    view.selected = view.row_count() - 1;
    app.profile_view = Some(view);

    let rendered = rendered_buffer(&mut app);
    assert!(
        rendered.contains("npubLASTFOLLOW"),
        "the selected follow renders inside the pane"
    );
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
    let account = "aa".repeat(32);
    // Keep all three original relay-source contrasts through the actual Profile
    // popup callers. Search-result follow effects have a separate owner.
    for (relay, setup, expected_prefix, expected_suffix) in [
        (None, true, "--json", " --relay wss://default"),
        (None, false, "--json", ""),
        (
            Some("wss://global"),
            true,
            "--json --relay wss://global",
            "",
        ),
    ] {
        for (key, peer, verb, acknowledgement) in [
            ('f', "npub1bob", "add", "followed npub1bob"),
            ('x', "npubselected", "remove", "unfollowed npubselected"),
        ] {
            for local_signing in [true, false] {
                let dir = tempfile::tempdir().expect("tempdir");
                let (exe, args_file) =
                    test_appending_arg_executable(dir.path(), r#"{"ok":true,"result":{}}"#);
                let client = WnClient {
                    exe,
                    home: None,
                    socket: None,
                    relay: relay.map(str::to_owned),
                    discovery_relays: if setup {
                        vec!["wss://discovery".into()]
                    } else {
                        Vec::new()
                    },
                    default_account_relays: if setup {
                        vec!["wss://default".into()]
                    } else {
                        Vec::new()
                    },
                    secret_store: None,
                    keychain_service: None,
                };
                let mut app = test_tui_app(client, &account);
                app.accounts[0].local_signing = local_signing;
                app.accounts.insert(
                    0,
                    AccountRow {
                        account_id: "bb".repeat(32),
                        npub: "npubother".into(),
                        display_name: None,
                        local_signing: true,
                    },
                );
                app.selected_account = 1;
                app.screen = Screen::Profile;
                app.profile_view = Some(ProfileView {
                    follows: vec!["npubfirst".into(), "npubselected".into()],
                    selected: 7,
                    ..ProfileView::default()
                });
                app.handle_key(char_key(key)).expect("open follow popup");
                assert!(app.popup.is_some());
                app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                    .expect("cancel");
                assert!(app.popup.is_none());
                assert!(!args_file.exists(), "cancel must not change follows");
                app.handle_key(char_key(key)).expect("reopen follow popup");
                if key == 'f' {
                    app.handle_paste(peer.to_owned());
                }
                app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                    .expect("submit");
                assert!(app.popup.is_none());
                if !local_signing {
                    assert_eq!(
                        app.status,
                        "error: selected account is public-only and cannot sign"
                    );
                    assert!(
                        !args_file.exists(),
                        "public-only account must not spawn a mutation"
                    );
                    continue;
                }
                assert_eq!(app.status, acknowledgement);
                let recorded = std::fs::read_to_string(&args_file).expect("recorded calls");
                let mutations: Vec<_> = recorded
                    .lines()
                    .filter(|line| line.contains(&format!(" follows {verb} ")))
                    .collect();
                assert_eq!(
                    mutations,
                    [format!(
                        "{expected_prefix} --account {account} follows {verb} {peer}{expected_suffix}"
                    )]
                );
            }
        }
    }
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
            following: false,
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
fn adding_a_found_user_from_group_detail_adds_them_and_returns_to_the_group() {
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
    let mut app = app_on_group_detail(client);
    app.handle_key(char_key('a')).expect("a on group detail");
    app.user_search.as_mut().expect("search view").results =
        vec![search_result_row("npubbob", "Bob")];
    app.user_search.as_mut().expect("search view").focus = UserSearchFocus::Results;
    app.handle_key(char_key('a')).expect("a on the result");

    app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
        .expect("confirm the add");

    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    assert!(
        recorded.contains(&format!("groups add-members g1 {}", "bb".repeat(32))),
        "the member is added to the group the search was opened for; got:\n{recorded}"
    );
    // Back where the flow started, not on the main view: the point of adding
    // from group detail is to see the member land in that list.
    assert_eq!(app.screen, Screen::GroupDetail);
    assert!(app.user_search.is_none(), "the search view is cleared");
    assert_eq!(
        app.loading_group_detail.as_deref(),
        Some("g1"),
        "the group detail reloads so the new member shows"
    );
    // The add published, so the status must report that and not be displaced by
    // the return that follows it. A completed add reported as anything else
    // would send the user to re-add a member who is already in the group.
    assert!(
        app.status.contains("added member(s)"),
        "the completed add is what the status reports; got: {:?}",
        app.status
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

// ---- Non-blocking effects: the dispatch-decision-as-value seam ----

#[test]
fn react_effect_maps_to_the_plural_messages_react_argv() {
    // The pure argv mapping is asserted without spawning a subprocess: the
    // effect resolves to exactly the call the worker will run.
    let effect = Effect::React {
        account: "aa".repeat(32),
        group: "bb".repeat(32),
        message_id: "m1".to_owned(),
        emoji: "+".to_owned(),
    };
    assert_eq!(
        effect.calls(),
        vec![WnCall {
            account: Some("aa".repeat(32)),
            args: vec![
                "messages".to_owned(),
                "react".to_owned(),
                "bb".repeat(32),
                "m1".to_owned(),
                "+".to_owned(),
            ],
        }]
    );
}

#[test]
fn react_key_in_messages_focus_resolves_to_the_selected_rows_effect() {
    // key + state -> invocation value, with no subprocess: the selected timeline
    // row and the loaded group/account resolve into the effect the app enqueues.
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some(group_id.clone());
    app.timeline = vec![timeline_row("m0", 0), timeline_row("m1", 10)];

    let effect = app.resolve_react("+".to_owned()).expect("resolves");
    assert_eq!(
        effect,
        Effect::React {
            account: account_id,
            group: group_id,
            message_id: "m1".to_owned(),
            emoji: "+".to_owned(),
        },
        "reacts to the newest (pinned-selected) row"
    );
}

#[cfg(unix)]
#[test]
fn queued_mutations_run_in_fifo_order_off_the_event_loop() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let mut gate = TestCommandGate::new(tempdir.path());
    let exe = tempdir.path().join("wn-json");
    let args_file = tempdir.path().join("recorded-args");
    write_fake_wn(
        &exe,
        &format!(
            "#!/bin/sh\ncase \" $* \" in *' react '*' 1 '*)\n{};;\nesac\necho \"$*\" >> '{}'\nprintf '%s\\n' '{{\"ok\":true,\"result\":{{}}}}'\n",
            gate.script(),
            args_file.display()
        ),
    );
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let (continue_tx, continue_rx) = mpsc::channel();
    let (ui_tx, ui_rx) = mpsc::channel();
    let (finish_tx, finish_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut app = test_tui_app(client, &account_id);
        app.messages_account_id = Some(account_id);
        app.messages_group_id = Some(group_id);
        app.timeline = vec![timeline_row("m1", 10)];
        app.react_to_selected_message("1".to_owned())
            .expect("react 1");
        continue_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("first child entered");
        app.react_to_selected_message("2".to_owned())
            .expect("react 2");
        app.handle_key(char_key('x'))
            .expect("typing while mutation is blocked");
        ui_tx
            .send(app.input.value().to_owned())
            .expect("report UI action");
        if finish_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("UI observation completed")
        {
            app.settle_effects(1);
            assert_eq!(
                app.status, "reacting...",
                "the second request still owns feedback"
            );
            app.settle_effects(1);
            assert_eq!(app.status, "reacted 2");
        }
    });
    gate.wait_until_entered();
    continue_tx.send(()).expect("first child is blocked");
    let typed_before_release = ui_rx.recv_timeout(Duration::from_secs(5));
    gate.release();
    finish_tx
        .send(typed_before_release.is_ok())
        .expect("finish observation");
    worker.join().expect("UI thread");
    assert_eq!(
        typed_before_release.expect("typing completed before child release"),
        "x"
    );

    let recorded = std::fs::read_to_string(&args_file).expect("recorded args");
    let react_lines: Vec<_> = recorded
        .lines()
        .filter(|line| line.contains(" react "))
        .collect();
    assert_eq!(react_lines.len(), 2, "both reacts ran: {recorded:?}");
    assert!(
        react_lines[0].ends_with(" 1") && react_lines[1].ends_with(" 2"),
        "queued reacts ran FIFO (emoji 1 then 2): {react_lines:?}"
    );
}

#[test]
fn react_reports_in_flight_then_final_status_via_the_fold() {
    // The kickoff reports "reacting..." immediately (honest in-flight feedback);
    // folding the worker result reports the final status. No timeline reload.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some("bb".repeat(32));
    app.timeline = vec![timeline_row("m1", 10)];

    app.react_to_selected_message("+".to_owned())
        .expect("react");
    assert_eq!(app.status, "reacting...", "in-flight feedback is honest");

    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::React {
            account: account_id,
            group: "bb".repeat(32),
            message_id: "m1".to_owned(),
            emoji: "+".to_owned(),
        },
        result: Ok(vec![serde_json::json!({})]),
    });
    assert_eq!(app.status, "reacted +");
    assert_eq!(app.timeline.len(), 1, "react never reloads the timeline");
}

#[test]
fn open_chat_load_maps_to_the_timeline_page_argv() {
    let effect = Effect::LoadTimeline {
        account: "aa".repeat(32),
        group: "bb".repeat(32),
        generation: 1,
    };
    assert_eq!(
        effect.calls(),
        vec![WnCall {
            account: Some("aa".repeat(32)),
            args: vec![
                "messages".to_owned(),
                "timeline".to_owned(),
                "list".to_owned(),
                "--group".to_owned(),
                "bb".repeat(32),
                "--limit".to_owned(),
                TUI_TIMELINE_PAGE_SIZE.to_string(),
            ],
        }]
    );
}

#[test]
fn opening_a_chat_reports_loading_then_folds_the_timeline_page() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.chats = vec![ChatRow {
        group_id: group_id.clone(),
        name: "general".to_owned(),
        archived: false,
        projection: ChatProjection::default(),
    }];
    app.selected_chat = 0;
    // Daemon is off in this app, so the load stays a pure fold with no spawned
    // subscription children.
    app.daemon.running = false;

    app.refresh_messages().expect("kickoff");
    assert_eq!(app.status, "loading chat...", "honest in-flight feedback");
    assert_eq!(
        app.loading_chat
            .as_ref()
            .map(|(_, group, _)| group.as_str()),
        Some(group_id.as_str())
    );
    assert!(
        app.timeline.is_empty(),
        "rows arrive only when the load folds"
    );

    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadTimeline {
            account: account_id.clone(),
            group: group_id.clone(),
            generation: app.timeline_load_generation,
        },
        result: Ok(vec![serde_json::json!({
            "messages": [{
                "message_id": "m1",
                "direction": "received",
                "from": "alice",
                "plaintext": "hello",
                "timeline_at": 100,
                "received_at": 100
            }],
            "has_more_before": true
        })]),
    });

    assert_eq!(app.timeline.len(), 1);
    assert_eq!(app.timeline[0].message_id, "m1");
    assert!(app.timeline_scroll.has_more_before);
    assert!(app.timeline_scroll.is_pinned());
    assert_eq!(app.messages_group_id.as_deref(), Some(group_id.as_str()));
    assert_eq!(app.loading_chat, None, "the load is settled");
    assert_eq!(app.status, "loaded 1 message(s)");
}

#[test]
fn a_stale_open_chat_load_for_a_superseded_chat_is_dropped() {
    // Open chat A, then open chat B before A's load lands. A's late result must
    // not clobber the pane now targeting B.
    let account_id = "aa".repeat(32);
    let group_a = "aa".repeat(32);
    let group_b = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.daemon.running = false;
    app.chats = vec![
        ChatRow {
            group_id: group_a.clone(),
            name: "a".to_owned(),
            archived: false,
            projection: ChatProjection::default(),
        },
        ChatRow {
            group_id: group_b.clone(),
            name: "b".to_owned(),
            archived: false,
            projection: ChatProjection::default(),
        },
    ];

    app.selected_chat = 0;
    app.refresh_messages().expect("open A");
    let generation_a = app.timeline_load_generation;
    app.selected_chat = 1;
    app.refresh_messages().expect("open B");
    assert_eq!(
        app.loading_chat
            .as_ref()
            .map(|(_, group, _)| group.as_str()),
        Some(group_b.as_str())
    );

    // A's late result arrives after the user moved to B.
    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadTimeline {
            account: account_id.clone(),
            group: group_a.clone(),
            generation: generation_a,
        },
        result: Ok(vec![serde_json::json!({
            "messages": [{"message_id":"stale","direction":"received","from":"x","plaintext":"old","timeline_at":1,"received_at":1}],
            "has_more_before": false
        })]),
    });
    assert!(
        app.timeline.is_empty(),
        "the superseded load is dropped; the pane still awaits B"
    );
    assert_ne!(
        app.messages_group_id.as_deref(),
        Some(group_a.as_str()),
        "the pane never adopts the stale chat"
    );
    assert_eq!(
        app.loading_chat
            .as_ref()
            .map(|(_, group, _)| group.as_str()),
        Some(group_b.as_str())
    );

    // B's result lands and is accepted.
    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadTimeline {
            account: account_id,
            group: group_b.clone(),
            generation: app.timeline_load_generation,
        },
        result: Ok(vec![serde_json::json!({
            "messages": [{"message_id":"fresh","direction":"received","from":"x","plaintext":"new","timeline_at":9,"received_at":9}],
            "has_more_before": false
        })]),
    });
    assert_eq!(app.timeline.len(), 1);
    assert_eq!(app.timeline[0].message_id, "fresh");
    assert_eq!(app.messages_group_id.as_deref(), Some(group_b.as_str()));
}

#[test]
fn a_switched_away_accounts_timeline_fold_is_dropped() {
    let account_a = "aa".repeat(32);
    let group_a = "cc".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_a);
    app.daemon.running = false;
    app.chats = vec![flick_chat(&group_a, "a")];
    app.selected_chat = 0;

    app.begin_timeline_load(account_a.clone(), group_a.clone());

    // Switch to a public-only account: refresh_chats takes its early return,
    // clearing the pane without queueing a superseding load.
    app.accounts.push(AccountRow {
        account_id: "bb".repeat(32),
        npub: "npub1bob".to_owned(),
        display_name: None,
        local_signing: false,
    });
    app.selected_account = 1;
    app.refresh_chats().expect("refresh_chats");
    assert!(app.messages_group_id.is_none());

    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadTimeline {
            account: account_a.clone(),
            group: group_a.clone(),
            generation: app.timeline_load_generation,
        },
        result: Ok(vec![serde_json::json!({"messages": []})]),
    });
    assert!(
        app.messages_group_id.is_none(),
        "a switched-away account's timeline fold repopulated the pane"
    );
    // The drop path clears the anchor so the pane's loading notice does not
    // stick on a group the user has left (nothing supersedes this load).
    assert!(
        app.loading_chat.is_none(),
        "the switched-away load left the loading anchor pointing at a left chat"
    );
}

#[test]
fn a_same_group_load_for_another_account_keeps_its_pane_and_pending_owner() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let group = "cc".repeat(16);
    let other_group = "ee".repeat(16);
    for changes_account in [false, true] {
        let target_account = if changes_account {
            &account_b
        } else {
            &account_a
        };
        let target_group = if changes_account {
            &group
        } else {
            &other_group
        };
        let mut app = test_tui_app(test_unused_client(), &account_a);
        app.daemon.running = false;
        app.accounts.push(AccountRow {
            account_id: account_b.clone(),
            npub: "npub1bob".into(),
            display_name: None,
            local_signing: true,
        });
        app.chats = vec![
            flick_chat(&group, "shared"),
            flick_chat(&other_group, "other"),
        ];
        app.chats_account_id = Some(account_a.clone());
        app.messages_account_id = Some(account_a.clone());
        app.messages_group_id = Some(group.clone());
        app.timeline = vec![timeline_row("old-account-row", 1)];
        let (tx, rx) = mpsc::channel();
        app.message_subscription = Some(MessageSubscription {
            account_id: account_a.clone(),
            child: test_sleep_child(),
            rx,
        });
        tx.send(SubscriptionEvent::Result(serde_json::json!({
            "type":"agent_stream_delta","agent_stream_delta":{
                "group_id":group,"stream_id":"dd".repeat(32),"text":"initial account stream"
            }
        })))
        .unwrap();
        assert!(app.drain_message_subscription());
        app.refresh_messages().expect("reload A");
        let generation_a = app.timeline_load_generation;
        assert_eq!(timeline_ids(&app.timeline), vec!["old-account-row"]);
        assert!(rendered_buffer(&mut app).contains("initial account stream"));

        app.selected_account = usize::from(changes_account);
        app.selected_chat = usize::from(!changes_account);
        app.chats_account_id = Some(target_account.clone());
        app.refresh_messages().expect("open the selected owner");
        // A second load can start before the first page returns. Its pending
        // owner must keep the same-account feed alive while the pane is empty.
        app.refresh_messages().expect("reload the pending owner");
        let pending_action_account =
            match app.resolve_send_message("pending message".into()).unwrap() {
                Effect::SendMessage {
                    account,
                    group: target,
                    ..
                } => {
                    assert_eq!(&target, target_group);
                    account
                }
                _ => panic!("send resolved the wrong effect"),
            };
        let pending_rows = timeline_ids(&app.timeline)
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        // The account-wide feed must survive a group change within A, while
        // opening B must disconnect A before its next delta can contaminate B.
        let outgoing_feed_closed = tx.send(SubscriptionEvent::Result(serde_json::json!({
            "type":"agent_stream_delta","agent_stream_delta":{
                "group_id":target_group,"stream_id":"ff".repeat(32),"text":"outgoing account stream"
            }
        }))).is_err();
        app.drain_message_subscription();
        app.apply_effect_done(EffectDone {
            status_owner: Some(app.status_ownership.revision),
            effect: Effect::LoadTimeline {
                account: account_a.clone(),
                group: group.clone(),
                generation: generation_a,
            },
            result: Ok(vec![serde_json::json!({"messages":[]})]),
        });
        let pending_survives_old_result = app.loading_chat.is_some();
        app.apply_effect_done(EffectDone {
            status_owner: Some(app.status_ownership.revision),
            effect: Effect::LoadTimeline {
                account: target_account.clone(),
                group: target_group.clone(),
                generation: app.timeline_load_generation,
            },
            result: Ok(vec![serde_json::json!({"messages":[{
                "message_id":"new-owner-row","direction":"received","from":"peer",
                "plaintext":"selected timeline","timeline_at":2,"received_at":2
            }],"has_more_before":false})]),
        });
        let outgoing_preview_visible = rendered_buffer(&mut app).contains("account stream");
        assert_eq!(
            (
                pending_action_account,
                pending_rows,
                pending_survives_old_result,
                timeline_ids(&app.timeline),
                app.messages_account_id.clone(),
                outgoing_feed_closed,
                outgoing_preview_visible
            ),
            (
                target_account.clone(),
                Vec::<String>::new(),
                true,
                vec!["new-owner-row"],
                Some(target_account.clone()),
                changes_account,
                !changes_account
            ),
        );
    }
}

#[cfg(unix)]
#[test]
fn an_empty_account_refresh_cannot_reuse_another_accounts_stream_preview() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let group = "cc".repeat(16);
    let dir = tempfile::tempdir().unwrap();
    let mut gate = TestCommandGate::new(dir.path());
    let chat = serde_json::json!({"ok":true,"result":{"type":"chat","chat":{
        "group_id":group,"profile":{"name":"B joined room"}
    }}})
    .to_string();
    let incoming =
        serde_json::json!({"ok":true,"result":{"type":"agent_stream_delta","agent_stream_delta":{
            "group_id":group,"stream_id":"dd".repeat(32),"text":"incoming account preview"
        }}})
        .to_string();
    let reconnected = serde_json::json!({"ok":true,"result":{
        "type":"agent_stream_delta","agent_stream_delta":{
            "group_id":group,"stream_id":"ee".repeat(32),"text":"reconnected account A preview"
        }
    }})
    .to_string();
    let exe = dir.path().join("wn-refresh");
    write_fake_wn(
        &exe,
        &format!(
            "#!/bin/sh\ncase \"$*\" in\n*'chats subscribe'*)\n{}printf '%s\\n' '{chat}'\nexec sleep 60\n;;\n*'--account {account_a} messages subscribe'*) printf '%s\\n' '{reconnected}'; exec sleep 60;;\n*'--account {account_b} messages subscribe'*) printf '%s\\n' '{incoming}'; exec sleep 60;;\n*subscribe*) exec sleep 60;;\n*) printf '%s\\n' '{{\"ok\":true,\"result\":{{\"chats\":[],\"messages\":[]}}}}';;\nesac\n",
            gate.script()
        ),
    );
    let mut app = test_tui_app(
        WnClient {
            exe,
            ..test_unused_client()
        },
        &account_a,
    );
    app.accounts.push(AccountRow {
        account_id: account_b.clone(),
        npub: "npub1bob".into(),
        display_name: None,
        local_signing: true,
    });
    app.chats = vec![flick_chat(&group, "A room")];
    app.chats_account_id = Some(account_a.clone());
    app.messages_account_id = Some(account_a.clone());
    app.messages_group_id = Some(group.clone());
    app.timeline = vec![timeline_row("A row", 1)];
    let (tx, rx) = mpsc::channel();
    app.message_subscription = Some(MessageSubscription {
        account_id: account_a.clone(),
        child: test_sleep_child(),
        rx,
    });
    tx.send(SubscriptionEvent::Result(
        serde_json::json!({"type":"agent_stream_delta","agent_stream_delta":{
            "group_id":group,"stream_id":"dd".repeat(32),"text":"outgoing account preview"
        }}),
    ))
    .unwrap();
    app.drain_message_subscription();
    assert!(rendered_buffer(&mut app).contains("outgoing account preview"));
    tx.send(SubscriptionEvent::Ended).unwrap();
    app.drain_message_subscription();
    assert!(app.message_subscription.is_none());
    app.daemon.running = true;
    app.ensure_message_subscription(&account_a)
        .expect("reconnect A's feed");
    assert_eq!(
        app.message_subscription.as_ref().unwrap().account_id,
        account_a
    );
    assert!(
        rendered_buffer(&mut app).contains("outgoing account preview"),
        "same-account reconnect preserves observed previews"
    );
    let reconnected_a_child = app.message_subscription.as_ref().unwrap().child.id();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !rendered_buffer(&mut app).contains("reconnected account A preview") {
        app.drain_message_subscription();
        assert!(
            Instant::now() < deadline,
            "A's actual reconnected child did not deliver"
        );
        thread::sleep(Duration::from_millis(1));
    }
    app.selected_account = 1;
    app.refresh_chats().expect("refresh B's empty list");
    gate.wait_until_entered();
    assert!(app.chats.is_empty());
    assert_eq!(app.messages_account_id.as_deref(), Some(account_b.as_str()));
    let b_feed = app
        .message_subscription
        .as_ref()
        .expect("B's empty-list feed");
    assert_eq!(b_feed.account_id, account_b);
    assert_ne!(b_feed.child.id(), reconnected_a_child);
    assert_eq!(
        app.stream_previews_account_id.as_deref(),
        Some(account_b.as_str())
    );
    assert!(
        app.live_stream_previews.is_empty(),
        "the empty-list transition clears A before any later load"
    );
    gate.release();
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.chats.is_empty() {
        app.drain_chat_subscription();
        assert!(
            Instant::now() < deadline,
            "B's real chat child did not deliver its row"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(app.chats[0].name, "B joined room");
    app.refresh_messages().unwrap();
    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),effect:Effect::LoadTimeline {account:account_b.clone(), group, generation: app.timeline_load_generation}, result:Ok(vec![serde_json::json!({"messages":[{
        "message_id":"B row","direction":"received","from":"peer","plaintext":"B timeline","timeline_at":2,"received_at":2
    }]})])});
    let deadline = Instant::now() + Duration::from_secs(5);
    while !rendered_buffer(&mut app).contains("incoming account preview") {
        app.drain_message_subscription();
        assert!(
            Instant::now() < deadline,
            "B's real message child did not deliver its preview"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(app.messages_account_id, Some(account_b));
    assert_eq!(timeline_ids(&app.timeline), vec!["B row"]);
    for text in ["outgoing account preview", "reconnected account A preview"] {
        assert!(
            !rendered_buffer(&mut app).contains(text),
            "A's preview must not survive B's empty-list account transition"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_failed_account_page_keeps_its_live_feed_and_reuses_it_on_retry() {
    let account_a = "aa".repeat(32);
    let account_b = "bb".repeat(32);
    let group = "cc".repeat(16);
    let dir = tempfile::tempdir().unwrap();
    let mut gate = TestCommandGate::new(dir.path());
    let first_page = dir.path().join("first-page");
    let chat = serde_json::json!({"ok":true,"result":{"chats":[{
        "group_id":group,"profile":{"name":"B room"}
    }]}})
    .to_string();
    let page = serde_json::json!({"ok":true,"result":{"messages":[{
        "message_id":"B retry row","direction":"received","from":"peer",
        "plaintext":"B recovered page","timeline_at":2,"received_at":2
    }],"has_more_before":false}})
    .to_string();
    let incoming = serde_json::json!({"ok":true,"result":{
        "type":"agent_stream_delta","agent_stream_delta":{
            "group_id":group,"stream_id":"dd".repeat(32),"text":"B live after page error"
        }
    }})
    .to_string();
    let exe = dir.path().join("wn-page-error");
    write_fake_wn(
        &exe,
        &format!(
            "#!/bin/sh\ncase \" $* \" in\n\
         *' --account {account_b} messages subscribe '*)\n{}printf '%s\\n' '{incoming}'\nexec sleep 60\n;;\n\
         *' chats list '*) printf '%s\\n' '{chat}';;\n\
         *' messages timeline list '*)\nif mkdir '{}' 2>/dev/null; then\nprintf '%s\\n' '{{\"ok\":false,\"error\":{{\"message\":\"timeline offline\"}}}}'\nelse\nprintf '%s\\n' '{page}'\nfi\n;;\n\
         *' subscribe '*|*' subscribe-state '*) exec sleep 60;;\n\
         *) printf '%s\\n' '{{\"ok\":true,\"result\":{{}}}}';;\nesac\n",
            gate.script(),
            first_page.display()
        ),
    );
    let mut app = test_tui_app(
        WnClient {
            exe,
            ..test_unused_client()
        },
        &account_a,
    );
    app.daemon.running = true;
    app.accounts.push(AccountRow {
        account_id: account_b.clone(),
        npub: "npub1bob".into(),
        display_name: None,
        local_signing: true,
    });
    app.chats = vec![flick_chat(&group, "A room")];
    app.chats_account_id = Some(account_a.clone());
    app.messages_account_id = Some(account_a.clone());
    app.messages_group_id = Some(group.clone());
    app.timeline = vec![timeline_row("A row", 1)];
    app.ensure_message_subscription(&account_a)
        .expect("A's live feed");
    let outgoing_child = app.message_subscription.as_ref().unwrap().child.id();
    app.select_account_by_selector(&account_b)
        .expect("B's real nonempty list");
    finish_queued_effects(&mut app);
    assert_eq!(app.status, "error: timeline offline");
    assert!(app.loading_chat.is_none());
    assert_eq!(
        app.message_subscription
            .as_ref()
            .map(|feed| feed.account_id.as_str()),
        Some(account_b.as_str()),
        "a failed B page must keep B's account-wide feed"
    );
    let incoming_child = app.message_subscription.as_ref().unwrap().child.id();
    assert_ne!(incoming_child, outgoing_child);
    gate.wait_until_entered();
    assert!(
        app.message_subscription
            .as_mut()
            .unwrap()
            .child
            .try_wait()
            .unwrap()
            .is_none()
    );
    gate.release();
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.live_stream_previews.is_empty() {
        app.drain_message_subscription();
        assert!(
            Instant::now() < deadline,
            "B's actual child did not deliver after the page error"
        );
        thread::sleep(Duration::from_millis(1));
    }
    app.refresh_messages().expect("retry B's page");
    assert_eq!(
        app.message_subscription.as_ref().unwrap().child.id(),
        incoming_child
    );
    finish_queued_effects(&mut app);
    assert_eq!(
        app.message_subscription.as_ref().unwrap().child.id(),
        incoming_child
    );
    assert_eq!(app.messages_account_id, Some(account_b));
    assert_eq!(timeline_ids(&app.timeline), vec!["B retry row"]);
    assert!(rendered_buffer(&mut app).contains("B live after page error"));
}

#[test]
fn same_chat_reload_merges_and_keeps_a_live_subscription_insert() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.daemon.running = false;
    // A chat is loaded and settled: the pane shows two messages and its group is
    // the loaded target, so a same-chat reload keeps the pane and its live
    // subscription (it never clears the pane like a different-chat open does).
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some(group_id.clone());
    app.timeline = vec![timeline_row("m1", 100), timeline_row("m2", 200)];
    // A same-chat reload is in flight (its group matches the loaded pane).
    app.timeline_load_generation = 1;
    app.loading_chat = Some((
        account_id.clone(),
        group_id.clone(),
        app.timeline_load_generation,
    ));

    // Between enqueue and fold, the live timeline subscription folds in a newer
    // message.
    app.timeline.push(timeline_row("m3", 300));

    // The reload page returns only what was materialized at enqueue time (m1, m2).
    app.apply_effect_done(EffectDone { status_owner: Some(app.status_ownership.revision),
        effect: Effect::LoadTimeline {
            account: account_id,
            group: group_id.clone(),
            generation: app.timeline_load_generation,
        },
        result: Ok(vec![serde_json::json!({
            "messages": [
                {"message_id":"m1","direction":"received","from":"x","plaintext":"one","timeline_at":100,"received_at":100},
                {"message_id":"m2","direction":"received","from":"x","plaintext":"two","timeline_at":200,"received_at":200}
            ],
            "has_more_before": false
        })]),
    });

    assert_eq!(
        timeline_ids(&app.timeline),
        vec!["m1", "m2", "m3"],
        "a same-chat reload merges the page by id instead of replacing, so a \
         subscription insert during the load window survives"
    );
    assert!(app.loading_chat.is_none(), "the reload settled");
    assert_eq!(app.messages_group_id.as_deref(), Some(group_id.as_str()));
}

#[test]
fn send_maps_to_the_plural_messages_send_argv() {
    let effect = Effect::SendMessage {
        account: "aa".repeat(32),
        group: "bb".repeat(32),
        text: "hi".to_owned(),
    };
    assert_eq!(
        effect.calls(),
        vec![WnCall {
            account: Some("aa".repeat(32)),
            args: vec![
                "messages".to_owned(),
                "send".to_owned(),
                "bb".repeat(32),
                "hi".to_owned(),
            ],
        }],
        "send uses the documented plural `messages send`, not the singular alias"
    );
}

#[test]
fn sending_reports_in_flight_then_folds_an_optimistic_row() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some(group_id.clone());

    app.send_message("hello there".to_owned()).expect("kickoff");
    assert_eq!(app.status, "sending...", "in-flight feedback is honest");
    assert!(
        app.timeline.is_empty(),
        "the row folds only when the send lands"
    );

    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::SendMessage {
            account: account_id,
            group: group_id,
            text: "hello there".to_owned(),
        },
        result: Ok(vec![
            serde_json::json!({"published": 1, "message_ids": ["m1"]}),
        ]),
    });

    assert_eq!(app.timeline.len(), 1);
    assert_eq!(app.timeline[0].message_id, "m1");
    assert_eq!(app.timeline[0].direction, "sent");
    assert_eq!(app.timeline[0].display_text, "hello there");
    assert!(
        app.timeline_scroll.is_pinned(),
        "an own send keeps the view pinned to the bottom"
    );
}

#[test]
fn an_optimistic_send_row_for_a_chat_the_user_left_is_dropped() {
    // The send still happened; folding its row into a pane now showing another
    // chat would be wrong, so the fold drops it (the group's subscription shows
    // it on return).
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.messages_group_id = Some("bb".repeat(32));

    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::SendMessage {
            account: account_id,
            group: "cc".repeat(32),
            text: "hello".to_owned(),
        },
        result: Ok(vec![
            serde_json::json!({"published": 1, "message_ids": ["m1"]}),
        ]),
    });
    assert!(
        app.timeline.is_empty(),
        "no optimistic row lands in the pane of a different chat"
    );
}

#[test]
fn reply_resolves_the_selected_target_and_folds_an_optimistic_reply() {
    let account_id = "aa".repeat(32);
    let group_id = "bb".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.messages_account_id = Some(account_id.clone());
    app.messages_group_id = Some(group_id.clone());
    app.timeline = vec![timeline_row("parent", 5)];

    let effect = app.resolve_reply("re: hi".to_owned()).expect("resolves");
    assert_eq!(
        effect,
        Effect::SendReply {
            account: account_id.clone(),
            group: group_id.clone(),
            reply_to: "parent".to_owned(),
            text: "re: hi".to_owned(),
        },
        "the reply targets the selected (pinned newest) row"
    );

    app.send_reply("re: hi".to_owned()).expect("kickoff");
    assert_eq!(app.status, "sending reply...");
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect,
        result: Ok(vec![
            serde_json::json!({"published": 1, "message_ids": ["r1"]}),
        ]),
    });
    let reply_row = app
        .timeline
        .iter()
        .find(|row| row.message_id == "r1")
        .expect("the optimistic reply row folded in");
    assert_eq!(reply_row.direction, "sent");
    assert_eq!(
        reply_row
            .reply
            .as_ref()
            .map(|reply| reply.reply_to_message_id.as_str()),
        Some("parent"),
        "the optimistic reply carries its parent id"
    );
}

// --- Daemon auto-start at launch ---
//
// `wn tui` needs a running daemon for group/invite flows and live feeds, and the
// field-proven footgun is forgetting `/daemon start`. Launch auto-starts the
// daemon off the event loop when it is down and the TUI holds a relay source to
// give it; without one it surfaces a single honest status and continues
// degraded. Deliberate divergence from the retired reference client: the daemon
// is never killed on exit, because other `wn` commands share it.

#[cfg(unix)]
#[test]
fn launch_with_no_daemon_and_relay_flags_auto_starts_the_daemon() {
    // Keep the original discovery-only admission edge as well as both-list forwarding.
    for (arguments, expected) in [
        (
            vec!["wn", "tui", "--discovery-relays", "wss://d.example"],
            vec![
                "--json",
                "daemon",
                "start",
                "--discovery-relays",
                "wss://d.example",
            ],
        ),
        (
            vec![
                "wn",
                "tui",
                "--discovery-relays",
                "wss://d.example,wss://d2.example",
                "--default-account-relays",
                "wss://a.example",
            ],
            vec![
                "--json",
                "daemon",
                "start",
                "--discovery-relays",
                "wss://d.example,wss://d2.example",
                "--default-account-relays",
                "wss://a.example",
            ],
        ),
    ] {
        let account_id = "aa".repeat(32);
        let tempdir = tempfile::tempdir().expect("tempdir");
        let (exe, args_file) = test_arg_recording_executable(
            tempdir.path(),
            r#"{"ok":true,"result":{"running":true,"pid":4242}}"#,
        );
        use clap::Parser;
        let cli = Cli::try_parse_from(arguments).expect("parse first-run TUI relays");
        let mut client = WnClient::from_cli(&cli).expect("construct first-run TUI client");
        client.exe = exe;
        let mut app = test_tui_app(client, &account_id);
        app.daemon = DaemonView::default();

        app.autostart_daemon_if_needed(None);
        assert_eq!(
            app.status, STARTING_DAEMON_STATUS,
            "the in-flight status shows before the outcome lands"
        );
        assert!(
            app.daemon_autostart.is_some(),
            "auto-start runs on its own one-shot thread, not the shared effect worker"
        );

        // Read the recorded argv after the result lands but before folding it: the
        // received result proves the `daemon start` child ran to completion, and
        // the fold below is what re-ensures the daemon-backed subscriptions —
        // spawning further `wn` children against this same fake, each of which
        // rewrites the truncating argv recorder. A read placed after the fold
        // races those children (on a loaded CI box they win: the recorder held
        // `messages subscribe` argv instead).
        let result = app.recv_daemon_autostart();
        let recorded = std::fs::read_to_string(&args_file).expect("the fake wn ran");
        let args: Vec<&str> = recorded.lines().collect();
        assert_eq!(
            args, expected,
            "both parsed first-run relay lists reach the daemon-start child"
        );

        app.fold_daemon_start(result);
        assert!(
            app.daemon.running,
            "the fold adopts the started daemon, flipping the status-bar dot's data source"
        );
        assert_eq!(app.status, "daemon running");
    }
}

#[cfg(unix)]
#[test]
fn the_launch_daemon_auto_start_does_not_stall_the_first_user_action() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let mut gate = TestCommandGate::new(tempdir.path());
    let exe = tempdir.path().join("wn-json");
    write_fake_wn(
        &exe,
        &format!(
            "#!/bin/sh\ncase \" $* \" in\n*' daemon start '*)\n{}printf '%s\\n' '{{\"ok\":true,\"result\":{{\"running\":true,\"pid\":4242}}}}'\n;;\n*) printf '%s\\n' '{{\"ok\":true,\"result\":{{}}}}'\n;;\nesac\n",
            gate.script()
        ),
    );
    let client = WnClient {
        exe,
        discovery_relays: vec!["wss://d.example".to_owned()],
        ..test_unused_client()
    };
    let (continue_tx, continue_rx) = mpsc::channel();
    let (ui_tx, ui_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let account_id = "aa".repeat(32);
        let mut app = test_tui_app(client, &account_id);
        app.daemon = DaemonView::default();
        app.autostart_daemon_if_needed(None);
        continue_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("daemon child entered");
        app.enqueue_effect(Effect::MarkRead {
            account: account_id,
            group: "g1".to_owned(),
        });
        let done = app.effects.recv_timeout(Duration::from_secs(5));
        ui_tx
            .send(done.map(|done| (done.effect, done.result)))
            .expect("report user completion");
        app.recv_daemon_autostart()
    });
    gate.wait_until_entered();
    continue_tx.send(()).expect("daemon start is blocked");
    // The start cannot complete until release. Receiving the user's result now
    // proves the two operations overlap; no short performance budget is needed.
    let user_before_release = ui_rx.recv_timeout(Duration::from_secs(5));
    gate.release();
    let started = worker
        .join()
        .expect("UI thread")
        .expect("daemon start result");
    let (effect, result) = user_before_release
        .expect("user completion before release")
        .expect("user effect completed while daemon start remained blocked");
    assert!(matches!(effect, Effect::MarkRead { group, .. } if group == "g1"));
    assert_eq!(result, Ok(vec![serde_json::json!({})]));
    assert_eq!(started, serde_json::json!({"running": true, "pid": 4242}));
}

#[test]
fn launch_with_no_daemon_and_no_relay_source_surfaces_one_honest_status() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.daemon = DaemonView::default();

    app.autostart_daemon_if_needed(None);

    assert_eq!(app.status, DAEMON_AUTOSTART_NO_RELAYS_STATUS);
    // The status must point at the only path that actually gives the daemon a
    // relay in this situation: relaunching `wn tui` with the relay flags (or
    // WN_RELAY). It must not suggest `/daemon start`, which reads the very same
    // relay sources and would fail identically -- non-actionable in-session.
    assert!(DAEMON_AUTOSTART_NO_RELAYS_STATUS.contains("restart"));
    assert!(DAEMON_AUTOSTART_NO_RELAYS_STATUS.contains("--discovery-relays"));
    assert!(DAEMON_AUTOSTART_NO_RELAYS_STATUS.contains("--default-account-relays"));
    assert!(DAEMON_AUTOSTART_NO_RELAYS_STATUS.contains("WN_RELAY"));
    assert!(
        !DAEMON_AUTOSTART_NO_RELAYS_STATUS.contains("/daemon start"),
        "the no-relays status must not point at the non-actionable /daemon start"
    );
    assert!(
        app.daemon_autostart.is_none(),
        "no start thread spawns without a relay source"
    );
    assert!(!app.daemon.running);
    assert!(
        app.running,
        "the session continues degraded, exactly as today"
    );
}

#[test]
fn launch_with_a_running_daemon_never_attempts_an_auto_start() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    assert!(app.daemon.running, "precondition: the daemon is already up");
    app.status = "2 chats".to_owned();

    app.autostart_daemon_if_needed(None);

    assert_eq!(app.status, "2 chats", "today's no-op behavior is preserved");
    assert!(
        app.daemon_autostart.is_none(),
        "no redundant start thread spawns for an already-running daemon"
    );
}

#[test]
fn a_failed_daemon_auto_start_reports_and_leaves_the_session_up() {
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.daemon = DaemonView::default();
    // The in-flight sentinel the auto-start sets before its thread reports.
    app.set_drain_status(STARTING_DAEMON_STATUS.to_owned());
    app.daemon_start_status_owner = Some(app.status_ownership.revision);

    app.fold_daemon_start(Err("daemon did not become ready".to_owned()));

    assert_eq!(
        app.status,
        "daemon start failed: daemon did not become ready"
    );
    assert!(
        !app.daemon.running,
        "a failed start never fakes a green dot"
    );
    assert!(
        app.running,
        "a failed auto-start never tears down the session"
    );
}

#[test]
fn a_daemon_auto_start_fold_keeps_a_users_in_flight_status() {
    // The auto-start runs off-loop, so a user may have queued an action (setting
    // e.g. "sending...") before its result folds. Adopting the started daemon
    // must not clobber that in-flight status with "daemon running"; the daemon
    // dot already tells that story. The status write is guarded on the
    // "starting daemon..." sentinel it set, and only replaces that.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.daemon = DaemonView::default();
    // Pre-attach the daemon-backed feeds so the re-adopt's subscription ensures
    // short-circuit (they are idempotent) rather than trying — and failing — to
    // spawn against the stub `wn`; that isolates the status guard under test.
    app.chat_subscription = Some(test_chat_subscription(&account_id, false));
    app.message_subscription = Some(test_message_subscription(&account_id));
    app.notification_subscription = Some(test_notification_subscription(&account_id));
    app.set_status("sending...".to_owned());

    app.fold_daemon_start(Ok(serde_json::json!({"running": true, "pid": 4242})));

    assert_eq!(
        app.status, "sending...",
        "the user's in-flight status survives the auto-start fold"
    );
    assert!(
        app.daemon.running,
        "the daemon view is still adopted so the dot flips green"
    );
}

#[test]
fn a_daemon_auto_start_fold_replaces_its_own_in_flight_sentinel() {
    // With no user action in between, the "starting daemon..." sentinel is still
    // showing, so the fold replaces it with the outcome sentence.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.daemon = DaemonView::default();
    // Pre-attach the feeds so the re-adopt's ensures short-circuit (see the
    // in-flight-status test): isolates the sentinel replacement under test.
    app.chat_subscription = Some(test_chat_subscription(&account_id, false));
    app.message_subscription = Some(test_message_subscription(&account_id));
    app.notification_subscription = Some(test_notification_subscription(&account_id));
    app.set_drain_status(STARTING_DAEMON_STATUS.to_owned());
    app.daemon_start_status_owner = Some(app.status_ownership.revision);

    app.fold_daemon_start(Ok(serde_json::json!({"running": true, "pid": 4242})));

    assert_eq!(app.status, "daemon running");
}

#[test]
fn a_daemon_auto_start_fold_re_adopts_manual_subscriptions_as_a_no_op() {
    // A user who ran `/daemon start` manually is already attached to the
    // daemon-backed feeds. The launch auto-start's late result then folds and
    // re-adopts the daemon view, which re-runs the subscription ensures. Those
    // must be idempotent: no feed is re-spawned (the fake `wn` here cannot spawn,
    // so any re-spawn attempt would fail and taint the status), and the existing
    // subscriptions are retained.
    let account_id = "aa".repeat(32);
    let mut app = test_tui_app(test_unused_client(), &account_id);
    app.chat_subscription = Some(test_chat_subscription(&account_id, false));
    app.message_subscription = Some(test_message_subscription(&account_id));
    app.notification_subscription = Some(test_notification_subscription(&account_id));
    app.status = "daemon running".to_owned();

    app.fold_daemon_start(Ok(serde_json::json!({"running": true, "pid": 4242})));

    assert!(
        app.chat_subscription.is_some()
            && app.message_subscription.is_some()
            && app.notification_subscription.is_some(),
        "the already-attached subscriptions are retained across the re-adopt"
    );
    assert!(
        !app.status.contains("subscription failed"),
        "re-adopt is idempotent: no feed is re-spawned, got {:?}",
        app.status
    );
    assert!(
        app.daemon.running,
        "the re-adopt keeps the daemon dot green"
    );
}

#[test]
fn every_daemon_start_relay_source_counts_for_the_auto_start_decision() {
    // The exact sources `wn daemon start` accepts, mirrored so the TUI never
    // declines to start a daemon that would in fact have started: the two
    // passthrough flag lists, the global --relay, and the WN_RELAY fallback.
    assert!(!daemon_start_has_relay_source(None, &[], &[], None));
    assert!(daemon_start_has_relay_source(
        None,
        &["wss://d.example".to_owned()],
        &[],
        None
    ));
    assert!(daemon_start_has_relay_source(
        None,
        &[],
        &["wss://a.example".to_owned()],
        None
    ));
    assert!(daemon_start_has_relay_source(
        Some("wss://r.example"),
        &[],
        &[],
        None
    ));
    assert!(daemon_start_has_relay_source(
        None,
        &[],
        &[],
        Some("wss://env.example")
    ));
    assert!(
        !daemon_start_has_relay_source(None, &[], &[], Some("   ")),
        "a blank WN_RELAY is not a relay source"
    );
    assert!(
        !daemon_start_has_relay_source(Some("   "), &[], &[], None),
        "a blank --relay is not a relay source (it would fail the start with missing_relay_url)"
    );
    assert!(
        !daemon_start_has_relay_source(Some(""), &[], &[], None),
        "an empty --relay is not a relay source"
    );
}

// --- Follow/unfollow from user-search results ---
//
// The retired reference client followed the highlighted result directly from
// the search screen; ours required leaving to the Profile screen with a pasted
// pubkey. `f`/`x` mirror the Profile screen's existing follow/unfollow keys,
// run through the effect worker, and fold into the per-row badge.

#[test]
fn follow_effects_map_to_the_follows_add_and_remove_argv() {
    // The relay travels on the variant (resolved at enqueue from the same
    // setup-relay rule the Profile screen's synchronous path uses), so `calls`
    // stays pure and the add/remove child always has the relay it requires.
    let follow = Effect::FollowUser {
        account: "aa".repeat(32),
        pubkey: "bb".repeat(32),
        label: "Bob".to_owned(),
        relay: Some("wss://setup.example".to_owned()),
    };
    assert_eq!(
        follow.calls(),
        vec![WnCall {
            account: Some("aa".repeat(32)),
            args: vec![
                "follows".to_owned(),
                "add".to_owned(),
                "bb".repeat(32),
                "--relay".to_owned(),
                "wss://setup.example".to_owned(),
            ],
        }]
    );
    let unfollow = Effect::UnfollowUser {
        account: "aa".repeat(32),
        pubkey: "bb".repeat(32),
        label: "Bob".to_owned(),
        relay: None,
    };
    assert_eq!(
        unfollow.calls(),
        vec![WnCall {
            account: Some("aa".repeat(32)),
            // No --relay here: a global --relay already covers every child.
            args: vec!["follows".to_owned(), "remove".to_owned(), "bb".repeat(32)],
        }]
    );
}

#[cfg(unix)]
#[test]
fn f_follows_the_highlighted_search_result_through_the_effect_worker() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) = test_arg_recording_executable(
        tempdir.path(),
        r#"{"ok":true,"result":{"follows":[{"account_id":"bb","npub":"npubbb"}]}}"#,
    );
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = user_search_app_with_selected_result(client);

    app.handle_key(char_key('f')).expect("f follows");
    assert_eq!(
        app.status, "following Bob...",
        "the in-flight status shows before the publish lands"
    );

    app.settle_effects(1);
    let recorded = std::fs::read_to_string(&args_file).expect("the fake wn ran");
    let args: Vec<&str> = recorded.lines().collect();
    assert!(
        args.windows(3).any(|w| w == ["follows", "add", "bb"]),
        "f runs `follows add` on the highlighted result; got {args:?}"
    );
    assert_eq!(app.status, "followed Bob");
    assert!(
        app.user_search.as_ref().expect("search view").results[0].following,
        "the badge folds in when the publish lands"
    );
}

#[cfg(unix)]
#[test]
fn x_unfollows_the_highlighted_search_result_through_the_effect_worker() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let (exe, args_file) =
        test_arg_recording_executable(tempdir.path(), r#"{"ok":true,"result":{"follows":[]}}"#);
    let client = WnClient {
        exe,
        ..test_unused_client()
    };
    let mut app = user_search_app_with_selected_result(client);
    if let Some(view) = app.user_search.as_mut() {
        view.results[0].following = true;
    }

    app.handle_key(char_key('x')).expect("x unfollows");
    assert_eq!(app.status, "unfollowing Bob...");

    app.settle_effects(1);
    let recorded = std::fs::read_to_string(&args_file).expect("the fake wn ran");
    let args: Vec<&str> = recorded.lines().collect();
    assert!(
        args.windows(3).any(|w| w == ["follows", "remove", "bb"]),
        "x runs `follows remove` on the highlighted result; got {args:?}"
    );
    assert_eq!(app.status, "unfollowed Bob");
    assert!(
        !app.user_search.as_ref().expect("search view").results[0].following,
        "the badge clears when the removal lands"
    );
}

#[test]
fn a_stale_follow_fold_reports_but_never_badges_a_left_or_changed_search() {
    // Left screen: the mutation outcome still surfaces (the publish happened),
    // but there is no view to badge — and nothing crashes.
    let mut app = test_tui_app(test_unused_client(), &"aa".repeat(32));
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::FollowUser {
            account: "aa".repeat(32),
            pubkey: "bb".to_owned(),
            label: "Bob".to_owned(),
            relay: None,
        },
        result: Ok(vec![serde_json::json!({"follows": []})]),
    });
    assert_eq!(app.status, "followed Bob");
    assert!(app.user_search.is_none());

    // Changed results: the fold is keyed by pubkey, so rows of a newer query
    // that no longer include the acted-on user never pick up its badge.
    let mut app = user_search_app_with_selected_result(test_unused_client());
    if let Some(view) = app.user_search.as_mut() {
        view.results[0].pubkey = "cc".to_owned();
    }
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::FollowUser {
            account: "aa".repeat(32),
            pubkey: "bb".to_owned(),
            label: "Bob".to_owned(),
            relay: None,
        },
        result: Ok(vec![serde_json::json!({"follows": []})]),
    });
    assert!(
        !app.user_search.as_ref().expect("search view").results[0].following,
        "a different row never picks up a stale fold's badge"
    );

    // Switched account: the badge is account-scoped truth, so a fold from a
    // since-switched account is dropped even if the same pubkey is on screen.
    let mut app = user_search_app_with_selected_result(test_unused_client());
    app.accounts[0].account_id = "dd".repeat(32);
    app.apply_effect_done(EffectDone {
        status_owner: Some(app.status_ownership.revision),
        effect: Effect::FollowUser {
            account: "aa".repeat(32),
            pubkey: "bb".to_owned(),
            label: "Bob".to_owned(),
            relay: None,
        },
        result: Ok(vec![serde_json::json!({"follows": []})]),
    });
    assert!(
        !app.user_search.as_ref().expect("search view").results[0].following,
        "a fold from a since-switched account never badges the new account's view"
    );
}

#[test]
fn the_search_results_hints_and_help_card_name_the_follow_keys() {
    let hint = user_search_hint(UserSearchFocus::Results, &UserSearchPurpose::Browse);
    assert!(
        hint.contains("f follow  x unfollow"),
        "the results-focus hints name the follow keys; got: {hint}"
    );
    let help = help_card_lines().join("\n");
    assert!(
        help.contains("f follow; x unfollow"),
        "the help card names the search-screen follow keys; got: {help}"
    );
}

#[cfg(unix)]
#[test]
fn wn_client_pipes_secret_stdin_and_forwards_global_options() {
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = dir.path().join("wn-json");
    let args_file = dir.path().join("argv");
    let stdin_file = dir.path().join("stdin");
    write_fake_wn(
        &exe,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncat > '{}'\nprintf '%s\\n' '{{\"ok\":true,\"result\":{{\"accepted\":true}}}}'\nexit 7\n",
            args_file.display(),
            stdin_file.display()
        ),
    );
    use clap::Parser;
    let cli = Cli::try_parse_from([
        "wn",
        "--home",
        "selected-home",
        "--socket",
        "selected-socket",
        "--relay",
        "wss://global.example",
        "--secret-store",
        "file",
        "--keychain-service",
        "selected-service",
        "tui",
    ])
    .expect("parse TUI settings");
    let mut client = WnClient::from_cli(&cli).expect("construct TUI command client");
    client.exe = exe;
    let invocation = account_setup_invocation(Some("nsec1synthetic".to_owned()), None);
    let result = client
        .run_json_with_stdin(
            Some("selected-account"),
            &invocation.args,
            invocation.stdin.as_deref().expect("secret stdin"),
        )
        .expect("ok envelope wins over exit code");
    assert_eq!(result, serde_json::json!({"accepted": true}));
    assert_eq!(
        std::fs::read_to_string(stdin_file).expect("captured stdin"),
        "nsec1synthetic\n"
    );
    let recorded = std::fs::read_to_string(args_file).expect("captured argv");
    assert_eq!(
        recorded.lines().collect::<Vec<_>>(),
        [
            "--json",
            "--home",
            "selected-home",
            "--socket",
            "selected-socket",
            "--relay",
            "wss://global.example",
            "--secret-store",
            "file",
            "--keychain-service",
            "selected-service",
            "--account",
            "selected-account",
            "login",
            "--nsec-stdin",
        ]
    );
}

#[cfg(unix)]
#[test]
fn wn_client_reports_envelope_errors_before_stderr() {
    for (stdout, stderr, expected) in [
        (
            r#"{"ok":false,"error":{"message":"message wins","code":"code loses"}}"#,
            "stderr loses",
            "message wins",
        ),
        (
            r#"{"ok":false,"error":{"code":"code wins"}}"#,
            "stderr loses",
            "code wins",
        ),
        (r#"{"ok":false}"#, "stderr fallback", "stderr fallback"),
    ] {
        let (_dir, client) = test_scripted_client(&format!(
            "cat <<'JSON'\n{stdout}\nJSON\nprintf '%s\\n' '{stderr}' >&2\n"
        ));
        let error = client
            .run_json(None, &["status"])
            .expect_err("error envelope");
        assert!(matches!(error, TuiError::Cli(message) if message == expected));
    }
    let (_dir, client) = test_scripted_client("printf broken\nprintf 'diagnostic\\n' >&2\n");
    let error = client
        .run_json(None, &["status"])
        .expect_err("malformed JSON");
    assert!(matches!(error, TuiError::Cli(message)
        if message.starts_with("wn returned invalid JSON:") && message.ends_with("; stderr: diagnostic")));
}

#[cfg(unix)]
#[test]
fn subscription_reader_preserves_frame_order_and_ends_once() {
    for explicit_end in [false, true] {
        let suffix = if explicit_end {
            "{\"stream_end\":true}\n{\"result\":{\"must_not_arrive\":true}}\n"
        } else {
            ""
        };
        let (_dir, client) = test_scripted_client(&format!(
            "cat <<'JSON'\n\nnot-json\n{{\"result\":{{\"sequence\":1}}}}\n{{\"error\":{{\"message\":\"feed error\"}}}}\n{suffix}JSON\n"
        ));
        let mut child = client
            .spawn_json_lines(None, &["messages", "subscribe"])
            .expect("spawn feed");
        let rx = spawn_subscription_reader(&mut child, "fixture").expect("real stdout reader");
        assert!(
            matches!(rx.recv_timeout(Duration::from_secs(5)).expect("malformed frame"),
            SubscriptionEvent::Error(message) if message.starts_with("invalid fixture subscription JSON:"))
        );
        assert!(
            matches!(rx.recv_timeout(Duration::from_secs(5)).expect("result after malformed frame"),
            SubscriptionEvent::Result(result) if result == serde_json::json!({"sequence": 1}))
        );
        assert!(
            matches!(rx.recv_timeout(Duration::from_secs(5)).expect("error frame"),
            SubscriptionEvent::Error(message) if message == "feed error")
        );
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(5))
                .expect("stream end or EOF"),
            SubscriptionEvent::Ended
        ));
        assert!(
            matches!(
                rx.recv_timeout(Duration::from_secs(5)),
                Err(mpsc::RecvTimeoutError::Disconnected)
            ),
            "the reader terminates after exactly one Ended event"
        );
        assert!(child.wait().expect("feed exited").success());
    }
}

#[test]
fn profile_card_sanitizes_fields_and_prefers_display_name() {
    for nested in [false, true] {
        let user = serde_json::json!({
            "npub": "npub1sa\u{202e}fe", "follows": ["a", "b"],
            "profile": {
                "display_name": if nested { " " } else { "Al\u{1b}\u{202e}\u{3164}ice" },
                "name": "Name\u{7}\u{202e}\u{2800} fallback",
                "about": "café \u{1b}\u{202e}\u{3164}中文",
                "nip05": "a\u{1b}\u{202e}\u{3164}@example.com",
                "lud16": "b\u{1b}\u{202e}\u{3164}@example.com",
                "picture": "https://p\u{1b}\u{202e}\u{3164}.example/image"
            }
        });
        let result = if nested {
            serde_json::json!({"user": user})
        } else {
            user
        };
        assert_eq!(
            profile_card_lines(&result),
            [
                if nested { "Name fallback" } else { "Alice" },
                "npub npub1safe",
                "about: café 中文",
                "nip05: a@example.com",
                "lud16: b@example.com",
                "picture: https://p.example/image",
                "follows: 2"
            ]
        );
    }
}

#[test]
fn chat_subscription_drain_preserves_loaded_pane_until_selection_changes() {
    for explicit_end in [false, true] {
        let account = "aa".repeat(32);
        let mut app = test_tui_app(test_unused_client(), &account);
        app.daemon.running = false;
        app.chats = vec![
            projected_chat("aa", "a", 0, Some(10)),
            projected_chat("bb", "b", 0, Some(5)),
        ];
        app.messages_account_id = Some(account.clone());
        app.messages_group_id = Some("aa".to_owned());
        app.timeline = vec![timeline_row("loaded", 10)];
        let (tx, rx) = mpsc::channel();
        app.chat_subscription = Some(ChatSubscription {
            account_id: account,
            include_archived: false,
            child: test_sleep_child(),
            rx,
        });
        assert!(
            !app.drain_chat_subscription(),
            "an empty feed does not dirty the frame"
        );
        tx.send(SubscriptionEvent::Result(serde_json::json!({
            "type": "chat", "chat": {"group_id": "bb", "profile": {"name": "renamed b"}, "activity_sort_at": 20}
        }))).expect("chat update");
        assert!(app.drain_chat_subscription());
        assert_eq!(app.chats[0].name, "renamed b");
        assert_eq!(app.selected_chat, 1);
        assert_eq!(app.selected_chat_row().expect("selection").group_id, "aa");
        assert_eq!(app.messages_group_id.as_deref(), Some("aa"));
        assert_eq!(app.timeline[0].message_id, "loaded");
        assert_eq!(app.status, "live chat update: chats=2");

        app.screen = Screen::Login(LoginMode::NsecEntry);
        app.status = "enter nsec".to_owned();
        tx.send(SubscriptionEvent::Error("offline".to_owned()))
            .expect("chat error");
        assert!(app.drain_chat_subscription());
        assert_eq!(app.status, "enter nsec");
        app.screen = Screen::Main;
        tx.send(SubscriptionEvent::Error("offline".to_owned()))
            .expect("chat error");
        assert!(app.drain_chat_subscription());
        assert_eq!(app.status, "chat subscription failed: offline");

        tx.send(SubscriptionEvent::Result(serde_json::json!({
            "type": "chat", "chat": {"group_id": "aa", "profile": {"name": "a"}, "archived": true}
        })))
        .expect("selected chat leaves visible list");
        assert!(app.drain_chat_subscription());
        assert_eq!(
            app.selected_chat_row()
                .expect("remaining selection")
                .group_id,
            "bb"
        );
        assert!(app.timeline.is_empty());
        assert!(app.messages_account_id.is_none());
        assert!(app.messages_group_id.is_none());
        if explicit_end {
            tx.send(SubscriptionEvent::Ended).expect("explicit end");
        }
        drop(tx);
        assert!(app.drain_chat_subscription());
        assert!(
            app.chat_subscription.is_none(),
            "end and disconnect tear down the handle"
        );
        assert!(!app.drain_chat_subscription());
        assert!(app.running);
    }
}

#[test]
fn group_state_subscription_drain_scopes_diagnostics_and_tears_down() {
    for explicit_end in [false, true] {
        let account = "aa".repeat(32);
        let mut app = test_tui_app(test_unused_client(), &account);
        let (tx, rx) = mpsc::channel();
        app.group_state_subscription = Some(GroupStateSubscription {
            account_id: account,
            group_id: "aa".to_owned(),
            child: test_sleep_child(),
            rx,
        });
        assert!(!app.drain_group_state_subscription());
        tx.send(SubscriptionEvent::Result(serde_json::json!({
            "type": "group_state", "group_id": "aa", "trigger": "GroupStateUpdated",
            "group": {"group_id": "aa", "profile": {"name": "loaded room"}},
            "mls": {"epoch": 8, "member_count": 2}
        })))
        .expect("matching update");
        assert!(app.drain_group_state_subscription());
        let diagnostics = app.group_diagnostics.clone().expect("diagnostics adopted");
        assert_eq!(diagnostics.group_id, "aa");
        assert_eq!(diagnostics.epoch, Some(8));
        assert_eq!(diagnostics.member_count, Some(2));
        assert_eq!(app.status, "live group state update: loaded room");
        tx.send(SubscriptionEvent::Result(serde_json::json!({
            "type": "group_state", "group_id": "bb", "trigger": "GroupStateUpdated",
            "group": {"group_id": "bb"}, "mls": {"epoch": 99}
        })))
        .expect("foreign update");
        assert!(app.drain_group_state_subscription());
        assert_eq!(app.group_diagnostics.as_ref(), Some(&diagnostics));
        assert_eq!(app.status, "live group state update: loaded room");

        tx.send(SubscriptionEvent::Result(serde_json::json!({
            "type": "group_state", "group_id": "aa", "trigger": "InitialGroupState"
        })))
        .expect("matching update without diagnostics");
        assert!(app.drain_group_state_subscription());
        assert_eq!(
            app.group_diagnostics,
            Some(GroupDiagnostics::unavailable(
                "aa",
                "group state update did not include diagnostics"
            ))
        );
        assert_eq!(
            app.status, "live group state update: loaded room",
            "initial state leaves status intact"
        );
        app.screen = Screen::Login(LoginMode::NsecEntry);
        app.status = "enter nsec".to_owned();
        tx.send(SubscriptionEvent::Error("offline".to_owned()))
            .expect("group error");
        assert!(app.drain_group_state_subscription());
        assert_eq!(app.status, "enter nsec");
        app.screen = Screen::Main;
        tx.send(SubscriptionEvent::Error("offline".to_owned()))
            .expect("group error");
        assert!(app.drain_group_state_subscription());
        assert_eq!(app.status, "group state subscription failed: offline");
        if explicit_end {
            tx.send(SubscriptionEvent::Ended).expect("explicit end");
        }
        drop(tx);
        assert!(app.drain_group_state_subscription());
        assert!(app.group_state_subscription.is_none());
        assert!(!app.drain_group_state_subscription());
        assert!(app.running);
    }
}

#[cfg(unix)]
#[test]
fn slash_account_setup_adopts_the_returned_identity_and_signing_state() {
    use nostr::prelude::ToBech32;
    let a = "aa".repeat(32);
    let keys = nostr::prelude::Keys::generate();
    let b = keys.public_key().to_hex();
    let nsec = keys.secret_key().to_bech32().unwrap();
    let npub = crate::npub_for_account_id(&b).unwrap();
    for (input, command, action, local_signing, account_id_result) in [
        (
            "/create-identity".to_owned(),
            vec!["create-identity".to_owned()],
            "created identity",
            true,
            true,
        ),
        (
            format!("/login {npub}"),
            vec!["login".to_owned(), npub.clone()],
            "logged in public identity",
            false,
            false,
        ),
        (
            format!("/login {nsec}"),
            vec!["login".to_owned(), "--nsec-stdin".to_owned()],
            "logged in identity",
            true,
            true,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut result = serde_json::json!({
            "npub":npub,"local_signing":local_signing,"profile":{"display_name":"Returned B"},
            "accounts":[
                {"account_id":a,"npub":"npub1alice","display_name":"Old A","local_signing":true},
                {"account_id":b,"npub":npub,"display_name":"Returned B","local_signing":local_signing}
            ],"chats":[]
        });
        if account_id_result {
            result["account_id"] = serde_json::json!(b);
        }
        let response = serde_json::json!({"ok":true,"result":result}).to_string();
        let exe = dir.path().join("wn-setup");
        let args = dir.path().join("args");
        let stdin = dir.path().join("stdin");
        let first = dir.path().join("first");
        let capture_stdin = if action == "logged in identity" {
            format!("cat > '{}'\n", stdin.display())
        } else {
            String::new()
        };
        write_fake_wn(
            &exe,
            &format!(
                "#!/bin/sh\nif mkdir '{}' 2>/dev/null; then\nprintf '%s\\n' \"$@\" > '{}'\n{capture_stdin}fi\ncat <<'JSON'\n{response}\nJSON\n",
                first.display(),
                args.display()
            ),
        );
        let mut app = test_tui_app(
            WnClient {
                exe,
                ..test_unused_client()
            },
            &a,
        );
        app.daemon.running = false;
        app.chats = vec![flick_chat("prior-group", "Old room")];
        app.messages_account_id = Some(a.clone());
        app.messages_group_id = Some("prior-group".into());
        app.timeline = vec![timeline_row("old-account-row", 1)];
        app.input.set_value(&input);
        app.submit_input().expect("dispatch account setup");
        assert_eq!(
            app.selected_account_row().unwrap().account_id,
            b,
            "{action}"
        );
        assert_eq!(
            app.status,
            format!(
                "{action} Returned B {}",
                if local_signing {
                    "local-signing"
                } else {
                    "public-only"
                }
            )
        );
        assert!(app.input.is_empty());
        assert!(app.chats.is_empty());
        assert!(app.timeline.is_empty());
        assert!(app.messages_group_id.is_none());
        assert_eq!(
            app.messages_account_id.as_deref(),
            local_signing.then_some(b.as_str())
        );
        let recorded = std::fs::read_to_string(args).unwrap();
        let mut expected = vec!["--json".to_owned()];
        expected.extend(command);
        assert!(!recorded.contains(&nsec), "the secret is never an argument");
        assert_eq!(recorded.lines().collect::<Vec<_>>(), expected);
        if action == "logged in identity" {
            assert!(
                std::fs::read_to_string(stdin).unwrap() == format!("{nsec}\n"),
                "the dispatcher must deliver the complete secret through stdin"
            );
        } else {
            assert!(!stdin.exists());
        }
    }
}

#[cfg(unix)]
#[test]
fn slash_management_commands_forward_the_selected_owner_and_requested_options() {
    let a = "aa".repeat(32);
    let group = "cc".repeat(16);
    let peer = "dd".repeat(32);
    for (input, command, selected_account, status) in [
        (
            "/chat rename Renamed Room".to_owned(),
            vec![
                "groups".into(),
                "update".into(),
                group.clone(),
                "--name".into(),
                "Renamed Room".into(),
            ],
            true,
            "updated chat; published=2",
        ),
        (
            "/chat describe Project marker".to_owned(),
            vec![
                "groups".into(),
                "update".into(),
                group.clone(),
                "--description".into(),
                "Project marker".into(),
            ],
            true,
            "updated chat; published=2",
        ),
        (
            format!("/members add {peer} {peer}"),
            vec!["group".into(), "invite".into(), group.clone(), peer.clone()],
            true,
            "added member(s); published=2",
        ),
        (
            format!("/members remove {peer} {peer}"),
            vec!["group".into(), "remove".into(), group.clone(), peer.clone()],
            true,
            "removed member(s); published=2",
        ),
        (
            "/members list".to_owned(),
            vec!["group".into(), "members".into(), group.clone()],
            true,
            "members: npub1...amrcaj",
        ),
        (
            format!("/keys fetch {peer}"),
            vec!["keys".into(), "fetch".into(), peer.clone()],
            false,
            "fetched key package bytes=57",
        ),
        (
            "/keys rotate".to_owned(),
            vec!["keys".into(), "rotate".into()],
            true,
            "rotated key package bytes=57",
        ),
        (
            "/profile name Requested Name".to_owned(),
            vec![
                "profile".into(),
                "update".into(),
                "--name".into(),
                "Requested Name".into(),
                "--display-name".into(),
                "Requested Name".into(),
            ],
            true,
            "published profile name Returned Name",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let response = serde_json::json!({"ok":true,"result":{
            "published":2,"key_package_bytes":57,
            "members":[{"npub":"npub1424242424242424242424242424242424242424242424242424qamrcaj"}],
            "profile":{"display_name":"Returned Name"},
            "accounts":[{"account_id":a,"npub":"npub1alice","local_signing":true}],
            "chats":[{"group_id":group,"profile":{"name":"Refreshed Room"}}],
            "messages":[],"has_more_before":false
        }})
        .to_string();
        let exe = dir.path().join("wn-management");
        let args = dir.path().join("args");
        let first = dir.path().join("first");
        write_fake_wn(
            &exe,
            &format!(
                "#!/bin/sh\nif mkdir '{}' 2>/dev/null; then\nprintf '%s\\n' \"$@\" > '{}'\nfi\ncat <<'JSON'\n{response}\nJSON\n",
                first.display(),
                args.display()
            ),
        );
        let mut app = test_tui_app(
            WnClient {
                exe,
                ..test_unused_client()
            },
            &a,
        );
        app.daemon.running = false;
        app.chats = vec![flick_chat(&group, "Selected room")];
        // Chat management follows the selected owner, even with an old pane.
        app.messages_account_id = Some("bb".repeat(32));
        app.messages_group_id = Some("ee".repeat(16));
        app.input.set_value(&input);
        app.submit_input().expect("dispatch management command");
        assert_eq!(app.status, status, "{input}");
        assert!(app.input.is_empty());
        finish_queued_effects(&mut app);
        let recorded = std::fs::read_to_string(args).unwrap();
        let mut expected: Vec<String> = vec!["--json".into()];
        if selected_account {
            expected.extend(["--account".into(), a.clone()]);
        }
        expected.extend(command);
        assert_eq!(recorded.lines().collect::<Vec<_>>(), expected, "{input}");
    }
}

#[cfg(unix)]
#[test]
fn timeline_completion_keeps_a_newer_command_status_and_folds_its_page() {
    let account = "aa".repeat(32);
    let group = "cc".repeat(16);
    for origin in ["refresh", "start", "composer"] {
        for outcome in ["success", "page-error", "subscription-error"] {
            let dir = tempfile::tempdir().unwrap();
            let mut gate = TestCommandGate::new(dir.path());
            let page = if outcome == "page-error" {
                serde_json::json!({"ok":false,"error":{"message":"timeline offline"}})
            } else {
                serde_json::json!({"ok":true,"result":{"messages":[{
                    "message_id":"loaded-row","direction":"received","from":"peer",
                    "plaintext":"loaded page body","timeline_at":2,"received_at":2
                }],"has_more_before":false}})
            };
            let ack = serde_json::json!({"ok":true,"result":{
                "stream_id":"dd".repeat(32),"published":2
            }});
            let exe = dir.path().join("wn-status");
            write_fake_wn(
                &exe,
                &format!(
                    "#!/bin/sh\ncase \" $* \" in\n\
                 *' messages timeline list '*)\n{}printf '%s\\n' '{page}'\n;;\n\
                 *' stream start '*|*' stream compose-open '*) printf '%s\\n' '{ack}';;\n\
                 *' subscribe '*|*' subscribe-state '*) exec sleep 60;;\n\
                 *) printf '%s\\n' '{{\"ok\":true,\"result\":{{}}}}';;\nesac\n",
                    gate.script()
                ),
            );
            let mut app = test_tui_app(
                WnClient {
                    exe,
                    ..test_unused_client()
                },
                &account,
            );
            app.daemon.running = outcome == "subscription-error";
            app.chats = vec![flick_chat(&group, "Room")];
            let immediate = match origin {
                "refresh" => {
                    app.refresh_messages().unwrap();
                    "loading chat..."
                }
                "start" => {
                    app.input
                        .set_value("/stream start --quic-candidate quic://127.0.0.1:4451");
                    app.submit_input().unwrap();
                    "started stream ddddddd...dddddddd; published=2"
                }
                "composer" => {
                    app.input
                        .set_value("/stream --quic-candidate quic://127.0.0.1:4451");
                    app.submit_input().unwrap();
                    "now streaming ddddddd...dddddddd; type text and press Enter to finish"
                }
                _ => unreachable!(),
            };
            gate.wait_until_entered();
            assert_eq!(
                app.status, immediate,
                "the action completes before page release"
            );
            if outcome == "subscription-error" {
                // The page child is already running; subsequent actual feed
                // acquisitions encounter an unavailable command executable.
                app.client.exe = dir.path().join("unavailable-wn");
            }
            gate.release();
            finish_queued_effects(&mut app);
            // A successful page fold enqueues diagnostics/mark-read after the
            // first marker. Complete those children before dropping the fixture.
            finish_queued_effects(&mut app);
            assert!(app.loading_chat.is_none());
            if outcome == "page-error" {
                assert!(app.timeline.is_empty());
            } else {
                assert_eq!(timeline_ids(&app.timeline), vec!["loaded-row"]);
                assert_eq!(app.messages_account_id.as_deref(), Some(account.as_str()));
                assert_eq!(app.messages_group_id.as_deref(), Some(group.as_str()));
            }
            if origin != "refresh" {
                assert_eq!(app.status, immediate, "{origin}: {outcome}");
            } else {
                match outcome {
                    "success" => assert_eq!(app.status, "loaded 1 message(s)"),
                    "page-error" => assert_eq!(app.status, "error: timeline offline"),
                    "subscription-error" => assert!(
                        app.status.starts_with("message subscription failed: ")
                            || app.status.starts_with("timeline subscription failed: "),
                        "ordinary loads must surface their actual feed failure"
                    ),
                    _ => unreachable!(),
                }
            }
        }
    }
    // Ambient drains and a provisional acquisition failure belong to this
    // request; neither is a newer command or prompt that can own its feedback.
    let mut observed = Vec::new();
    for origin in [
        "chat-update",
        "dispatch-error",
        "chat-update-start",
        "chat-update-composer",
    ] {
        for outcome in ["success", "page-error", "subscription-error"] {
            let dir = tempfile::tempdir().unwrap();
            let mut page_gate = TestCommandGate::new(dir.path());
            let chat_dir = dir.path().join("chat");
            std::fs::create_dir(&chat_dir).unwrap();
            let mut chat_gate = TestCommandGate::new(&chat_dir);
            let page = if outcome == "page-error" {
                serde_json::json!({"ok":false,"error":{"message":"timeline offline"}})
            } else {
                serde_json::json!({"ok":true,"result":{"messages":[{
                    "message_id":"loaded-row","direction":"received","from":"peer",
                    "plaintext":"loaded page body","timeline_at":2,"received_at":2
                }],"has_more_before":false}})
            };
            let chat = serde_json::json!({"ok":true,"result":{
                "type":"chat","chat":{"group_id":group,
                    "profile":{"name":"Changed room"},"unread_count":3}
            }});
            let exe = dir.path().join("wn-status");
            write_fake_wn(
                &exe,
                &format!(
                    "#!/bin/sh\ncase \" $* \" in\n\
                 *' messages timeline list '*)\n{}printf '%s\\n' '{page}'\n;;\n\
                 *' chats subscribe '*)\n{}printf '%s\\n' '{chat}'\nexec sleep 60;;\n\
                 *' stream start '*|*' stream compose-open '*) printf '%s\\n' '{{\"ok\":true,\"result\":{{\"stream_id\":\"dddd\",\"published\":2}}}}';;\n\
                 *' subscribe '*|*' subscribe-state '*) exec sleep 60;;\n\
                 *) printf '%s\\n' '{{\"ok\":true,\"result\":{{}}}}';;\nesac\n",
                    page_gate.script(),
                    chat_gate.script(),
                ),
            );
            let mut app = test_tui_app(
                WnClient {
                    exe: exe.clone(),
                    ..test_unused_client()
                },
                &account,
            );
            app.daemon.running = true;
            app.chats = vec![flick_chat(&group, "Room")];
            if origin.starts_with("chat-update") {
                app.ensure_chat_subscription(&account).unwrap();
                chat_gate.wait_until_entered();
            } else {
                // The real FIFO worker already owns its valid client clone.
                // Only the foreground acquisition encounters a missing child.
                app.client.exe = dir.path().join("unavailable-wn");
            }
            let retained = if origin == "chat-update-start" || origin == "chat-update-composer" {
                app.input.set_value(if origin == "chat-update-start" {
                    "/stream start --quic-candidate quic://127.0.0.1:4451"
                } else {
                    "/stream --quic-candidate quic://127.0.0.1:4451"
                });
                app.submit_input().unwrap();
                Some(app.status.clone())
            } else {
                app.refresh_messages().unwrap();
                None
            };
            page_gate.wait_until_entered();
            assert!(
                app.loading_chat.is_some(),
                "dispatch returned before release"
            );
            let dispatch_status = app.status.clone();
            if origin == "dispatch-error" {
                assert!(
                    app.message_subscription.is_none(),
                    "initial feed spawn failed"
                );
            }
            if origin.starts_with("chat-update") {
                if outcome == "subscription-error" {
                    // The chat drain also tries a real group-feed acquisition.
                    app.client.exe = dir.path().join("unavailable-wn");
                }
                chat_gate.release();
                let deadline = Instant::now() + Duration::from_secs(5);
                while app.chats[0].name != "Changed room" {
                    assert!(Instant::now() < deadline, "chat child update did not drain");
                    app.tick();
                    thread::sleep(Duration::from_millis(1));
                }
                assert_eq!(app.chats[0].projection.unread_count, 3);
                assert!(app.loading_chat.is_some(), "chat update preceded page fold");
            }
            let pending_status = app.status.clone();
            app.client.exe = if outcome == "subscription-error" {
                dir.path().join("unavailable-wn")
            } else {
                exe
            };
            page_gate.release();
            let deadline = Instant::now() + Duration::from_secs(5);
            while app.loading_chat.is_some() {
                assert!(Instant::now() < deadline, "page child did not fold on tick");
                app.tick();
                thread::sleep(Duration::from_millis(1));
            }
            finish_queued_effects(&mut app);
            finish_queued_effects(&mut app);
            let feedback = retained.as_deref().unwrap_or(match outcome {
                "success" => "loaded 1 message(s)",
                "page-error" => "error: timeline offline",
                "subscription-error" if origin == "dispatch-error" => {
                    "message subscription failed: "
                }
                "subscription-error" => "timeline subscription failed: ",
                _ => unreachable!(),
            });
            let rows_folded = if outcome == "page-error" {
                app.timeline.is_empty() && app.messages_group_id.is_none()
            } else {
                timeline_ids(&app.timeline) == vec!["loaded-row"]
                    && app.messages_account_id.as_deref() == Some(account.as_str())
                    && app.messages_group_id.as_deref() == Some(group.as_str())
            };
            let visible = rendered_buffer(&mut app).contains(feedback.trim());
            let healed = origin != "dispatch-error"
                || outcome != "success"
                || app.message_subscription.is_some();
            observed.push((
                origin,
                outcome,
                dispatch_status,
                pending_status,
                app.status.clone(),
                rows_folded && healed && visible && app.status.starts_with(feedback),
            ));
        }
    }
    assert!(
        observed.iter().all(|row| row.5),
        "ambient updates and this request's acquisition must preserve completion feedback: {observed:?}"
    );
}

#[cfg(unix)]
#[test]
fn older_send_cannot_steal_a_newer_chat_loads_feedback() {
    let account = "aa".repeat(32);
    let group_a = "cc".repeat(16);
    let group_b = "dd".repeat(16);
    let mut observed = Vec::new();
    for outcome in [
        "success",
        "page-error",
        "subscription-error",
        "no-id-refresh",
        "newer-command-before-preview",
        "no-id-pending-success",
        "no-id-pending-error",
        "ambient-before-preview-error",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut send_gate = TestCommandGate::new(dir.path());
        let page_dir = dir.path().join("page");
        std::fs::create_dir(&page_dir).unwrap();
        let mut page_gate = TestCommandGate::new(&page_dir);
        let page = if matches!(
            outcome,
            "page-error" | "no-id-pending-error" | "ambient-before-preview-error"
        ) {
            serde_json::json!({"ok":false,"error":{"message":"new chat offline"}})
        } else {
            serde_json::json!({"ok":true,"result":{"messages":[{
                "message_id":"new-page-row","direction":"received","from":"peer",
                "plaintext":"new chat body","timeline_at":2,"received_at":2
            }],"has_more_before":false}})
        };
        let send = if outcome.starts_with("no-id-") {
            serde_json::json!({"ok":true,"result":{"published":2}})
        } else {
            serde_json::json!({"ok":true,"result":{"message_ids":["sent-id"],"published":2}})
        };
        let exe = dir.path().join("wn-ordered-status");
        write_fake_wn(
            &exe,
            &format!(
                "#!/bin/sh\ncase \" $* \" in\n\
             *' messages send '*)\n{}printf '%s\\n' '{send}';;\n\
             *' messages timeline list '*)\nif mkdir '{}' 2>/dev/null; then\n{}fi\nprintf '%s\\n' '{page}';;\n\
             *' subscribe '*|*' subscribe-state '*) exec sleep 60;;\n\
             *) printf '%s\\n' '{{\"ok\":true,\"result\":{{}}}}';;\nesac\n",
                send_gate.script(),
                page_dir.join("first").display(),
                page_gate.script()
            ),
        );
        let mut app = test_tui_app(
            WnClient {
                exe,
                ..test_unused_client()
            },
            &account,
        );
        app.daemon.running = outcome == "subscription-error";
        app.chats = vec![
            flick_chat(&group_a, "Chat A"),
            flick_chat(&group_b, "Chat B"),
        ];
        app.messages_account_id = Some(account.clone());
        app.messages_group_id = Some(group_a.clone());
        app.send_message("outgoing body".to_owned()).unwrap();
        send_gate.wait_until_entered();
        if outcome.starts_with("no-id-pending-") {
            app.refresh_messages().unwrap();
        } else if outcome != "no-id-refresh" {
            app.focus = Focus::Chats;
            app.move_selection(1);
            if outcome == "ambient-before-preview-error" {
                let (tx, rx) = mpsc::channel();
                app.chat_subscription = Some(ChatSubscription {
                    account_id: account.clone(),
                    include_archived: false,
                    child: test_sleep_child(),
                    rx,
                });
                tx.send(SubscriptionEvent::Error("ambient notice".to_owned()))
                    .unwrap();
                assert!(app.drain_chat_subscription());
            }
            if outcome == "newer-command-before-preview" {
                app.run_slash_command(SlashCommand::Diagnostics).unwrap();
            }
            for _ in 0..FLICK_PREVIEW_DEBOUNCE_TICKS {
                app.tick();
            }
            assert_eq!(
                app.status,
                if outcome == "newer-command-before-preview" {
                    "diagnostics panel on"
                } else {
                    "loading chat..."
                },
                "navigation returned before send release"
            );
        }
        send_gate.release();
        // The no-ID completion itself queues its subordinate page.
        if outcome == "no-id-refresh" {
            app.settle_effects(1);
        }
        page_gate.wait_until_entered();
        if outcome != "no-id-refresh" {
            app.tick();
        }
        let pending = app.status.clone();
        if outcome == "subscription-error" {
            app.client.exe = dir.path().join("unavailable-wn");
        }
        page_gate.release();
        finish_queued_effects(&mut app);
        finish_queued_effects(&mut app);
        let correct = match outcome {
            "newer-command-before-preview" => {
                app.status == "diagnostics panel on"
                    && timeline_ids(&app.timeline) == vec!["new-page-row"]
            }
            "page-error" | "no-id-pending-error" | "ambient-before-preview-error" => {
                app.status == "error: new chat offline" && app.timeline.is_empty()
            }
            "subscription-error" => {
                app.status.starts_with("timeline subscription failed: ")
                    && timeline_ids(&app.timeline) == vec!["new-page-row"]
            }
            "no-id-refresh" => {
                app.status == "sent message; published=2"
                    && timeline_ids(&app.timeline) == vec!["new-page-row"]
            }
            _ => {
                app.status == "loaded 1 message(s)"
                    && timeline_ids(&app.timeline) == vec!["new-page-row"]
            }
        };
        observed.push((outcome, pending, app.status.clone(), correct));
    }
    assert!(
        observed.iter().all(|row| row.3),
        "action order and causal refresh feedback: {observed:?}"
    );
}

#[cfg(unix)]
#[test]
fn daemon_autostart_cannot_supersede_the_first_timeline_feedback() {
    let account = "aa".repeat(32);
    let group = "cc".repeat(16);
    let mut observed = Vec::new();
    for page_error in [false, true] {
        for daemon_first in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut page_gate = TestCommandGate::new(dir.path());
            let daemon_dir = dir.path().join("daemon");
            std::fs::create_dir(&daemon_dir).unwrap();
            let mut daemon_gate = TestCommandGate::new(&daemon_dir);
            let catalog = serde_json::json!({"ok":true,"result":{
                "accounts":[{"account_id":account,"npub":"npub1alice","local_signing":true}],
                "chats":[{"group_id":group,"profile":{"name":"First chat"}}]
            }});
            let page = if page_error {
                serde_json::json!({"ok":false,"error":{"message":"first page offline"}})
            } else {
                serde_json::json!({"ok":true,"result":{"messages":[{
                    "message_id":"first-row","direction":"received","from":"peer",
                    "plaintext":"first page body","timeline_at":2,"received_at":2
                }],"has_more_before":false}})
            };
            let exe = dir.path().join("wn-startup");
            write_fake_wn(
                &exe,
                &format!(
                    "#!/bin/sh\ncase \" $* \" in\n\
                 *' messages timeline list '*)\n{}printf '%s\\n' '{page}';;\n\
                 *' daemon start '*)\n{}printf '%s\\n' '{{\"ok\":true,\"result\":{{\"running\":true}}}}';;\n\
                 *' subscribe '*|*' subscribe-state '*) exec sleep 60;;\n\
                 *) printf '%s\\n' '{catalog}';;\nesac\n",
                    page_gate.script(),
                    daemon_gate.script()
                ),
            );
            let mut app = test_tui_app(
                WnClient {
                    exe,
                    ..test_unused_client()
                },
                &account,
            );
            app.daemon.running = false;
            app.start().unwrap();
            page_gate.wait_until_entered();
            app.autostart_daemon_if_needed(Some("wss://relay.example".to_owned()));
            daemon_gate.wait_until_entered();
            if daemon_first {
                daemon_gate.release();
                let result = app.recv_daemon_autostart();
                app.fold_daemon_start(result);
            }
            page_gate.release();
            finish_queued_effects(&mut app);
            finish_queued_effects(&mut app);
            if !daemon_first {
                daemon_gate.release();
                let result = app.recv_daemon_autostart();
                app.fold_daemon_start(result);
            }
            let expected = if page_error {
                "error: first page offline"
            } else {
                "loaded 1 message(s)"
            };
            observed.push((
                page_error,
                daemon_first,
                app.status.clone(),
                app.status == expected,
            ));
            assert!(app.daemon.running, "startup still adopts daemon resources");
            assert_eq!(app.timeline.is_empty(), page_error);
        }
    }
    assert!(
        observed.iter().all(|row| row.3),
        "background startup cannot own foreground load feedback: {observed:?}"
    );
}

#[cfg(unix)]
#[test]
fn same_account_group_reloads_fold_the_newest_real_page() {
    let account = "aa".repeat(32);
    let group = "cc".repeat(16);
    let mut observed = Vec::new();
    for (first_error, second_error, subscription_error) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut gate = TestCommandGate::new(dir.path());
        let row = |id: &str, at: u64| {
            serde_json::json!({
                "message_id":id,"direction":"received","from":"peer",
                "plaintext":id,"timeline_at":at,"received_at":at
            })
        };
        let page = |error: bool, newer: bool| {
            if error {
                serde_json::json!({"ok":false,"error":{"message":if newer {"new page offline"} else {"old page offline"}}})
            } else {
                let rows = if newer {
                    vec![row("old-row", 1), row("new-row", 2)]
                } else {
                    vec![row("old-row", 1)]
                };
                serde_json::json!({"ok":true,"result":{"messages":rows,"has_more_before":false}})
            }
        };
        let catalog = serde_json::json!({"ok":true,"result":{
            "accounts":[{"account_id":account,"npub":"npub1alice","local_signing":true}],
            "chats":[{"group_id":group,"profile":{"name":"Room"}}]
        }});
        let first = page(first_error, false);
        let second = page(second_error, true);
        let calls = dir.path().join("pages");
        let all_calls = dir.path().join("all-calls");
        let exe = dir.path().join("wn-pages");
        write_fake_wn(
            &exe,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \" $* \" in\n\
             *' messages timeline list '*)\n\
             printf 'page\\n' >> '{}'\n\
             if mkdir '{}' 2>/dev/null; then\n{}printf '%s\\n' '{first}'\n\
             else printf '%s\\n' '{second}'; fi;;\n\
             *' subscribe '*|*' subscribe-state '*) exec sleep 60;;\n\
             *) printf '%s\\n' '{catalog}';;\nesac\n",
                all_calls.display(),
                calls.display(),
                dir.path().join("first").display(),
                gate.script()
            ),
        );
        let mut app = test_tui_app(
            WnClient {
                exe,
                ..test_unused_client()
            },
            &account,
        );
        app.daemon.running = subscription_error;
        app.chats = vec![flick_chat(&group, "Room")];
        app.input.set_value("/refresh");
        app.submit_input().expect("dispatch refresh");
        gate.wait_until_entered();
        app.input.set_value("/refresh");
        app.submit_input().expect("dispatch refresh");
        assert_eq!(
            app.status, "loading chat...",
            "second request returns before the old page is released"
        );
        if subscription_error {
            app.client.exe = dir.path().join("unavailable-wn");
        }
        gate.release();
        finish_queued_effects(&mut app);
        finish_queued_effects(&mut app);
        assert_eq!(
            std::fs::read_to_string(calls).unwrap().lines().count(),
            2,
            "both real page children completed"
        );
        let recorded = std::fs::read_to_string(all_calls).unwrap();
        let current_followups = usize::from(!second_error);
        assert_eq!(
            recorded
                .lines()
                .filter(|line| line.contains("chats mark-read")
                    && !line.contains("test-fifo-completion-marker"))
                .count(),
            current_followups,
            "only the newest successful page may mark read"
        );
        assert_eq!(
            recorded
                .lines()
                .filter(|line| line.contains("groups show"))
                .count(),
            current_followups,
            "only the newest successful page may fetch diagnostics"
        );
        let correct = if second_error {
            app.status == "error: new page offline"
        } else {
            timeline_ids(&app.timeline).contains(&"new-row")
                && rendered_buffer(&mut app).contains("new-row")
                && app.messages_account_id.as_deref() == Some(account.as_str())
                && app.messages_group_id.as_deref() == Some(group.as_str())
                && if subscription_error {
                    app.status.starts_with("timeline subscription failed: ")
                } else {
                    app.status == "loaded 2 message(s)"
                }
        };
        observed.push((
            first_error,
            second_error,
            subscription_error,
            timeline_ids(&app.timeline)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            app.status.clone(),
            correct,
        ));
    }
    assert!(
        observed.iter().all(|row| row.5),
        "the newest requested page must own the final view/feedback: {observed:?}"
    );
}
