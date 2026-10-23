//! Exercise the released CLI's privacy-safe startup diagnostic.

#[cfg(unix)]
#[test]
fn socket_path_too_long_cli_reports_actionable_error_without_private_path() {
    use std::os::unix::ffi::OsStrExt;

    // Keep the home short without passing macOS's /tmp directory alias into
    // the private-home preparation path. Production alias checks stay intact.
    let short_temp_base = std::fs::canonicalize("/tmp").unwrap();
    let root = tempfile::tempdir_in(short_temp_base).unwrap();
    let probe = root.path().join("x").join("wn-agent.sock");
    let limit = (1..=256)
        .take_while(|bytes| {
            std::os::unix::net::SocketAddr::from_pathname("x".repeat(*bytes)).is_ok()
        })
        .last()
        .unwrap();
    // The final address fits exactly even if the child has a different PID width.
    // Only the private staging overhead makes startup fail.
    let parent_len = 1 + limit - probe.as_os_str().as_bytes().len();
    let socket = root
        .path()
        .join("x".repeat(parent_len))
        .join("wn-agent.sock");
    assert_eq!(socket.as_os_str().as_bytes().len(), limit);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_wn-agent"))
        .arg("--home")
        .arg(root.path())
        .arg("--socket")
        .arg(&socket)
        .env_remove("MARMOT_RELAYS")
        .env_remove("MARMOT_RELAY")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("code=socket_path_too_long"));
    assert!(stderr.contains("shorten --home or --socket"));
    assert!(!stderr.contains(root.path().to_str().unwrap()));
    assert!(!socket.parent().unwrap().exists());
}

#[cfg(unix)]
#[test]
fn world_accessible_socket_directory_cli_names_the_fix_without_the_path() {
    use std::os::unix::fs::PermissionsExt;

    // The reported case: a socket placed directly in a 0755 home. A short base
    // keeps the socket path under the platform limit.
    let root = tempfile::tempdir_in(std::fs::canonicalize("/tmp").unwrap()).unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_wn-agent"))
        .arg("--home")
        .arg(&home)
        .arg("--socket")
        .arg(home.join("wn-agent.sock"))
        .env_remove("MARMOT_RELAYS")
        .env_remove("MARMOT_RELAY")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("code=io_error"), "{stderr}");
    assert!(
        stderr.contains("detail=the control socket directory must not be world-accessible"),
        "{stderr}"
    );
    assert!(stderr.contains("io_kind=PermissionDenied"), "{stderr}");
    assert!(!stderr.contains(root.path().to_str().unwrap()), "{stderr}");
    assert_eq!(home.metadata().unwrap().permissions().mode() & 0o777, 0o755);
}

#[cfg(unix)]
#[test]
fn serve_reads_marmot_relays_and_prefers_the_relay_flag() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir_in(std::fs::canonicalize("/tmp").unwrap()).unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let serve = |relay_flag: Option<&str>| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_wn-agent"));
        command
            .arg("--home")
            .arg(&home)
            .env("MARMOT_RELAYS", "ws://relay.example")
            .env_remove("MARMOT_RELAY");
        if let Some(relay) = relay_flag {
            command.arg("--relay").arg(relay);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        String::from_utf8(output.stderr).unwrap()
    };

    // `serve` reads the variable: its plaintext public relay fails startup with
    // the reason, before any socket or network work, and without the URL.
    let stderr = serve(None);
    assert!(stderr.contains("code=invalid_relay_url"), "{stderr}");
    assert!(stderr.contains("reason=unsupported_scheme"), "{stderr}");
    assert!(!stderr.contains("relay.example"), "{stderr}");
    assert!(!home.join("dev").exists());

    // A `--relay` value wins over the variable, so the same start gets past
    // relay validation and stops at the socket instead: a regular file where
    // the socket belongs.
    std::fs::create_dir(home.join("dev")).unwrap();
    std::fs::set_permissions(home.join("dev"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(home.join("dev").join("wn-agent.sock"), b"not a socket").unwrap();
    let stderr = serve(Some("wss://relay.example"));
    assert!(stderr.contains("code=io_error"), "{stderr}");
    assert!(stderr.contains("is not a Unix socket"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn auth_token_file_failures_keep_the_path_off_the_startup_line() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir_in(std::fs::canonicalize("/tmp").unwrap()).unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let empty = root.path().join("empty.token");
    std::fs::write(&empty, b"  \n").unwrap();
    for (token_file, expected) in [
        (
            root.path().join("missing.token"),
            "detail=could not read the auth token file (NotFound)",
        ),
        (empty, "detail=the auth token file is empty"),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_wn-agent"))
            .arg("--home")
            .arg(&home)
            .arg("--auth-token-file")
            .arg(&token_file)
            .env_remove("MARMOT_RELAYS")
            .env_remove("MARMOT_RELAY")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("code=auth_token_file"), "{stderr}");
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!stderr.contains(root.path().to_str().unwrap()), "{stderr}");
    }
}

#[cfg(unix)]
#[test]
fn bootstrap_splits_comma_separated_relays_like_serve() {
    let root = tempfile::tempdir_in(std::fs::canonicalize("/tmp").unwrap()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_wn-agent"))
        .arg("bootstrap")
        .arg("--home")
        .arg(root.path())
        .arg("--socket")
        .arg(root.path().join("missing.sock"))
        .arg("--relay")
        .arg("wss://one.example,wss://two.example")
        .arg("--wait-for-socket")
        .arg("0")
        .env_remove("MARMOT_RELAYS")
        .env_remove("MARMOT_RELAY")
        .env_remove("MARMOT_AGENT_AUTH_TOKEN")
        .env_remove("MARMOT_AGENT_AUTH_TOKEN_FILE")
        .output()
        .unwrap();
    // Both relays pass validation, so bootstrap gets as far as the missing
    // socket; one unsplit `a,b` value would fail relay validation first.
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("wn-agent socket not found"), "{stderr}");
}
