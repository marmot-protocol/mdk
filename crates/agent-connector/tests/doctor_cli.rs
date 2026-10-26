//! Exercise `wn-agent doctor` as an operator runs it.

#[cfg(unix)]
fn doctor(home: &std::path::Path, extra: &[&str]) -> std::process::Output {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_wn-agent"));
    command.arg("doctor").arg("--home").arg(home).args(extra);
    for name in [
        "MARMOT_HOME",
        "MARMOT_AGENT_SOCKET",
        "MARMOT_AGENT_AUTH_TOKEN",
        "MARMOT_AGENT_AUTH_TOKEN_FILE",
        "MARMOT_RELAYS",
        "MARMOT_RELAY",
    ] {
        command.env_remove(name);
    }
    command.output().unwrap()
}

#[cfg(unix)]
#[test]
fn doctor_cli_fails_an_empty_home_without_naming_it() {
    use std::os::unix::fs::PermissionsExt;

    let short_temp_base = std::fs::canonicalize("/tmp").unwrap();
    let root = tempfile::tempdir_in(short_temp_base).unwrap();
    let home = root.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();

    let output = doctor(&home, &["--json"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let status = |id: &str| {
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["id"] == id)
            .map(|check| check["status"].as_str().unwrap().to_owned())
    };
    assert_eq!(status("accounts").as_deref(), Some("fail"));
    assert_eq!(status("daemon").as_deref(), Some("fail"));
    assert!(!stdout.contains(root.path().to_str().unwrap()));
    assert_eq!(
        std::fs::read_dir(&home).unwrap().count(),
        0,
        "doctor wrote into the home"
    );

    let text = doctor(&home, &[]);
    assert_eq!(text.status.code(), Some(1));
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("fail    accounts"));
    assert!(text.contains("does not prove end-to-end delivery"));
    assert!(!text.contains(root.path().to_str().unwrap()));
}

#[cfg(unix)]
#[test]
fn doctor_cli_invalid_socket_dir_mode_does_not_echo_input() {
    let root = tempfile::tempdir().unwrap();
    let secret = "/private/secret-account-path";
    let output = doctor(root.path(), &["--socket-dir-mode", secret]);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--socket-dir-mode"));
    assert!(!stderr.contains(secret));
    assert!(!String::from_utf8(output.stdout).unwrap().contains(secret));
}
