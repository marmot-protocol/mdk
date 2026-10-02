//! Exercise the released CLI's privacy-safe startup diagnostic.

#[cfg(unix)]
#[test]
fn socket_path_too_long_cli_reports_actionable_error_without_private_path() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let socket = root.path().join("é".repeat(60)).join("wn-agent.sock");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_wn-agent"))
        .arg("--home")
        .arg(root.path())
        .arg("--socket")
        .arg(&socket)
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
