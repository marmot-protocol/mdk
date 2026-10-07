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
