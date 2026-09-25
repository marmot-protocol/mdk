//! Process-level root ownership must also cover CLI fallback and daemon startup.
#![cfg(unix)]
use marmot_app::MarmotRootRuntimeLease;
use std::process::Command;

#[test]
fn read_only_account_listing_survives_owned_root_but_mutation_does_not() {
    let home = tempfile::tempdir().unwrap();
    let lease = MarmotRootRuntimeLease::try_acquire(home.path()).unwrap();
    let command = |subcommand: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wn"));
        command
            .env_remove("WN_SOCKET")
            .env_remove("WN_ACCOUNT")
            .env("WN_SECRET_STORE", "file")
            .args(["--home", home.path().to_str().unwrap(), "--json"])
            .args(subcommand);
        command
    };
    let children = (0..6)
        .map(|_| {
            command(&["accounts", "list"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    for child in children {
        let listed = child.wait_with_output().unwrap();
        assert!(
            listed.status.success(),
            "{}",
            String::from_utf8_lossy(&listed.stdout)
        );
    }
    let blocked = command(&["logout", &"aa".repeat(32)]).output().unwrap();
    assert!(!blocked.status.success());
    let error: serde_json::Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(error["error"]["code"], "runtime_busy");
    assert!(!home.path().join("shared.sqlite3").exists());
    // An abandoned implicit daemon socket must not turn fallback into a lease bypass.
    let socket = wn_cli::daemon::default_socket_path(home.path());
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    let fallback = command(&["logout", &"aa".repeat(32)]).output().unwrap();
    assert!(!fallback.status.success());
    let fallback_error: serde_json::Value = serde_json::from_slice(&fallback.stdout).unwrap();
    assert_eq!(fallback_error["error"]["code"], "runtime_busy");
    drop(lease);
    let released = command(&["accounts", "list"]).output().unwrap();
    assert!(
        released.status.success(),
        "{}",
        String::from_utf8_lossy(&released.stderr)
    );
}

#[test]
fn daemon_refuses_owned_root_before_removing_socket_artifacts() {
    let home = tempfile::tempdir().unwrap();
    let _lease = MarmotRootRuntimeLease::try_acquire(home.path()).unwrap();
    let socket = home.path().join("test.sock");
    std::fs::write(&socket, b"preserve existing artifact").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_wnd"))
        .args([
            "--home",
            home.path().to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
            "--discovery-relays",
            "wss://relay.example.com",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("already in use"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(socket).unwrap(),
        b"preserve existing artifact"
    );
}
