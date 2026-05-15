use std::process::{Child, Command};
use std::time::{Duration, Instant};

use serde_json::Value;

fn dm(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dm"));
    command.arg("--home").arg(home).arg("--json");
    command.env("DM_SECRET_STORE", "file");
    command
}

fn run_json(home: &std::path::Path, args: &[&str]) -> Value {
    let output = dm(home)
        .args(args)
        .output()
        .expect("dm command should start");
    assert!(
        output.status.success(),
        "dm failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["ok"], true);
    value["result"].clone()
}

fn run_json_error(home: &std::path::Path, args: &[&str]) -> Value {
    let output = dm(home)
        .args(args)
        .output()
        .expect("dm command should start");
    assert!(
        !output.status.success(),
        "dm unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["ok"], false);
    value["error"].clone()
}

fn run_json_with_env(home: &std::path::Path, args: &[&str], envs: &[(&str, &str)]) -> Value {
    let mut command = dm(home);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().expect("dm command should start");
    assert!(
        output.status.success(),
        "dm failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["ok"], true);
    value["result"].clone()
}

fn member_accounts(value: &Value) -> Vec<String> {
    let mut accounts = value["members"]
        .as_array()
        .expect("members array")
        .iter()
        .filter_map(|member| member["account"].as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    accounts.sort();
    accounts
}

fn wait_for_daemon(socket: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let output = Command::new(env!("CARGO_BIN_EXE_dm"))
            .arg("--socket")
            .arg(socket)
            .arg("--json")
            .args(["daemon", "status"])
            .output()
            .expect("dm daemon status should start");
        if output.status.success() {
            let value: Value =
                serde_json::from_slice(&output.stdout).expect("status stdout should be JSON");
            if value["result"]["running"].as_bool() == Some(true) {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("daemon did not become ready at {}", socket.display());
}

fn stop_daemon(socket: &std::path::Path, child: &mut Child) {
    let _ = Command::new(env!("CARGO_BIN_EXE_dm"))
        .arg("--socket")
        .arg(socket)
        .arg("--json")
        .args(["daemon", "stop"])
        .output();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn account_create_list_and_status_are_json_addressable() {
    let home = tempfile::tempdir().expect("tempdir");

    let created = run_json(home.path(), &["account", "create", "alice"]);
    let account_id = created["account_id"].as_str().expect("account id");
    assert_eq!(created["account"], "alice");

    let listed = run_json(home.path(), &["account", "list"]);
    assert_eq!(listed["accounts"][0]["account"], "alice");
    assert_eq!(listed["accounts"][0]["account_id"], account_id);

    let status = run_json(home.path(), &["account", "status", "alice"]);
    assert_eq!(status["account"], "alice");
    assert_eq!(status["account_id"], account_id);
    assert_eq!(status["relay_lists"]["complete"], false);
}

#[test]
fn account_import_accepts_nsec_without_echoing_it() {
    let home = tempfile::tempdir().expect("tempdir");
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let output = dm(home.path())
        .args([
            "account",
            "import",
            "alice",
            "--nsec",
            nsec,
            "--default-relays",
            "wss://relay.example",
            "--bootstrap-relays",
            "marmot-local://seed",
            "--publish-missing-relay-lists",
        ])
        .output()
        .expect("dm command should start");
    assert!(
        output.status.success(),
        "dm failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(nsec));

    let imported: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    let account_id = imported["result"]["account_id"]
        .as_str()
        .expect("account id");
    assert_eq!(account_id.len(), 64);

    let status = run_json(home.path(), &["account", "status", "alice"]);
    assert_eq!(status["account_id"], account_id);
}

#[test]
fn account_create_publishes_required_relay_lists_from_default_relays() {
    let home = tempfile::tempdir().expect("tempdir");

    let created = run_json(
        home.path(),
        &[
            "account",
            "create",
            "alice",
            "--default-relays",
            "wss://relay1.example,wss://relay2.example",
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );
    assert_eq!(created["relay_lists"]["complete"], true);
    assert_eq!(
        created["relay_lists"]["default_relays"],
        serde_json::json!(["wss://relay1.example", "wss://relay2.example"])
    );
    assert_eq!(
        created["relay_lists"]["bootstrap_relays"],
        serde_json::json!(["marmot-local://seed"])
    );
    assert_eq!(created["relay_lists"]["nip65"]["kind"], 10002);
    assert_eq!(created["relay_lists"]["inbox"]["kind"], 10050);
    assert_eq!(created["relay_lists"]["key_package"]["kind"], 10051);

    let status = run_json(home.path(), &["account", "status", "alice"]);
    assert_eq!(status["relay_lists"], created["relay_lists"]);
}

#[test]
fn account_import_reports_missing_relay_lists_without_storing_the_nsec() {
    let home = tempfile::tempdir().expect("tempdir");
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let error = run_json_error(
        home.path(),
        &[
            "account",
            "import",
            "alice",
            "--nsec",
            nsec,
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );
    assert_eq!(error["code"], "missing_relay_lists");
    assert_eq!(
        error["missing"],
        serde_json::json!(["nip65", "inbox", "key_package"])
    );
    assert_eq!(error["repair"]["flag"], "--publish-missing-relay-lists");
    assert!(!error.to_string().contains(nsec));

    let listed = run_json(home.path(), &["account", "list"]);
    assert_eq!(listed["accounts"], serde_json::json!([]));
}

#[test]
fn account_create_rolls_back_when_relay_list_publication_fails() {
    let home = tempfile::tempdir().expect("tempdir");

    let error = run_json_error(
        home.path(),
        &[
            "account",
            "create",
            "alice",
            "--default-relays",
            "not-a-relay-url",
        ],
    );
    assert_ne!(error["code"], "usage");

    let listed = run_json(home.path(), &["account", "list"]);
    assert_eq!(listed["accounts"], serde_json::json!([]));
}

#[test]
fn account_import_can_publish_missing_relay_lists_from_default_relays() {
    let home = tempfile::tempdir().expect("tempdir");
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let imported = run_json(
        home.path(),
        &[
            "account",
            "import",
            "alice",
            "--nsec",
            nsec,
            "--default-relays",
            "wss://relay1.example,wss://relay2.example",
            "--bootstrap-relays",
            "marmot-local://seed",
            "--publish-missing-relay-lists",
        ],
    );

    assert_eq!(imported["relay_lists"]["complete"], true);
    assert_eq!(
        imported["relay_lists"]["default_relays"],
        serde_json::json!(["wss://relay1.example", "wss://relay2.example"])
    );
    let listed = run_json(home.path(), &["account", "list"]);
    assert_eq!(listed["accounts"][0]["account"], "alice");
}

#[test]
fn account_import_rolls_back_when_missing_relay_list_publication_fails() {
    let home = tempfile::tempdir().expect("tempdir");
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let error = run_json_error(
        home.path(),
        &[
            "account",
            "import",
            "alice",
            "--nsec",
            nsec,
            "--default-relays",
            "not-a-relay-url",
            "--publish-missing-relay-lists",
        ],
    );
    assert_ne!(error["code"], "usage");
    assert!(!error.to_string().contains(nsec));

    let listed = run_json(home.path(), &["account", "list"]);
    assert_eq!(listed["accounts"], serde_json::json!([]));
}

#[test]
fn account_relay_lists_checks_a_pubkey_from_bootstrap_relays() {
    let home = tempfile::tempdir().expect("tempdir");

    let created = run_json(
        home.path(),
        &[
            "account",
            "create",
            "alice",
            "--default-relays",
            "wss://relay1.example,wss://relay2.example",
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );
    let account_id = created["account_id"].as_str().expect("account id");

    let checked = run_json(
        home.path(),
        &[
            "account",
            "relay-lists",
            "--pubkey",
            account_id,
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );

    assert_eq!(checked["account_id"], account_id);
    assert_eq!(checked["relay_lists"]["complete"], true);
    assert_eq!(
        checked["relay_lists"]["bootstrap_relays"],
        serde_json::json!(["marmot-local://seed"])
    );
}

#[test]
fn key_package_fetches_latest_package_via_relay_list_discovery() {
    let home = tempfile::tempdir().expect("tempdir");

    let created = run_json(
        home.path(),
        &[
            "account",
            "create",
            "bob",
            "--default-relays",
            "marmot-local://key-packages",
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );
    let account_id = created["account_id"].as_str().expect("account id");

    let published = run_json(home.path(), &["--account", "bob", "keys", "publish"]);
    let published_bytes = published["key_package_bytes"].as_u64().expect("bytes");
    assert!(published_bytes > 0);

    let fetched = run_json(
        home.path(),
        &[
            "keys",
            "fetch",
            "--pubkey",
            account_id,
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );

    assert_eq!(fetched["account_id"], account_id);
    assert_eq!(fetched["key_package_bytes"].as_u64(), Some(published_bytes));
    assert_eq!(
        fetched["relay_lists"]["key_package"]["relays"],
        serde_json::json!(["marmot-local://key-packages"])
    );
    assert_eq!(
        fetched["source_relays"],
        serde_json::json!(["marmot-local://key-packages"])
    );
}

#[test]
fn global_account_selects_subject_for_keys_fetch_and_relay_lists() {
    let home = tempfile::tempdir().expect("tempdir");

    let created = run_json(
        home.path(),
        &[
            "account",
            "create",
            "bob",
            "--default-relays",
            "marmot-local://key-packages",
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );
    let account_id = created["account_id"].as_str().expect("account id");

    let relay_lists = run_json(
        home.path(),
        &[
            "--account",
            "bob",
            "account",
            "relay-lists",
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );
    assert_eq!(relay_lists["account_id"], account_id);
    assert_eq!(relay_lists["relay_lists"]["complete"], true);

    let published = run_json(home.path(), &["--account", "bob", "keys", "publish"]);
    let fetched = run_json(home.path(), &["--account", "bob", "keys", "fetch"]);
    assert_eq!(fetched["account_id"], account_id);
    assert_eq!(fetched["key_package_bytes"], published["key_package_bytes"]);
}

#[test]
fn keys_namespace_uses_account_resolution() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "bob"]);

    let published = run_json(home.path(), &["keys", "publish"]);
    assert_eq!(published["account"], "bob");
    assert!(published["key_package_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn legacy_or_duplicate_command_shapes_are_not_supported() {
    let home = tempfile::tempdir().expect("tempdir");

    assert_eq!(
        run_json_error(home.path(), &["key-package", "publish"])["code"],
        "usage"
    );
    assert_eq!(
        run_json_error(home.path(), &["directory", "get", "--pubkey", "00"])["code"],
        "usage"
    );
    assert_eq!(
        run_json_error(home.path(), &["group", "list"])["code"],
        "usage"
    );
    assert_eq!(
        run_json_error(home.path(), &["group", "show", "00"])["code"],
        "usage"
    );
    assert_eq!(
        run_json_error(home.path(), &["keys", "publish", "--account", "bob"])["code"],
        "usage"
    );
}

#[test]
fn account_resolution_errors_are_stable_json_contracts() {
    let home = tempfile::tempdir().expect("tempdir");

    let missing = run_json_error(home.path(), &["keys", "publish"]);
    assert_eq!(missing["code"], "missing_account");
    assert_eq!(missing["repair"]["select"], "--account <name-or-pubkey>");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);

    let multiple = run_json_error(home.path(), &["keys", "publish"]);
    assert_eq!(multiple["code"], "multiple_accounts");
    assert_eq!(multiple["repair"]["env"], "DM_ACCOUNT");

    let unknown = run_json_error(home.path(), &["--account", "carol", "keys", "publish"]);
    assert_eq!(unknown["code"], "unknown_account");
    assert_eq!(unknown["account"], "carol");
}

#[test]
fn positional_group_and_message_commands_use_global_or_env_account() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["--account", "bob", "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", "alice", "group", "create", "general", "bob"],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");

    let bob_join = run_json_with_env(home.path(), &["sync"], &[("DM_ACCOUNT", "bob")]);
    assert_eq!(bob_join["joined_groups"][0], group_id);

    run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "message",
            "send",
            group_id,
            "hello bob",
        ],
    );

    let bob_sync = run_json_with_env(home.path(), &["sync"], &[("DM_ACCOUNT", "bob")]);
    assert_eq!(bob_sync["messages"][0]["plaintext"], "hello bob");
}

#[test]
fn message_send_accepts_hyphen_leading_text_after_group_flag() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["--account", "bob", "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", "alice", "group", "create", "general", "bob"],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", "bob", "sync"]);

    run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "message",
            "send",
            "--group",
            group_id,
            "--starts-with-dash",
        ],
    );

    let bob_sync = run_json(home.path(), &["--account", "bob", "sync"]);
    assert_eq!(bob_sync["messages"][0]["plaintext"], "--starts-with-dash");
}

#[test]
fn chats_list_exposes_visible_groups() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["--account", "bob", "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", "alice", "group", "create", "general", "bob"],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", "bob", "sync"]);

    let chats = run_json(home.path(), &["--account", "bob", "chats", "list"]);
    assert_eq!(chats["chats"][0]["group_id"], group_id);
    assert_eq!(chats["chats"][0]["profile"]["name"], "general");
}

#[test]
fn daemon_executes_cli_commands_over_socket() {
    let home = tempfile::tempdir().expect("tempdir");
    let socket = home.path().join("dev").join("dmd.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dmd"))
        .arg("--home")
        .arg(home.path())
        .arg("--socket")
        .arg(&socket)
        .arg("--secret-store")
        .arg("file")
        .spawn()
        .expect("dmd should start");

    wait_for_daemon(&socket);

    let output = Command::new(env!("CARGO_BIN_EXE_dm"))
        .arg("--socket")
        .arg(&socket)
        .arg("--json")
        .args(["account", "create", "alice"])
        .output()
        .expect("dm should start");
    assert!(
        output.status.success(),
        "dm failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["result"]["account"], "alice");

    stop_daemon(&socket, &mut child);
}

#[test]
fn daemon_start_status_execute_and_stop_are_user_facing_commands() {
    let home = tempfile::tempdir().expect("tempdir");
    let socket = home.path().join("dev").join("dmd.sock");

    let start = Command::new(env!("CARGO_BIN_EXE_dm"))
        .arg("--home")
        .arg(home.path())
        .arg("--socket")
        .arg(&socket)
        .arg("--secret-store")
        .arg("file")
        .arg("--json")
        .args(["daemon", "start"])
        .output()
        .expect("dm daemon start should run");
    assert!(
        start.status.success(),
        "daemon start failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&start.stdout),
        String::from_utf8_lossy(&start.stderr)
    );

    let status = Command::new(env!("CARGO_BIN_EXE_dm"))
        .arg("--socket")
        .arg(&socket)
        .arg("--json")
        .args(["daemon", "status"])
        .output()
        .expect("dm daemon status should run");
    assert!(
        status.status.success(),
        "daemon status failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    let status_json: Value =
        serde_json::from_slice(&status.stdout).expect("status stdout should be JSON");
    assert_eq!(status_json["result"]["running"], true);

    let created = Command::new(env!("CARGO_BIN_EXE_dm"))
        .arg("--socket")
        .arg(&socket)
        .arg("--json")
        .args(["account", "create", "alice"])
        .output()
        .expect("dm account create should run through daemon");
    assert!(
        created.status.success(),
        "daemon execute failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&created.stdout),
        String::from_utf8_lossy(&created.stderr)
    );
    let created_json: Value =
        serde_json::from_slice(&created.stdout).expect("created stdout should be JSON");
    assert_eq!(created_json["result"]["account"], "alice");

    let stop = Command::new(env!("CARGO_BIN_EXE_dm"))
        .arg("--socket")
        .arg(&socket)
        .arg("--json")
        .args(["daemon", "stop"])
        .output()
        .expect("dm daemon stop should run");
    assert!(
        stop.status.success(),
        "daemon stop failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stop.stdout),
        String::from_utf8_lossy(&stop.stderr)
    );
}

#[test]
fn missing_key_package_errors_include_repair_guidance() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);

    let error = run_json_error(
        home.path(),
        &[
            "--account",
            "alice",
            "group",
            "create",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );

    assert_eq!(error["code"], "missing_key_package");
    assert_eq!(error["account"], "bob");
    assert_eq!(error["repair"]["local"], "dm --account bob keys publish");
    assert_eq!(
        error["repair"]["remote"],
        "dm keys fetch --pubkey <npub-or-hex> --bootstrap-relays <relay-url>"
    );
}

#[test]
fn group_create_can_invite_a_member_by_fetched_pubkey() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    let bob = run_json(
        home.path(),
        &[
            "account",
            "create",
            "bob",
            "--default-relays",
            "marmot-local://key-packages",
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );
    let bob_account_id = bob["account_id"].as_str().expect("bob account id");

    run_json(home.path(), &["--account", "bob", "keys", "publish"]);
    run_json(
        home.path(),
        &[
            "keys",
            "fetch",
            "--pubkey",
            bob_account_id,
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );

    let created_group = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "group",
            "create",
            "--name",
            "pubkey",
            "--member",
            bob_account_id,
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");

    let bob_join = run_json(home.path(), &["--account", "bob", "sync"]);
    assert_eq!(bob_join["joined_groups"][0], group_id);
}

#[test]
fn group_archive_is_local_state_not_membership_state() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["--account", "bob", "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "group",
            "create",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", "bob", "sync"]);

    let archived = run_json(
        home.path(),
        &["--account", "bob", "chats", "archive", group_id],
    );
    assert_eq!(archived["group"]["archived"], true);

    let visible = run_json(home.path(), &["--account", "bob", "chats", "list"]);
    assert_eq!(visible["chats"], serde_json::json!([]));

    let included = run_json(
        home.path(),
        &["--account", "bob", "chats", "list", "--include-archived"],
    );
    assert_eq!(included["chats"][0]["group_id"], group_id);
    assert_eq!(included["chats"][0]["archived"], true);

    let bob_members = run_json(
        home.path(),
        &["--account", "bob", "group", "members", group_id],
    );
    assert_eq!(member_accounts(&bob_members), vec!["alice", "bob"]);

    let alice_chats = run_json(home.path(), &["--account", "alice", "chats", "list"]);
    assert_eq!(alice_chats["chats"][0]["archived"], false);

    let unarchived = run_json(
        home.path(),
        &["--account", "bob", "chats", "unarchive", group_id],
    );
    assert_eq!(unarchived["group"]["archived"], false);
    let visible = run_json(home.path(), &["--account", "bob", "chats", "list"]);
    assert_eq!(visible["chats"][0]["group_id"], group_id);
}

#[test]
fn local_group_message_workflow_runs_through_the_dm_contract() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["--account", "bob", "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "group",
            "create",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");

    let bob_join = run_json(home.path(), &["--account", "bob", "sync"]);
    assert_eq!(bob_join["joined_groups"][0], group_id);

    run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "message",
            "send",
            "--group",
            group_id,
            "hello",
            "bob",
        ],
    );

    let bob_sync = run_json(home.path(), &["--account", "bob", "sync"]);
    assert_eq!(bob_sync["messages"][0]["from"], "alice");
    assert_eq!(bob_sync["messages"][0]["group_id"], group_id);
    assert_eq!(bob_sync["messages"][0]["plaintext"], "hello bob");

    let bob_messages = run_json(home.path(), &["--account", "bob", "message", "list"]);
    assert_eq!(bob_messages["messages"][0]["from"], "alice");
    assert_eq!(bob_messages["messages"][0]["group_id"], group_id);
    assert_eq!(bob_messages["messages"][0]["plaintext"], "hello bob");
}

#[test]
fn cli_can_inspect_projected_groups_messages_and_status() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["--account", "bob", "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "group",
            "create",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    assert_eq!(created_group["profile"]["component_id"], 0x8001);
    assert_eq!(
        created_group["profile"]["component"],
        "marmot.group.profile.v1"
    );
    assert_eq!(created_group["profile"]["name"], "general");
    assert_eq!(
        created_group["image"]["component"],
        "marmot.group.blossom.image.v1"
    );
    assert_eq!(created_group["image"]["present"], false);
    run_json(home.path(), &["--account", "bob", "sync"]);

    let chats = run_json(home.path(), &["--account", "bob", "chats", "list"]);
    assert_eq!(chats["chats"][0]["group_id"], group_id);
    assert_eq!(chats["chats"][0]["profile"]["name"], "general");

    let group = run_json(
        home.path(),
        &["--account", "bob", "chats", "show", group_id],
    );
    assert_eq!(group["group"]["group_id"], group_id);
    assert_eq!(group["group"]["profile"]["name"], "general");

    let first_send = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "message",
            "send",
            "--group",
            group_id,
            "first",
        ],
    );
    let first_message_id = first_send["message_ids"][0].as_str().expect("message id");
    let alice_messages = run_json(home.path(), &["--account", "alice", "message", "list"]);
    assert_eq!(alice_messages["messages"].as_array().unwrap().len(), 1);
    assert_eq!(alice_messages["messages"][0]["direction"], "sent");
    assert_eq!(
        alice_messages["messages"][0]["message_id"],
        first_message_id
    );
    assert_eq!(alice_messages["messages"][0]["from"], "alice");
    assert_eq!(alice_messages["messages"][0]["plaintext"], "first");

    run_json(home.path(), &["--account", "alice", "sync"]);
    let alice_messages_after_echo =
        run_json(home.path(), &["--account", "alice", "message", "list"]);
    assert_eq!(
        alice_messages_after_echo["messages"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "author relay echoes should not duplicate a published outbound message"
    );

    let second_send = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "message",
            "send",
            "--group",
            group_id,
            "second",
        ],
    );
    assert!(second_send["message_ids"][0].as_str().is_some());
    run_json(home.path(), &["--account", "bob", "sync"]);

    let messages = run_json(
        home.path(),
        &[
            "--account",
            "bob",
            "message",
            "list",
            "--group",
            group_id,
            "--limit",
            "1",
        ],
    );
    assert_eq!(messages["messages"].as_array().unwrap().len(), 1);
    assert_eq!(messages["messages"][0]["direction"], "received");
    assert!(messages["messages"][0]["message_id"].as_str().is_some());
    assert_eq!(messages["messages"][0]["plaintext"], "second");

    let status = run_json(home.path(), &["account", "status", "bob"]);
    assert_eq!(status["counts"]["groups"], 1);
    assert_eq!(status["counts"]["messages"], 2);
    assert_eq!(status["secret_store"]["backend"], "file");
    assert_eq!(status["projections"]["account"]["exists"], true);
    assert_eq!(status["projections"]["account"]["encrypted"], true);
}

#[test]
fn group_update_publishes_profile_component_changes() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["--account", "bob", "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "group",
            "create",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", "bob", "sync"]);

    let updated = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "group",
            "update",
            group_id,
            "--name",
            "team room",
            "--description",
            "daily coordination",
        ],
    );
    assert_eq!(updated["group"]["profile"]["name"], "team room");
    assert_eq!(
        updated["group"]["profile"]["description"],
        "daily coordination"
    );
    assert_eq!(updated["published"], 1);

    run_json(home.path(), &["--account", "bob", "sync"]);
    let bob_group = run_json(
        home.path(),
        &["--account", "bob", "chats", "show", group_id],
    );
    assert_eq!(bob_group["group"]["profile"]["name"], "team room");
    assert_eq!(
        bob_group["group"]["profile"]["description"],
        "daily coordination"
    );
}

#[test]
fn group_members_invite_and_remove_flow_updates_projected_members() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["account", "create", "carol"]);
    run_json(home.path(), &["--account", "bob", "keys", "publish"]);
    run_json(home.path(), &["--account", "carol", "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "group",
            "create",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", "bob", "sync"]);

    let initial_members = run_json(
        home.path(),
        &["--account", "alice", "group", "members", group_id],
    );
    assert_eq!(member_accounts(&initial_members), vec!["alice", "bob"]);

    let invite = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "group",
            "invite",
            group_id,
            "--member",
            "carol",
        ],
    );
    assert_eq!(invite["published"], 2);
    run_json(home.path(), &["--account", "carol", "sync"]);

    let invited_members = run_json(
        home.path(),
        &["--account", "alice", "group", "members", group_id],
    );
    assert_eq!(
        member_accounts(&invited_members),
        vec!["alice", "bob", "carol"]
    );

    run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "message",
            "send",
            "--group",
            group_id,
            "history",
            "stays",
        ],
    );
    run_json(home.path(), &["--account", "bob", "sync"]);
    run_json(home.path(), &["--account", "carol", "sync"]);

    let remove = run_json(
        home.path(),
        &[
            "--account",
            "alice",
            "group",
            "remove",
            group_id,
            "--member",
            "bob",
        ],
    );
    assert_eq!(remove["published"], 1);
    run_json(home.path(), &["--account", "bob", "sync"]);
    run_json(home.path(), &["--account", "carol", "sync"]);

    let alice_members = run_json(
        home.path(),
        &["--account", "alice", "group", "members", group_id],
    );
    assert_eq!(member_accounts(&alice_members), vec!["alice", "carol"]);

    let carol_members = run_json(
        home.path(),
        &["--account", "carol", "group", "members", group_id],
    );
    assert_eq!(member_accounts(&carol_members), vec!["alice", "carol"]);

    let bob_group = run_json(
        home.path(),
        &["--account", "bob", "chats", "show", group_id],
    );
    assert_eq!(bob_group["group"]["profile"]["name"], "general");
    let bob_members = run_json(
        home.path(),
        &["--account", "bob", "group", "members", group_id],
    );
    assert_eq!(member_accounts(&bob_members), vec!["alice", "carol"]);
    let bob_history = run_json(
        home.path(),
        &["--account", "bob", "message", "list", "--group", group_id],
    );
    assert_eq!(bob_history["messages"][0]["plaintext"], "history stays");
}
