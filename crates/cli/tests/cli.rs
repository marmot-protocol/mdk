use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use serde_json::Value;

fn dm(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dm"));
    command.arg("--home").arg(home).arg("--json");
    command.env("DM_SECRET_STORE", "file");
    command
}

fn dm_with_relay(home: &std::path::Path, relay: &str) -> Command {
    let mut command = dm(home);
    command.arg("--relay").arg(relay);
    command
}

fn command_output_summary(output: &Output) -> String {
    format!(
        "status={}\nstdout_len={}\nstderr_len={}",
        output.status,
        output.stdout.len(),
        output.stderr.len()
    )
}

fn json_value_summary(label: &str, value: &Value) -> String {
    format!("{label}_json_len={}", value.to_string().len())
}

fn run_json(home: &std::path::Path, args: &[&str]) -> Value {
    let output = dm(home)
        .args(args)
        .output()
        .expect("dm command should start");
    assert!(
        output.status.success(),
        "dm failed\n{}",
        command_output_summary(&output)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["ok"], true);
    value["result"].clone()
}

fn run_json_with_relay(home: &std::path::Path, relay: &str, args: &[&str]) -> Value {
    let output = dm_with_relay(home, relay)
        .args(args)
        .output()
        .expect("dm command should start");
    assert!(
        output.status.success(),
        "dm failed\nrelay=<REDACTED_RELAY>\n{}",
        command_output_summary(&output)
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
        "dm unexpectedly succeeded\n{}",
        command_output_summary(&output)
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
        "dm failed\n{}",
        command_output_summary(&output)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["ok"], true);
    value["result"].clone()
}

fn create_account(home: &std::path::Path) -> String {
    run_json(home, &["account", "create"])["account_id"]
        .as_str()
        .expect("account id")
        .to_owned()
}

fn create_account_with_relays(
    home: &std::path::Path,
    default_relays: &str,
    bootstrap_relays: &str,
) -> Value {
    run_json(
        home,
        &[
            "account",
            "create",
            "--default-relays",
            default_relays,
            "--bootstrap-relays",
            bootstrap_relays,
        ],
    )
}

fn member_accounts(value: &Value) -> Vec<String> {
    let mut accounts = value["members"]
        .as_array()
        .expect("members array")
        .iter()
        .filter_map(|member| member["member_id"].as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    accounts.sort();
    accounts
}

fn sorted_accounts<const N: usize>(accounts: [&str; N]) -> Vec<String> {
    let mut accounts = accounts
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    accounts.sort();
    accounts
}

fn message_plaintexts(value: &Value) -> Vec<String> {
    value["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .map(|message| {
            message["plaintext"]
                .as_str()
                .expect("message plaintext")
                .to_owned()
        })
        .collect()
}

fn assert_message_plaintexts(value: &Value, expected: &[&str]) {
    let actual = message_plaintexts(value);
    for expected in expected {
        assert!(
            actual.iter().any(|plaintext| plaintext == expected),
            "expected message {expected:?} in {actual:?}"
        );
    }
}

fn assert_no_message_plaintext(value: &Value, unexpected: &str) {
    let actual = message_plaintexts(value);
    assert!(
        actual.iter().all(|plaintext| plaintext != unexpected),
        "did not expect message {unexpected:?} in {actual:?}"
    );
}

fn real_relay_urls() -> Vec<String> {
    env::var("DARKMATTER_E2E_RELAYS")
        .ok()
        .map(|relays| {
            relays
                .split(',')
                .map(str::trim)
                .filter(|relay| !relay.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|relays| !relays.is_empty())
        .unwrap_or_else(|| {
            vec![
                "ws://127.0.0.1:28080".to_owned(),
                "ws://127.0.0.1:27777".to_owned(),
            ]
        })
}

fn require_real_relays() -> bool {
    env::var("DARKMATTER_E2E_REQUIRE_RELAYS")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn local_relay_available(relay: &str) -> bool {
    let Some(address) = relay
        .strip_prefix("wss://")
        .or_else(|| relay.strip_prefix("ws://"))
    else {
        return false;
    };
    let address = address.split('/').next().expect("relay authority");
    let Ok(addresses) = address.to_socket_addrs() else {
        return false;
    };
    addresses.into_iter().any(|socket_address| {
        TcpStream::connect_timeout(&socket_address, Duration::from_millis(200)).is_ok()
    })
}

fn create_account_with_real_relay(home: &std::path::Path, relay: &str) -> String {
    run_json_with_relay(
        home,
        relay,
        &[
            "account",
            "create",
            "--default-relays",
            relay,
            "--bootstrap-relays",
            relay,
        ],
    )["account_id"]
        .as_str()
        .expect("account id")
        .to_owned()
}

fn sync_until_joined(home: &std::path::Path, relay: &str, account: &str, group_id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        let sync = run_json_with_relay(home, relay, &["--account", account, "sync"]);
        if sync["joined_groups"]
            .as_array()
            .is_some_and(|groups| groups.iter().any(|group| group == group_id))
        {
            return sync;
        }
        last = sync;
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "account <REDACTED_ACCOUNT> did not join <REDACTED_GROUP> via <REDACTED_RELAY>; {}",
        json_value_summary("last_sync", &last)
    );
}

fn sync_until_message(
    home: &std::path::Path,
    relay: &str,
    account: &str,
    plaintext: &str,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last = Value::Null;
    while Instant::now() < deadline {
        let sync = run_json_with_relay(home, relay, &["--account", account, "sync"]);
        if message_plaintexts(&sync)
            .iter()
            .any(|message| message == plaintext)
        {
            return sync;
        }
        last = sync;
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "account <REDACTED_ACCOUNT> did not receive <REDACTED_MESSAGE> via <REDACTED_RELAY>; {}",
        json_value_summary("last_sync", &last)
    );
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

    let created = run_json(home.path(), &["account", "create"]);
    let account_id = created["account_id"].as_str().expect("account id");
    assert_eq!(created["local_signing"], true);
    assert!(created["npub"].as_str().expect("npub").starts_with("npub1"));

    let listed = run_json(home.path(), &["account", "list"]);
    assert_eq!(listed["accounts"][0]["account_id"], account_id);
    assert_eq!(listed["accounts"][0]["npub"], created["npub"]);

    let status = run_json(home.path(), &["account", "status", account_id]);
    assert_eq!(status["account_id"], account_id);
    assert_eq!(status["npub"], created["npub"]);
    assert_eq!(status["relay_lists"]["complete"], false);
}

#[test]
fn account_create_accepts_nsec_without_echoing_it() {
    let home = tempfile::tempdir().expect("tempdir");
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let output = dm(home.path())
        .args([
            "account",
            "create",
            nsec,
            "--default-relays",
            "wss://relay.example",
            "--bootstrap-relays",
            "marmot-local://seed",
        ])
        .output()
        .expect("dm command should start");
    assert!(
        output.status.success(),
        "dm failed\n{}",
        command_output_summary(&output)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(nsec));

    let imported: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    let account_id = imported["result"]["account_id"]
        .as_str()
        .expect("account id");
    assert_eq!(account_id.len(), 64);
    assert_eq!(imported["result"]["local_signing"], true);

    let status = run_json(home.path(), &["account", "status", account_id]);
    assert_eq!(status["account_id"], account_id);
}

#[test]
fn account_create_accepts_public_nostr_identity_without_signing() {
    let home = tempfile::tempdir().expect("tempdir");
    let public_key = "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy";
    let account_id = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";

    let created = run_json(home.path(), &["account", "create", public_key]);

    assert_eq!(created["account_id"], account_id);
    assert_eq!(created["local_signing"], false);
    assert!(created["npub"].as_str().unwrap().starts_with("npub1"));

    let status = run_json(home.path(), &["account", "status", public_key]);
    assert_eq!(status["account_id"], account_id);
    assert_eq!(status["local_signing"], false);

    let error = run_json_error(home.path(), &["--account", public_key, "keys", "publish"]);
    assert_eq!(error["code"], "public_account_cannot_sign");
}

#[test]
fn account_create_publishes_required_relay_lists_from_default_relays() {
    let home = tempfile::tempdir().expect("tempdir");

    let created = create_account_with_relays(
        home.path(),
        "wss://relay1.example,wss://relay2.example",
        "marmot-local://seed",
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

    let account_id = created["account_id"].as_str().expect("account id");
    let status = run_json(home.path(), &["account", "status", account_id]);
    assert_eq!(status["relay_lists"], created["relay_lists"]);
}

#[test]
fn account_create_reports_missing_relay_lists_without_storing_the_nsec() {
    let home = tempfile::tempdir().expect("tempdir");
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let error = run_json_error(
        home.path(),
        &[
            "account",
            "create",
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
    assert_eq!(error["repair"]["requires"], "--default-relays");
    assert!(!error.to_string().contains(nsec));

    let listed = run_json(home.path(), &["account", "list"]);
    assert_eq!(listed["accounts"], serde_json::json!([]));
}

#[test]
fn account_create_rolls_back_when_relay_list_publication_fails() {
    let home = tempfile::tempdir().expect("tempdir");

    let error = run_json_error(
        home.path(),
        &["account", "create", "--default-relays", "not-a-relay-url"],
    );
    assert_ne!(error["code"], "usage");

    let listed = run_json(home.path(), &["account", "list"]);
    assert_eq!(listed["accounts"], serde_json::json!([]));
}

#[test]
fn account_create_can_publish_missing_relay_lists_from_default_relays() {
    let home = tempfile::tempdir().expect("tempdir");
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let imported = run_json(
        home.path(),
        &[
            "account",
            "create",
            nsec,
            "--default-relays",
            "wss://relay1.example,wss://relay2.example",
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );

    assert_eq!(imported["relay_lists"]["complete"], true);
    assert_eq!(
        imported["relay_lists"]["default_relays"],
        serde_json::json!(["wss://relay1.example", "wss://relay2.example"])
    );
    let listed = run_json(home.path(), &["account", "list"]);
    assert_eq!(listed["accounts"][0]["account_id"], imported["account_id"]);
}

#[test]
fn account_create_rolls_back_when_missing_relay_list_publication_fails() {
    let home = tempfile::tempdir().expect("tempdir");
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

    let error = run_json_error(
        home.path(),
        &[
            "account",
            "create",
            nsec,
            "--default-relays",
            "not-a-relay-url",
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

    let created = create_account_with_relays(
        home.path(),
        "wss://relay1.example,wss://relay2.example",
        "marmot-local://seed",
    );
    let account_id = created["account_id"].as_str().expect("account id");

    let checked = run_json(
        home.path(),
        &[
            "account",
            "relay-lists",
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

    let created = create_account_with_relays(
        home.path(),
        "marmot-local://key-packages",
        "marmot-local://seed",
    );
    let account_id = created["account_id"].as_str().expect("account id");

    let published = run_json(home.path(), &["--account", account_id, "keys", "publish"]);
    let published_bytes = published["key_package_bytes"].as_u64().expect("bytes");
    assert!(published_bytes > 0);

    let fetched = run_json(
        home.path(),
        &[
            "keys",
            "fetch",
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

    let created = create_account_with_relays(
        home.path(),
        "marmot-local://key-packages",
        "marmot-local://seed",
    );
    let account_id = created["account_id"].as_str().expect("account id");

    let relay_lists = run_json(
        home.path(),
        &[
            "--account",
            account_id,
            "account",
            "relay-lists",
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );
    assert_eq!(relay_lists["account_id"], account_id);
    assert_eq!(relay_lists["relay_lists"]["complete"], true);

    let published = run_json(home.path(), &["--account", account_id, "keys", "publish"]);
    let fetched = run_json(home.path(), &["--account", account_id, "keys", "fetch"]);
    assert_eq!(fetched["account_id"], account_id);
    assert_eq!(fetched["key_package_bytes"], published["key_package_bytes"]);
}

#[test]
fn keys_namespace_uses_account_resolution() {
    let home = tempfile::tempdir().expect("tempdir");

    let account_id = create_account(home.path());

    let published = run_json(home.path(), &["keys", "publish"]);
    assert_eq!(published["account_id"], account_id);
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
        run_json_error(
            home.path(),
            &["account", "import", "alice", "--nsec", "nsec1"]
        )["code"],
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
    assert_eq!(
        run_json_error(home.path(), &["group", "create", "--name", "general"])["code"],
        "usage"
    );
    assert_eq!(
        run_json_error(home.path(), &["group", "invite", "00", "--member", "bob"])["code"],
        "usage"
    );
}

#[test]
fn account_resolution_errors_are_stable_json_contracts() {
    let home = tempfile::tempdir().expect("tempdir");

    let missing = run_json_error(home.path(), &["keys", "publish"]);
    assert_eq!(missing["code"], "missing_account");
    assert_eq!(missing["repair"]["select"], "--account <npub-or-hex>");

    create_account(home.path());
    create_account(home.path());

    let multiple = run_json_error(home.path(), &["keys", "publish"]);
    assert_eq!(multiple["code"], "multiple_accounts");
    assert_eq!(multiple["repair"]["env"], "DM_ACCOUNT");

    let unknown = run_json_error(
        home.path(),
        &["--account", "not-a-pubkey", "keys", "publish"],
    );
    assert_eq!(unknown["code"], "invalid_public_key");
}

#[test]
fn positional_group_and_message_commands_use_global_or_env_account() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");

    let bob_join = run_json_with_env(home.path(), &["sync"], &[("DM_ACCOUNT", &bob)]);
    assert_eq!(bob_join["joined_groups"][0], group_id);

    run_json(
        home.path(),
        &[
            "--account",
            &alice,
            "message",
            "send",
            group_id,
            "hello bob",
        ],
    );

    let bob_sync = run_json_with_env(home.path(), &["sync"], &[("DM_ACCOUNT", &bob)]);
    assert_eq!(bob_sync["messages"][0]["plaintext"], "hello bob");
}

#[test]
fn group_create_includes_agent_text_streams_by_default() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "agent", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    assert_eq!(created_group["agent_text_stream"]["required"], true);
    assert_eq!(created_group["agent_text_stream"]["component_id"], 0x8006);
    assert_eq!(
        created_group["agent_text_stream"]["component"],
        "marmot.group.agent-text-stream.quic.v1"
    );
    assert_eq!(
        created_group["agent_text_stream"]["data_hex"],
        "010300001000000000000000"
    );

    run_json(home.path(), &["--account", &bob, "sync"]);
    let bob_group = run_json(home.path(), &["--account", &bob, "chats", "show", group_id]);
    assert_eq!(bob_group["group"]["agent_text_stream"]["required"], true);
}

#[test]
fn message_send_accepts_hyphen_leading_text_after_group_flag() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", &bob, "sync"]);

    run_json(
        home.path(),
        &[
            "--account",
            &alice,
            "message",
            "send",
            "--group",
            group_id,
            "--starts-with-dash",
        ],
    );

    let bob_sync = run_json(home.path(), &["--account", &bob, "sync"]);
    assert_eq!(bob_sync["messages"][0]["plaintext"], "--starts-with-dash");
}

#[test]
fn chats_list_exposes_visible_groups() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", &bob, "sync"]);

    let chats = run_json(home.path(), &["--account", &bob, "chats", "list"]);
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
        .args(["account", "create"])
        .output()
        .expect("dm should start");
    assert!(
        output.status.success(),
        "dm failed\n{}",
        command_output_summary(&output)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["result"]["local_signing"], true);
    assert!(
        value["result"]["npub"]
            .as_str()
            .unwrap()
            .starts_with("npub1")
    );

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
        .args(["daemon", "start", "--sync-interval-ms", "100"])
        .output()
        .expect("dm daemon start should run");
    assert!(
        start.status.success(),
        "daemon start failed\n{}",
        command_output_summary(&start)
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
        "daemon status failed\n{}",
        command_output_summary(&status)
    );
    let status_json: Value =
        serde_json::from_slice(&status.stdout).expect("status stdout should be JSON");
    assert_eq!(status_json["result"]["running"], true);
    assert!(status_json["result"]["pid"].as_u64().is_some());
    assert!(status_json["result"]["pid_file"].as_str().is_some());
    assert_eq!(status_json["result"]["sync_interval_ms"], 100);

    let created = Command::new(env!("CARGO_BIN_EXE_dm"))
        .arg("--socket")
        .arg(&socket)
        .arg("--json")
        .args(["account", "create"])
        .output()
        .expect("dm account create should run through daemon");
    assert!(
        created.status.success(),
        "daemon execute failed\n{}",
        command_output_summary(&created)
    );
    let created_json: Value =
        serde_json::from_slice(&created.stdout).expect("created stdout should be JSON");
    assert_eq!(created_json["result"]["local_signing"], true);

    let stop = Command::new(env!("CARGO_BIN_EXE_dm"))
        .arg("--socket")
        .arg(&socket)
        .arg("--json")
        .args(["daemon", "stop"])
        .output()
        .expect("dm daemon stop should run");
    assert!(
        stop.status.success(),
        "daemon stop failed\n{}",
        command_output_summary(&stop)
    );
}

#[test]
fn daemon_background_sync_updates_local_accounts() {
    let home = tempfile::tempdir().expect("tempdir");
    let socket = home.path().join("dev").join("dmd.sock");
    let alice = create_account(home.path());
    let bob = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);
    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");

    let start = Command::new(env!("CARGO_BIN_EXE_dm"))
        .arg("--home")
        .arg(home.path())
        .arg("--socket")
        .arg(&socket)
        .arg("--secret-store")
        .arg("file")
        .arg("--json")
        .args(["daemon", "start", "--sync-interval-ms", "100"])
        .output()
        .expect("dm daemon start should run");
    assert!(
        start.status.success(),
        "daemon start failed\n{}",
        command_output_summary(&start)
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_group = false;
    while Instant::now() < deadline {
        let output = Command::new(env!("CARGO_BIN_EXE_dm"))
            .arg("--socket")
            .arg(&socket)
            .arg("--account")
            .arg(&bob)
            .arg("--json")
            .args(["chats", "list"])
            .output()
            .expect("dm chats list should run through daemon");
        if output.status.success() {
            let value: Value =
                serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
            if value["result"]["chats"]
                .as_array()
                .is_some_and(|chats| chats.iter().any(|chat| chat["group_id"] == group_id))
            {
                saw_group = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = Command::new(env!("CARGO_BIN_EXE_dm"))
        .arg("--socket")
        .arg(&socket)
        .arg("--json")
        .args(["daemon", "stop"])
        .output();

    assert!(
        saw_group,
        "daemon background sync did not join Bob to the group"
    );
}

#[test]
fn missing_key_package_errors_include_repair_guidance() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());

    let error = run_json_error(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
    );

    assert_eq!(error["code"], "missing_key_package");
    assert_eq!(error["account_id"], bob);
    assert_eq!(
        error["repair"]["local"],
        format!("dm --account {bob} keys publish")
    );
    assert_eq!(
        error["repair"]["remote"],
        "dm keys fetch <npub-or-hex> --bootstrap-relays <relay-url>"
    );
}

#[test]
fn group_create_can_invite_a_member_by_fetched_pubkey() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account_with_relays(
        home.path(),
        "marmot-local://key-packages",
        "marmot-local://seed",
    );
    let bob_account_id = bob["account_id"].as_str().expect("bob account id");

    run_json(
        home.path(),
        &["--account", bob_account_id, "keys", "publish"],
    );
    run_json(
        home.path(),
        &[
            "keys",
            "fetch",
            bob_account_id,
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );

    let created_group = run_json(
        home.path(),
        &[
            "--account",
            &alice,
            "group",
            "create",
            "pubkey",
            bob_account_id,
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");

    let bob_join = run_json(home.path(), &["--account", bob_account_id, "sync"]);
    assert_eq!(bob_join["joined_groups"][0], group_id);
}

#[test]
fn group_create_fetches_missing_key_package_for_pubkey_members() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account_with_relays(
        home.path(),
        "marmot-local://key-packages",
        "marmot-local://seed",
    );
    let bob_account_id = bob["account_id"].as_str().expect("bob account id");

    run_json(
        home.path(),
        &["--account", bob_account_id, "keys", "publish"],
    );

    let created_group = run_json(
        home.path(),
        &[
            "--account",
            &alice,
            "group",
            "create",
            "pubkey",
            bob_account_id,
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");

    let bob_join = run_json(home.path(), &["--account", bob_account_id, "sync"]);
    assert_eq!(bob_join["joined_groups"][0], group_id);
}

#[test]
fn group_archive_is_local_state_not_membership_state() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", &bob, "sync"]);

    let archived = run_json(
        home.path(),
        &["--account", &bob, "chats", "archive", group_id],
    );
    assert_eq!(archived["group"]["archived"], true);

    let visible = run_json(home.path(), &["--account", &bob, "chats", "list"]);
    assert_eq!(visible["chats"], serde_json::json!([]));

    let included = run_json(
        home.path(),
        &["--account", &bob, "chats", "list", "--include-archived"],
    );
    assert_eq!(included["chats"][0]["group_id"], group_id);
    assert_eq!(included["chats"][0]["archived"], true);

    let bob_members = run_json(
        home.path(),
        &["--account", &bob, "group", "members", group_id],
    );
    assert_eq!(
        member_accounts(&bob_members),
        sorted_accounts([&alice, &bob])
    );

    let alice_chats = run_json(home.path(), &["--account", &alice, "chats", "list"]);
    assert_eq!(alice_chats["chats"][0]["archived"], false);

    let unarchived = run_json(
        home.path(),
        &["--account", &bob, "chats", "unarchive", group_id],
    );
    assert_eq!(unarchived["group"]["archived"], false);
    let visible = run_json(home.path(), &["--account", &bob, "chats", "list"]);
    assert_eq!(visible["chats"][0]["group_id"], group_id);
}

#[test]
fn local_group_message_workflow_runs_through_the_dm_contract() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");

    let bob_join = run_json(home.path(), &["--account", &bob, "sync"]);
    assert_eq!(bob_join["joined_groups"][0], group_id);

    run_json(
        home.path(),
        &[
            "--account",
            &alice,
            "message",
            "send",
            "--group",
            group_id,
            "hello",
            "bob",
        ],
    );

    let bob_sync = run_json(home.path(), &["--account", &bob, "sync"]);
    assert_eq!(bob_sync["messages"][0]["from"], alice);
    assert_eq!(bob_sync["messages"][0]["group_id"], group_id);
    assert_eq!(bob_sync["messages"][0]["plaintext"], "hello bob");

    let bob_messages = run_json(home.path(), &["--account", &bob, "message", "list"]);
    assert_eq!(bob_messages["messages"][0]["from"], alice);
    assert_eq!(bob_messages["messages"][0]["group_id"], group_id);
    assert_eq!(bob_messages["messages"][0]["plaintext"], "hello bob");
}

#[test]
fn cli_can_inspect_projected_groups_messages_and_status() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
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
    assert_eq!(created_group["admin_policy"]["component_id"], 0x8003);
    assert_eq!(
        created_group["admin_policy"]["component"],
        "marmot.group.admin-policy.v1"
    );
    assert_eq!(
        created_group["admin_policy"]["admins"],
        serde_json::json!([alice])
    );
    run_json(home.path(), &["--account", &bob, "sync"]);

    let chats = run_json(home.path(), &["--account", &bob, "chats", "list"]);
    assert_eq!(chats["chats"][0]["group_id"], group_id);
    assert_eq!(chats["chats"][0]["profile"]["name"], "general");
    assert_eq!(
        chats["chats"][0]["admin_policy"]["admins"],
        serde_json::json!([alice])
    );

    let group = run_json(home.path(), &["--account", &bob, "chats", "show", group_id]);
    assert_eq!(group["group"]["group_id"], group_id);
    assert_eq!(group["group"]["profile"]["name"], "general");

    let first_send = run_json(
        home.path(),
        &[
            "--account",
            &alice,
            "message",
            "send",
            "--group",
            group_id,
            "first",
        ],
    );
    let first_message_id = first_send["message_ids"][0].as_str().expect("message id");
    let alice_messages = run_json(home.path(), &["--account", &alice, "message", "list"]);
    assert_eq!(alice_messages["messages"].as_array().unwrap().len(), 1);
    assert_eq!(alice_messages["messages"][0]["direction"], "sent");
    assert_eq!(
        alice_messages["messages"][0]["message_id"],
        first_message_id
    );
    assert_eq!(alice_messages["messages"][0]["from"], alice);
    assert_eq!(alice_messages["messages"][0]["plaintext"], "first");

    run_json(home.path(), &["--account", &alice, "sync"]);
    let alice_messages_after_echo =
        run_json(home.path(), &["--account", &alice, "message", "list"]);
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
            &alice,
            "message",
            "send",
            "--group",
            group_id,
            "second",
        ],
    );
    assert!(second_send["message_ids"][0].as_str().is_some());
    run_json(home.path(), &["--account", &bob, "sync"]);

    let messages = run_json(
        home.path(),
        &[
            "--account",
            &bob,
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

    let status = run_json(home.path(), &["account", "status", &bob]);
    assert_eq!(status["counts"]["groups"], 1);
    assert_eq!(status["counts"]["messages"], 2);
    assert_eq!(status["secret_store"]["backend"], "file");
    assert_eq!(status["projections"]["account"]["exists"], true);
    assert_eq!(status["projections"]["account"]["encrypted"], true);
}

#[test]
fn group_update_publishes_profile_component_changes() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", &bob, "sync"]);

    let updated = run_json(
        home.path(),
        &[
            "--account",
            &alice,
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

    run_json(home.path(), &["--account", &bob, "sync"]);
    let bob_group = run_json(home.path(), &["--account", &bob, "chats", "show", group_id]);
    assert_eq!(bob_group["group"]["profile"]["name"], "team room");
    assert_eq!(
        bob_group["group"]["profile"]["description"],
        "daily coordination"
    );
}

#[test]
fn non_admin_group_mutations_return_admin_policy_errors() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    let carol = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);
    run_json(home.path(), &["--account", &carol, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", &bob, "sync"]);

    let invite_error = run_json_error(
        home.path(),
        &["--account", &bob, "group", "invite", group_id, &carol],
    );
    assert_eq!(invite_error["code"], "not_group_admin");

    let update_error = run_json_error(
        home.path(),
        &[
            "--account",
            &bob,
            "group",
            "update",
            group_id,
            "--name",
            "nope",
        ],
    );
    assert_eq!(update_error["code"], "not_group_admin");
}

#[test]
fn group_members_invite_and_remove_flow_updates_projected_members() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    let carol = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);
    run_json(home.path(), &["--account", &carol, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "general", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", &bob, "sync"]);

    let initial_members = run_json(
        home.path(),
        &["--account", &alice, "group", "members", group_id],
    );
    assert_eq!(
        member_accounts(&initial_members),
        sorted_accounts([&alice, &bob])
    );

    let invite = run_json(
        home.path(),
        &["--account", &alice, "group", "invite", group_id, &carol],
    );
    assert_eq!(invite["published"], 2);
    run_json(home.path(), &["--account", &carol, "sync"]);

    let invited_members = run_json(
        home.path(),
        &["--account", &alice, "group", "members", group_id],
    );
    assert_eq!(
        member_accounts(&invited_members),
        sorted_accounts([&alice, &bob, &carol])
    );

    run_json(
        home.path(),
        &[
            "--account",
            &alice,
            "message",
            "send",
            "--group",
            group_id,
            "history",
            "stays",
        ],
    );
    run_json(home.path(), &["--account", &bob, "sync"]);
    run_json(home.path(), &["--account", &carol, "sync"]);

    let remove = run_json(
        home.path(),
        &["--account", &alice, "group", "remove", group_id, &bob],
    );
    assert_eq!(remove["published"], 1);
    run_json(home.path(), &["--account", &bob, "sync"]);
    run_json(home.path(), &["--account", &carol, "sync"]);

    let alice_members = run_json(
        home.path(),
        &["--account", &alice, "group", "members", group_id],
    );
    assert_eq!(
        member_accounts(&alice_members),
        sorted_accounts([&alice, &carol])
    );

    let carol_members = run_json(
        home.path(),
        &["--account", &carol, "group", "members", group_id],
    );
    assert_eq!(
        member_accounts(&carol_members),
        sorted_accounts([&alice, &carol])
    );

    let bob_group = run_json(home.path(), &["--account", &bob, "chats", "show", group_id]);
    assert_eq!(bob_group["group"]["profile"]["name"], "general");
    let bob_members = run_json(
        home.path(),
        &["--account", &bob, "group", "members", group_id],
    );
    assert_eq!(
        member_accounts(&bob_members),
        sorted_accounts([&alice, &carol])
    );
    let bob_history = run_json(
        home.path(),
        &["--account", &bob, "message", "list", "--group", group_id],
    );
    assert_eq!(bob_history["messages"][0]["plaintext"], "history stays");
}

#[test]
fn three_user_message_lifecycle_covers_invite_remove_and_later_delivery() {
    let home = tempfile::tempdir().expect("tempdir");

    let alice = create_account(home.path());
    let bob = create_account(home.path());
    let carol = create_account(home.path());
    run_json(home.path(), &["--account", &bob, "keys", "publish"]);
    run_json(home.path(), &["--account", &carol, "keys", "publish"]);

    let created_group = run_json(
        home.path(),
        &["--account", &alice, "group", "create", "three-way", &bob],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["--account", &bob, "sync"]);

    run_json(
        home.path(),
        &[
            "--account",
            &alice,
            "message",
            "send",
            "--group",
            group_id,
            "before",
            "carol",
        ],
    );
    let bob_sync = run_json(home.path(), &["--account", &bob, "sync"]);
    assert_message_plaintexts(&bob_sync, &["before carol"]);

    let invite = run_json(
        home.path(),
        &["--account", &alice, "group", "invite", group_id, &carol],
    );
    assert_eq!(invite["published"], 2);
    run_json(home.path(), &["--account", &bob, "sync"]);
    let carol_join = run_json(home.path(), &["--account", &carol, "sync"]);
    assert_eq!(carol_join["joined_groups"][0], group_id);

    run_json(
        home.path(),
        &[
            "--account",
            &carol,
            "message",
            "send",
            "--group",
            group_id,
            "carol",
            "joined",
        ],
    );
    let alice_after_carol = run_json(home.path(), &["--account", &alice, "sync"]);
    assert_message_plaintexts(&alice_after_carol, &["carol joined"]);
    let bob_after_carol = run_json(home.path(), &["--account", &bob, "sync"]);
    assert_message_plaintexts(&bob_after_carol, &["carol joined"]);

    let remove = run_json(
        home.path(),
        &["--account", &alice, "group", "remove", group_id, &bob],
    );
    assert_eq!(remove["published"], 1);
    run_json(home.path(), &["--account", &bob, "sync"]);
    run_json(home.path(), &["--account", &carol, "sync"]);

    run_json(
        home.path(),
        &[
            "--account",
            &carol,
            "message",
            "send",
            "--group",
            group_id,
            "after",
            "bob",
            "removed",
        ],
    );
    let alice_after_remove = run_json(home.path(), &["--account", &alice, "sync"]);
    assert_message_plaintexts(&alice_after_remove, &["after bob removed"]);
    let bob_after_remove = run_json(home.path(), &["--account", &bob, "sync"]);
    assert_no_message_plaintext(&bob_after_remove, "after bob removed");

    let bob_messages = run_json(
        home.path(),
        &["--account", &bob, "message", "list", "--group", group_id],
    );
    assert_message_plaintexts(&bob_messages, &["before carol", "carol joined"]);
    assert_no_message_plaintext(&bob_messages, "after bob removed");

    let bob_send_error = run_json_error(
        home.path(),
        &[
            "--account",
            &bob,
            "message",
            "send",
            "--group",
            group_id,
            "removed",
            "sender",
        ],
    );
    assert_eq!(bob_send_error["code"], "engine_error");
}

#[test]
fn real_local_relays_deliver_cli_messages_over_sdk_path() {
    let relays = real_relay_urls();
    let available_relays = relays
        .iter()
        .filter(|relay| local_relay_available(relay))
        .collect::<Vec<_>>();
    if available_relays.is_empty() {
        assert!(
            !require_real_relays(),
            "real relay CLI E2E requires one of these relays to be reachable: {relays:?}"
        );
        eprintln!("skipping real relay CLI E2E: no local relay ports are reachable");
        return;
    }

    for relay in available_relays {
        let relay = relay.as_str();
        let home = tempfile::tempdir().expect("tempdir");
        let alice = create_account_with_real_relay(home.path(), relay);
        let bob = create_account_with_real_relay(home.path(), relay);
        run_json_with_relay(home.path(), relay, &["--account", &bob, "keys", "publish"]);

        let group_name = format!(
            "real-relay-{}",
            relay.rsplit(':').next().unwrap_or("unknown")
        );
        let created_group = run_json_with_relay(
            home.path(),
            relay,
            &["--account", &alice, "group", "create", &group_name, &bob],
        );
        let group_id = created_group["group_id"].as_str().expect("group id");

        let bob_join = sync_until_joined(home.path(), relay, &bob, group_id);
        assert_eq!(bob_join["joined_groups"][0], group_id);

        let body = format!("hello over {relay}");
        run_json_with_relay(
            home.path(),
            relay,
            &[
                "--account",
                &alice,
                "message",
                "send",
                "--group",
                group_id,
                &body,
            ],
        );
        let bob_sync = sync_until_message(home.path(), relay, &bob, &body);
        assert_message_plaintexts(&bob_sync, &[&body]);

        let bob_messages = run_json_with_relay(
            home.path(),
            relay,
            &["--account", &bob, "message", "list", "--group", group_id],
        );
        assert_message_plaintexts(&bob_messages, &[&body]);
    }
}
