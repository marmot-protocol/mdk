use std::process::Command;

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

    let published = run_json(home.path(), &["key-package", "publish", "--account", "bob"]);
    let published_bytes = published["key_package_bytes"].as_u64().expect("bytes");
    assert!(published_bytes > 0);

    let fetched = run_json(
        home.path(),
        &[
            "key-package",
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
fn directory_caches_relay_lists_and_key_packages_for_pubkeys() {
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

    let refreshed = run_json(
        home.path(),
        &[
            "directory",
            "refresh",
            "--pubkey",
            account_id,
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );
    assert_eq!(refreshed["account_id"], account_id);
    assert_eq!(refreshed["relay_lists"]["complete"], true);
    assert_eq!(refreshed["key_package"], serde_json::Value::Null);

    let cached = run_json(home.path(), &["directory", "get", "--pubkey", account_id]);
    assert_eq!(cached, refreshed);

    let published = run_json(home.path(), &["key-package", "publish", "--account", "bob"]);
    let fetched = run_json(
        home.path(),
        &[
            "key-package",
            "fetch",
            "--pubkey",
            account_id,
            "--bootstrap-relays",
            "marmot-local://seed",
        ],
    );
    assert_eq!(
        fetched["key_package_bytes"], published["key_package_bytes"],
        "fetched package should be the one that was just published"
    );

    let cached = run_json(home.path(), &["directory", "get", "--pubkey", account_id]);
    assert_eq!(cached["account_id"], account_id);
    assert_eq!(
        cached["key_package"]["bytes"],
        published["key_package_bytes"]
    );
    assert_eq!(
        cached["key_package"]["source_relays"],
        serde_json::json!(["marmot-local://key-packages"])
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
            "group",
            "create",
            "--account",
            "alice",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );

    assert_eq!(error["code"], "missing_key_package");
    assert_eq!(error["account"], "bob");
    assert_eq!(
        error["repair"]["local"],
        "dm key-package publish --account bob"
    );
}

#[test]
fn group_create_can_invite_a_member_from_the_directory_by_pubkey() {
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

    run_json(home.path(), &["key-package", "publish", "--account", "bob"]);
    run_json(
        home.path(),
        &[
            "key-package",
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
            "group",
            "create",
            "--account",
            "alice",
            "--name",
            "directory",
            "--member",
            bob_account_id,
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");

    let bob_join = run_json(home.path(), &["sync", "--account", "bob"]);
    assert_eq!(bob_join["joined_groups"][0], group_id);
}

#[test]
fn group_archive_is_local_state_not_membership_state() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["key-package", "publish", "--account", "bob"]);

    let created_group = run_json(
        home.path(),
        &[
            "group",
            "create",
            "--account",
            "alice",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["sync", "--account", "bob"]);

    let archived = run_json(
        home.path(),
        &["group", "archive", "--account", "bob", group_id],
    );
    assert_eq!(archived["group"]["archived"], true);

    let visible = run_json(home.path(), &["group", "list", "--account", "bob"]);
    assert_eq!(visible["groups"], serde_json::json!([]));

    let included = run_json(
        home.path(),
        &["group", "list", "--account", "bob", "--include-archived"],
    );
    assert_eq!(included["groups"][0]["group_id"], group_id);
    assert_eq!(included["groups"][0]["archived"], true);

    let bob_members = run_json(
        home.path(),
        &["group", "members", "--account", "bob", group_id],
    );
    assert_eq!(member_accounts(&bob_members), vec!["alice", "bob"]);

    let alice_groups = run_json(home.path(), &["group", "list", "--account", "alice"]);
    assert_eq!(alice_groups["groups"][0]["archived"], false);

    let unarchived = run_json(
        home.path(),
        &["group", "unarchive", "--account", "bob", group_id],
    );
    assert_eq!(unarchived["group"]["archived"], false);
    let visible = run_json(home.path(), &["group", "list", "--account", "bob"]);
    assert_eq!(visible["groups"][0]["group_id"], group_id);
}

#[test]
fn local_group_message_workflow_runs_through_the_dm_contract() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["key-package", "publish", "--account", "bob"]);

    let created_group = run_json(
        home.path(),
        &[
            "group",
            "create",
            "--account",
            "alice",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");

    let bob_join = run_json(home.path(), &["sync", "--account", "bob"]);
    assert_eq!(bob_join["joined_groups"][0], group_id);

    run_json(
        home.path(),
        &[
            "message",
            "send",
            "--account",
            "alice",
            "--group",
            group_id,
            "hello",
            "bob",
        ],
    );

    let bob_sync = run_json(home.path(), &["sync", "--account", "bob"]);
    assert_eq!(bob_sync["messages"][0]["from"], "alice");
    assert_eq!(bob_sync["messages"][0]["group_id"], group_id);
    assert_eq!(bob_sync["messages"][0]["plaintext"], "hello bob");

    let bob_messages = run_json(home.path(), &["message", "list", "--account", "bob"]);
    assert_eq!(bob_messages["messages"][0]["from"], "alice");
    assert_eq!(bob_messages["messages"][0]["group_id"], group_id);
    assert_eq!(bob_messages["messages"][0]["plaintext"], "hello bob");
}

#[test]
fn cli_can_inspect_projected_groups_messages_and_status() {
    let home = tempfile::tempdir().expect("tempdir");

    run_json(home.path(), &["account", "create", "alice"]);
    run_json(home.path(), &["account", "create", "bob"]);
    run_json(home.path(), &["key-package", "publish", "--account", "bob"]);

    let created_group = run_json(
        home.path(),
        &[
            "group",
            "create",
            "--account",
            "alice",
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
    run_json(home.path(), &["sync", "--account", "bob"]);

    let groups = run_json(home.path(), &["group", "list", "--account", "bob"]);
    assert_eq!(groups["groups"][0]["group_id"], group_id);
    assert_eq!(groups["groups"][0]["profile"]["name"], "general");

    let group = run_json(
        home.path(),
        &["group", "show", "--account", "bob", group_id],
    );
    assert_eq!(group["group"]["group_id"], group_id);
    assert_eq!(group["group"]["profile"]["name"], "general");

    let first_send = run_json(
        home.path(),
        &[
            "message",
            "send",
            "--account",
            "alice",
            "--group",
            group_id,
            "first",
        ],
    );
    let first_message_id = first_send["message_ids"][0].as_str().expect("message id");
    let alice_messages = run_json(home.path(), &["message", "list", "--account", "alice"]);
    assert_eq!(alice_messages["messages"].as_array().unwrap().len(), 1);
    assert_eq!(alice_messages["messages"][0]["direction"], "sent");
    assert_eq!(
        alice_messages["messages"][0]["message_id"],
        first_message_id
    );
    assert_eq!(alice_messages["messages"][0]["from"], "alice");
    assert_eq!(alice_messages["messages"][0]["plaintext"], "first");

    run_json(home.path(), &["sync", "--account", "alice"]);
    let alice_messages_after_echo =
        run_json(home.path(), &["message", "list", "--account", "alice"]);
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
            "message",
            "send",
            "--account",
            "alice",
            "--group",
            group_id,
            "second",
        ],
    );
    assert!(second_send["message_ids"][0].as_str().is_some());
    run_json(home.path(), &["sync", "--account", "bob"]);

    let messages = run_json(
        home.path(),
        &[
            "message",
            "list",
            "--account",
            "bob",
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
    run_json(home.path(), &["key-package", "publish", "--account", "bob"]);

    let created_group = run_json(
        home.path(),
        &[
            "group",
            "create",
            "--account",
            "alice",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["sync", "--account", "bob"]);

    let updated = run_json(
        home.path(),
        &[
            "group",
            "update",
            "--account",
            "alice",
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

    run_json(home.path(), &["sync", "--account", "bob"]);
    let bob_group = run_json(
        home.path(),
        &["group", "show", "--account", "bob", group_id],
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
    run_json(home.path(), &["key-package", "publish", "--account", "bob"]);
    run_json(
        home.path(),
        &["key-package", "publish", "--account", "carol"],
    );

    let created_group = run_json(
        home.path(),
        &[
            "group",
            "create",
            "--account",
            "alice",
            "--name",
            "general",
            "--member",
            "bob",
        ],
    );
    let group_id = created_group["group_id"].as_str().expect("group id");
    run_json(home.path(), &["sync", "--account", "bob"]);

    let initial_members = run_json(
        home.path(),
        &["group", "members", "--account", "alice", group_id],
    );
    assert_eq!(member_accounts(&initial_members), vec!["alice", "bob"]);

    let invite = run_json(
        home.path(),
        &[
            "group",
            "invite",
            "--account",
            "alice",
            group_id,
            "--member",
            "carol",
        ],
    );
    assert_eq!(invite["published"], 2);
    run_json(home.path(), &["sync", "--account", "carol"]);

    let invited_members = run_json(
        home.path(),
        &["group", "members", "--account", "alice", group_id],
    );
    assert_eq!(
        member_accounts(&invited_members),
        vec!["alice", "bob", "carol"]
    );

    run_json(
        home.path(),
        &[
            "message",
            "send",
            "--account",
            "alice",
            "--group",
            group_id,
            "history",
            "stays",
        ],
    );
    run_json(home.path(), &["sync", "--account", "bob"]);
    run_json(home.path(), &["sync", "--account", "carol"]);

    let remove = run_json(
        home.path(),
        &[
            "group",
            "remove",
            "--account",
            "alice",
            group_id,
            "--member",
            "bob",
        ],
    );
    assert_eq!(remove["published"], 1);
    run_json(home.path(), &["sync", "--account", "bob"]);
    run_json(home.path(), &["sync", "--account", "carol"]);

    let alice_members = run_json(
        home.path(),
        &["group", "members", "--account", "alice", group_id],
    );
    assert_eq!(member_accounts(&alice_members), vec!["alice", "carol"]);

    let carol_members = run_json(
        home.path(),
        &["group", "members", "--account", "carol", group_id],
    );
    assert_eq!(member_accounts(&carol_members), vec!["alice", "carol"]);

    let bob_group = run_json(
        home.path(),
        &["group", "show", "--account", "bob", group_id],
    );
    assert_eq!(bob_group["group"]["profile"]["name"], "general");
    let bob_members = run_json(
        home.path(),
        &["group", "members", "--account", "bob", group_id],
    );
    assert_eq!(member_accounts(&bob_members), vec!["alice", "carol"]);
    let bob_history = run_json(
        home.path(),
        &["message", "list", "--account", "bob", "--group", group_id],
    );
    assert_eq!(bob_history["messages"][0]["plaintext"], "history stays");
}
