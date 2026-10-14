#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use marmot_terminal_harness::test_support::{
    HarnessContext, MAX_REPLY_BYTES, SENDER_ACCOUNT_ID_HEX, SpawnedChild,
    run_connector_reset_replay_e2e, run_connector_resume_e2e,
};

#[tokio::test]
#[ignore = "spawns real wn-agent and wn-goose processes"]
async fn debug_inbound_reaches_fake_goose_and_records_chunked_finals() {
    run_connector_resume_e2e("wn-goose", spawn_wn_goose).await;
}

#[tokio::test]
#[ignore = "spawns real wn-agent and wn-goose processes"]
async fn reset_replay_after_restart_preserves_the_newer_goose_session() {
    run_connector_reset_replay_e2e(
        "wn-goose",
        "Goose",
        "wn-goose-state/sessions.json",
        spawn_wn_goose,
    )
    .await;
}

fn spawn_wn_goose(context: HarnessContext<'_>) -> SpawnedChild {
    let fake_goose = write_fake_goose(context.root);
    let mut command = Command::new(env!("CARGO_BIN_EXE_wn-goose"));
    command
        .env("MARMOT_HOME", context.root.join("wn-goose-home"))
        .env("MARMOT_AGENT_SOCKET", context.socket)
        .env("WN_GOOSE_ACCOUNT_ID_HEX", context.account_id_hex)
        .env("WN_GOOSE_ALLOWED_SENDERS_HEX", SENDER_ACCOUNT_ID_HEX)
        .env("WN_GOOSE_BIN", fake_goose)
        .env("WN_GOOSE_PATH_ROOT", context.root.join("goose-root"))
        .env("MARMOT_HARNESS_EXECUTION_PROFILE", "inherit")
        .env(
            "WN_GOOSE_STATE_PATH",
            context.root.join("wn-goose-state/sessions.json"),
        )
        .env("WN_GOOSE_MAX_REPLY_BYTES", MAX_REPLY_BYTES.to_string())
        .env("WN_GOOSE_TIMEOUT_SECS", "5")
        .env("WN_GOOSE_REQUEST_TIMEOUT_SECS", "5")
        .env("RUST_LOG", "warn,marmot_terminal_harness=info");
    SpawnedChild::spawn("wn-goose", &mut command, context.root)
}

/// Mimics Goose's named-session contract: `--name` without `--resume` creates a session,
/// and `--resume --name` fails before streaming when the name is unknown.
fn write_fake_goose(root: &Path) -> PathBuf {
    let script = root.join("fake-goose");
    fs::write(
        &script,
        r#"#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then
  printf '%s\n' ' 1.53.0'
  exit 0
fi
if [ "$1" != run ] || [ "$2" != --instructions ] || [ "$3" != - ] || [ "$4" != --output-format ] || [ "$5" != stream-json ] || [ "$6" != --quiet ]; then
  echo "unexpected Goose args: $*" >&2
  exit 64
fi
shift 6
mode=new
if [ "${1:-}" = --resume ]; then
  mode=resume
  shift
fi
if [ "$#" -ne 2 ] || [ "$1" != --name ]; then
  echo "missing explicit Goose session name" >&2
  exit 64
fi
session="$2"
if [[ ! "$session" =~ ^wn-goose-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo "invalid Goose session name" >&2
  exit 64
fi
if [ -z "${GOOSE_PATH_ROOT:-}" ]; then
  echo "GOOSE_PATH_ROOT was not forwarded" >&2
  exit 64
fi
sessions="$GOOSE_PATH_ROOT/sessions"
mkdir -p "$sessions"
if [ "$mode" = resume ]; then
  if [ ! -e "$sessions/$session" ]; then
    echo "Error: No session found with name '$session'" >&2
    exit 1
  fi
else
  touch "$sessions/$session"
fi
prompt="$(cat)"
emit() {
  printf '{"type":"message","message":{"id":"%s","role":"%s","created":1,"content":%s,"metadata":{"userVisible":true,"agentVisible":true}}}\n' "$1" "$2" "$3"
}
emit m0 assistant '[{"type":"thinking","thinking":"ignore","signature":""}]'
if [ "$mode" = resume ]; then
  emit m1 assistant "[{\"type\":\"text\",\"text\":\"marmot-e2e-resume-ok: \"}]"
  emit m1 assistant "[{\"type\":\"text\",\"text\":\"$prompt\"}]"
  emit m1 assistant '[{"type":"toolRequest","id":"t1"}]'
  printf '%s\n' '{"type":"complete","total_tokens":1}'
  exit 0
fi
tail=""
for _ in $(seq 1 40); do
  tail="${tail}chunk "
done
emit m1 assistant "[{\"type\":\"text\",\"text\":\"marmot-e2e-ok: $prompt \"}]"
emit m1 assistant "[{\"type\":\"text\",\"text\":\"$tail\"}]"
emit m2 user '[{"type":"toolResponse","id":"t1"}]'
printf '%s\n' '{"type":"notification","extension_id":"developer","log":{"message":"ignore"}}'
printf '%s\n' '{"type":"complete","total_tokens":1}'
"#,
    )
    .expect("write fake Goose");
    let mut permissions = fs::metadata(&script)
        .expect("fake Goose metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).expect("chmod fake Goose");
    script
}
