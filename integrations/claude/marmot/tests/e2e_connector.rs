#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use marmot_terminal_harness::test_support::{
    HarnessContext, MAX_REPLY_BYTES, SENDER_ACCOUNT_ID_HEX, SpawnedChild, run_connector_resume_e2e,
};

#[tokio::test]
#[ignore = "spawns real wn-agent and wn-claude processes"]
async fn debug_inbound_reaches_fake_claude_and_records_chunked_finals() {
    run_connector_resume_e2e("wn-claude", spawn_wn_claude).await;
}

fn spawn_wn_claude(context: HarnessContext<'_>) -> SpawnedChild {
    let fake_claude = write_fake_claude(context.root);
    let mut command = Command::new(env!("CARGO_BIN_EXE_wn-claude"));
    command
        .env("MARMOT_HOME", context.root.join("wn-claude-home"))
        .env("MARMOT_AGENT_SOCKET", context.socket)
        .env("WN_CLAUDE_ACCOUNT_ID_HEX", context.account_id_hex)
        .env("WN_CLAUDE_ALLOWED_SENDERS_HEX", SENDER_ACCOUNT_ID_HEX)
        .env("WN_CLAUDE_BIN", fake_claude)
        .env("MARMOT_HARNESS_EXECUTION_PROFILE", "inherit")
        .env(
            "WN_CLAUDE_STATE_PATH",
            context.root.join("wn-claude-state/sessions.json"),
        )
        .env("WN_CLAUDE_MAX_REPLY_BYTES", MAX_REPLY_BYTES.to_string())
        .env("WN_CLAUDE_TIMEOUT_SECS", "5")
        .env("WN_CLAUDE_REQUEST_TIMEOUT_SECS", "5")
        .env("RUST_LOG", "warn,marmot_terminal_harness=info");
    SpawnedChild::spawn("wn-claude", &mut command, context.root)
}

fn write_fake_claude(root: &Path) -> PathBuf {
    let script = root.join("fake-claude");
    fs::write(
        &script,
        r#"#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then
  printf '%s\n' '2.1.270 (Claude Code)'
  exit 0
fi
if [ "$#" -ne 6 ] || [ "$1" != "-p" ] || [ "$2" != "--output-format" ] || [ "$3" != "stream-json" ] || [ "$4" != "--verbose" ]; then
  echo "unexpected Claude args: $*" >&2
  exit 64
fi
case "$5" in
  --session-id) mode=new ;;
  --resume) mode=resume ;;
  *) echo "missing explicit Claude session selector" >&2; exit 64 ;;
esac
session="$6"
if [[ ! "$session" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo "invalid Claude session UUID" >&2
  exit 64
fi
prompt="$(cat)"
printf '{"type":"system","subtype":"init","session_id":"%s"}\n' "$session"
if [ "$mode" = resume ]; then
  printf '{"type":"assistant","parent_tool_use_id":null,"message":{"role":"assistant","content":[{"type":"thinking","thinking":"ignore"},{"type":"text","text":"marmot-e2e-resume-ok: %s"},{"type":"tool_use","name":"Read"}]}}\n' "$prompt"
  printf '{"type":"result","subtype":"success","is_error":false,"result":"marmot-e2e-resume-ok: %s","session_id":"%s"}\n' "$prompt" "$session"
  exit 0
fi
tail=""
for _ in $(seq 1 40); do
  tail="${tail}chunk "
done
printf '{"type":"assistant","parent_tool_use_id":null,"message":{"role":"assistant","content":[{"type":"thinking","thinking":"ignore"},{"type":"text","text":"marmot-e2e-ok: %s %s"},{"type":"tool_use","name":"Read"}]}}\n' "$prompt" "$tail"
printf '{"type":"result","subtype":"success","is_error":false,"result":"marmot-e2e-ok: %s %s","session_id":"%s"}\n' "$prompt" "$tail" "$session"
"#,
    )
    .expect("write fake Claude Code");
    let mut permissions = fs::metadata(&script)
        .expect("fake Claude metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).expect("chmod fake Claude");
    script
}
