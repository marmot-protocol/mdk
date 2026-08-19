#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use marmot_terminal_harness::test_support::{
    HarnessContext, MAX_REPLY_BYTES, SENDER_ACCOUNT_ID_HEX, SpawnedChild, run_connector_resume_e2e,
};

#[tokio::test]
#[ignore = "spawns real wn-agent and wn-codex processes"]
async fn debug_inbound_reaches_fake_codex_and_records_chunked_finals() {
    run_connector_resume_e2e("wn-codex", spawn_wn_codex).await;
}

fn spawn_wn_codex(context: HarnessContext<'_>) -> SpawnedChild {
    let fake_codex = write_fake_codex(context.root);
    let mut command = Command::new(env!("CARGO_BIN_EXE_wn-codex"));
    command
        .env("MARMOT_HOME", context.root.join("wn-codex-home"))
        .env("MARMOT_AGENT_SOCKET", context.socket)
        .env("WN_CODEX_ACCOUNT_ID_HEX", context.account_id_hex)
        .env("WN_CODEX_ALLOWED_SENDERS_HEX", SENDER_ACCOUNT_ID_HEX)
        .env("WN_CODEX_BIN", fake_codex)
        .env(
            "WN_CODEX_STATE_PATH",
            context.root.join("wn-codex-state/sessions.json"),
        )
        .env("WN_CODEX_MAX_REPLY_BYTES", MAX_REPLY_BYTES.to_string())
        .env("WN_CODEX_TIMEOUT_SECS", "5")
        .env("WN_CODEX_REQUEST_TIMEOUT_SECS", "5")
        .env("RUST_LOG", "warn,marmot_terminal_harness=info");
    SpawnedChild::spawn("wn-codex", &mut command, context.root)
}

fn write_fake_codex(root: &Path) -> PathBuf {
    let script = root.join("fake-codex");
    fs::write(
        &script,
        r#"#!/usr/bin/env bash
set -euo pipefail
mode=""
if [ "$#" -eq 3 ] && [ "$1" = "exec" ] && [ "$2" = "--json" ] && [ "$3" = "-" ]; then
  mode="new"
elif [ "$#" -eq 5 ] && [ "$1" = "exec" ] && [ "$2" = "resume" ] && [ "$3" = "--json" ] && [ "$4" = "thread_e2e" ] && [ "$5" = "-" ]; then
  mode="resume"
else
  echo "unexpected codex args: $*" >&2
  exit 64
fi
prompt="$(cat)"
if [ "$mode" = "resume" ]; then
  printf '%s\n' '{"type":"thread.started","thread_id":"thread_e2e"}'
  printf '{"type":"item.completed","item":{"type":"agent_message","text":"marmot-e2e-resume-ok: %s"}}\n' "$prompt"
  exit 0
fi
tail=""
for _ in $(seq 1 40); do
  tail="${tail}chunk "
done
printf '%s\n' '{"type":"thread.started","thread_id":"thread_e2e"}'
printf '%s\n' '{"type":"item.completed","item":{"type":"reasoning","text":"ignore"}}'
printf '{"type":"item.completed","item":{"type":"agent_message","text":"marmot-e2e-ok: %s %s"}}\n' "$prompt" "$tail"
"#,
    )
    .expect("write fake codex");
    let mut permissions = fs::metadata(&script)
        .expect("fake codex metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).expect("chmod fake codex");
    script
}
