#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use marmot_terminal_harness::test_support::{
    HarnessContext, MAX_REPLY_BYTES, SENDER_ACCOUNT_ID_HEX, SpawnedChild, run_connector_e2e,
};

#[tokio::test]
#[ignore = "spawns real wn-agent and wn-opencode processes"]
async fn debug_inbound_reaches_fake_opencode_and_records_chunked_finals() {
    run_connector_e2e("wn-opencode", spawn_wn_opencode).await;
}

fn spawn_wn_opencode(context: HarnessContext<'_>) -> SpawnedChild {
    let fake_opencode = write_fake_opencode(context.root);
    let mut command = Command::new(env!("CARGO_BIN_EXE_wn-opencode"));
    command
        .env("MARMOT_AGENT_SOCKET", context.socket)
        .env("WN_OPENCODE_ACCOUNT_ID_HEX", context.account_id_hex)
        .env("WN_OPENCODE_ALLOWED_SENDERS_HEX", SENDER_ACCOUNT_ID_HEX)
        .env("WN_OPENCODE_BIN", fake_opencode)
        .env(
            "WN_OPENCODE_STATE_PATH",
            context.root.join("wn-opencode-state/sessions.json"),
        )
        .env("WN_OPENCODE_MAX_REPLY_BYTES", MAX_REPLY_BYTES.to_string())
        .env("WN_OPENCODE_TIMEOUT_SECS", "5")
        .env("WN_OPENCODE_REQUEST_TIMEOUT_SECS", "5")
        .env("RUST_LOG", "warn,marmot_terminal_harness=info");
    SpawnedChild::spawn("wn-opencode", &mut command, context.root)
}

fn write_fake_opencode(root: &Path) -> PathBuf {
    let script = root.join("fake-opencode");
    fs::write(
        &script,
        r#"#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" != "run" ] || [ "${2:-}" != "--format" ] || [ "${3:-}" != "json" ]; then
  echo "unexpected opencode args: $*" >&2
  exit 64
fi
shift 3
if [ "$#" -ne 0 ]; then
  echo "prompt or unexpected option exposed in opencode args: $*" >&2
  exit 64
fi
prompt="$(cat)"
tail=""
for _ in $(seq 1 40); do
  tail="${tail}chunk "
done
printf '%s\n' '{"type":"step_start","sessionID":"ses_e2e"}'
printf '{"type":"text","part":{"text":"marmot-e2e-ok: %s %s"}}\n' "$prompt" "$tail"
"#,
    )
    .expect("write fake opencode");
    let mut permissions = fs::metadata(&script)
        .expect("fake opencode metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).expect("chmod fake opencode");
    script
}
