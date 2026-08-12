#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use marmot_terminal_harness::test_support::{
    HarnessContext, MAX_REPLY_BYTES, SENDER_ACCOUNT_ID_HEX, SpawnedChild, run_connector_e2e,
};

#[tokio::test]
#[ignore = "spawns real wn-agent and wn-pi processes"]
async fn debug_inbound_reaches_fake_pi_and_records_chunked_finals() {
    run_connector_e2e("wn-pi", spawn_wn_pi).await;
}

fn spawn_wn_pi(context: HarnessContext<'_>) -> SpawnedChild {
    let fake_pi = write_fake_pi(context.root);
    let mut command = Command::new(env!("CARGO_BIN_EXE_wn-pi"));
    command
        .env("MARMOT_HOME", context.root.join("wn-pi-home"))
        .env("MARMOT_AGENT_SOCKET", context.socket)
        .env("WN_PI_ACCOUNT_ID_HEX", context.account_id_hex)
        .env("WN_PI_ALLOWED_SENDERS_HEX", SENDER_ACCOUNT_ID_HEX)
        .env("WN_PI_BIN", fake_pi)
        .env(
            "WN_PI_STATE_PATH",
            context.root.join("wn-pi-state/sessions.json"),
        )
        .env("WN_PI_MAX_REPLY_BYTES", MAX_REPLY_BYTES.to_string())
        .env("WN_PI_TIMEOUT_SECS", "5")
        .env("WN_PI_REQUEST_TIMEOUT_SECS", "5")
        .env("RUST_LOG", "warn,marmot_terminal_harness=info");
    SpawnedChild::spawn("wn-pi", &mut command, context.root)
}

fn write_fake_pi(root: &Path) -> PathBuf {
    let script = root.join("fake-pi");
    fs::write(
        &script,
        r#"#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" != "--mode" ] || [ "${2:-}" != "json" ]; then
  echo "unexpected pi args: $*" >&2
  exit 64
fi
prompt="$(cat)"
tail=""
for _ in $(seq 1 40); do
  tail="${tail}chunk "
done
printf '%s\n' '{"type":"session","version":3,"id":"ses_e2e","cwd":"/tmp"}'
printf '{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"marmot-e2e-ok: %s %s"}],"stopReason":"stop"}}\n' "$prompt" "$tail"
"#,
    )
    .expect("write fake pi");
    let mut permissions = fs::metadata(&script)
        .expect("fake pi metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).expect("chmod fake pi");
    script
}
