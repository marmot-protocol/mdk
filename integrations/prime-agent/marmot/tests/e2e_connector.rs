#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use marmot_terminal_harness::test_support::{
    HarnessContext, MAX_REPLY_BYTES, SENDER_ACCOUNT_ID_HEX, SpawnedChild, run_connector_resume_e2e,
};

fn spawn_prime_harness(context: HarnessContext) -> SpawnedChild {
    let wrapper = context.root.join("fake-prime-agent");
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-prime-agent.py");
    fs::write(
        &wrapper,
        format!("#!/bin/sh\nexec python3 '{}' \"$@\"\n", fixture.display()),
    )
    .expect("write fake Prime Agent wrapper");
    let mut permissions = fs::metadata(&wrapper).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&wrapper, permissions).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_wn-prime-agent"));
    command
        .env("MARMOT_AGENT_SOCKET", context.socket)
        .env("MARMOT_HOME", context.root.join("prime-home"))
        .env(
            "WN_PRIME_AGENT_STATE_PATH",
            context.root.join("prime-state.json"),
        )
        .env("WN_PRIME_AGENT_BIN", &wrapper)
        .env(
            "WN_PRIME_AGENT_DAEMON_SOCKET",
            context.root.join("prime.sock"),
        )
        .env(
            "WN_PRIME_AGENT_MAX_REPLY_BYTES",
            MAX_REPLY_BYTES.to_string(),
        )
        // Non-empty candidates exercise StreamBegin/Append/Finalize. The invalid
        // candidate deliberately selects wn-agent's no-live-broker compose path.
        .env("MARMOT_QUIC_CANDIDATES", "not-a-quic-candidate")
        .env("WN_PRIME_AGENT_ACCOUNT_ID_HEX", context.account_id_hex)
        .env("WN_PRIME_AGENT_ALLOWED_SENDERS_HEX", SENDER_ACCOUNT_ID_HEX);
    SpawnedChild::spawn("wn-prime-agent", &mut command, context.root)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the real wn-agent binary and runs a local multi-client connector flow"]
async fn prompt_streams_preview_and_publishes_durable_final() {
    run_connector_resume_e2e("wn-prime-agent", spawn_prime_harness).await;
}
