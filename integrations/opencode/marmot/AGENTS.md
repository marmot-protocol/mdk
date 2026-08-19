# AGENTS.md - integrations/opencode/marmot

Rust opencode harness for Marmot through the local `wn-agent` control socket.
Read `README.md`, `../../AGENTS.md`, and `../../terminal-harness/AGENTS.md` first.

## Scope

- A dedicated **control-plane-only** harness. `wn-agent` owns the Marmot account, MLS state, Nostr transport, durable
  sends, and allowlist-backed invite handling; this crate only speaks `marmot.agent-control.v2` over the local Unix
  socket and runs `opencode`.
- Every message from an allowed sender is treated as a prompt. This is intentionally a pure harness, not a gateway
  plugin with mention activation, media handling, profile onboarding, or live previews.
- No QUIC, crypto, relay, or MLS logic here.
- Split large opencode text events into byte-budgeted Marmot messages. Keep the default below the Marmot message cap:
  `WN_OPENCODE_MAX_REPLY_BYTES=30000`.
- Privacy-safe logging only: no account ids, group ids, message ids, pubkeys, relay URLs, payloads, ciphertext,
  plaintext, local paths, or key material.

## Key Files

- `src/main.rs` - binary entrypoint, CLI help, tracing setup.
- `src/opencode.rs` - `opencode run --format json` process execution and event parsing.
- `src/config.rs` - OpenCode-specific environment configuration and shared runtime wiring.
- `tests/e2e_connector.rs` - ignored process-level test using real `wn-agent` and a fake OpenCode executable.
- `tests/test_installer.sh` - OpenCode entrypoint for the shared terminal-harness installer test suite.
- `scripts/install-opencode-marmot.sh` - release-installer wrapper over the shared terminal-harness installer.

## Rules

- Do not add gateway behaviors here unless the product direction changes; Hermes/OpenClaw own gateway integrations.
- Keep shared control, queueing, chunking, workdir, session-map, and process lifecycle behavior in
  `integrations/terminal-harness`; keep only OpenCode command/event behavior here.
- Keep state files restrictive-by-construction through `fs-private` or an equivalent mode-tested path.
- Keep opencode prompts on stdin and out of process arguments. The supported
  minimum OpenCode version is 1.18.18, whose non-interactive `run` path consumes
  piped stdin when no message argument is present.

## Verification

```sh
cargo test -p wn-opencode
cargo fmt --check -p wn-opencode
cargo clippy -p wn-opencode --all-targets -- -D warnings
bash -n scripts/install-opencode-marmot.sh scripts/install-terminal-harness-marmot.sh
just opencode-dev-e2e-connector
just opencode-installer-test
```
