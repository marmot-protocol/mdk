# AGENTS.md - integrations/opencode/marmot

Rust opencode harness for Marmot through the local `wn-agent` control socket.
Read `README.md` first.

## Scope

- A dedicated **control-plane-only** harness. `wn-agent` owns the Marmot account, MLS state, Nostr transport, durable
  sends, and allowlist-backed invite handling; this crate only speaks `marmot.agent-control.v1` over the local Unix
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
- `src/bridge.rs` - startup, inbound subscription/reconnect, allowlist mirroring, per-group queueing, durable replies.
- `src/control.rs` - agent-control request/response client and inbound subscription stream.
- `src/opencode.rs` - `opencode run --format json` process execution and event parsing.
- `src/chunking.rs` - UTF-8 byte-budgeted reply chunking.
- `src/store.rs` - private session mapping persistence.
- `src/config.rs` - environment configuration.
- `scripts/install-opencode-marmot.sh` - release installer.

## Rules

- Do not add gateway behaviors here unless the product direction changes; Hermes/OpenClaw own gateway integrations.
- Keep request/response validation strict: protocol tag, response id, response type, and non-empty `FinalSent` ids.
- Keep state files restrictive-by-construction through `fs-private` or an equivalent mode-tested path.
- Keep opencode prompts after a `--` delimiter so prompt text cannot be parsed as `opencode run` flags.

## Verification

```sh
cargo test -p wn-opencode
cargo fmt --check -p wn-opencode
cargo clippy -p wn-opencode --all-targets -- -D warnings
bash -n scripts/install-opencode-marmot.sh
integrations/opencode/marmot/tests/test_installer.sh
```
