# AGENTS.md - integrations/codex/marmot

Rust Codex harness for Marmot through the local `wn-agent` control socket. Read
`README.md`, `../../AGENTS.md`, and `../../terminal-harness/AGENTS.md` first.

## Scope

- A control-plane-only harness. `wn-agent` owns Marmot state, MLS, Nostr,
  durable sends, and invite handling; this crate invokes Codex and parses its
  JSONL event stream.
- Every message from an allowed sender is a prompt. Do not add gateway,
  mention-activation, media, profile, or QUIC preview behavior here.
- Send prompts over stdin, emit only completed `agent_message` text, and never
  expose reasoning, command output, tool output, or partial items.
- Preserve the shared workdir/session mapping rules. One Marmot group maps to
  one Codex thread id and later prompts use `codex exec resume`.
- The CLI contract is `codex exec --json -` for a new thread and
  `codex exec resume --json <thread-id> -` for a resumed thread. Re-verify the
  official non-interactive-mode contract before changing invocation flags or
  JSON event parsing.

## Key Files

- `src/main.rs` - binary entrypoint, CLI help, tracing setup, and shared runtime wiring.
- `src/config.rs` - Codex-specific environment configuration.
- `src/codex.rs` - Codex command construction, stdin prompting, JSONL parsing, and process lifecycle.
- `tests/e2e_connector.rs` - ignored process-level test using real `wn-agent` and a fake Codex executable.
- `tests/test_installer.sh` - Codex entrypoint for the shared terminal-harness installer test suite.
- `scripts/install-codex-marmot.sh` - release-installer wrapper over the shared terminal-harness installer.

## Rules

- Keep prompts on stdin; do not move prompt text into process arguments.
- Do not add `--full-auto`, `--dangerously-bypass-approvals-and-sandbox`, or
  connector-specific sandbox/approval overrides until the shared connector
  permission model is designed.
- Split completed assistant text into byte-budgeted Marmot messages. Keep
  `WN_CODEX_MAX_REPLY_BYTES=30000` below the Marmot message cap.
- Keep request/response and Codex event validation strict; malformed or
  unsupported events must not become durable replies.

## Verification

```sh
cargo test -p wn-codex
cargo fmt --check -p wn-codex
cargo clippy -p wn-codex --all-targets -- -D warnings
bash -n scripts/install-codex-marmot.sh scripts/install-terminal-harness-marmot.sh
just codex-dev-e2e-connector
just codex-installer-test
```
