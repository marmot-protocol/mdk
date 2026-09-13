# AGENTS.md - integrations/claude/marmot

Rust Claude Code harness for Marmot through the local `wn-agent` control
socket. Read `README.md`, `../../AGENTS.md`, and
`../../terminal-harness/AGENTS.md` first.

## Scope

- A control-plane-only terminal harness. `wn-agent` owns Marmot state, MLS,
  Nostr transport, durable sends, and invite handling; this crate invokes
  Claude Code and parses its `stream-json` event stream.
- Every message from an allowed sender is a prompt. Do not add gateway,
  mention-activation, profile, QUIC-preview, or protocol behavior here.
- Send prompts over stdin and emit only the completed final `result` text.
  Never expose assistant intermediate messages, reasoning, tool calls/output,
  user echoes, partial events, or raw backend errors.
- Preserve the shared workdir/session-lane rules. A fresh lane uses an explicit
  adapter-generated UUID; later prompts resume only that stored UUID.

## Key Files

- `src/main.rs` - binary entrypoint and shared runtime wiring.
- `src/config.rs` - Claude-specific environment configuration.
- `src/claude.rs` - Claude command construction, UUID handling, JSONL parsing,
  supported-version check, and shared subprocess invocation.
- `tests/e2e_connector.rs` - ignored process-level test using real `wn-agent`
  and a fake Claude executable.
- `tests/test_installer.sh` - Claude entrypoint for the shared installer suite.
- `scripts/install-claude-marmot.sh` - release-installer wrapper.

## Rules

- Keep prompts on stdin and out of process arguments.
- Never use `--continue`, a named session, transcript-path resume, or cwd
  inference. Fresh sessions use `--session-id`; resumed sessions use the exact
  stored UUID with `--resume`.
- Keep execution argv derived from the shared typed execution profile. Do not
  add free-form backend arguments or mutate Claude Code settings.
- Keep `WN_CLAUDE_MAX_REPLY_BYTES=30000` below the Marmot message cap.
- Keep event validation strict and diagnostics privacy-safe.
- The supported minimum is Claude Code 2.1.0. The required print, streaming,
  UUID session, resume, verbose, and permission flags were verified against
  2.1.0 and 2.1.270; re-verify that surface before changing the contract.

## Verification

```sh
cargo test -p wn-claude
cargo fmt --check -p wn-claude
cargo clippy -p wn-claude --all-targets -- -D warnings
bash -n scripts/install-claude-marmot.sh scripts/install-terminal-harness-marmot.sh
just claude-dev-e2e-connector
just claude-installer-test
```
