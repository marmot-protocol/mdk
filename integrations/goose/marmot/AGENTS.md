# AGENTS.md - integrations/goose/marmot

Rust Goose harness for Marmot through the local `wn-agent` control socket. Read
`README.md`, `../../AGENTS.md`, and `../../terminal-harness/AGENTS.md` first.

## Scope

- A control-plane-only terminal harness. `wn-agent` owns Marmot state, MLS,
  Nostr transport, durable sends, and invite handling; this crate invokes
  `goose run` and parses its `stream-json` event stream.
- Every message from an allowed sender is a prompt. Do not add gateway,
  mention-activation, profile, QUIC-preview, or protocol behavior here.
- Send prompts over stdin (`--instructions -`) and emit each assistant
  message's joined text deltas once the next message starts or `complete`
  arrives. Never expose thinking, tool requests/responses, notifications,
  hidden messages, model-only text, partial text at a terminal error, or raw
  backend errors.
- Goose `stream-json` carries no session id. Session identity is a
  connector-generated `wn-goose-<uuid>` name: fresh lanes pass `--name`, later
  prompts pass `--resume --name` with the exact stored name. The parser reports
  that name as the observed session only after Goose emits a valid event, which
  happens only after Goose has created or resolved the session.
- Attachments are unsupported; the default `Backend` rejection stays in place.
- ACP (`goose acp`) is a possible later backend; do not mix it into this
  per-turn `goose run` adapter.

## Key Files

- `src/main.rs` - binary entrypoint and shared runtime wiring.
- `src/config.rs` - Goose-specific environment configuration, including
  `WN_GOOSE_PATH_ROOT`.
- `src/goose.rs` - Goose command construction, session-name handling, profile
  mapping, stateful `stream-json` parsing, version check, and shared subprocess
  invocation.
- `tests/e2e_connector.rs` - ignored process-level test using real `wn-agent`
  and a fake Goose executable.
- `tests/test_installer.sh` - Goose entrypoint for the shared installer suite.
- `scripts/install-goose-marmot.sh` - release-installer wrapper.

## Rules

- Keep prompts on stdin and out of process arguments.
- Never use `--session-id`, a bare `--resume`, `--no-session`, `--path`, or a
  name the connector did not generate. Without `--resume`, `--name` always
  creates a new session; never reuse a name for a fresh lane.
- Keep the profile mapping typed: `inherit` changes nothing, `unrestricted`
  sets `GOOSE_MODE=auto` on the child only, and `autonomous` fails at startup
  (Goose auto mode ignores `never_allow`; approve modes abort headless runs).
  Never write Goose configuration files.
- Keep `WN_GOOSE_MAX_REPLY_BYTES=30000` below the Marmot message cap.
- Keep event validation strict: validate an event before mutating parser state,
  and never turn malformed or unknown events into replies.
- The supported minimum is Goose 1.53.0. The `run` flags, `stream-json` event
  shapes, chunk merging by message id, user-provided session-name resolution,
  and `--version` output (` 1.53.0`, from an empty clap display name) were
  checked against the 1.53.0 source. Re-verify before changing the contract.

## Verification

```sh
cargo test -p wn-goose
cargo fmt --check -p wn-goose
cargo clippy -p wn-goose --all-targets -- -D warnings
bash -n scripts/install-goose-marmot.sh scripts/install-terminal-harness-marmot.sh
just goose-dev-e2e-connector
just goose-installer-test
```
