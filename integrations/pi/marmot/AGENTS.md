# AGENTS.md - integrations/pi/marmot

Rust Pi harness for Marmot through the local `wn-agent` control socket. Read
`README.md`, `../../AGENTS.md`, and `../../terminal-harness/AGENTS.md` first.

## Scope

- A control-plane-only harness. `wn-agent` owns Marmot state, MLS, Nostr,
  durable sends, and invite handling; this crate invokes Pi and parses its JSON
  event stream.
- Every text-only message from an allowed sender is a prompt. Do not add gateway,
  mention-activation, backend attachment support, profile, or QUIC preview behavior here.
  For a non-empty attachment batch, the shared harness enforces its count/aggregate-byte
  limits and stages the complete batch, then the default backend contract rejects the
  whole turn before Pi is spawned; accompanying text is not forwarded.
- Send prompts over stdin, emit only completed assistant text, and never expose
  thinking or tool output.
- Keep Pi sessions in the configured private session directory and preserve the
  shared workdir/session mapping rules.
- The CLI contract was verified end-to-end against Pi `0.79.6`: JSON mode reads
  a piped prompt from stdin, emits a version-3 `session` event and completed
  assistant `message_end`, and `--session-id` creates the exact session when it
  is missing from `--session-dir`. Re-verify this contract before changing the
  minimum supported Pi version or invocation flags.

## Key Files

- `src/main.rs` - binary entrypoint, CLI help, tracing setup, and shared runtime wiring.
- `src/config.rs` - Pi-specific environment configuration and private session-directory setup.
- `src/pi.rs` - Pi command construction, stdin prompting, JSON event parsing, and process lifecycle.
- `tests/e2e_connector.rs` - ignored process-level test using real `wn-agent` and a fake Pi executable.
- `tests/test_installer.sh` - Pi entrypoint for the shared terminal-harness installer test suite.
- `scripts/install-pi-marmot.sh` - release-installer wrapper over the shared terminal-harness installer.

## Rules

- Keep prompts on stdin; do not move prompt text into process arguments.
- Split completed assistant text into byte-budgeted Marmot messages. Keep
  `WN_PI_MAX_REPLY_BYTES=30000` below the Marmot message cap.
- Keep state and Pi session directories restrictive-by-construction through
  `fs-private` or an equivalent mode-tested path.
- Keep request/response and Pi event validation strict; malformed or unsupported
  events must not become durable replies.

## Verification

```sh
cargo test -p wn-pi
cargo fmt --check -p wn-pi
cargo clippy -p wn-pi --all-targets -- -D warnings
bash -n scripts/install-pi-marmot.sh scripts/install-terminal-harness-marmot.sh
just pi-dev-e2e-connector
just pi-installer-test
```
