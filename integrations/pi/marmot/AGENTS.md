# AGENTS.md - integrations/pi/marmot

Rust Pi harness for Marmot through the local `wn-agent` control socket. Read
`README.md`, `../../AGENTS.md`, and `../../terminal-harness/AGENTS.md` first.

## Scope

- A control-plane-only harness. `wn-agent` owns Marmot state, MLS, Nostr,
  durable sends, and invite handling; this crate invokes Pi and parses its JSON
  event stream.
- Every message from an allowed sender is a prompt. Do not add gateway,
  mention-activation, media, profile, or QUIC preview behavior here.
- Send prompts over stdin, emit only completed assistant text, and never expose
  thinking or tool output.
- Keep Pi sessions in the configured private session directory and preserve the
  shared workdir/session mapping rules.
- The CLI contract was verified end-to-end against Pi `0.79.6`: JSON mode reads
  a piped prompt from stdin, emits a version-3 `session` event and completed
  assistant `message_end`, and `--session-id` creates the exact session when it
  is missing from `--session-dir`. Re-verify this contract before changing the
  minimum supported Pi version or invocation flags.

## Verification

```sh
cargo test -p wn-pi
cargo fmt --check -p wn-pi
cargo clippy -p wn-pi --all-targets -- -D warnings
```
