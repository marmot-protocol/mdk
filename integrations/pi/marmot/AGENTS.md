# AGENTS.md - integrations/pi/marmot

Rust Pi harness for Marmot through the local `wn-agent` control socket. Read
`README.md`, `../../AGENTS.md`, and `../../terminal-harness/AGENTS.md` first.

## Scope

- A control-plane-only harness. `wn-agent` owns Marmot state, MLS, Nostr,
  durable sends, and invite handling; this crate invokes Pi and parses its JSON
  event stream.
- Every message from an allowed sender is a prompt. Do not add gateway,
  mention-activation, profile, or QUIC preview behavior here.
- Attachment batches map to ordered `@<absolute staged path>` operands after all
  Pi options, in one turn. `prepare_attachments` in `src/pi.rs` revalidates each
  staged copy through the shared `attachment_preflight` and classifies it with
  Pi's own image sniffer (PNG without `acTL`, JPEG without `F7`, GIF, WebP) or
  as NUL-free UTF-8 text; anything else, including empty files and BMP, rejects
  the whole batch before spawn. `PiEventParser` returns
  `ParsedEvent::AttachmentNotProcessed` when Pi's first user `message_end`
  carries fewer image parts than accepted images, or an assistant `message_end`
  arrives first; the shared runner then kills the process group and drops the
  observed session. Pi may already have acted before rejection is reported.
  Keep the sniffer in step with Pi's
  `utils/mime.ts` for the minimum supported version.
- Send prompts over stdin, emit only completed assistant text, and never expose
  thinking or tool output.
- Keep Pi sessions in the configured private session directory and preserve the
  shared workdir/session mapping rules.
- The CLI contract was verified end-to-end against Pi `0.79.6`: JSON mode reads
  a piped prompt from stdin, emits a version-3 `session` event and completed
  assistant `message_end`, and `--session-id` creates the exact session when it
  is missing from `--session-dir`. Re-verify this contract before changing the
  minimum supported Pi version or invocation flags.
- The `@file` contract (ordered `fileArgs`, stdin prompt joined ahead of file
  text, typed image content in the user `message_end`) is the minimum-version
  contract for attachments. Pi `0.87.1` passed `real_pi_attachment_contract`
  end to end. On Pi `0.79.6` the same argv produced the stdin caption, both
  `<file>` blocks, and one image part in the user `message_end`; its model call
  was not completed because that release could not use the available
  credentials. Re-run the contract test on the minimum before relying on it.

## Key Files

- `src/main.rs` - binary entrypoint, CLI help, tracing setup, and shared runtime wiring.
- `src/config.rs` - Pi-specific environment configuration and private session-directory setup.
- `src/pi.rs` - Pi command construction, `@file` attachment preflight, stdin prompting, JSON event parsing, and process lifecycle.
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
