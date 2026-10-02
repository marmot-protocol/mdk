# wn-opencode

`wn-opencode` is a terminal-harness backend for Marmot. It runs
[OpenCode](https://opencode.ai/) through the local `wn-agent` connector and
sends every message from an allowed sender to `opencode run --format json`.

`wn-agent` owns the Marmot account, MLS state, Nostr transport, invite allowlist,
and durable encrypted sends. `wn-opencode` is intentionally thinner than the
Hermes and OpenClaw gateway integrations: it has no mention activation, profile
onboarding, or live previews. It is a pure harness for an authorized operator.
Files sent with a message reach OpenCode through `opencode run --file`; see
[Inbound attachments](#inbound-attachments).

For the current guided install, runtime chooser, and steps to finish in White Noise, use the canonical
[White Noise + Agents quickstart](../../README.md#get-started-white-noise--agents).

## Contents

- [Install (OpenCode Already Installed)](#install-opencode-already-installed)
- [Configuration](#configuration)
- [Workdir Picker](#workdir-picker)
- [Chat Commands](#chat-commands)
- [OpenCode Transport Contract](#opencode-transport-contract)
- [Inbound attachments](#inbound-attachments)
- [Security Notes](#security-notes)
- [Development](#development)

## Install (OpenCode Already Installed)

Versioned `wn-agent` builds publish the `wn-agent` binary, this harness binary,
and an installer under [`wn-agent-v*`](https://github.com/marmot-protocol/mdk/releases)
GitHub pre-releases.

Prerequisites:

- OpenCode 1.18.18 or newer installed locally and runnable on `PATH`, or an
  executable path set with `WN_OPENCODE_BIN` / `--opencode-bin`
- White Noise phone app pointed at the same public relay set
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

Verified install (the helper also forwards any installer arguments after the two URLs):

```sh
install_verified() (
  set -eu
  installer_url="$1"
  checksum_url="$2"
  shift 2
  installer_script="${installer_url##*/}"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' 0 HUP INT TERM
  curl -fsSL "$installer_url" -o "$tmpdir/$installer_script"
  curl -fsSL "$checksum_url" -o "$tmpdir/$installer_script.sha256"
  if command -v shasum >/dev/null 2>&1; then
    (cd "$tmpdir" && shasum -a 256 -c "$installer_script.sha256")
  elif command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmpdir" && sha256sum -c "$installer_script.sha256")
  else
    echo "error: need shasum or sha256sum to verify the installer" >&2
    exit 1
  fi
  bash "$tmpdir/$installer_script" "$@"
)

base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.12.0"
install_verified "$base_url/install-opencode-marmot.sh" \
  "$base_url/install-opencode-marmot.sh.sha256"
```

For repeatable noninteractive setup, pass the allowed inviter and prompt sender
as either an `npub` or raw hex public key:

Run this example in the same shell where `install_verified` above was defined.

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.12.0"
install_verified "$base_url/install-opencode-marmot.sh" \
  "$base_url/install-opencode-marmot.sh.sha256" \
  --yes --allow-welcomer npub1...
```

The installer puts `wn-agent` and `wn-opencode` in `~/.local/bin`, starts a
same-user terminal-harness `wn-agent` service where supported, bootstraps or
reuses `~/.marmot-agents/harnesses`, mirrors the allowlist into `wn-agent`,
writes `~/.marmot-agents/harnesses/dev/wn-opencode.env`, and starts a same-user
`wn-opencode` service where supported.

Use the exact release version when reporting bugs:

```sh
wn-agent --version
wn-opencode --version
```

Manual equivalent:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/harnesses"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_OPENCODE_ALLOWED_SENDERS_HEX="..."

wn-agent --home "$MARMOT_HOME" \
  --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat

wn-agent bootstrap \
  --home "$MARMOT_HOME" \
  --socket "$MARMOT_AGENT_SOCKET" \
  --label terminal-harness-agent \
  --allow-welcomer "$WN_OPENCODE_ALLOWED_SENDERS_HEX" \
  --qr

wn-opencode
```

Invite the printed agent account from the phone app.

## Configuration

Configure with environment variables:

| Env | Default | Meaning |
| --- | --- | --- |
| `MARMOT_HOME` | `~/.marmot-agents/harnesses` | terminal-harness `wn-agent` data directory |
| `MARMOT_AGENT_SOCKET` | `$MARMOT_HOME/dev/wn-agent.sock` | Unix control socket |
| `MARMOT_AGENT_AUTH_TOKEN_FILE` | unset | Optional bearer-token file for group-readable socket setups |
| `MARMOT_AGENT_AUTH_TOKEN` | unset | Optional bearer token value |
| `WN_OPENCODE_ALLOWED_SENDERS_HEX` | required | Comma-separated sender account ids allowed to prompt OpenCode |
| `WN_OPENCODE_ADMIN_HEX` | unset | Legacy alias for `WN_OPENCODE_ALLOWED_SENDERS_HEX` |
| `WN_OPENCODE_ACCOUNT_ID_HEX` | sole local account | Specific `wn-agent` account to use; required when several local-signing accounts exist |
| `WN_OPENCODE_BIN` | `opencode` | OpenCode binary or executable path |
| `MARMOT_HARNESS_EXECUTION_PROFILE` | `inherit` | Shared `inherit`, `autonomous`, or `unrestricted` execution policy |
| `WN_OPENCODE_IDLE_TIMEOUT_SECS` | `120` | Presentation-idle interval before liveness is reported as unknown; does not stop the invocation |
| `WN_OPENCODE_TIMEOUT_SECS` | `3600` | Total invocation policy limit; ongoing output does not reset it |
| `WN_OPENCODE_REQUEST_TIMEOUT_SECS` | `30` | Timeout for each control-socket request |
| `WN_OPENCODE_MAX_REPLY_BYTES` | `30000` | UTF-8 byte limit for each durable Marmot reply chunk |
| `WN_OPENCODE_MAX_BACKEND_RECORD_BYTES`, `WN_OPENCODE_MAX_BACKEND_STDOUT_BYTES`, `WN_OPENCODE_MAX_BACKEND_EVENTS`, `WN_OPENCODE_MAX_ASSISTANT_TEXT_BYTES`, `WN_OPENCODE_MAX_ASSISTANT_TEXT_EVENTS`, `WN_OPENCODE_MAX_ARTIFACT_BUFFER_BYTES`, `WN_OPENCODE_MAX_REPLY_CHUNKS`, `WN_OPENCODE_MAX_DURABLE_SENDS` | shared defaults | Per-turn backend output and durable-send limits; see [Output Limits](../../terminal-harness/README.md#output-limits) |
| `WN_OPENCODE_MAX_PENDING_PER_GROUP` | `4` | Per-group in-flight/queued prompt cap |
| `WN_OPENCODE_MAX_ATTACHMENTS` | `8` | Maximum inbound files in one turn |
| `WN_OPENCODE_MAX_ATTACHMENT_BYTES` | `67108864` | Maximum aggregate plaintext bytes in one inbound batch |
| `WN_OPENCODE_STATE_PATH` | `$XDG_STATE_HOME/wn-opencode/sessions.json` | Session map path |
| `WN_OPENCODE_ACTIVATION` | `always` | Only `always` is supported today |
| `RUST_LOG` | `info,marmot_terminal_harness=info` | tracing filter |

The optional bearer token grants the complete `wn-agent` control API for every
account in its home; the harness sender allowlist does not narrow that token's
authority. Do not give it to an untrusted harness. Use a separate connector
home, socket, token, and account for a separate trust boundary.

`autonomous` passes OpenCode's `--auto`, which auto-approves asks while
preserving explicit denies. `unrestricted` also supplies a connector-owned,
process-local allow-all permission overlay; it does not rewrite OpenCode's
global or project configuration, and it clears an inherited
`OPENCODE_PERMISSION` in the child. Managed organization policy may still
override the process-local setting. OpenCode provides no built-in OS isolation;
use external OS isolation for unrestricted deployments. See the shared
[execution-profile capability matrix](../../terminal-harness/README.md#execution-profiles).

The reply limit is byte-based, not character-based. The default is 30KB, well
below Marmot's roughly 60KB message ceiling. Splitting prefers paragraph,
newline, then space boundaries and never splits a UTF-8 code point.

## Workdir Picker

On the first message in a new Marmot group, a leading `/<path>` selects
`~/<path>` as the OpenCode working directory if the canonical target is inside
`$HOME`. Path segments are separated by `/` and each segment must be
ASCII-alphanumeric or `.`, `_`, `-`; empty, `.`, and `..` segments are rejected.

Examples:

```text
/mdk fix the failing test
/mdk
/projects/mdk fix the failing test
```

When the message is only the picker, `wn-opencode` stores the workdir and asks
for the next prompt. Symlinks that resolve outside `$HOME` are rejected after
canonicalization. Picker-looking messages with invalid segments are rejected
and are not forwarded to OpenCode as prompts.

## Chat Commands

`opencode run` does not expand OpenCode's interactive slash commands. The shared
harness answers its own reserved commands before OpenCode is invoked; send
`/help` in a chat to list them. The full table and the `//` literal escape are
documented in the
[shared chat-command reference](../../terminal-harness/README.md#chat-commands).

`/new` and `/reset-session` clear the current Marmot group's OpenCode session
id. The harness intercepts the command, preserves the group's validated workdir,
does not delete OpenCode-owned transcripts, and confirms the result. The next
normal prompt creates and records a new OpenCode session in that workdir. A
failed resumed prompt is never retried automatically because the original
invocation may already have produced side effects.

Reserved names are not forwarded to OpenCode. Send `//reset-session` when the
literal `/reset-session` text should reach OpenCode; a reserved name with
arguments it does not accept, such as `/reset-session please`, returns a usage
reply.

## OpenCode Transport Contract

The minimum supported OpenCode version is 1.18.18. The harness retains the
process-per-message [`opencode run --format json`](https://opencode.ai/docs/cli/)
integration, including `--session` resume and the existing completed-text event
filter. It supplies the prompt only through the child's stdin. OpenCode 1.18.18
explicitly reads piped stdin when no message argument is present in its
[tagged `run` implementation](https://github.com/anomalyco/opencode/blob/v1.18.18/packages/opencode/src/cli/cmd/run.ts#L416-L422).

The bounded transport comparison was:

| Candidate | Contract fit | Decision |
| --- | --- | --- |
| `opencode run --format json` with stdin | Preserves durable session ids, process isolation, completed-event filtering, timeouts, cancellation, cleanup, and future `run` permission flags while removing prompt argv exposure. | Selected. |
| [`opencode acp`](https://opencode.ai/docs/acp/) | Moves prompts to stdio, but adds a stateful JSON-RPC connection, initialize/load/prompt/cancel framing, and permission-request replies. | Not selected; no benefit over `run` stdin for this harness. |
| [`opencode serve`](https://opencode.ai/docs/server/) | Provides a local OpenAPI HTTP interface, but adds server startup/readiness, authentication, port ownership, event-stream, and crash-recovery obligations. | Not selected; it weakens the current process-per-message boundary. |

This ACP decision concerns only the OpenCode backend below the shared `Backend`
trait. It does not change `marmot.agent-control.v2` and does not imply an ACP
migration for other terminal harnesses.

## Inbound attachments

The shared harness downloads every file in one Marmot message in message order,
enforces the count and aggregate-byte limits, and copies the batch into one
owner-only temporary directory. `wn-opencode` then starts exactly one
`opencode run` for the message:

```text
opencode run --format json [--auto] [--session <id>] --file <staged path> ... --
```

Each staged file gets its own `--file <path>` pair, in message order, after
every other option. The final `--` ends option parsing. Staged paths are
absolute, so a file name that begins with `-` cannot be read as an option. The
caption or request text goes to stdin only, exactly as for a text-only turn.
New and resumed groups use the same shape; a resumed group keeps its stored
`--session` id, so the files join the existing OpenCode session. Execution
profiles, the `unrestricted` config overlay, and the completed-text event filter
are unchanged. A text-only turn has no `--file` arguments and no `--`.

Without `--attach`, OpenCode 1.18.18 labels every `--file` path as `text/plain`
([`run.ts`](https://github.com/anomalyco/opencode/blob/v1.18.18/packages/opencode/src/cli/cmd/run.ts#L357-L414))
and resolves it through its Read tool
([`prompt.ts`](https://github.com/anomalyco/opencode/blob/v1.18.18/packages/opencode/src/session/prompt.ts#L808-L907),
[`read.ts`](https://github.com/anomalyco/opencode/blob/v1.18.18/packages/opencode/src/tool/read.ts#L300-L331)).
When the Read tool fails, OpenCode keeps going and gives the model an error note
in place of the file. To stop that from happening silently, the connector
re-opens every staged file right before spawning OpenCode and applies the same
rules the Read tool uses:

| File | How OpenCode classifies it | Connector decision |
| --- | --- | --- |
| PNG, JPEG, GIF, WebP, or PDF | First bytes match the signature in [`util/media.ts`](https://github.com/anomalyco/opencode/blob/v1.18.18/packages/opencode/src/util/media.ts) | Accepted; OpenCode attaches the bytes as an image or PDF |
| Text | Valid UTF-8; no NUL byte and at most 30% control characters in the first 4 KiB; extension not on OpenCode's binary list | Accepted; OpenCode inlines it with line numbers |
| Signature missing but extension is `.png`, `.jpg`, `.jpeg`, `.jpe`, `.gif`, `.webp`, or `.pdf` | OpenCode would trust the extension and send non-matching bytes as media | Rejected |
| Extension `.zip`, `.tar`, `.gz`, `.7z`, `.jar`, `.war`, `.class`, `.exe`, `.dll`, `.so`, `.o`, `.a`, `.lib`, `.obj`, `.wasm`, `.pyc`, `.pyo`, `.bin`, `.dat`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.odt`, `.ods`, or `.odp` | Read tool refuses it as binary, whatever the content | Rejected |
| BMP, audio, archives, other binary, or non-UTF-8 text | Read tool refuses it as binary, or would decode it lossily | Rejected |

Extensions come from the connector-sanitized staged name, which keeps the
sender's extension unless the name is longer than 128 characters. One rejected,
missing, size-changed, symlinked, or non-regular file fails the whole message
before OpenCode starts: the other files and the caption are not forwarded, and
nothing is split into separate turns. The sender gets the shared attachment
failure reply. An error that OpenCode itself reports during the turn fails that
turn and is not retried.

OpenCode applies its own limits after these checks. The Read tool inlines at
most 2000 lines or 50 KiB of a text file, cuts lines longer than 2000
characters, and appends a note that tells the model where the output stopped.
Images and PDFs pass through unchanged apart from OpenCode's own image
resizing, so the configured model must accept image or PDF input. The connector
does not check model capabilities. OpenCode 1.18.32 uses the same `run`, Read
tool, and media-sniffing code for these paths as 1.18.18.

Staged copies stay in place for the whole OpenCode process and are removed after
success, OpenCode error, timeout, or cancellation. A cancelled or timed-out turn
stops the OpenCode process group before the batch is deleted. Leftover batch
directories are removed when the connector restarts. Logs and the session map
never record file names, paths, contents, or prompt text.

## Security Notes

- The control socket is local Unix-domain only. Use the normal `wn-agent`
  socket mode and bearer-token options for shared local-user setups.
- The same allowlist controls invite acceptance in `wn-agent` and prompt
  execution in `wn-opencode`.
- On startup, `wn-opencode` adds any configured prompt senders that are missing
  from the `wn-agent` welcomer allowlist. This mirroring is additive: it does not
  remove extra `wn-agent` welcomers. To revoke OpenCode execution, remove the
  sender from `WN_OPENCODE_ALLOWED_SENDERS_HEX` and restart the harness; remove
  the sender from `wn-agent` separately if you also want to revoke invite
  acceptance.
- Logs are structured and privacy-safe: no account ids, group ids, message ids,
  local paths, prompt text, OpenCode output, relay URLs, pubkeys, ciphertext, or
  key material.
- Prompt text is written to `opencode run` over stdin and is absent from spawned
  process arguments and privacy-safe logs.
- Attachment paths appear in `opencode run` arguments as private staged paths.
  Their contents, sender file names, and captions never do.
- The session map is written through `fs-private` with owner-only file and
  directory modes.

## Development

```sh
cargo test -p wn-opencode
just opencode-dev-e2e-connector
just opencode-installer-test
cargo run -p wn-opencode
bash scripts/install-opencode-marmot.sh --dry-run --yes --allow-welcomer "$(printf '11%.0s' {1..32})" --opencode-bin /bin/echo
```

The crate is a workspace member at `integrations/opencode/marmot`.

The real OpenCode contract test is ignored by default because it needs an
installed, authenticated OpenCode CLI and makes model requests. Its first turn
checks that the model can read a staged text file passed with `--file`. Its
second turn resumes the same session with a different file and checks that the
model can read both. Set `WN_OPENCODE_BIN` to run it against a specific
OpenCode build, such as the 1.18.18 minimum:

```sh
cargo test -p wn-opencode real_opencode_run_file_contract -- --ignored --nocapture
```
