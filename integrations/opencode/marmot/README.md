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

- [What you can do](#what-you-can-do)
- [First-install checklist](#first-install-checklist)
- [Install (OpenCode Already Installed)](#install-opencode-already-installed)
- [Configuration](#configuration)
- [Workdir Picker](#workdir-picker)
- [Chat Commands](#chat-commands)
- [OpenCode Transport Contract](#opencode-transport-contract)
- [Inbound attachments](#inbound-attachments)
- [Security Notes](#security-notes)
- [Development](#development)

## What you can do

For task titles and progress reactions, use the shared
[recommended chat setup](../../README.md#recommended-chat-setup), including
admin promotion, the suggested instruction block and the phone acceptance test.
This harness does not register title/reaction tools. For that experience,
configure and verify a trusted helper available to the backend; admin promotion
or a `/goal` instruction alone is insufficient.

- **Work through OpenCode from your phone.** Send a prompt from an authorized
  White Noise account and use the backend's configured model and tools.
  Every allowed message activates the harness; mentioning the agent is not required.
- **Choose a project for this chat.** Send `/cd src/my-project`, then an ordinary
  request such as `Explain the failing test`. The path must resolve beneath the
  service user's home. This selects a working directory, not a sandbox.
- **Continue or reset the conversation.** OpenCode uses its non-interactive JSON interface and retains a session per chat. Its text events are returned as durable replies; the connector does not mirror the interactive TUI.
  `/new` resets the backend session while retaining the project.
- **Keep a standing instruction.** `/goal Run the affected tests after edits`
  applies to later prompts in this chat; `/goal clear` removes it. This stores
  instructions for future turns, not a scheduler or a background task.
- **Inspect and recover a turn.** `/help`, `/status` and `/pwd` report local
  chat settings. After a reported recovery barrier, inspect side effects before
  `/retry-last`, or use `/discard-last` to proceed without replaying that turn.
  See [Chat Commands](#chat-commands) for all commands and slash escaping.
- **Know the file contract.** Supported images, PDFs and readable text files reach OpenCode in one ordered batch; unsupported files reject the whole prompt. Generated-file return is not implemented. See [Inbound attachments](#inbound-attachments).

Tool access, credentials and model choices come from the backend's native
configuration and the [execution profile](../../terminal-harness/README.md#execution-profiles).
The harness does not implement mention activation, reaction/profile management
or live previews. An interactive backend's slash commands are not automatically
available through this chat; shared harness commands are handled locally.

## First-install checklist

Follow the [shared terminal-harness first-install guide](../../terminal-harness/README.md#first-installation-and-verification)
before the release command below. It covers the two services, matching home and
socket, sender authorization, manual environment loading, independent instance
state, execution policy and the required phone/model round trip.

Verify the selected OpenCode binary, provider/model configuration and a local
`opencode run` turn under the service user's normal home. Use `WN_OPENCODE_BIN`
/ `--opencode-bin` for a nonstandard executable. The connector uses the
non-interactive JSON interface, not an existing TUI, and does not copy login
state into the Marmot home. OpenCode's own project/configuration permissions
remain active; do not silently choose `unrestricted` to make an install pass.

After pairing, select the intended trusted directory in chat and verify a
text-only model reply before attachments. Files must fit the documented
OpenCode classification; arbitrary audio/archives are not made readable merely
by staging them. Generated-file return is not implemented in this harness;
`MEDIA:` is not an OpenCode connector send action.

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

The example below requires Python 3 and resolves the latest published
`wn-agent-v*` release once, then uses its immutable URL for all downloads.
WN Agent releases are currently marked GitHub pre-releases; the resolver accepts
published numeric tags and excludes draft releases and `-rc`/other suffixes.
GitHub's repository-wide `/releases/latest` may select MDK or MarmotKit instead.
Resolution or checksum failure stops installation; no unverified fallback runs.
For the default cohort, remove stale `MARMOT_RELEASE_REPO`, `MARMOT_RELEASE_TAG`,
`WN_AGENT_VERSION` and `WN_AGENT_SHA` overrides; the published installer defaults
its companion assets to its own release. Explicit overrides are a custom install.
For repeatable deployments, save the printed `base_url` and reuse that exact
release rather than resolving again. The release publisher is the trust anchor;
the sibling checksum verifies downloaded bytes, not an independent endorsement.
A reviewed numeric release URL can replace the resolved value for a pinned install. Minimum host versions and pinned test
cohorts below describe compatibility, not a required MDK install version.

```sh
install_verified() (
  set -eu
  installer_url="$1"
  checksum_url="$2"
  shift 2
  case "$installer_url" in
    https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v*/install-*-marmot.sh) ;;
    *) echo "error: resolve a WN Agent release before installing" >&2; exit 1 ;;
  esac
  if [ "$checksum_url" != "$installer_url.sha256" ]; then
    echo "error: checksum must accompany the same release installer" >&2
    exit 1
  fi
  installer_script="${installer_url##*/}"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' 0 HUP INT TERM
  curl -fsSL --connect-timeout 10 --max-time 180 "$installer_url" -o "$tmpdir/$installer_script"
  curl -fsSL --connect-timeout 10 --max-time 180 "$checksum_url" -o "$tmpdir/$installer_script.sha256"
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

if base_url="$(python3 - <<'RELEASE'
import json, re, urllib.request
candidates = []
for page in range(1, 11):
    url = f"https://api.github.com/repos/marmot-protocol/mdk/releases?per_page=100&page={page}"
    with urllib.request.urlopen(url, timeout=30) as response:
        releases = json.load(response)
    for release in releases:
        tag = release["tag_name"]
        match = re.fullmatch(r"wn-agent-v([0-9]+)\.([0-9]+)\.([0-9]+)", tag)
        if match and not release["draft"] and release["published_at"]:
            candidates.append((tuple(map(int, match.groups())), tag))
    if len(releases) < 100:
        break
else:
    raise SystemExit("Release listing exceeded 1000 entries; choose a reviewed tag explicitly")
if not candidates:
    raise SystemExit("No published WN Agent release found")
tag = max(candidates)[1]
print(f"https://github.com/marmot-protocol/mdk/releases/download/{tag}")
RELEASE
)" && test -n "$base_url"; then
  printf 'Selected WN Agent release: %s\n' "$base_url"
else
  base_url=""
  printf '%s\n' 'error: release lookup failed; installation is unavailable until resolved' >&2
fi
```

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-opencode-marmot.sh" \
  "$base_url/install-opencode-marmot.sh.sha256"
```

For repeatable noninteractive setup, pass the allowed inviter and prompt sender
as either an `npub` or raw hex public key:

Run this example in the same shell where `install_verified` above was defined.

```sh
# Reuse the resolved base_url from the same shell above.
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

In terminal 1, run the daemon only if its service is not already running:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/harnesses"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_OPENCODE_ALLOWED_SENDERS_HEX="<phone-public-key-as-64-hex-characters>"
wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
```

In terminal 2, export the same settings again, bootstrap the single sender in
this example, then start the harness only if its service is not already running:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/harnesses"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_OPENCODE_ALLOWED_SENDERS_HEX="<phone-public-key-as-64-hex-characters>"
wn-agent bootstrap --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --label terminal-harness-agent --allow-welcomer "$WN_OPENCODE_ALLOWED_SENDERS_HEX" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat --qr
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
