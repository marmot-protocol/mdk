# wn-pi

`wn-pi` is a terminal-harness connector that sends authorized Marmot group
messages to [Pi](https://pi.dev) through the local `wn-agent` control socket.
It is intentionally a thin harness: no mention activation, profile onboarding,
live previews, MLS, or relay logic.

For the current guided install, runtime chooser, and steps to finish in White Noise, use the canonical
[White Noise + Agents quickstart](../../README.md#get-started-white-noise--agents).

## Contents

- [What you can do](#what-you-can-do)
- [Attachments](#attachments)
- [First-install checklist](#first-install-checklist)
- [Install (Pi Already Installed)](#install-pi-already-installed)
- [Manual setup](#manual-setup)
- [Chat Commands](#chat-commands)
- [Configuration](#configuration)
- [Security Notes](#security-notes)
- [Development](#development)

## What you can do

For task titles and progress reactions, use the shared
[recommended chat setup](../../README.md#recommended-chat-setup), including
admin promotion and the phone acceptance test. Agent policy is in
[the integration instructions](../../AGENTS.md#suggested-agent-chat-instructions).
Each ordinary turn exposes the shared `wn-agent group-profile` route for
admin name/description updates. Verify that the installed release includes it,
`wn-agent` is on the backend's PATH, and the backend's shell/sandbox policy permits
access to the connector socket. See [Admin group profile updates](#admin-group-profile-updates).
Progress reactions require a separately configured tool; the harness has none built in.

- **Work through Pi from your phone.** Send a prompt from an authorized
  White Noise account and use the backend's configured model and tools.
  Every allowed message activates the harness; mentioning the agent is not required.

- **Continue or reset the conversation.** Pi uses JSON mode and a private session directory, retaining a separate session per chat. Completed assistant text reaches the phone; thinking and tool output do not.
  `/new` resets the backend session while retaining the project.

- **Know the file contract.** Supported images and non-empty NUL-free UTF-8 text reach Pi in one ordered batch. PDFs, audio, archives and other unsupported bytes reject the whole prompt. Generated-file return is not implemented. See [Attachments](#attachments).

Project selection (`/cd`), standing instructions (`/goal`), and recovery
commands share the [terminal-harness command guide](../../terminal-harness/README.md#chat-commands).

Tool access, credentials and model choices come from the backend's native
configuration and the [execution profile](../../terminal-harness/README.md#execution-profiles).
The harness does not implement mention activation, reaction tools
or live previews. An interactive backend's slash commands are not automatically
available through this chat; shared harness commands are handled locally.

## Attachments

A Marmot message with files becomes one Pi turn. The shared terminal harness
applies its attachment-count and aggregate-byte limits and downloads the whole
ordered batch into owner-only staging. `wn-pi` then runs:

```text
pi --mode json --session-dir <dir> [--session-id <id>] @<staged-file-1> @<staged-file-2> ...
```

There is one `@` operand per file, in message order, after all Pi options. The
message text still goes to Pi on stdin and never appears in argv. Staged paths
are absolute and staged file names are reduced to `NNN-` plus ASCII letters,
digits, `.`, `-`, and `_`, so a file name cannot turn into a Pi option.

Pi embeds text files in the initial message and sends images as image content.
Immediately before starting Pi, `wn-pi` reopens every staged copy without
following symlinks, checks its size, and sorts it the way Pi's `@file`
processor will:

| Staged bytes | Result |
| --- | --- |
| PNG (not animated), JPEG (not arithmetic-coded), GIF, WebP, detected by content like Pi does | Sent to Pi as an image |
| Non-empty UTF-8 without NUL bytes (source, logs, Markdown, JSON, CSV, and so on) | Embedded by Pi as text |
| Empty files, other binaries (PDF, archives, audio, BMP, office documents), invalid UTF-8 | Whole message rejected; Pi is not started |

The declared media type and file extension are ignored. BMP is rejected
because Pi 0.79.6 reads it as text; newer Pi releases convert it.

Files are never dropped while the caption goes through. If one file in the
batch is unsupported, changed, or missing, the whole message gets one error
reply and Pi does not run. Pi replaces an image it cannot convert or resize
with a text note instead of failing, so `wn-pi` counts the image parts in
Pi's initial user `message_end` event. If that count is short, `wn-pi` kills
Pi's process group as soon as the decoder reports the mismatch. If an assistant
`message_end` arrives first, the decoder also rejects the turn, but Pi may
already have processed the prompt before rejection. In either case, the chat
gets an attachment-processing error warning that Pi may already have acted
and to check for changes before retrying. A session Pi created for that turn is
not kept, so the next prompt starts fresh. A resumed session remains stored
with any messages Pi recorded before it was stopped.

The staged batch stays on disk until the Pi process exits, then the shared
harness removes it after success, failure, timeout, or cancellation. Stale
batches are removed when the connector starts. Resumed turns keep using the
group's `--session-id`, so a later text-only prompt can refer back to files
from an earlier turn.

`wn-pi` requires Pi `0.79.6` or newer for attachments. That release has the
`@file` processor, image detection, and stdin-plus-files initial message this
adapter mirrors (checked against Pi source at
[`36b60d2e`](https://github.com/earendil-works/pi/tree/36b60d2e8985899743c4cf5bd5f8929832a3f05d/packages/coding-agent/src/cli)).

## First-install checklist

Follow the [shared terminal-harness first-install guide](../../terminal-harness/README.md#first-installation-and-verification)
before the release command below. It covers the two services, matching home and
socket, sender authorization, manual environment loading, independent instance
state, execution policy and the required phone/model round trip.

Verify the configured Pi executable, native provider/model login and a local
JSON-mode turn as the service user. Use `WN_PI_BIN` / `--pi-bin` when Pi is not
on the service's PATH. Its connector sessions live in the private Pi session
directory; do not attach another client to a connector-owned session. Pi's
normal tool invocation is approval-free and provides no OS sandbox, so choose
an OS/user boundary appropriate for the allowed phone sender.

Start with a text-only phone round trip. Supported attachments are classified
from bytes and passed as ordered `@file` operands, with all items validated
before spawn. Unsupported mixed batches are refused rather than forwarding
just their caption. Generated-file export and Hermes `MEDIA:` delivery are not
implemented for `wn-pi`; only the documented Codex export path provides that
terminal-harness feature today.

## Install (Pi Already Installed)

Versioned `wn-agent-v*` releases publish `wn-agent`, `wn-pi`, checksums, and a
same-user service installer for Linux and macOS.

Prerequisites:

- Pi installed, authenticated, and runnable on `PATH`, or an executable path
  set with `WN_PI_BIN` / `--pi-bin`
- White Noise phone app pointed at the same public relay set
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

First copy the [verified installer helper](../../README.md#verified-installer-helper)
into this shell. Then select the release documented here:

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.12.0"
```

Run this example in the same shell where `install_verified` was defined.

```sh
install_verified "$base_url/install-pi-marmot.sh" \
  "$base_url/install-pi-marmot.sh.sha256"
```

For noninteractive setup, provide the allowed inviter and prompt sender:

Run this example in the same shell where `install_verified` was defined.

```sh
# Reuse the selected base_url from the same shell above.
install_verified "$base_url/install-pi-marmot.sh" \
  "$base_url/install-pi-marmot.sh.sha256" \
  --yes --allow-welcomer npub1...
```

The default install uses its own `~/.marmot-agents/pi` identity and services,
so it does not share prompts or replies with installed Claude Code, Codex, or
OpenCode harnesses.
It installs `wn-agent` and `wn-pi` in `~/.local/bin`, writes a private
`~/.marmot-agents/pi/dev/wn-pi.env`, and starts `wn-agent-pi` and `wn-pi`
same-user services where supported.

Report all installed versions when filing a connector bug:

```sh
wn-agent --version
wn-pi --version
pi --version
```

## Manual setup

Install Pi first and authenticate it normally, then run an isolated `wn-agent`
identity and the harness:

In terminal 1, run the daemon only if its service is not already running:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/pi"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_PI_ALLOWED_SENDERS_HEX="<phone-public-key-as-64-hex-characters>"
wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
```

In terminal 2, export the same settings again, bootstrap the single sender in
this example, then start the harness only if its service is not already running:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/pi"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_PI_ALLOWED_SENDERS_HEX="<phone-public-key-as-64-hex-characters>"
wn-agent bootstrap --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --label pi-harness-agent --allow-welcomer "$WN_PI_ALLOWED_SENDERS_HEX" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat --qr
wn-pi
```

On the first message in a group, use `/<path>` to select a working directory
under `$HOME`, using the same picker rules as `wn-opencode`. Subsequent prompts
resume that group's Pi session.

## Chat Commands

Pi's non-interactive interface does not expand interactive slash commands. The
shared harness answers its own reserved commands, including `/help`, `/status`,
`/pwd`, `/cd`, `/new`, `/reset-session`, and `/goal`, before Pi is invoked. Send
`/help` in a chat to list them; the full table and the `//` literal escape are
documented in the
[shared chat-command reference](../../terminal-harness/README.md#chat-commands).

## Admin group profile updates

This harness exposes the shared `wn-agent group-profile` command to the agent
for the active conversation. It supports name and description changes for
current admins, partial updates and explicit clearing. See the
[shared control-command contract](../../terminal-harness/README.md#admin-group-profile-updates)
for routing, release compatibility, permissions and uncertain outcomes.

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `MARMOT_HOME` | `~/.marmot-agents/pi` | Isolated Pi connector home |
| `MARMOT_AGENT_SOCKET` | `$MARMOT_HOME/dev/wn-agent.sock` | Control socket |
| `MARMOT_AGENT_AUTH_TOKEN_FILE` / `MARMOT_AGENT_AUTH_TOKEN` | unset | Optional control authentication |
| `WN_PI_ALLOWED_SENDERS_HEX` | required | Comma-separated authorized sender ids |
| `WN_PI_ACCOUNT_ID_HEX` | sole local account | Explicit account selection |
| `WN_PI_BIN` | `pi` | Pi executable |
| `MARMOT_HARNESS_EXECUTION_PROFILE` | `inherit` | Shared `inherit`, `autonomous`, or `unrestricted` execution policy |
| `WN_PI_SESSION_DIR` | `$MARMOT_HOME/dev/pi-sessions` | Private Pi session directory |
| `WN_PI_IDLE_TIMEOUT_SECS` | `120` | Presentation-idle interval before liveness is reported as unknown; does not stop the invocation |
| `WN_PI_TIMEOUT_SECS` | `3600` | Total invocation cap |
| `WN_PI_REQUEST_TIMEOUT_SECS` | `30` | Control request timeout |
| `WN_PI_MAX_REPLY_BYTES` | `30000` | Durable reply chunk limit |
| `WN_PI_MAX_PENDING_PER_GROUP` | `4` | Per-group prompt queue limit |
| `WN_PI_MAX_ATTACHMENTS` | `8` | Maximum inbound files validated before backend rejection |
| `WN_PI_MAX_ATTACHMENT_BYTES` | `67108864` | Maximum aggregate inbound bytes validated before rejection |
| `WN_PI_STATE_PATH` | `$XDG_STATE_HOME/wn-pi/sessions.json` | Group session/workdir map |
| `WN_PI_ACTIVATION` | `always` | Only supported activation mode |

Pi's global credentials, model, tools, extensions, settings, and normal
noninteractive project-trust policy remain authoritative. Prompts are written
to Pi over stdin; only completed assistant text is returned to Marmot.

Pi has no built-in approval prompt or OS sandbox. Its normal non-interactive
invocation is already approval-free, so all three profiles use the same Pi
arguments; `autonomous` and `unrestricted` describe deployment intent rather
than adding a containment mechanism. See the shared
[execution-profile capability matrix](../../terminal-harness/README.md#execution-profiles).

## Security Notes

- Group-profile routing passes a configured bearer token as a raw child
  environment value, including tokens loaded from files. Trusted tool shells,
  MCP servers and other descendants may inherit its full connector authority.
  Backend environment filtering must preserve the turn's route and token;
  see the [shared control-command contract](../../terminal-harness/README.md#admin-group-profile-updates).

- The same configured sender list controls prompt execution and is mirrored
  additively into the `wn-agent` welcomer allowlist. To revoke access, remove the
  sender from `WN_PI_ALLOWED_SENDERS_HEX`, restart `wn-pi`, and remove it from
  `wn-agent` separately if invite acceptance must also be revoked.
- Prompts are passed to Pi over stdin rather than process arguments.
- Attachment operands carry only staged paths. Staging directories are
  owner-only and each staged file is owner-readable; other processes running as
  the same operating-system user can still read them while the turn runs.
- Only completed assistant text is returned. Thinking, tool calls, tool output,
  and other Pi event types are not sent to Marmot.
- Logs exclude identifiers, paths, file names, file contents, prompts, Pi
  output, relay URLs, pubkeys, ciphertext, plaintext, and key material.
- Connector state and Pi session directories are created with owner-only
  permissions.
- The optional control-socket bearer token grants the complete `wn-agent`
  control API for every account in its home; the sender allowlist does not
  narrow that authority. Use a separate connector home, socket, token, and
  account for a separate trust boundary.

## Development

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-pi
just pi-dev-e2e-connector
just pi-installer-test
cargo run -p wn-pi
bash scripts/install-pi-marmot.sh --dry-run --yes --allow-welcomer "$(printf '11%.0s' {1..32})" --pi-bin /bin/echo
```

The real Pi `0.79.6` contract test is ignored by default because it requires an
installed, authenticated Pi and makes a model request:

```sh
cargo test -p wn-pi real_pi_0_79_6_contract -- --ignored --nocapture
```

The attachment contract test runs against any installed Pi `0.79.6` or newer.
It sends a text file with a token and a PNG in one turn, checks that Pi inlined
the image and quoted the token, then resumes the same session without files:

```sh
cargo test -p wn-pi real_pi_attachment_contract -- --ignored --nocapture
```

The crate is a workspace member at `integrations/pi/marmot`.
