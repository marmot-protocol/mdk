# wn-pi

`wn-pi` is a terminal-harness connector that sends authorized Marmot group
messages to [Pi](https://pi.dev) through the local `wn-agent` control socket.
It is intentionally a thin harness: no mention activation, profile onboarding,
live previews, MLS, or relay logic.

For the current guided install, runtime chooser, and steps to finish in White Noise, use the canonical
[White Noise + Agents quickstart](../../README.md#get-started-white-noise--agents).

## Contents

- [Attachments](#attachments)
- [Install (Pi Already Installed)](#install-pi-already-installed)
- [Manual setup](#manual-setup)
- [Chat Commands](#chat-commands)
- [Configuration](#configuration)
- [Security Notes](#security-notes)
- [Development](#development)

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
Pi's initial user message. If that count is short, or Pi answers before that
message appears, `wn-pi` kills Pi's process group at once instead of letting
the model turn run, and the chat gets `Pi could not process an attachment in this
batch and was stopped before acting on it.` A session Pi created for that
turn is not kept, so the next prompt starts fresh. A resumed session keeps the
user message Pi recorded before it was stopped.

The staged batch stays on disk until the Pi process exits, then the shared
harness removes it after success, failure, timeout, or cancellation. Stale
batches are removed when the connector starts. Resumed turns keep using the
group's `--session-id`, so a later text-only prompt can refer back to files
from an earlier turn.

`wn-pi` requires Pi `0.79.6` or newer for attachments. That release has the
`@file` processor, image detection, and stdin-plus-files initial message this
adapter mirrors (checked against Pi source at
[`36b60d2e`](https://github.com/earendil-works/pi/tree/36b60d2e8985899743c4cf5bd5f8929832a3f05d/packages/coding-agent/src/cli)).

## Install (Pi Already Installed)

Versioned `wn-agent-v*` releases publish `wn-agent`, `wn-pi`, checksums, and a
same-user service installer for Linux and macOS.

Prerequisites:

- Pi installed, authenticated, and runnable on `PATH`, or an executable path
  set with `WN_PI_BIN` / `--pi-bin`
- White Noise phone app pointed at the same public relay set
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

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

base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.11.0"
install_verified "$base_url/install-pi-marmot.sh" \
  "$base_url/install-pi-marmot.sh.sha256"
```

For noninteractive setup, provide the allowed inviter and prompt sender:

Run this example in the same shell where `install_verified` above was defined.

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.11.0"
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

```sh
export MARMOT_HOME="$HOME/.marmot-agents/pi"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_PI_ALLOWED_SENDERS_HEX="..."

# Shell 1: wn-agent runs in the foreground.
wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat

# Shell 2: bootstrap the identity, then start the harness.
wn-agent bootstrap --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --label pi-harness-agent --allow-welcomer "$WN_PI_ALLOWED_SENDERS_HEX" --qr

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
