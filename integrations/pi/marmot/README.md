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
admin promotion, the suggested instruction block and the phone acceptance test.
This harness does not register title/reaction tools. For that experience,
configure and verify a trusted helper available to the backend; admin promotion
or a `/goal` instruction alone is insufficient.

- **Work through Pi from your phone.** Send a prompt from an authorized
  White Noise account and use the backend's configured model and tools.
  Every allowed message activates the harness; mentioning the agent is not required.
- **Choose a project for this chat.** Send `/cd src/my-project`, then an ordinary
  request such as `Explain the failing test`. The path must resolve beneath the
  service user's home. This selects a working directory, not a sandbox.
- **Continue or reset the conversation.** Pi uses JSON mode and a private session directory, retaining a separate session per chat. Completed assistant text reaches the phone; thinking and tool output do not.
  `/new` resets the backend session while retaining the project.
- **Keep a standing instruction.** `/goal Run the affected tests after edits`
  applies to later prompts in this chat; `/goal clear` removes it. This stores
  instructions for future turns, not a scheduler or a background task.
- **Inspect and recover a turn.** `/help`, `/status` and `/pwd` report local
  chat settings. After a reported recovery barrier, inspect side effects before
  `/retry-last`, or use `/discard-last` to proceed without replaying that turn.
  See [Chat Commands](#chat-commands) for all commands and slash escaping.
- **Know the file contract.** Supported images and non-empty NUL-free UTF-8 text reach Pi in one ordered batch. PDFs, audio, archives and other unsupported bytes reject the whole prompt. Generated-file return is not implemented. See [Attachments](#attachments).

Tool access, credentials and model choices come from the backend's native
configuration and the [execution profile](../../terminal-harness/README.md#execution-profiles).
The harness does not implement mention activation, reaction/profile management
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

The example below requires Python 3 and resolves the latest published
`wn-agent-v*` release once, then uses its immutable URL for all downloads.
WN Agent releases are currently marked GitHub pre-releases; the resolver accepts
published numeric tags and excludes draft releases and `-rc`/other suffixes.
GitHub's repository-wide `/releases/latest` may select MDK or MarmotKit instead.
Resolution or checksum failure stops installation; no unverified fallback runs.
If lookup fails due to a GitHub API rate limit, offline networking or Python TLS
certificates, fix that cause or set `base_url` to a reviewed numeric WN Agent
release URL from the [release list](https://github.com/marmot-protocol/mdk/releases).
Keep the checksum verification; do not fall back to an unverified script.
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
    *[!a-zA-Z0-9:/._-]*) echo "error: invalid installer URL" >&2; exit 1 ;;
  esac
  if ! printf '%s\n' "$installer_url" | LC_ALL=C grep -Eq '^https://github[.]com/marmot-protocol/mdk/releases/download/wn-agent-v[0-9]+[.][0-9]+[.][0-9]+/install-(hermes|openclaw|claude|codex|opencode|pi)-marmot[.]sh$'; then
    echo "error: resolve a numeric WN Agent release before installing" >&2
    exit 1
  fi
  if [ "$checksum_url" != "$installer_url.sha256" ]; then
    echo "error: checksum must accompany the same release installer" >&2
    exit 1
  fi
  installer_script="${installer_url##*/}"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' 0 HUP INT TERM
  curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 180 "$installer_url" -o "$tmpdir/$installer_script"
  curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 180 "$checksum_url" -o "$tmpdir/$installer_script.sha256"
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
install_verified "$base_url/install-pi-marmot.sh" \
  "$base_url/install-pi-marmot.sh.sha256"
```

For noninteractive setup, provide the allowed inviter and prompt sender:

Run this example in the same shell where `install_verified` above was defined.

```sh
# Reuse the resolved base_url from the same shell above.
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
