# wn-codex

`wn-codex` is a terminal-harness connector that sends authorized Marmot group
messages to [Codex](https://learn.chatgpt.com/) through the local
`wn-agent` control socket. It is intentionally a thin harness: no mention
activation, profile onboarding, live previews, MLS, or relay logic. The shared
terminal harness downloads and privately stages inbound files; this adapter
maps ordered image batches to repeated Codex `--image` arguments. Optional
artifact export reuses `wn-agent`'s existing encrypted `send_media` path.

For the current guided install, runtime chooser, and steps to finish in White Noise, use the canonical
[White Noise + Agents quickstart](../../README.md#get-started-white-noise--agents).

It uses Codex's documented non-interactive JSONL interface: a new group starts
with `codex exec --json -`, and later messages resume the group's Codex thread
with `codex exec resume --json <thread-id> -`.

## Contents

- [What you can do](#what-you-can-do)
- [First-install checklist](#first-install-checklist)
- [Install (Codex Already Installed)](#install-codex-already-installed)
- [Manual Setup](#manual-setup)
- [Chat Commands](#chat-commands)
- [Configuration](#configuration)
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

- **Work through Codex from your phone.** Send a prompt from an authorized
  White Noise account and use the backend's configured model and tools.
  Every allowed message activates the harness; mentioning the agent is not required.
- **Choose a project for this chat.** Send `/cd src/my-project`, then an ordinary
  request such as `Explain the failing test`. The path must resolve beneath the
  service user's home. This selects a working directory, not a sandbox.
- **Continue or reset the conversation.** Codex creates a separate thread for each chat and resumes that thread on later prompts. Completed assistant messages reach the phone; reasoning, tool/command output and partial events do not.
  `/new` resets the backend session while retaining the project.
- **Keep a standing instruction.** `/goal Run the affected tests after edits`
  applies to later prompts in this chat; `/goal clear` removes it. This stores
  instructions for future turns, not a scheduler or a background task.
- **Inspect and recover a turn.** `/help`, `/status` and `/pwd` report local
  chat settings. After a reported recovery barrier, inspect side effects before
  `/retry-last`, or use `/discard-last` to proceed without replaying that turn.
  See [Chat Commands](#chat-commands) for all commands and slash escaping.
- **Know the file contract.** Images use native CLI image inputs; other supported files use a staged-file manifest and normal file tools. Native audio/PDF interpretation is not guaranteed. Generated-file return is available only through opt-in, exact chat/root grants and a completion manifest. See [Configuration](#configuration) and [Inbound attachments](#inbound-attachments).

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

Verify native Codex authentication and a local non-interactive turn as the
service user, with the intended configuration and a trusted Git working
directory. `WN_CODEX_BIN` / `--codex-bin` selects the executable; the connector
does not log in, rewrite global Codex settings or implement TUI slash commands.
Select the repository in the phone chat before the first model prompt: the
harness's default working directory is the service user's home, which may not
be a Git repository.

Use a text-only round trip first. Native image inputs require the documented
CLI image capability; other supported files are offered through a staged-file
manifest and ordinary file tools. A staged audio/PDF path is not a promise of
native transcription/PDF processing. Generated files are returned only when
Codex artifact export is explicitly enabled with an exact chat/root grant,
backend write access and a connector-approved staging root. An assistant's
`MEDIA:` line or Markdown download link does not trigger this exporter.

## Install (Codex Already Installed)

Versioned `wn-agent-v*` releases publish `wn-agent`, `wn-codex`, checksums, and
a same-user service installer for Linux and macOS.

Prerequisites:

- Codex installed, authenticated, and runnable on `PATH`, or an executable path
  set with `WN_CODEX_BIN` / `--codex-bin`
- White Noise phone app pointed at the same public relay set
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

Use the canonical [White Noise + Agents quickstart](../../README.md#codex) for
the current guided install command and the steps to finish in White Noise.

For noninteractive setup, provide the allowed inviter and prompt sender:

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
install_verified "$base_url/install-codex-marmot.sh" \
  "$base_url/install-codex-marmot.sh.sha256" \
  --yes --allow-welcomer npub1...
```

The default install uses its own `~/.marmot-agents/codex` identity and services,
so it does not share prompts or replies with installed OpenCode or Pi harnesses.
It installs `wn-agent` and `wn-codex` in `~/.local/bin`, writes a private
`~/.marmot-agents/codex/dev/wn-codex.env`, and starts `wn-agent-codex` and
`wn-codex` same-user services where supported.

Report all installed versions when filing a connector bug:

```sh
wn-agent --version
wn-codex --version
codex --version
```

## Manual Setup

Install Codex first and authenticate it normally, then run an isolated
`wn-agent` identity and the harness:

In terminal 1, run the daemon only if its service is not already running:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/codex"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_CODEX_ALLOWED_SENDERS_HEX="<phone-public-key-as-64-hex-characters>"
wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
```

In terminal 2, export the same settings again, bootstrap the single sender in
this example, then start the harness only if its service is not already running:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/codex"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_CODEX_ALLOWED_SENDERS_HEX="<phone-public-key-as-64-hex-characters>"
wn-agent bootstrap --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --label codex-harness-agent --allow-welcomer "$WN_CODEX_ALLOWED_SENDERS_HEX" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat --qr
wn-codex
```

On the first message in a group, use `/<path>` to select a Git working
directory under `$HOME`. A picker-only message stores the workdir without
starting Codex. Subsequent prompts resume that group's Codex thread. Without a
picker, the shared harness uses `$HOME`; Codex rejects a non-Git working
directory by default, so select a repository before sending the first prompt.

## Chat Commands

`codex exec` does not expand Codex's interactive TUI slash commands, so Codex's
own `/goal`, `/plan`, `/review`, and the rest of that TUI set never run here.
The shared harness intercepts its reserved chat commands — including `/goal` —
before Codex is invoked. Send `/help` in a chat to list them; the full table and
the `//` literal escape are documented in the
[shared chat-command reference](../../terminal-harness/README.md#chat-commands).

`/new` and `/reset-session` clear the current group's Codex thread id while
preserving its selected workdir and Codex-owned transcript files. The next
normal prompt starts and records a new Codex thread; a failed resumed prompt is
never retried automatically. `/goal <text>` stores a standing instruction that
the harness prepends to every later prompt in that chat, which keeps the
instruction alive across thread resets and Codex-side context compaction.

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `MARMOT_HOME` | `~/.marmot-agents/codex` | Isolated Codex connector home |
| `MARMOT_AGENT_SOCKET` | `$MARMOT_HOME/dev/wn-agent.sock` | Control socket |
| `MARMOT_AGENT_AUTH_TOKEN_FILE` / `MARMOT_AGENT_AUTH_TOKEN` | unset | Optional control authentication |
| `WN_CODEX_ALLOWED_SENDERS_HEX` | required | Comma-separated authorized sender ids |
| `WN_CODEX_ACCOUNT_ID_HEX` | sole local account | Explicit account selection |
| `WN_CODEX_BIN` | `codex` | Codex executable |
| `MARMOT_HARNESS_EXECUTION_PROFILE` | `inherit` | Shared `inherit`, `autonomous`, or `unrestricted` execution policy |
| `WN_CODEX_IDLE_TIMEOUT_SECS` | `120` | Presentation-idle interval before liveness is reported as unknown; does not stop the invocation |
| `WN_CODEX_TIMEOUT_SECS` | `3600` | Total invocation cap |
| `WN_CODEX_REQUEST_TIMEOUT_SECS` | `30` | Control connect/write and ordinary response timeout. Inbound media-download responses wait at least 16 minutes. Artifact `send_media` responses wait at least 451 minutes: 10 attachments, 3 Blossom servers each, 15 minutes per upload, plus 1 minute |
| `WN_CODEX_MAX_REPLY_BYTES` | `30000` | Durable reply chunk limit |
| `WN_CODEX_MAX_PENDING_PER_GROUP` | `4` | Per-group prompt queue limit |
| `WN_CODEX_MAX_ATTACHMENTS` | `8` | Maximum inbound files in one turn |
| `WN_CODEX_MAX_ATTACHMENT_BYTES` | `67108864` | Maximum aggregate plaintext bytes in one inbound batch |
| `WN_CODEX_STATE_PATH` | `$XDG_STATE_HOME/wn-codex/sessions.json` | Group thread/workdir map |
| `WN_CODEX_ACTIVATION` | `always` | Only supported activation mode |
| `WN_CODEX_ARTIFACT_EXPORTS_ENABLED` | `false` | Opt in to typed Codex completion-file artifact delivery |
| `WN_CODEX_ARTIFACT_GRANTS_JSON` | unset | Required JSON array of exact `group_id_hex`, absolute `export_root`, and positive `ttl_seconds` grants |
| `WN_CODEX_ARTIFACT_MAX_COUNT` | `10` | Maximum artifacts accepted per result; configurable from 1 to 10 |
| `WN_CODEX_ARTIFACT_STAGING_ROOT` | `$MARMOT_HOME/media-uploads` | Private staging root that must also be passed to `wn-agent --media-allowed-root` |

Artifact export is fail-closed and Codex-only in the initial release. Enable it
only with both layers configured.

The following is a manual daemon example, not a second daemon to run beside
an installed service. Update/restart the existing daemon with the same approved
staging-root flag, or run it manually as shown. Create the private staging root
first, configure the real chat/root grant, and start `wn-codex` in a second
terminal that exports these same `WN_CODEX_ARTIFACT_*` values and the account /
sender settings. For managed installs, persist the values in the harness's
actual service environment; changing only `dev/wn-codex.env` does not change the
generated service. Do not start with a placeholder grant or claim export works
before a completion manifest is accepted and the file appears in White Noise.

```sh
export WN_CODEX_ARTIFACT_EXPORTS_ENABLED=true
export WN_CODEX_ARTIFACT_GRANTS_JSON='[{"group_id_hex":"<opaque-hex-group-id>","export_root":"'"$HOME"'/src/my-project/output","ttl_seconds":300}]'
export WN_CODEX_ARTIFACT_STAGING_ROOT="$MARMOT_HOME/media-uploads"
install -d -m 0700 "$WN_CODEX_ARTIFACT_STAGING_ROOT"
wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --media-allowed-root "$WN_CODEX_ARTIFACT_STAGING_ROOT" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
```

Codex receives one connector-minted, turn-scoped capability only through `WN_ARTIFACT_AUTHORIZATION_ID`. The authorized export location is supplied as a workdir-relative path when it sits under the working directory; otherwise Codex sees `$WN_ARTIFACT_EXPORT_ROOT` and the path stays in that process-local environment variable. The private completion-manifest path is never written into the prompt: when it cannot be expressed relative to the workdir, Codex receives it only as `$WN_ARTIFACT_MANIFEST`. The harness never scans assistant prose for paths. Each declaration uses a relative path to a regular non-symlink file beneath the authorized root. The harness copies accepted bytes into its private staging root, persists the pending send before calling `send_media`, and replays that idempotent send after restart until `wn-agent` confirms it.

Codex credentials, model, config, and project trust remain authoritative.
`autonomous` overrides only `approval_policy` to `never`, preserving configured
sandbox and network policy. `unrestricted` passes
`--dangerously-bypass-approvals-and-sandbox` for both new and resumed threads.
See the shared
[execution-profile capability matrix](../../terminal-harness/README.md#execution-profiles).
Prompts are written to Codex over stdin, and only completed `agent_message`
text is returned to Marmot.

## Inbound attachments

All attachments from one Marmot message are downloaded in message order, copied into one owner-only temporary batch, and passed to one Codex turn. The connector revalidates every staged file immediately before starting Codex and supplies an ordered JSON manifest in the prompt. The manifest marks attachment content and metadata as untrusted data and gives Codex the private path, connector-sanitized staged file name, declared media type, byte size, and source ordinal. Delivery is selected from file bytes, never from sender-controlled MIME strings or extensions:

| File class | Byte-level recognition | Codex delivery |
| --- | --- | --- |
| Native images | PNG, JPEG, GIF, or WebP signature | Ordered native `--image` argument plus staged-file manifest entry |
| Text and source | Complete file is valid UTF-8 and contains no NUL byte (ANSI-coloured logs are accepted) | Staged-file manifest entry |
| PDF | `%PDF-` signature | Staged-file manifest entry |
| Audio | WAV, MP3, or FLAC header; or an Ogg first packet identifying Vorbis, Opus, or FLAC | Staged-file manifest entry |
| Archives | ZIP, gzip, bzip2, xz, 7z, RAR, or ustar-format tar signature | Staged-file manifest entry |
| Other image formats, opaque binary, or any unrecognized format | No supported signature and not UTF-8 text | Unsupported; reject the complete batch before starting Codex |

The compatibility pin for this matrix is Codex CLI 0.155.1. Its `codex exec` surface exposes native file input only through `--image`; the connector probes `codex exec --help` before any native-image turn and gives an actionable pre-spawn error when that capability is absent or cannot be checked. A failed image capability probe rejects the complete mixed batch instead of silently dropping or demoting an image. Non-image files do not rely on a version-specific CLI flag: their private paths are supplied in the stdin prompt manifest and Codex reads them with its normal file tools. The app-server v2 protocol separately exposes structured local image and audio inputs at [`openai/codex@78245b47`](https://github.com/openai/codex/blob/78245b47af2a7aafcabe025828ceecca69db4df1/codex-rs/app-server-protocol/src/protocol/v2/turn.rs#L425-L456), but this connector invokes `codex exec`, not app-server, so audio uses the staged-file fallback instead of being mislabeled as an image.

The same delivery contract applies to new and resumed threads. Missing, size-changed, unreadable, non-regular, unsupported-format, count-limit, or aggregate-size failures reject the complete batch before Codex starts; no attachment is silently dropped. Recognition is capability routing rather than a content-security boundary: short magic signatures can be spoofed, and attachment contents remain untrusted.

The ordinary 30-second control timeout applies to socket connection and request writing, but not to waiting for a media download: that response gets at least sixteen minutes. This permits the runtime's full fifteen-minute acquisition plus local validation without making unrelated control calls hang for minutes. A failed download still rejects the whole batch before Codex starts; the longer wait does not weaken file or ciphertext validation.

Batch copies remain available for the complete turn and are removed after success, failure, timeout, or cancellation. Stale batch directories are reconciled when the connector starts. The staging directory is owner-only and each file is owner-readable only. On Unix, immediate pre-spawn validation refuses a symlink final component and performs an exact-size bounded read through the opened file descriptor; the backend necessarily receives a path, so other processes running as the connector's own operating-system user remain inside the trust boundary.

## Security Notes

- The configured sender list controls prompt execution and is mirrored
  additively into the `wn-agent` welcomer allowlist. To revoke access, remove the
  sender from `WN_CODEX_ALLOWED_SENDERS_HEX`, restart `wn-codex`, and remove it
  from `wn-agent` separately if invite acceptance must also be revoked.
- Prompts are passed to Codex over stdin rather than process arguments.
- Only completed assistant messages are returned. Reasoning, command/tool
  events, partial items, and usage events are not sent to Marmot.
- Artifact export is disabled by default, rejects undeclared prose paths, and emits privacy-safe per-artifact rejection or pending-retry status without exposing host paths.
- Logs exclude identifiers, paths, prompts, Codex output, relay URLs, pubkeys,
  ciphertext, plaintext, and key material.
- Connector state is created with owner-only permissions by the shared harness.
- The optional control-socket bearer token grants the complete `wn-agent` control
  API for every account in its home; the sender allowlist does not narrow that
  authority. Use a separate connector home, socket, token, and account for a
  separate trust boundary.

## Development

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-codex
just codex-dev-e2e-connector
just codex-installer-test
cargo run -p wn-codex
bash scripts/install-codex-marmot.sh --dry-run --yes --allow-welcomer "$(awk 'BEGIN { for (i = 0; i < 32; i++) printf "11" }')" --codex-bin /bin/echo
```

The real Codex contract test is ignored by default because it requires an
installed, authenticated Codex CLI and makes model requests. The documented
compatibility matrix was validated with Codex CLI 0.155.1.
Its first turn proves that a staged non-image text attachment is readable, and
its second turn verifies session resume:

```sh
cargo test -p wn-codex real_codex_exec_contract -- --ignored --nocapture
```

The crate is a workspace member at `integrations/codex/marmot`. The upstream
event contract is documented in [Codex non-interactive
mode](https://learn.chatgpt.com/docs/non-interactive-mode).
