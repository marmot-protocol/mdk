# wn-opencode

`wn-opencode` is a terminal-harness backend for Marmot. It runs
[OpenCode](https://opencode.ai/) through the local `wn-agent` connector and
sends every message from an allowed sender to `opencode run --format json`.

`wn-agent` owns the Marmot account, MLS state, Nostr transport, invite allowlist,
and durable encrypted sends. `wn-opencode` is intentionally thinner than the
Hermes and OpenClaw gateway integrations: it has no mention activation, media
handling, profile onboarding, or live previews. It is a pure harness for an
authorized operator.

For the current guided install, runtime chooser, and steps to finish in White Noise, use the canonical
[White Noise + Agents quickstart](../../README.md#get-started-white-noise--agents).

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

base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.15"
install_verified "$base_url/install-opencode-marmot.sh" \
  "$base_url/install-opencode-marmot.sh.sha256"
```

For repeatable noninteractive setup, pass the allowed inviter and prompt sender
as either an `npub` or raw hex public key:

Run this example in the same shell where `install_verified` above was defined.

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.15"
install_verified "$base_url/install-opencode-marmot.sh" \
  "$base_url/install-opencode-marmot.sh.sha256" \
  --yes --allow-welcomer npub1...
```

Use a versioned `wn-agent-v<version>` release URL when you need a pinned install.

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
| `WN_OPENCODE_ACCOUNT_ID_HEX` | first local account | Specific `wn-agent` account to use |
| `WN_OPENCODE_BIN` | `opencode` | OpenCode binary or executable path |
| `MARMOT_HARNESS_EXECUTION_PROFILE` | `inherit` | Shared `inherit`, `autonomous`, or `unrestricted` execution policy |
| `WN_OPENCODE_IDLE_TIMEOUT_SECS` | `120` | Kill the invocation when OpenCode produces no stdout line for this long |
| `WN_OPENCODE_TIMEOUT_SECS` | `3600` | Generous total safety cap for wedge recovery; ongoing output resets only the idle timer |
| `WN_OPENCODE_REQUEST_TIMEOUT_SECS` | `30` | Timeout for each control-socket request |
| `WN_OPENCODE_MAX_REPLY_BYTES` | `30000` | UTF-8 byte limit for each durable Marmot reply chunk |
| `WN_OPENCODE_MAX_PENDING_PER_GROUP` | `4` | Per-group in-flight/queued prompt cap |
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

## Session Reset

Send exactly `/reset-session` to clear the current Marmot group's OpenCode
session id. The harness intercepts the command, preserves the group's validated
workdir, does not delete OpenCode-owned transcripts, and confirms the result.
The next normal prompt creates and records a new OpenCode session in that
workdir. A failed resumed prompt is never retried automatically because the
original invocation may already have produced side effects.

The command name is reserved. Send `//reset-session` when the literal
`/reset-session` text should reach OpenCode; messages such as
`/reset-session please` are ordinary prompts.

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
