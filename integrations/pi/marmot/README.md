# wn-pi

`wn-pi` is a terminal-harness connector that sends authorized Marmot group
messages to [Pi](https://pi.dev) through the local `wn-agent` control socket.
It is intentionally a thin harness: no mention activation, media handling,
profile onboarding, live previews, MLS, or relay logic.

For the current guided install, runtime chooser, and steps to finish in White Noise, use the canonical
[White Noise + Agents quickstart](../../README.md#get-started-white-noise--agents).

## Install (Pi Already Installed)

Versioned `wn-agent-v*` releases publish `wn-agent`, `wn-pi`, checksums, and a
same-user service installer for Linux and macOS:

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

base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.14"
install_verified "$base_url/install-pi-marmot.sh" \
  "$base_url/install-pi-marmot.sh.sha256"
```

For noninteractive setup, provide the allowed inviter and prompt sender:

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.14"
install_verified "$base_url/install-pi-marmot.sh" \
  "$base_url/install-pi-marmot.sh.sha256" \
  --yes --allow-welcomer npub1...
```

The default install uses its own `~/.marmot-agents/pi` identity and services,
so it does not share prompts or replies with an installed OpenCode harness.
It installs `wn-agent` and `wn-pi` in `~/.local/bin`, writes a private
`~/.marmot-agents/pi/dev/wn-pi.env`, and starts `wn-agent-pi` and `wn-pi`
same-user services where supported.

Use a versioned `wn-agent-v<version>` release URL for a pinned install. Report
all installed versions when filing a connector bug:

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
| `WN_PI_IDLE_TIMEOUT_SECS` | `120` | Maximum silence per invocation |
| `WN_PI_TIMEOUT_SECS` | `3600` | Total invocation cap |
| `WN_PI_REQUEST_TIMEOUT_SECS` | `30` | Control request timeout |
| `WN_PI_MAX_REPLY_BYTES` | `30000` | Durable reply chunk limit |
| `WN_PI_MAX_PENDING_PER_GROUP` | `4` | Per-group prompt queue limit |
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

The optional bearer token grants the complete `wn-agent` control API for every
account in its home; the sender allowlist does not narrow that authority. Use a
separate connector home, socket, token, and account for a separate trust
boundary.

## Security Notes

- The same configured sender list controls prompt execution and is mirrored
  additively into the `wn-agent` welcomer allowlist. To revoke access, remove the
  sender from `WN_PI_ALLOWED_SENDERS_HEX`, restart `wn-pi`, and remove it from
  `wn-agent` separately if invite acceptance must also be revoked.
- Prompts are passed to Pi over stdin rather than process arguments.
- Only completed assistant text is returned. Thinking, tool calls, tool output,
  and other Pi event types are not sent to Marmot.
- Logs exclude identifiers, paths, prompts, Pi output, relay URLs, pubkeys,
  ciphertext, plaintext, and key material.
- Connector state and Pi session directories are created with owner-only
  permissions.

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

The crate is a workspace member at `integrations/pi/marmot`.
