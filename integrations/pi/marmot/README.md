# wn-pi

`wn-pi` is a terminal-harness connector that sends authorized Marmot group
messages to [Pi](https://pi.dev) through the local `wn-agent` control socket.
It is intentionally a thin harness: no mention activation, media handling,
profile onboarding, live previews, MLS, or relay logic.

## Install (Pi Already Installed)

Versioned `wn-agent-v*` releases publish `wn-agent`, `wn-pi`, checksums, and a
same-user service installer for Linux and macOS:

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-pi-marmot.sh" | bash
```

For noninteractive setup, provide the allowed inviter and prompt sender:

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-pi-marmot.sh" | \
  bash -s -- --yes --allow-welcomer npub1...
```

The default install uses its own `~/.marmot-agents/pi` identity and services,
so it does not share prompts or replies with an installed OpenCode harness.

## Manual setup

Install Pi first and authenticate it normally, then run an isolated `wn-agent`
identity and the harness:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/pi"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_PI_ALLOWED_SENDERS_HEX="..."

wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat

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

## Development

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-pi
cargo run -p wn-pi
```
