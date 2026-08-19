# wn-codex

`wn-codex` is a terminal-harness connector that sends authorized Marmot group
messages to [Codex](https://learn.chatgpt.com/) through the local
`wn-agent` control socket. It is intentionally a thin harness: no mention
activation, media handling, profile onboarding, live previews, MLS, or relay
logic.

It uses Codex's documented non-interactive JSONL interface: a new group starts
with `codex exec --json -`, and later messages resume the group's Codex thread
with `codex exec resume --json <thread-id> -`.

## Install (Codex Already Installed)

Versioned `wn-agent-v*` releases publish `wn-agent`, `wn-codex`, checksums, and
a same-user service installer for Linux and macOS.

Prerequisites:

- Codex installed, authenticated, and runnable on `PATH`, or an executable path
  set with `WN_CODEX_BIN` / `--codex-bin`
- White Noise phone app pointed at the same public relay set
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-codex-marmot.sh" | bash
```

For noninteractive setup, provide the allowed inviter and prompt sender:

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-codex-marmot.sh" | \
  bash -s -- --yes --allow-welcomer npub1...
```

The default install uses its own `~/.marmot-agents/codex` identity and services,
so it does not share prompts or replies with installed OpenCode or Pi harnesses.
It installs `wn-agent` and `wn-codex` in `~/.local/bin`, writes a private
`~/.marmot-agents/codex/dev/wn-codex.env`, and starts `wn-agent-codex` and
`wn-codex` same-user services where supported.

Use a versioned `wn-agent-v<version>` release URL for a pinned install. Report
all installed versions when filing a connector bug:

```sh
wn-agent --version
wn-codex --version
codex --version
```

## Manual Setup

Install Codex first and authenticate it normally, then run an isolated
`wn-agent` identity and the harness:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/codex"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_CODEX_ALLOWED_SENDERS_HEX="..."

# Shell 1: wn-agent runs in the foreground.
wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat

# Shell 2: bootstrap the identity, then start the harness.
wn-agent bootstrap --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --label codex-harness-agent --allow-welcomer "$WN_CODEX_ALLOWED_SENDERS_HEX" --qr

wn-codex
```

On the first message in a group, use `/<path>` to select a Git working
directory under `$HOME`. A picker-only message stores the workdir without
starting Codex. Subsequent prompts resume that group's Codex thread.

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `MARMOT_HOME` | `~/.marmot-agents/codex` | Isolated Codex connector home |
| `MARMOT_AGENT_SOCKET` | `$MARMOT_HOME/dev/wn-agent.sock` | Control socket |
| `MARMOT_AGENT_AUTH_TOKEN_FILE` / `MARMOT_AGENT_AUTH_TOKEN` | unset | Optional control authentication |
| `WN_CODEX_ALLOWED_SENDERS_HEX` | required | Comma-separated authorized sender ids |
| `WN_CODEX_ACCOUNT_ID_HEX` | sole local account | Explicit account selection |
| `WN_CODEX_BIN` | `codex` | Codex executable |
| `WN_CODEX_IDLE_TIMEOUT_SECS` | `120` | Maximum silence per invocation |
| `WN_CODEX_TIMEOUT_SECS` | `3600` | Total invocation cap |
| `WN_CODEX_REQUEST_TIMEOUT_SECS` | `30` | Control request timeout |
| `WN_CODEX_MAX_REPLY_BYTES` | `30000` | Durable reply chunk limit |
| `WN_CODEX_MAX_PENDING_PER_GROUP` | `4` | Per-group prompt queue limit |
| `WN_CODEX_STATE_PATH` | `$XDG_STATE_HOME/wn-codex/sessions.json` | Group thread/workdir map |
| `WN_CODEX_ACTIVATION` | `always` | Only supported activation mode |

Codex credentials, model, config, sandbox, approval policy, and project trust
remain authoritative. This first connector version deliberately adds no
permission-broadening flags; common permission/configuration controls will be
designed across all terminal harnesses separately. Prompts are written to Codex
over stdin, and only completed `agent_message` text is returned to Marmot.

The optional bearer token grants the complete `wn-agent` control API for every
account in its home; the sender allowlist does not narrow that authority. Use a
separate connector home, socket, token, and account for a separate trust
boundary.

## Security Notes

- The configured sender list controls prompt execution and is mirrored
  additively into the `wn-agent` welcomer allowlist. To revoke access, remove the
  sender from `WN_CODEX_ALLOWED_SENDERS_HEX`, restart `wn-codex`, and remove it
  from `wn-agent` separately if invite acceptance must also be revoked.
- Prompts are passed to Codex over stdin rather than process arguments.
- Only completed assistant messages are returned. Reasoning, command/tool
  events, partial items, and usage events are not sent to Marmot.
- Logs exclude identifiers, paths, prompts, Codex output, relay URLs, pubkeys,
  ciphertext, plaintext, and key material.
- Connector state is created with owner-only permissions by the shared harness.

## Development

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-codex
just codex-dev-e2e-connector
just codex-installer-test
cargo run -p wn-codex
bash scripts/install-codex-marmot.sh --dry-run --yes --allow-welcomer "$(printf '11%.0s' {1..32})" --codex-bin /bin/echo
```

The real Codex contract test is ignored by default because it requires an
installed, authenticated Codex and makes a model request:

```sh
cargo test -p wn-codex real_codex_exec_contract -- --ignored --nocapture
```

The crate is a workspace member at `integrations/codex/marmot`. The upstream
event contract is documented in [Codex non-interactive
mode](https://learn.chatgpt.com/docs/non-interactive-mode).
