# wn-claude

`wn-claude` is a terminal-harness connector that sends authorized Marmot group
messages to [Claude Code](https://code.claude.com/docs/en/overview) through the
local `wn-agent` control socket. It is intentionally a thin harness: no mention
activation, profile onboarding, live previews, MLS, relay, or storage logic.

The adapter uses Claude Code's documented non-interactive contract. It sends
prompts over stdin with `claude -p --output-format stream-json --verbose`,
creates fresh conversations with an adapter-generated UUID passed to
`--session-id`, and resumes only the stored UUID with `--resume`. It forwards
completed main-conversation assistant text messages, including assistant text
emitted between tool calls. Reasoning, tool calls and output, user echoes,
subagent messages, partial stream events, and the duplicate terminal `result`
text are ignored.

For the current guided install, runtime chooser, and White Noise setup, use the
canonical [White Noise + Agents quickstart](../../README.md#get-started-white-noise--agents).

## Install (Claude Code Already Installed)

Prerequisites:

- Claude Code 2.1.0 or newer, installed, authenticated, and runnable on `PATH`,
  or an executable path set with `WN_CLAUDE_BIN` / `--claude-bin`
- White Noise pointed at the same public relay set
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

Versioned `wn-agent-v*` releases publish `wn-agent`, `wn-claude`, checksums, and
a same-user service installer. Verify the installer before executing it:

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

base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.10.4"
install_verified "$base_url/install-claude-marmot.sh" \
  "$base_url/install-claude-marmot.sh.sha256" \
  --yes --allow-welcomer npub1...
```

The default install uses an isolated `~/.marmot-agents/claude` home, Marmot
identity, socket, and `wn-agent-claude` / `wn-claude` same-user services. It
does not share prompts, sessions, or replies with Codex, OpenCode, or Pi
harnesses unless an operator explicitly configures a shared deployment.

Report all installed versions when filing a connector bug:

```sh
wn-agent --version
wn-claude --version
claude --version
```

The startup version probe has a five-second deadline covering both process exit
and stdout EOF, with a 4 KiB output limit. Probe failure or timeout cleans up
inherited-pipe descendants as well as the direct process.

## Manual Setup

Install and authenticate Claude Code normally, then run an isolated `wn-agent`
identity and the harness:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/claude"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_CLAUDE_ALLOWED_SENDERS_HEX="..."

wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat

wn-agent bootstrap --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --label claude-harness-agent --allow-welcomer "$WN_CLAUDE_ALLOWED_SENDERS_HEX" --qr

wn-claude
```

On the first message, use `/<path>` to select a working directory under
`$HOME`. A picker-only message stores the directory without starting Claude.
Later prompts resume that group's exact Claude session UUID. `/new` and
`/reset-session` clear only the stored UUID while retaining the workdir and
Claude-owned transcript; the next prompt starts a fresh UUID. `/help` lists the
shared harness commands.

## Chat Commands

Claude Code's interactive slash commands are not a remote control protocol for
this connector. The shared harness intercepts its reserved chat commands —
including `/goal`, `/new`, and `/reset-session` — before Claude Code starts.
Send `/help` in a chat for the complete list and use the documented `//` escape
when a literal slash-prefixed prompt should reach Claude Code.

The adapter starts one print-mode process per message. The shared harness runs
one invocation at a time within each group and permits separate groups to run
as independent lanes. Do not resume the connector-owned UUID concurrently from
another Claude Code client. V1 does not claim simultaneous TUI observation or
a shared event bus.

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `MARMOT_HOME` | `~/.marmot-agents/claude` | Isolated Claude connector home |
| `MARMOT_AGENT_SOCKET` | `$MARMOT_HOME/dev/wn-agent.sock` | Control socket |
| `MARMOT_AGENT_AUTH_TOKEN_FILE` / `MARMOT_AGENT_AUTH_TOKEN` | unset | Optional full control-socket authentication |
| `WN_CLAUDE_ALLOWED_SENDERS_HEX` | required | Comma-separated authorized sender ids |
| `WN_CLAUDE_ACCOUNT_ID_HEX` | sole local account | Explicit account selection |
| `WN_CLAUDE_BIN` | `claude` | Claude Code executable |
| `MARMOT_HARNESS_EXECUTION_PROFILE` | `inherit` | Shared `inherit`, `autonomous`, or `unrestricted` policy |
| `WN_CLAUDE_IDLE_TIMEOUT_SECS` | `120` | Presentation-idle interval before unknown-liveness status |
| `WN_CLAUDE_TIMEOUT_SECS` | `3600` | Total invocation cap |
| `WN_CLAUDE_REQUEST_TIMEOUT_SECS` | `30` | Control request timeout |
| `WN_CLAUDE_MAX_REPLY_BYTES` | `30000` | Durable reply chunk limit |
| `WN_CLAUDE_MAX_PENDING_PER_GROUP` | `4` | Per-group prompt queue limit |
| `WN_CLAUDE_MAX_ATTACHMENTS` | `8` | Maximum inbound files validated before backend rejection |
| `WN_CLAUDE_MAX_ATTACHMENT_BYTES` | `67108864` | Maximum aggregate inbound bytes validated before rejection |
| `WN_CLAUDE_STATE_PATH` | `$XDG_STATE_HOME/wn-claude/sessions.json` | Group session/workdir map |
| `WN_CLAUDE_ACTIVATION` | `always` | Only supported activation mode |

`inherit` leaves Claude Code's permission configuration unchanged.
`autonomous` selects `acceptEdits`, preserving configured denies while allowing
file edits without an interactive prompt; other unanswered permissions remain
denied in print mode. `unrestricted` passes
`--dangerously-skip-permissions` and requires explicit installer
acknowledgement plus external isolation. Claude Code does not provide an OS
sandbox for these modes.

Claude Code authentication, model choice, settings, hooks, MCP servers, and
project instructions remain authoritative. The adapter validates the installed
version at startup without reading or changing credentials or configuration.
The CLI contract and event schema were checked against Claude Code 2.1.270.

## Security Notes

- An allowlisted sender can cause Claude Code to read, modify, and execute code
  with the service user's authority. Use a dedicated OS user, container, or VM
  for broad execution profiles.
- Claude Code print mode skips its interactive workspace-trust dialog. Select
  only a working directory you already trust.
- Prompts travel over stdin and never appear in process arguments.
- Completed main-conversation assistant text is returned to Marmot. Raw errors,
  reasoning, tool events, user echoes, subagent messages, partial events, and
  the duplicate terminal `result` text are excluded.
- Non-empty attachment batches are rejected before Claude Code starts. The
  accompanying text is not forwarded.
- Connector state is owner-only, and logs exclude identifiers, paths, prompts,
  responses, session UUIDs, backend output, and key material.
- A configured control-socket bearer token grants the complete `wn-agent`
  control API for that home; it is not narrowed by the prompt sender allowlist.
- Never send provider credentials through Marmot. The connector reuses Claude
  Code's native local authentication.

## Development

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-claude
just claude-dev-e2e-connector
just claude-installer-test
cargo run -p wn-claude
```

The real backend contract test is ignored because it requires authenticated
Claude Code and makes model requests:

```sh
cargo test -p wn-claude real_claude_code_contract -- --ignored --nocapture
```

The upstream contracts are the official [CLI reference](https://code.claude.com/docs/en/cli-usage)
and [programmatic usage guide](https://code.claude.com/docs/en/headless).
