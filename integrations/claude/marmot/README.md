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

## Contents

- [What you can do](#what-you-can-do)
- [First-install checklist](#first-install-checklist)
- [Install (Claude Code Already Installed)](#install-claude-code-already-installed)
- [Manual Setup](#manual-setup)
- [Chat Commands](#chat-commands)
- [Configuration](#configuration)
- [Security Notes](#security-notes)
- [Development](#development)

## What you can do

For task titles and progress reactions, use the shared
[recommended chat setup](../../README.md#recommended-chat-setup), including
admin promotion and the phone acceptance test. Agent policy is in
[the integration instructions](../../AGENTS.md#suggested-agent-chat-instructions).
This harness does not register title/reaction tools. For that experience,
configure and verify a trusted helper available to the backend; admin promotion
or a `/goal` instruction alone is insufficient.

- **Work through Claude Code from your phone.** Send a prompt from an authorized
  White Noise account and use the backend's configured model and tools.
  Every allowed message activates the harness; mentioning the agent is not required.

- **Continue or reset the conversation.** Claude Code keeps a private UUID session for each chat and resumes that exact session. Completed main-conversation assistant text, including messages between tool calls, reaches the phone; reasoning and tool output do not.
  `/new` resets the backend session while retaining the project.

- **Know the file contract.** This adapter accepts text-only prompts. Any attachment batch, including its caption, is rejected before the backend runs. Generated-file return is not implemented.

Project selection (`/cd`), standing instructions (`/goal`), and recovery
commands share the [terminal-harness command guide](../../terminal-harness/README.md#chat-commands).

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

Verify Claude Code's native login and an ordinary local print-mode turn under
the service user. `WN_CLAUDE_BIN` / `--claude-bin` selects its executable; the
connector does not provision credentials, change model settings or reproduce
interactive TUI onboarding. Select a trusted project before prompting: print
mode skips the workspace-trust dialog, and `inherit` can deny unanswered
permission requests. Choose another execution profile only as an explicit
operator decision, not as an installation workaround.

Use a text-only first phone prompt. This backend rejects any non-empty
attachment batch before Claude Code starts, including the accompanying text;
there is no generated-file export or `MEDIA:` handling. The shared harness has
other backends with file support, but their capabilities are not inherited by
`wn-claude`. Do not resume its connector-owned UUID in another Claude client.

## Install (Claude Code Already Installed)

Prerequisites:

- Claude Code 2.1.0 or newer, installed, authenticated, and runnable on `PATH`,
  or an executable path set with `WN_CLAUDE_BIN` / `--claude-bin`
- White Noise pointed at the same public relay set
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

Versioned `wn-agent-v*` releases publish `wn-agent`, `wn-claude`, checksums, and
a same-user service installer. Verify the installer before executing it:

First copy the [verified installer helper](../../README.md#verified-installer-helper)
into this shell. Then select the release documented here:

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.12.0"
```

Run this example in the same shell where `install_verified` was defined.

```sh
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

In terminal 1, run the daemon only if its service is not already running:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/claude"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_CLAUDE_ALLOWED_SENDERS_HEX="<phone-public-key-as-64-hex-characters>"
wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
```

In terminal 2, export the same settings again, bootstrap the single sender in
this example, then start the harness only if its service is not already running:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/claude"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_CLAUDE_ALLOWED_SENDERS_HEX="<phone-public-key-as-64-hex-characters>"
wn-agent bootstrap --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --label claude-harness-agent --allow-welcomer "$WN_CLAUDE_ALLOWED_SENDERS_HEX" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat --qr
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

## Admin group profile updates

This harness exposes the shared `wn-agent group-profile` command to the agent
for the active conversation. It supports name and description changes for
current admins, partial updates and explicit clearing. See the
[shared control-command contract](../../terminal-harness/README.md#admin-group-profile-updates)
for routing, release compatibility, permissions and uncertain outcomes.

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

- Group-profile routing passes a configured bearer token as a raw child
  environment value, including tokens loaded from files. Trusted tool shells,
  MCP servers and other descendants may inherit its full connector authority.
  Backend environment filtering must preserve the turn's route and token;
  see the [shared control-command contract](../../terminal-harness/README.md#admin-group-profile-updates).

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
