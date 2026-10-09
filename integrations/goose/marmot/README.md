# wn-goose

`wn-goose` is a terminal-harness connector that sends authorized Marmot group
messages to [Goose](https://github.com/aaif-goose/goose) through the local
`wn-agent` control socket. It is intentionally a thin harness: no mention
activation, profile onboarding, live previews, MLS, relay, or storage logic.

The adapter uses Goose's headless `run` contract. It sends prompts over stdin
with `goose run --instructions - --output-format stream-json --quiet`. It
creates new conversations with an adapter-generated session name passed to
`--name`, and resumes only that stored name with `--resume --name`. Goose's
stream output carries no session id, so the user-provided name is the session
handle; Goose never auto-renames a session whose name the caller provided.

Goose streams each assistant message as text deltas that share a message id.
The adapter joins those deltas and forwards each assistant message's text once
the next message starts or the run reports `complete`, including text emitted
between tool calls. Thinking, tool requests and responses, extension
notifications, hidden messages, and text addressed only to the model are
ignored. Text still pending when Goose reports a terminal error is dropped.

For the current guided install, runtime chooser, and White Noise setup, use the
canonical [White Noise + Agents quickstart](../../README.md#get-started-white-noise--agents).

## Contents

- [Install (Goose Already Installed)](#install-goose-already-installed)
- [Manual Setup](#manual-setup)
- [Chat Commands](#chat-commands)
- [Configuration](#configuration)
- [Security Notes](#security-notes)
- [Development](#development)

## Install (Goose Already Installed)

Prerequisites:

- Goose CLI 1.53.0 or newer, installed, configured with a provider, and
  runnable on `PATH`, or an executable path set with `WN_GOOSE_BIN` /
  `--goose-bin`. Follow Goose's own installation guide and verify what you
  download before running it.
- White Noise pointed at the same public relay set
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

Versioned `wn-agent-v*` releases publish `wn-agent`, `wn-goose`, checksums, and
a same-user service installer. Define the [verified installer helper](../../README.md#verified-installer-helper) first, then run this command in the same shell with `install_verified`:

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.12.0"
install_verified "$base_url/install-goose-marmot.sh" \
  "$base_url/install-goose-marmot.sh.sha256" \
  --yes --allow-welcomer npub1...
```

The default install uses an isolated `~/.marmot-agents/goose` home, Marmot
identity, socket, and `wn-agent-goose` / `wn-goose` same-user services. It does
not share prompts, sessions, or replies with the Claude Code, Codex, OpenCode,
or Pi harnesses unless an operator explicitly configures a shared deployment.

Report all installed versions when filing a connector bug:

```sh
wn-agent --version
wn-goose --version
goose --version
```

The startup version probe has a five-second deadline covering both process exit
and stdout EOF, with a 4 KiB output limit.

## Manual Setup

Install Goose and configure a provider with `goose configure`, then run an
isolated `wn-agent` identity and the harness:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/goose"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export WN_GOOSE_ALLOWED_SENDERS_HEX="..."

wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat

wn-agent bootstrap --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --label goose-harness-agent --allow-welcomer "$WN_GOOSE_ALLOWED_SENDERS_HEX" --qr

wn-goose
```

On the first message, use `/<path>` to select a working directory under
`$HOME`. A picker-only message stores the directory without starting Goose.
Later prompts resume that group's stored Goose session name. `/new` and
`/reset-session` clear only the stored name while retaining the workdir and the
Goose-owned session history; the next prompt starts a fresh session. `/help`
lists the shared harness commands.

## Chat Commands

Goose's interactive slash commands are not a remote control protocol for this
connector. The shared harness intercepts its reserved chat commands — including
`/goal`, `/new`, and `/reset-session` — before Goose starts. Send `/help` in a
chat for the complete list and use the documented `//` escape when a literal
slash-prefixed prompt should reach Goose.

The adapter starts one `goose run` process per message. The shared harness runs
one invocation at a time within each group and permits separate groups to run
as independent lanes. Do not resume a connector-owned `wn-goose-*` session from
another Goose client while the connector may use it.

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `MARMOT_HOME` | `~/.marmot-agents/goose` | Isolated Goose connector home |
| `MARMOT_AGENT_SOCKET` | `$MARMOT_HOME/dev/wn-agent.sock` | Control socket |
| `MARMOT_AGENT_AUTH_TOKEN_FILE` / `MARMOT_AGENT_AUTH_TOKEN` | unset | Optional full control-socket authentication |
| `WN_GOOSE_ALLOWED_SENDERS_HEX` | required | Comma-separated authorized sender ids |
| `WN_GOOSE_ACCOUNT_ID_HEX` | sole local account | Explicit account selection |
| `WN_GOOSE_BIN` | `goose` | Goose executable |
| `WN_GOOSE_PATH_ROOT` | unset | Optional absolute `GOOSE_PATH_ROOT` for the Goose child; created owner-only |
| `MARMOT_HARNESS_EXECUTION_PROFILE` | `inherit` | Shared `inherit` or `unrestricted` policy; `autonomous` is rejected |
| `WN_GOOSE_IDLE_TIMEOUT_SECS` | `120` | Presentation-idle interval before unknown-liveness status |
| `WN_GOOSE_TIMEOUT_SECS` | `3600` | Total invocation cap |
| `WN_GOOSE_REQUEST_TIMEOUT_SECS` | `30` | Control request timeout |
| `WN_GOOSE_MAX_REPLY_BYTES` | `30000` | Durable reply chunk limit |
| `WN_GOOSE_MAX_PENDING_PER_GROUP` | `4` | Per-group prompt queue limit |
| `WN_GOOSE_MAX_ATTACHMENTS` | `8` | Maximum inbound files validated before backend rejection |
| `WN_GOOSE_MAX_ATTACHMENT_BYTES` | `67108864` | Maximum aggregate inbound bytes validated before rejection |
| `WN_GOOSE_STATE_PATH` | `$XDG_STATE_HOME/wn-goose/sessions.json` | Group session/workdir map |
| `WN_GOOSE_ACTIVATION` | `always` | Only supported activation mode |

`inherit` leaves `GOOSE_MODE` and the Goose configuration unchanged. Goose's
headless `run` aborts the turn the first time a tool needs confirmation in
`approve` or `smart_approve` mode, so an inherited approval mode fails closed
rather than waiting for an answer. `unrestricted` sets `GOOSE_MODE=auto` on the
spawned process only; Goose's auto mode approves every tool call and does not
consult `never_allow` tool permissions, so it requires explicit installer
acknowledgement plus external isolation. `autonomous` is rejected at startup
and by the installer because no Goose mode avoids interactive asks while
keeping configured denies. Goose does not provide an OS sandbox.

Goose provider credentials, model choice, extensions, recipes, and session
storage remain authoritative. By default the child uses the operator's normal
Goose configuration and session database, where connector sessions appear as
`wn-goose-<uuid>`. Set `WN_GOOSE_PATH_ROOT` to give the connector its own Goose
config, data, and state root; that root then needs its own provider
configuration (`GOOSE_PATH_ROOT=... goose configure`). The adapter validates
the installed version at startup without reading or changing credentials or
configuration. The CLI contract and event schema were checked against the Goose
1.53.0 source.

## Security Notes

- An allowlisted sender can cause Goose to read, modify, and execute code with
  the service user's authority through its enabled extensions. Use a dedicated
  OS user, container, or VM for broad execution profiles.
- Select only a working directory you already trust; Goose loads project hints
  from it.
- Prompts travel over stdin and never appear in process arguments.
- Completed assistant text is returned to Marmot. Raw errors, thinking, tool
  events, notifications, hidden messages, and partial text are excluded.
- Non-empty attachment batches are rejected before Goose starts. The
  accompanying text is not forwarded.
- Connector state is owner-only, and logs exclude identifiers, paths, prompts,
  responses, session names, backend output, and key material.
- A configured control-socket bearer token grants the complete `wn-agent`
  control API for that home; it is not narrowed by the prompt sender allowlist.
- Never send provider credentials through Marmot. The connector reuses Goose's
  native local configuration.

## Development

```sh
cargo test -p marmot-terminal-harness
cargo test -p wn-goose
just goose-dev-e2e-connector
just goose-installer-test
cargo run -p wn-goose
```

The real backend contract test is ignored because it requires a configured
Goose provider and makes model requests:

```sh
cargo test -p wn-goose real_goose_contract -- --ignored --nocapture
```

The upstream contracts are Goose's CLI command and headless-run guides and its
`goose-cli` source (`src/cli.rs` and `src/session/mod.rs`).
