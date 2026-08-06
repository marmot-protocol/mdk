# Prime Agent Marmot Connector

`wn-prime-agent` connects Marmot groups to Prime Agent 0.7.0 through its daemon protocol v7. It reuses `marmot-terminal-harness` for the `wn-agent` control socket, allowlists, bounded per-group queues, durable replies, private session mappings, and optional QUIC previews. The connector is a native Rust adapter; it does not depend on Prime Agent's TypeScript client library.

## Architecture

```text
Marmot group
    |
    v
wn-agent control socket
    |
    v
wn-prime-agent (shared terminal harness + protocol adapter)
    |
    v
Prime Agent daemon protocol v7 over a private Unix socket
    |
    v
resident Prime Agent session/worker
```

The adapter attaches to an existing daemon when one is listening. Otherwise it starts:

```sh
prime-agent --mode daemon --daemon-socket <private-socket>
```

The harness service owns that child process through its service cgroup. A normal service stop or restart therefore stops the daemon as well; the next harness process starts it again. A separately managed daemon at `WN_PRIME_AGENT_DAEMON_SOCKET` can also be used.

## Requirements

- `wn-agent` and `wn-prime-agent` from the same MDK release.
- Prime Agent **0.7.0**, installed and authenticated for the service user.
- One or more explicitly allowlisted Marmot sender keys.

The production installer verifies the exact supported Prime Agent version before writing services. At runtime the connector also requires daemon protocol `7`, schema revision `13`, and app version `0.7.0` exactly before sending a command. Compatibility is pinned to upstream commit `c22549a37b73cc603c6f0d202517cb0ca856c7d3`. Override `WN_PRIME_AGENT_REQUIRED_VERSION` only while developing against a deliberate protocol-compatible build; a runtime app-version mismatch remains a hard failure.

## Install

From a checkout:

```sh
scripts/install-prime-agent-marmot.sh \
  --allow-welcomer <npub-or-hex> \
  --allow-sender <hex-pubkey>
```

From a release:

```sh
curl -fsSL \
  https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v<VERSION>/install-prime-agent-marmot.sh \
  | bash -s -- --allow-welcomer <npub-or-hex> --allow-sender <hex-pubkey>
```

The default installation is isolated under `~/.marmot-agents/prime-agent` and creates two per-user services:

- `wn-agent-prime-agent` / `org.marmot.wn-agent.prime-agent`
- `wn-prime-agent` / `org.marmot.wn-prime-agent`

These names and paths do not collide with Hermes, OpenClaw, OpenCode, or Pi connector installations.

## Configuration

The installer writes a private environment file. Direct launches use the same variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `WN_PRIME_AGENT_ALLOWED_SENDERS_HEX` | Comma-separated Marmot sender hex keys | required |
| `WN_PRIME_AGENT_BIN` | Prime Agent executable | `prime-agent` |
| `WN_PRIME_AGENT_DAEMON_SOCKET` | Prime Agent daemon Unix socket | `$MARMOT_HOME/dev/prime-agent.sock` |
| `MARMOT_AGENT_SOCKET` | `wn-agent` control socket | `$MARMOT_HOME/dev/wn-agent.sock` |
| `MARMOT_HOME` | Connector state root | `~/.marmot-agents/prime-agent` |
| `WN_PRIME_AGENT_STATE_PATH` | Private group/session mapping | `$MARMOT_HOME/dev/sessions.json` |
| `MARMOT_ACCOUNT_ID_HEX` | Explicit local Marmot account | auto-resolved |
| `WN_PRIME_AGENT_TIMEOUT_SECS` | Total prompt timeout | `3600` |
| `WN_PRIME_AGENT_IDLE_TIMEOUT_SECS` | Daemon-output idle timeout | `120` |
| `WN_PRIME_AGENT_REQUEST_TIMEOUT_SECS` | `wn-agent` request timeout | `30` |
| `WN_PRIME_AGENT_MAX_PENDING_PER_GROUP` | Bounded per-group queue | `4` |
| `WN_PRIME_AGENT_MAX_REPLY_BYTES` | Durable reply chunk size | `30000` |
| `WN_PRIME_AGENT_QUIC_CANDIDATES` | Optional live-preview broker candidates | empty |

`WN_PRIME_AGENT_ACCOUNT_ID_HEX` remains accepted as a legacy fallback, but
`MARMOT_ACCOUNT_ID_HEX` takes precedence.

## Group and Session Semantics

The first group message must be `/<path>` selecting a canonical directory beneath the service user's home. The harness stores only the canonical directory, Prime Agent session file path and current active session id, and a stable hashed session name in a mode-`0600` state file. After a harness or Prime Agent daemon restart, it reloads the durable session file to recover conversation history before attaching to the new active session id.

Prompts for one Marmot group are serialized. A prompt received while that group's Prime Agent run is active is queued within the configured bound; it is not sent as a daemon steering message. Different groups may run concurrently.

The initial prompt creates a resident Prime Agent session with the selected repository as `cwd` and a stable top-level session name. Later prompts reopen the persisted `sessionPath`, which reuses the resident worker while the daemon is live. After a daemon restart, the connector recreates the resident session from that path, attaches to the newly assigned active session id, and persists the replacement id.

## Models and Attachments

A message consisting of `/model provider/model` changes the current Prime Agent
session model and returns a confirmation. Prime Agent validates the requested
pair during `set_model`; the command text is never submitted as a prompt.

Inbound images are sent as Prime Agent image content using base64 data and the validated media type. Other inbound files stay on the connector host and are referenced by their private downloaded path in the prompt. OpenCode and Pi retain their narrower no-attachment behavior.

Thinking, tool calls, and internal daemon events are not delivered to Marmot. Append-only assistant text deltas may drive an ephemeral QUIC preview, while only the daemon's final assistant text is sent durably.

## Development

```sh
cargo test -p wn-prime-agent --all-targets
just prime-agent-dev-e2e-connector
just prime-agent-installer-test
```

The process E2E test uses a fake protocol-v7 daemon fixture and requires no model credentials.

A real-daemon smoke test is ignored by default. Start an authenticated Prime Agent 0.7.0 daemon, then run:

```sh
WN_PRIME_AGENT_LIVE_SMOKE=1 \
WN_PRIME_AGENT_DAEMON_SOCKET=/path/to/prime-agent.sock \
cargo test -p wn-prime-agent live_daemon_smoke -- --ignored --nocapture
```

Set `WN_PRIME_AGENT_LIVE_SMOKE_CWD` to select a different repository. The smoke test sends one real model prompt and expects the exact response `PRIME_AGENT_CONNECTOR_OK`.

Diagnostics expose aggregate lengths, counts, protocol classifications, and session-presence booleans only. Do not add account ids, group ids, session ids, paths, prompts, assistant text, tool payloads, or credentials to tracing fields.
