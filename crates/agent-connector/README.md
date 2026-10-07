# WN Agent Connector

This crate ships the `wn-agent` binary: the local White Noise agent connector.

`wn-agent` is the headless Marmot process that lets an agent runtime appear as a normal Marmot member. It owns the
Marmot account home, MLS state, Nostr relay IO, invite allowlists, durable encrypted sends, and live QUIC preview
composition. Agent runtimes stay thin: they run models and tools, then talk to `wn-agent` through the local
agent-control socket.

Supported integrations, all speaking the same [`agent-control`](../agent-control) protocol to this connector:

- Hermes (first supported adapter) at [`integrations/hermes/marmot`](../../integrations/hermes/marmot);
- OpenClaw, a TypeScript channel plugin at [`integrations/openclaw/marmot`](../../integrations/openclaw/marmot);
- `wn-claude`, `wn-codex`, `wn-opencode`, `wn-pi`, and `wn-goose`, pure Rust harnesses for Claude Code, Codex,
  OpenCode, Pi, and Goose at
  [`integrations/claude/marmot`](../../integrations/claude/marmot),
  [`integrations/codex/marmot`](../../integrations/codex/marmot),
  [`integrations/opencode/marmot`](../../integrations/opencode/marmot),
  [`integrations/pi/marmot`](../../integrations/pi/marmot), and
  [`integrations/goose/marmot`](../../integrations/goose/marmot). All five use the shared hardened runtime in
  [`integrations/terminal-harness`](../../integrations/terminal-harness).

## Contents

- [Names and versions](#names-and-versions)
- [What this crate owns](#what-this-crate-owns)
- [Run locally](#run-locally)
- [Invite policy](#invite-policy)
- [Outbound media paths](#outbound-media-paths)
- [Group profile updates](#group-profile-updates)
- [Control plane security](#control-plane-security)
- [Usage and diagnostics](#usage-and-diagnostics)
- [Portable admin profile command](#portable-admin-profile-command)
- [Release installs](#release-installs)

## Names and versions

- `agent-connector` is the Rust crate.
- `wn-agent` is the installed binary.
- "WN Agent" is the release track used for binary and adapter-install releases.

The WN Agent release tag has its own prefix (`wn-agent-v<version>`), but the numeric version is the root workspace
version from `Cargo.toml`. That keeps the agent binary, agent-control protocol, app runtime, and generated bindings in
one compatibility cohort while still letting maintainers publish only the WN Agent artifacts when that is all that
changed. See [`release.md`](../../release.md#wn-agent-release) for versioning and for cutting a release
(`just release-wn-agent <version>`, or `just release-all <version>` for the whole cohort).

## What this crate owns

This crate is process glue. It owns:

- `AgentConnector` and `serve_socket`;
- the `wn-agent` Unix-socket daemon;
- `wn-agent bootstrap`, `wn-agent import-identity`, and `wn-agent usage-diagnostics`;
- local socket binding, peer checks, file modes, and optional bearer-token auth;
- allowlist-backed welcome confirmation for local agent accounts;
- final Marmot sends and QUIC live-preview composition through the app runtime.

Agent-facing wire types live in [`agent-control`](../agent-control) and stream composition behavior in
[`agent-stream-compose`](../agent-stream-compose).

## Run locally

Start the connector with the same public relay set the phone app uses (`--home` is required):

```sh
install -d -m 0700 ~/.marmot-agent/dev/outbound-media
cargo run -p agent-connector --bin wn-agent -- \
  --home ~/.marmot-agent \
  --media-allowed-root ~/.marmot-agent/dev/outbound-media \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
```

By default the control socket is `<home>/dev/wn-agent.sock`, here:

```text
~/.marmot-agent/dev/wn-agent.sock
```

If startup reports `socket_path_too_long`, use a shorter `--home` or a shorter
`--socket` path inside a private directory. The private bind needs more room than
the final socket address alone. A custom `--socket` does not move the local
usage-diagnostics socket: use a shorter home if those controls are unavailable.
Regular control continues when the optional diagnostics socket cannot bind.
Keep the existing directory and socket permissions.

In another terminal, create or reuse the local agent account and print the phone invite details:

```sh
cargo run -p agent-connector --bin wn-agent -- bootstrap \
  --home ~/.marmot-agent \
  --qr
```

`bootstrap` prints the agent account id, `npub`, `nprofile`, relay hints, QUIC preview candidates, and optional
terminal QR. Invite that account from the phone app. When flags are omitted, `bootstrap` reads `MARMOT_HOME` (default
`~/.marmot-agent`), `MARMOT_AGENT_SOCKET`, `MARMOT_AGENT_AUTH_TOKEN` / `MARMOT_AGENT_AUTH_TOKEN_FILE` (default
`<home>/control.token` when present), `MARMOT_RELAYS`, and `MARMOT_QUIC_CANDIDATES` (default
`quic://quic-broker.ipf.dev:4450`; `--no-quic` omits it).

To keep an existing Nostr identity instead of generating one, import it before bootstrapping with
`wn-agent import-identity --identity-file <path>` (an owner-only regular file) or `--prompt` (masked `/dev/tty`
entry), optionally pinned with `--expected-identity <npub-or-hex>`.

Other daemon flags: `--socket`, `--socket-dir-mode` (default `0700`), `--socket-mode` (default `0600`),
`--auth-token-file`, and `--max-connections` (default 64). Development-only flags `--insecure-local-broker` (literal
loopback `quic://` candidates without certificate verification) and `--allow-loopback-relays` (loopback relays only;
private, link-local, and CGNAT stay rejected) must not be used in production.

Check the installed or locally built version with:

```sh
wn-agent --version
```

## Invite policy

Invite policy is account-scoped and defaults to `allowlist`: a pending group invite is accepted only when its
authenticated welcomer is on the account's configured `--allow-welcomer` list. An empty allowlist rejects every invite.

Set a production invite policy while bootstrapping or reusing an account:

```sh
wn-agent bootstrap \
  --home ~/.marmot-agent \
  --invite-policy any-authenticated-direct
```

The available policies are:

- `deny` — decline every invite while retaining any stored allowlist entries;
- `allowlist` — accept only authenticated welcomers on the account allowlist;
- `any-authenticated-direct` — accept any authenticated welcomer only when the resulting MLS group has exactly two
  members (the agent and one peer); the member count is checked once, when the invite is confirmed, and does not
  prevent later membership changes;
- `any-authenticated` — accept any authenticated welcomer, including invites to multi-party groups.

Every policy fails closed when the Welcome has no authenticated welcomer. Invite policy controls group admission only;
the Hermes, OpenClaw, or terminal-harness integration independently controls which admitted senders may invoke the
agent and whether multi-party messages require activation.

Local development may use `--dev-allow-any-invites` together with `--debug-controls`. The connector warns when this
mode is active and accepts any authenticated welcomer, but it still rejects a welcome whose authenticated author is
missing. Do not enable either development option in production.

## Outbound media paths

Path-based media sends are denied unless `wn-agent` starts with one or more `--media-allowed-root PATH` options. The
connector opens each root at startup, then accepts only regular files reached beneath that directory handle without
following symlinks. Hermes and OpenClaw validate their original media source, stage a short-lived copy under
`$MARMOT_OUTBOUND_MEDIA_DIR`, send that staged path, and remove it after the connector responds.

Use a dedicated staging directory, never `/`, a home directory, or a broad application data tree. For split Unix
users, make the gateway the directory owner and give the connector's shared group read/traverse access; staged files
are created `0640`. In split-container deployments, mount the same directory read-write in the gateway and read-only
in the connector. Omitting `--media-allowed-root` deliberately leaves media sends disabled.

## Group profile updates

The `group_profile_update` control request accepts an account id, group id, and at least one of `name` or
`description`. Omitted fields retain their current authenticated value; an empty string clears a field. MDK enforces the
256-byte name and 4096-byte description limits and requires the selected account to be a current group admin when
constructing the MLS commit. A successful `group_profile_updated` response carries the published commit's message ids.
A timeout can leave the result uncertain: read current group metadata before retrying, because this mutation has no
idempotency key yet.

## Control plane security

The v2 control plane is local-only:

- Unix socket only;
- default parent directory mode `0700`;
- default socket mode `0600`;
- same effective UID required when no token is configured;
- no TCP listener.

Live-preview sessions have a second, narrower bearer boundary. `StreamBegin` requires a nonempty envelope request id
and returns a fresh 256-bit capability. Every later stream operation must present that capability, which is compared
without data-dependent early exit and is never logged or persisted. A begin retry must reuse its original request id;
an exact retry returns the original capability, while a different request or a colliding stream id is rejected without
replacing the active session.

When the gateway and `wn-agent` run as different local service users, use a bearer token file plus group-readable socket
modes:

```sh
sudo install -d -m 0750 -o root -g marmot-agent /etc/marmot-agent
sudo sh -c 'umask 0137; openssl rand -hex 32 > /etc/marmot-agent/control.token'
sudo chown root:marmot-agent /etc/marmot-agent/control.token

cargo run -p agent-connector --bin wn-agent -- \
  --home ~/.marmot-agent \
  --auth-token-file /etc/marmot-agent/control.token \
  --socket-dir-mode 0770 \
  --socket-mode 0660 \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat

export MARMOT_AGENT_AUTH_TOKEN_FILE=/etc/marmot-agent/control.token
```

The control token is intentionally all-or-nothing. When configured, it replaces the peer-UID decision: every request
must present the token, and any process that can read it can subscribe to plaintext for every hosted account, send or
delete messages as those accounts, create accounts, change allowlists, publish account material, transfer media, and
use any enabled debug controls. There are no read-only, command, or per-account scopes.

Same-UID authorization is also full-control; the token changes who may cross the boundary, not what an authorized
client may do.

Treat one connector and token as one trust boundary. Give the token only to one trusted gateway identity, keep the file
owner-only (`0600`) where possible, and use group-read (`0640`) only for the specific split-user gateway deployment.
Processes sharing that gateway UID inherit the same authority. If Hermes, OpenClaw, another plugin, or another tenant
must not share full access, run a separate `wn-agent` with its own home, socket, token, and agent account instead of
sharing this socket. Rotate the token after suspected disclosure, and never place it in logs, command arguments, source
control, or a world-readable environment/config file.

World-readable or world-writable socket modes are rejected. Split-host gateways need a later authenticated remote control
plane; do not expose the Unix socket over TCP.

## Usage and diagnostics

`wn-agent usage-diagnostics show|enable|disable --home PATH [--json]` manages local combined OTLP/product consent. An
active daemon handles updates on a separate owner-only local socket; the agent-control protocol cannot grant consent.
The agent root has its own permission, independent from White Noise. See the
[host and operator contract](../../docs/marmot-architecture/usage-diagnostics.md).

## Portable admin profile command

`wn-agent group-profile` accepts one bounded JSON object on stdin with `name`,
`description`, or both and prints a JSON result. It requires an explicit
`MARMOT_AGENT_SOCKET`, `MARMOT_ACCOUNT_ID_HEX` and `MARMOT_GROUP_ID_HEX`; token
or token-file authentication uses the common connector environment.
`MARMOT_GROUP_PROFILE_TIMEOUT_SECS` defaults to 30 and accepts 1 through 300.
The four terminal harnesses supply this route per turn. The command does not
auto-select accounts or start another daemon. It preserves the protocol
operation's omission/clear semantics, UTF-8 limits and current-admin check.
Only a matching response with nonempty valid commit ids is success. An
unconfirmed transport or protocol outcome is unknown, never an automatic retry.

## Release installs

The canonical [White Noise + Agents quickstart](../../integrations/README.md#get-started-white-noise--agents) owns the
current release URLs, runtime chooser, phone onboarding, and repeatable agent/CI example for Hermes, OpenClaw,
Claude Code, Codex, OpenCode, Pi, and Goose. Connector-specific configuration, manual setup, security notes, and development
workflows live in each integration README under [`integrations/`](../../integrations/README.md).
