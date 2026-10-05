# WN Agent Connector

This crate ships the `wn-agent` binary: the local White Noise agent connector.

`wn-agent` is the headless Marmot process that lets an agent runtime appear as a normal Marmot member. It owns the
Marmot account home, MLS state, Nostr relay IO, invite allowlists, durable encrypted sends, and live QUIC preview
composition. Agent runtimes stay thin: they run models and tools, then talk to `wn-agent` through the local
agent-control socket.

Supported integrations, all speaking the same [`agent-control`](../agent-control) protocol to this connector:

- Hermes (first supported adapter) at [`integrations/hermes/marmot`](../../integrations/hermes/marmot);
- OpenClaw, a TypeScript channel plugin at [`integrations/openclaw/marmot`](../../integrations/openclaw/marmot);
- `wn-claude`, `wn-codex`, `wn-opencode`, and `wn-pi`, pure Rust harnesses for Claude Code, Codex, OpenCode, and Pi at
  [`integrations/claude/marmot`](../../integrations/claude/marmot),
  [`integrations/codex/marmot`](../../integrations/codex/marmot),
  [`integrations/opencode/marmot`](../../integrations/opencode/marmot), and
  [`integrations/pi/marmot`](../../integrations/pi/marmot). All four use the shared hardened runtime in
  [`integrations/terminal-harness`](../../integrations/terminal-harness).

## Contents

- [Names and versions](#names-and-versions)
- [What this crate owns](#what-this-crate-owns)
- [First installation from a White Noise prompt](#first-installation-from-a-white-noise-prompt)
- [Run locally](#run-locally)
- [Invite policy](#invite-policy)
- [Outbound media paths](#outbound-media-paths)
- [Group profile updates](#group-profile-updates)
- [Control plane security](#control-plane-security)
- [Usage and diagnostics](#usage-and-diagnostics)
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

## First installation from a White Noise prompt

The [recommended chat setup](../../integrations/README.md#recommended-chat-setup)
covers the trusted-agent admin default, task titles, progress reactions,
missing preference questions and a complete phone acceptance checklist.

White Noise's copied installation prompt links to this README. Installation
also requires the selected runtime's guide: the
[quickstart](../../integrations/README.md#get-started-white-noise--agents) links
Hermes, OpenClaw, Claude Code, Codex, OpenCode and Pi. Installing `wn-agent`
alone does not connect the model runtime or start its gateway/harness.
The detailed preflight is [Hermes profile selection](../../integrations/hermes/marmot/README.md#first-install-and-profile-selection),
[OpenClaw instance selection](../../integrations/openclaw/marmot/README.md#first-install-checklist),
or the [terminal-harness installation guide](../../integrations/terminal-harness/README.md#first-installation-and-verification)
with each backend's checklist. Compare the [connector capabilities](../../integrations/README.md#connector-capabilities)
to select the runtime that supports the required chat and file workflow.

The setup plan identifies the connector's local account/socket/service, the
runtime configuration being changed, the supplied **public** phone `npub`
authorization and the verification steps. The installation prompt includes an
approval step for that plan. The phone's npub is an inviter/sender identity,
not the agent's identity and never a secret key to import.

1. **Identify the runtime and its real state home.** Confirm its version,
   authentication and executable on PATH under the user that will run the
   service. A chat's working directory, profile display name or remembered
   default is not evidence of the active configuration directory. For Hermes,
   follow [First install and profile selection](../../integrations/hermes/marmot/README.md#first-install-and-profile-selection)
   before running the installer; pin `HERMES_HOME` for installation, plugin
   commands and gateway startup.
2. **Choose the topology.** For one gateway, reuse one connector home and one
   service owning its socket. For independent profile agents, choose a distinct
   `MARMOT_HOME`, socket, bootstrap label and same-user service name per profile.
   Changing only the Hermes home does not change the default `wn-agent-hermes`
   service. See [isolated and shared deployments](../../integrations/README.md#sharing-options).
   Do not start a second daemon against an existing home/socket to fix routing.
3. **Install a matching release cohort.** Download the chosen runtime's
   versioned release installer and checksum, verify the checksum, then run the
   local file with explicit home, relay and public-key allowlist options. Use
   the verified helper in the [quickstart](../../integrations/README.md#get-started-white-noise--agents).
   A checkout's installer/help may be newer than the published asset: use that
   asset's `--help` and the matching release, rather than mixing a new plugin
   with an older `wn-agent`. Source-only plugin installation does not install
   or start the connector.
4. **Verify the local wiring before the phone test.** The daemon, adapter and
   bootstrap must agree on home, socket and selected agent account. Use public
   relays shared with the phone; relay WebSocket URLs and Blossom HTTP upload
   URLs are different settings. Verify both the invite allowlist and the host
   runtime's allowed-message-sender list. An accepted invite does not grant
   permission to invoke the model. Restart only the intended gateway after
   plugin/configuration changes, using the deployment's supported procedure.
   If no service manager is available, the installer's bootstrap process is
   temporary; arrange a supervised connector and gateway/harness before leaving.
5. **Complete the round trip.** Return the bootstrapped **agent** npub/nprofile.
   The phone owner invites that identity and sends a test from the allowed
   phone account. Confirm an actual model reply reaches the same White Noise
   conversation. A socket, successful bootstrap, healthy doctor report or
   relay acknowledgement alone is not end-to-end delivery. If the phone test
   cannot be performed, report local checks separately and leave phone
   verification pending. Do not claim the installation complete.

### Sending a generated file

For Hermes, `MEDIA:<absolute-path>` only sends a regular file under the active
adapter's approved source roots; **stage the file there first**. Its default
source root is `$MARMOT_HOME/dev/inbound-media`. The adapter then copies it into
its separate outbound staging directory, which `wn-agent` must allow with
`--media-allowed-root`. See the [copy-and-send example](../../integrations/hermes/marmot/README.md#sending-a-generated-file).
Do not widen either root to `/` or the whole home to make a send succeed.

This convention is runtime-specific. OpenClaw uses its normal message tool's
media/attachment fields; terminal harnesses use only their documented artifact
export support. `MEDIA:` is not a universal `wn-agent` command. In a split-user
or container deployment, both processes must see the staged path with the
required permissions/mounts; a path in the model's workspace is not necessarily
a path the connector can read.

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

## Release installs

The canonical [White Noise + Agents quickstart](../../integrations/README.md#get-started-white-noise--agents) owns the
current release URLs, runtime chooser, phone onboarding, and repeatable agent/CI example for Hermes, OpenClaw,
Claude Code, Codex, OpenCode, and Pi. Connector-specific configuration, manual setup, security notes, and development
workflows live in each integration README under [`integrations/`](../../integrations/README.md).
