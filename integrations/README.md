# Marmot Integrations

This directory contains the connectors that let White Noise users chat with
existing agent runtimes through the local `wn-agent` service.

## Get Started: White Noise + Agents

You need:

- White Noise on your phone, with your account `npub` available;
- one supported agent runtime already installed, authenticated, and working on
  the same Mac or Linux machine where you will run the connector;
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel.

Choose the runtime you already use:

| Runtime | Connector style | Best fit |
| --- | --- | --- |
| Hermes | Gateway plugin | Rich chat history, reactions, media, and live previews |
| OpenClaw | Channel plugin | Rich gateway routing, media, and live previews |
| Codex | Terminal harness | Repository and coding tasks through Codex |
| OpenCode | Terminal harness | Repository and coding tasks through OpenCode |
| Pi | Terminal harness | Repository and coding tasks through Pi |

The guided installers prompt on the terminal for the White Noise account that
may invite and message the agent. They install release `wn-agent-v0.9.14`, create
an isolated White Noise identity for the selected connector, and start same-user
services where supported. Download each installer with its adjacent checksum,
verify it, and only then execute the local file:

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
```

### Hermes

Hermes 0.19.0 or newer must already be installed and working.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-hermes-marmot.sh" \
  "$base_url/install-hermes-marmot.sh.sha256"
```

### OpenClaw

OpenClaw 2026.7.1 or newer and Node 22.19 or newer must already be installed.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-openclaw-marmot.sh" \
  "$base_url/install-openclaw-marmot.sh.sha256"
```

### Codex

Codex must already be installed, authenticated, and runnable as `codex`.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-codex-marmot.sh" \
  "$base_url/install-codex-marmot.sh.sha256"
```

### OpenCode

OpenCode 1.18.18 or newer must already be installed and runnable as `opencode`.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-opencode-marmot.sh" \
  "$base_url/install-opencode-marmot.sh.sha256"
```

### Pi

Pi must already be installed, authenticated, and runnable as `pi`.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-pi-marmot.sh" \
  "$base_url/install-pi-marmot.sh.sha256"
```

### Finish In White Noise

Release 0.9.14 records the new agent's `npub` and `nprofile` in the
`bootstrap.json` path printed at completion. Display them with:

```sh
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["npub"]); print(d["nprofile"])' \
  "$HOME/.marmot-agents/codex/bootstrap.json"
```

Use `hermes`, `openclaw`, `codex`, `harnesses` (OpenCode), or `pi` in that path.
The updated source installers also show these values directly and render a
terminal QR when `qrencode` is installed; that improvement will apply to the
next immutable release.

1. Add the displayed agent identity in White Noise.
2. Invite it to a direct message or group from the account you authorized.
3. Send a test message.

Hermes and OpenClaw print one final gateway restart command because the installer
does not restart an existing gateway. Codex, OpenCode, and Pi services are
started by the default install. Their first group message can be `/<path>` to
select a working directory under your home directory.

### Repeatable Agent Or CI Setup

Use the immutable release URL and provide the authorized White Noise account
explicitly. Terminal harnesses and OpenClaw use the welcomer entry for both
invitation and prompt authorization.

Run this example in the same shell where `install_verified` above was defined.

```sh
OWNER_NPUB=npub1...
install_verified "$base_url/install-codex-marmot.sh" \
  "$base_url/install-codex-marmot.sh.sha256" \
  --yes --allow-welcomer "$OWNER_NPUB"
```

Replace `codex` in the URL with `openclaw`, `opencode`, or `pi`. Hermes keeps
invite acceptance and message-sender authorization explicit:

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-hermes-marmot.sh" \
  "$base_url/install-hermes-marmot.sh.sha256" \
  --yes --allow-welcomer "$OWNER_NPUB" --allow-user "$OWNER_NPUB"
```

Every installer verifies the downloaded binary and plugin assets against the
checksums from the same immutable release. For independent
verification of the installer itself, download its adjacent `.sha256` asset
before running it.

Use each connector's README for existing-identity imports, shared deployments,
execution profiles, manual service control, and development workflows.

## How The Connectors Fit Together

Current integrations:

- [`hermes/marmot`](hermes/marmot) - Hermes platform plugin.
- [`openclaw/marmot`](openclaw/marmot) - OpenClaw channel plugin.
- [`codex/marmot`](codex/marmot) - `wn-codex` Codex harness binary.
- [`opencode/marmot`](opencode/marmot) - `wn-opencode` OpenCode harness binary.
- [`pi/marmot`](pi/marmot) - `wn-pi` Pi harness binary.
- [`terminal-harness`](terminal-harness) - shared hardened runtime for the
  Codex, OpenCode, and Pi terminal harnesses.

All integrations are intentionally thin at the Marmot boundary. They do not own MLS
state, Nostr transport, local account storage, relay access, QUIC preview
transport, or durable encrypted sends. `wn-agent` owns those concerns and exposes
the local `marmot.agent-control.v2` newline-delimited JSON protocol over a Unix
socket.

Live-preview clients retain the v2 `stream_capability` returned by `stream_begin` only for the life of that preview and
present it on every later stream operation. They also reuse one stable envelope request id when retrying a timed-out
`stream_begin`; capabilities and control bearer tokens must never appear in logs.

## Default Install Topology

The release installers are published with the `wn-agent-v*` release family:

- `scripts/install-hermes-marmot.sh`
- `scripts/install-openclaw-marmot.sh`
- `scripts/install-codex-marmot.sh`
- `scripts/install-opencode-marmot.sh`
- `scripts/install-pi-marmot.sh`

By default the production-shaped installs create separate local agent identities
per connector:

| Integration | Home | Same-user service |
| --- | --- | --- |
| Hermes | `$HOME/.marmot-agents/hermes` | `wn-agent-hermes.service` / `org.marmot.wn-agent.hermes` |
| OpenClaw | `$HOME/.marmot-agents/openclaw` | `wn-agent-openclaw.service` / `org.marmot.wn-agent.openclaw` |
| Codex harness | `$HOME/.marmot-agents/codex` | `wn-agent-codex.service` / `org.marmot.wn-agent.codex` plus `wn-codex.service` / `org.marmot.wn-codex` |
| OpenCode harness | `$HOME/.marmot-agents/harnesses` | `wn-agent-harnesses.service` / `org.marmot.wn-agent.harnesses` plus `wn-opencode.service` / `org.marmot.wn-opencode` |
| Pi harness | `$HOME/.marmot-agents/pi` | `wn-agent-pi.service` / `org.marmot.wn-agent.pi` plus `wn-pi.service` / `org.marmot.wn-pi` |

Each home derives its own default socket at `$MARMOT_HOME/dev/wn-agent.sock` and
uses the public relay defaults shared with the phone app pilot setup. Codex,
OpenCode, and Pi use separate connector homes and Marmot identities by default. They share
implementation in `integrations/terminal-harness`, but they do not share prompts,
sessions, sockets, or services unless an operator explicitly configures a shared
deployment.

Hermes and OpenClaw install or patch their host-runtime plugin configuration and
then print restart guidance for the existing gateway. They do not restart the
gateway automatically. `wn-codex`, `wn-opencode`, and `wn-pi` each install their own harness
binary and service in addition to `wn-agent`, because they are standalone
harnesses rather than plugins loaded by an existing gateway.

## Identity Model

The default topology creates or reuses one Marmot account per connector home,
which means Hermes, OpenClaw, Codex, OpenCode, and Pi present as separate Nostr
identities when installed with default options.

Within each home, `wn-agent bootstrap` lists local-signing accounts and reuses one
when selection is unambiguous. If no local account exists, bootstrap creates one.
If more than one local-signing account exists, production integrations should
require an explicit account id instead of guessing.

The installers persist the selected account into connector-specific config:

- Hermes uses `MARMOT_ACCOUNT_ID_HEX` or the Marmot plugin config.
- OpenClaw uses `channels.marmot.accountIdHex` or `MARMOT_ACCOUNT_ID_HEX`.
- `wn-codex` uses `WN_CODEX_ACCOUNT_ID_HEX`.
- `wn-opencode` uses `WN_OPENCODE_ACCOUNT_ID_HEX`.
- `wn-pi` uses `WN_PI_ACCOUNT_ID_HEX`.

Installing all five connectors on one machine with default options therefore
creates distinct agent identities and distinct chat/group memberships.

## What Is Shared

Within one connector home, the host integration and its `wn-agent` share:

- the local Marmot account and Nostr public key;
- the local MLS/group state and app runtime projection;
- relay configuration and key-package/profile publication through `wn-agent`;
- the account-scoped welcomer allowlist used for invite acceptance;
- the local control socket and optional bearer-token gate;
- durable sends, deletes, media download staging, and idempotency handled by
  `wn-agent`;
- the inbound event stream exposed by `SubscribeInbound`.

Across different default connector homes, those items are not shared.

Advanced deployments can still point multiple integrations at the same
`MARMOT_HOME` and socket. The control socket supports multiple clients, and
multiple integrations can subscribe to inbound events for the same account at the
same time.

## What Is Separate

Each host runtime keeps its own runtime state:

- Hermes keeps Hermes gateway/plugin state under `HERMES_HOME`.
- OpenClaw keeps OpenClaw gateway/channel state under `OPENCLAW_HOME`.
- `wn-codex` keeps harness configuration in `$MARMOT_HOME/dev/wn-codex.env`
  and session state under `$XDG_STATE_HOME/wn-codex` by default.
- `wn-opencode` keeps harness configuration in
  `$MARMOT_HOME/dev/wn-opencode.env` and session state under
  `$XDG_STATE_HOME/wn-opencode` by default.
- `wn-pi` keeps harness configuration in `$MARMOT_HOME/dev/wn-pi.env`, connector
  state under `$XDG_STATE_HOME/wn-pi`, and Pi sessions under
  `$MARMOT_HOME/dev/pi-sessions` by default.

Each integration also makes its own activation decision:

- Hermes and OpenClaw are gateway/channel integrations. In multi-party groups
  they default to mention-style activation and always reply in effective DMs.
  They also support richer gateway features such as live previews, durable reply
  routing, profile onboarding, and media handling.
- `wn-codex`, `wn-opencode`, and `wn-pi` are pure harnesses. They currently support only
  `always` activation for prompt messages from explicitly allowed senders, and
  have no media, profile onboarding, or live-preview behavior.

Because activation is per integration, there is no global "claim this message"
lease in shared-account deployments. If several integrations subscribe to the
same account and group, every eligible integration can reply. For example, a
direct message from an allowlisted sender could trigger Hermes/OpenClaw,
`wn-codex`, `wn-opencode`, and `wn-pi` if all are running and configured for that account.

## Allowlist Behavior

The `wn-agent` welcomer allowlist is account-scoped, not integration-scoped. In
the default installer topology that means each connector has its own allowlist.
It matters most when several integrations are intentionally configured to manage
the same account.

Hermes and OpenClaw can mirror configured `allowFrom`/welcomer entries into
`wn-agent`. Their sync path is config-driven and may reconcile the connector
allowlist to the configured set. All terminal harnesses require at least one
allowed sender and install those senders into both the prompt allowlist and the
`wn-agent` welcomer allowlist. Their startup mirroring is additive: removing a
sender only from `wn-agent` is not a full harness revoke while the sender remains
in `WN_CODEX_ALLOWED_SENDERS_HEX`, `WN_OPENCODE_ALLOWED_SENDERS_HEX`, or
`WN_PI_ALLOWED_SENDERS_HEX`.

For shared-account deployments, prefer one explicit source of truth for the
account's allowed welcomers, or configure every integration with the same
intended union.

## Sharing Options

Run the default installers when you want each connector to appear as its own
agent identity.

Use an explicit shared deployment when you want one Marmot identity behind
several integrations:

- one shared `MARMOT_HOME`;
- one shared `MARMOT_AGENT_SOCKET`;
- one `wn-agent` service owning that socket;
- explicit account ids in each integration config;
- `--no-service` for secondary installers, or manual service units with a single
  owner for the shared socket;
- separate host-runtime homes such as `HERMES_HOME` and `OPENCLAW_HOME` if the
  gateway runtimes themselves should stay isolated.

The current Hermes, OpenClaw, and terminal-harness release installers are
optimized for isolated defaults. They also expose `MARMOT_HOME`,
`MARMOT_AGENT_SOCKET`, `MARMOT_AGENT_SERVICE_NAME`, and
`MARMOT_AGENT_LAUNCHD_LABEL` overrides for advanced layouts.

If `wn-agent` and a host gateway run as different local users, keep the socket
Unix-domain only and use the existing socket mode plus bearer-token options:
`--auth-token-file`, group-readable socket modes, and
`MARMOT_AGENT_AUTH_TOKEN_FILE`.

That bearer is a full-daemon credential, not an account selector or a read-only
integration key. A holder can read all inbound plaintext and perform every
control operation for every account in that connector home. Share a connector
only among integrations in the same trust boundary. For a less-trusted plugin,
gateway, or tenant, use another `wn-agent` home, socket, token, and account.

## Development Paths

Each integration has its own README and AGENTS file for local details. Common
entry points from the repo root:

```sh
just hermes-dev-script-test
just hermes-dev-e2e-deterministic
just hermes-dev-e2e-connector

just openclaw-dev-test
just openclaw-dev-script-test
just openclaw-dev-e2e-connector

cargo test -p wn-codex
just codex-dev-e2e-connector
just codex-installer-test

cargo test -p wn-opencode
just opencode-dev-e2e-connector
just opencode-installer-test

cargo test -p marmot-terminal-harness

cargo test -p wn-pi
just pi-dev-e2e-connector
just pi-installer-test
```

For release-installer work, test dry-runs and real release assets from the
`wn-agent-v*` release family. Do not assume a source checkout script exactly
matches the published installer.
