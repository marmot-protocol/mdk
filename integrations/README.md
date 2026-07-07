# Marmot Integrations

This directory contains host integrations that let external agent runtimes talk
to Marmot through the local `wn-agent` connector.

Current integrations:

- [`hermes/marmot`](hermes/marmot) - Hermes platform plugin.
- [`openclaw/marmot`](openclaw/marmot) - OpenClaw channel plugin.
- [`opencode/marmot`](opencode/marmot) - `wn-opencode` harness binary.

All three are intentionally thin at the Marmot boundary. They do not own MLS
state, Nostr transport, local account storage, relay access, QUIC preview
transport, or durable encrypted sends. `wn-agent` owns those concerns and exposes
the local `marmot.agent-control.v1` newline-delimited JSON protocol over a Unix
socket.

## Default Install Topology

The release installers are published with the `wn-agent-v*` release family:

- `scripts/install-hermes-marmot.sh`
- `scripts/install-openclaw-marmot.sh`
- `scripts/install-opencode-marmot.sh`

By default they all use the same local connector deployment:

- `MARMOT_HOME=$HOME/.marmot-agent`
- `MARMOT_AGENT_SOCKET=$MARMOT_HOME/dev/wn-agent.sock`
- same-user `wn-agent` service where the platform supports it
- public relay defaults shared with the phone app pilot setup

Hermes and OpenClaw install or patch their host-runtime plugin configuration and
then print restart guidance for the existing gateway. They do not restart the
gateway automatically. `wn-opencode` installs its own harness binary and service
in addition to `wn-agent`, because it is a standalone harness rather than a
plugin loaded by an existing gateway.

## Identity Model

The default topology shares one Marmot account and therefore one Nostr identity.
`wn-agent bootstrap` lists local-signing accounts in `MARMOT_HOME` and reuses one
when selection is unambiguous. If no local account exists, bootstrap creates one.
If more than one local-signing account exists, production integrations should
require an explicit account id instead of guessing.

The installers persist the selected account into connector-specific config:

- Hermes uses `MARMOT_ACCOUNT_ID_HEX` or the Marmot plugin config.
- OpenClaw uses `channels.marmot.accountIdHex` or `MARMOT_ACCOUNT_ID_HEX`.
- `wn-opencode` uses `WN_OPENCODE_ACCOUNT_ID_HEX`.

So installing Hermes, OpenClaw, and opencode on one machine with default options
does not create three Marmot identities. It creates or reuses one `wn-agent`
identity and has each integration connect to it.

## What Is Shared

When integrations point at the same `MARMOT_HOME` and socket, they share:

- the local Marmot account and Nostr public key;
- the local MLS/group state and app runtime projection;
- relay configuration and key-package/profile publication through `wn-agent`;
- the account-scoped welcomer allowlist used for invite acceptance;
- the local control socket and optional bearer-token gate;
- durable sends, deletes, media download staging, and idempotency handled by
  `wn-agent`;
- the inbound event stream exposed by `SubscribeInbound`.

The control socket supports multiple clients. Multiple integrations can
subscribe to inbound events for the same account at the same time.

## What Is Separate

Each host runtime keeps its own runtime state:

- Hermes keeps Hermes gateway/plugin state under `HERMES_HOME`.
- OpenClaw keeps OpenClaw gateway/channel state under `OPENCLAW_HOME`.
- `wn-opencode` keeps harness configuration in
  `$MARMOT_HOME/dev/wn-opencode.env` and session state under
  `$XDG_STATE_HOME/wn-opencode` by default.

Each integration also makes its own activation decision:

- Hermes and OpenClaw are gateway/channel integrations. In multi-party groups
  they default to mention-style activation and always reply in effective DMs.
  They also support richer gateway features such as live previews, durable reply
  routing, profile onboarding, and media handling.
- `wn-opencode` is a pure harness. It currently supports only `always`
  activation for prompt messages from explicitly allowed senders, and it has no
  media, profile onboarding, or live-preview behavior.

Because activation is per integration, there is no global "claim this message"
lease. If several integrations subscribe to the same account and group, every
eligible integration can reply. For example, a direct message from an allowlisted
sender could trigger Hermes/OpenClaw and `wn-opencode` if all are running and
configured for that account.

## Allowlist Behavior

The `wn-agent` welcomer allowlist is account-scoped, not integration-scoped.
That is a good fit for the default shared identity model, but it matters when
several integrations manage the same account.

Hermes and OpenClaw can mirror configured `allowFrom`/welcomer entries into
`wn-agent`. Their sync path is config-driven and may reconcile the connector
allowlist to the configured set. `wn-opencode` requires at least one allowed
sender and installs those senders into both the prompt allowlist and the
`wn-agent` welcomer allowlist.

For shared deployments, prefer one explicit source of truth for the account's
allowed welcomers, or configure every integration with the same intended union.

## Isolation Options

Run the default installers when you want one machine identity shared by the
available gateways and harnesses.

Use explicit isolation when you want separate Marmot identities:

- separate `MARMOT_HOME` values;
- separate `MARMOT_AGENT_SOCKET` paths;
- explicit account ids in each integration config;
- separate service units or LaunchAgents with distinct names;
- separate host-runtime homes such as `HERMES_HOME` and `OPENCLAW_HOME`.

The current release installers are optimized for the shared default and use
fixed service labels such as `wn-agent.service`, `org.marmot.wn-agent`, and
`wn-opencode.service`. For multiple isolated identities on the same login, use
manual service units or the dev setup scripts as a template rather than running
the default installer repeatedly with only a different home path.

If `wn-agent` and a host gateway run as different local users, keep the socket
Unix-domain only and use the existing socket mode plus bearer-token options:
`--auth-token-file`, group-readable socket modes, and
`MARMOT_AGENT_AUTH_TOKEN_FILE`.

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

cargo test -p wn-opencode
just opencode-dev-e2e-connector
just opencode-installer-test
```

For release-installer work, test dry-runs and real release assets from the
`wn-agent-v*` release family. Do not assume a source checkout script exactly
matches the published installer.
