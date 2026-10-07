# OpenClaw Marmot Plugin

This directory is an [OpenClaw](https://docs.openclaw.ai) **channel plugin** for the
local `wn-agent` connector. OpenClaw runs the agent, model, tools, and channel
routing. `wn-agent` owns the Marmot account, MLS group state, Nostr transport,
durable encrypted sends, and QUIC live-preview stream records.

For the current guided install, runtime chooser, and steps to finish in White Noise, use the canonical
[White Noise + Agents quickstart](../../README.md#get-started-white-noise--agents).

The plugin is intentionally thin and **control-plane only**: it speaks the
`marmot.agent-control.v2` newline-delimited JSON protocol to `wn-agent` over a
local Unix socket. It never opens a QUIC connection, encrypts a record, or talks
to a relay — all of that stays in `wn-agent`. It is the OpenClaw counterpart of
the Python Hermes plugin in [`../../hermes/marmot/`](../../hermes/marmot).

- Pinned OpenClaw development SDK: **`openclaw@2026.7.1-2`**.
- Toolchain: TypeScript, pnpm, Node ≥ 22.19, Vitest.

## Contents

- [What you can do](#what-you-can-do)
- [First-install checklist](#first-install-checklist)

- [Admin group profile tool](#admin-group-profile-tool)
- [Install (release)](#install-release)
- [Dev setup](#dev-setup)
- [Docker phone test](#docker-phone-test)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Local gateway harness](#local-gateway-harness)
- [Tests](#tests)

## What you can do

For task titles and progress reactions, use the shared
[recommended chat setup](../../README.md#recommended-chat-setup), including
admin promotion and the phone acceptance test. Agent policy is in
[the integration instructions](../../AGENTS.md#suggested-agent-chat-instructions).
The registered `marmot_group_profile` tool updates the group name/description
when the account is an admin; the normal message tool supplies reactions.
Verify both tools in the installed release. See [Admin group profile tool](#admin-group-profile-tool).

- **Use your configured OpenClaw agent from White Noise.** Authorized prompts
  reach the gateway's model/tools and replies return to that conversation.
  Effective DMs activate automatically; multi-party groups use mentions or
  configured triggers unless `groupActivation: "always"` is selected.
- **Continue a group conversation.** Routing uses the full Marmot group id;
  distinct groups have independent FIFO dispatch. Reply quotes, recent history
  and quiet edit/delete/reaction/group changes supply context. `marmot_history`
  reads exact messages or pages older history.
- **Exchange files.** Received media is downloaded into the host's media path;
  actual interpretation depends on the model. Send files with OpenClaw's normal
  `message` tool media/attachment fields from an authorized workspace/store.
  Source authorization and connector staging authorization are separate checks.
  See [first file verification](#verify-text-and-files-separately).
- **Reply, react and retract own messages.** Normal assistant replies
  need no manual target. Explicit `message` sends target the MLS group id (a DM
  is also a group); the registered delete action retracts a prior own message. `message(action: "react",
  emoji: "👀", messageId: <id>, to: <group-id>)` adds a reaction; `remove: true`
  removes it. Use the exact target from the active conversation.
- **Publish an account display name with consent.** Profile-name onboarding
  asks before publishing a public Nostr name and remembers the answer.
- **Inspect channel readiness.** Healthy channel status requires the inbound
  subscription, invitation-policy reconciliation and a valid sender policy.
  A socket alone does not show that a sender can invoke the model.

The full settings and behavior contracts are in [Configuration](#configuration)
and [How it works](#how-it-works). Inbound turns currently deliver completed
answers only: live-preview primitives are tested but are not wired into that
turn path. Models, tools, routing policies and permissions remain OpenClaw-owned.
There is no connector setting for a personal Blossom server list today.

## First-install checklist

Use the connector's [first-install checklist](../../../crates/agent-connector/README.md#first-installation-from-a-white-noise-prompt)
with the [verified release instructions](#install-release) below. OpenClaw and
its model/provider configuration must already work as the OS user that runs
the gateway; the Marmot installer does not install or authenticate OpenClaw.

### Resolve the actual gateway configuration

Record which OpenClaw instance/profile and agent workspace the phone should
reach, then identify that gateway's effective state and config paths. The
[upstream environment guide](https://docs.openclaw.ai/help/environment) describes
`OPENCLAW_HOME`, `OPENCLAW_STATE_DIR` and `OPENCLAW_CONFIG_PATH`; explicit state /
config overrides can take precedence over home defaults. The Marmot installer
currently patches **`$OPENCLAW_HOME/.openclaw/openclaw.json`**. Its
`--openclaw-home` option is a base home, not a config-file path or OpenClaw
`--profile` selector, and it does not automatically follow a separately selected
state/config path.

For a default layout, export the confirmed base `OPENCLAW_HOME` before installing
so child plugin commands use the intended environment too. Check the dry-run's
config path and the gateway's real path agree. For a custom/named-profile
layout that does not match that path, do not let the installer write another
instance's default config: use `--no-configure-openclaw` and configure
`channels.marmot` in the intended instance with its supported configuration
workflow. Plugin installation/discovery must target that instance as well.
Do not assume selecting a profile only on a later gateway command repairs an
installation performed in a different profile.

Choose a distinct `MARMOT_HOME`, socket, bootstrap label and
`MARMOT_AGENT_SERVICE_NAME` / `MARMOT_AGENT_LAUNCHD_LABEL` for each independent
connector instance. Changing only the OpenClaw home does not rename the default
`wn-agent-openclaw` service. Keep one owner for an intentionally shared socket;
shared tokens grant full control, and overlapping active consumers can reply
more than once. Persist the actual configuration/environment in the owning
service, not merely in the shell used to run the installer.

### Configure both invitation and message authorization

`--allow-welcomer` and `dm.allowFrom` admit invitations. They do **not** configure
the account-global sender gate that permits OpenClaw model turns. After the
installer writes the selected agent `accountIdHex`, set the phone sender's
**public 64-character hex key** in the target config's sender policy, preserving
all other channel settings:

```json
{
  "channels": {
    "marmot": {
      "senderPolicy": {
        "allowedUsers": ["<phone-public-key-as-64-hex-characters>"],
        "allowAll": false
      }
    }
  }
}
```

This is a fragment to merge, not a replacement for the whole config file. Use
a real hex key, not the `npub1...` form accepted by the installer. An explicit
`senderPolicy` takes precedence over environment fallback; an invalid or empty
policy fails closed. For named channel accounts, put `senderPolicy` under
`channels.marmot.accounts.<name>`; they do not inherit a root or sibling policy.
Keep open access an explicit operator choice. Reload only
the selected gateway using its existing supervisor; the installer does not
restart it, and an additional foreground gateway is not a restart of an active
managed instance.

### Verify text and files separately

Invite the bootstrapped **agent** npub from the allowed phone account, send an
ordinary prompt, and verify a model reply in the same White Noise conversation.
Address the agent in a multi-party group according to its configured activation;
effective DMs activate without a mention. A running daemon, installed plugin
or successful invite alone does not prove dispatch or phone delivery.

For a generated file, place a regular readable source under the routed agent's
active workspace or an OpenClaw-managed media store and use the normal message
tool's `media` / `attachments` fields. Do not use a raw control-client call or
Hermes `MEDIA:` syntax. The plugin restages authorized bytes under
`MARMOT_OUTBOUND_MEDIA_DIR`; the one daemon must allow that same path with
`--media-allowed-root`. Before the file test, persist the daemon-approved
absolute path as `MARMOT_OUTBOUND_MEDIA_DIR` in the selected OpenClaw gateway's
service environment, then restart that gateway. This also applies to managed
release installs: the installer configures `channels.marmot.home` and the
daemon's allowed root, but does not set the existing gateway's media-staging
environment. An export in the installer shell does not configure a running
managed gateway. For the default release home, use the absolute path to
`~/.marmot-agents/openclaw/dev/outbound-media` (expand `~` before configuring the
service). Manual/container deployments must configure both sides and shared
path visibility. A successful text reply does not prove file delivery,
and local source-root permission does not change the remote Blossom endpoint.

## Admin group profile tool

The model-callable `marmot_group_profile` tool updates an existing group name,
description, or both through the selected Marmot delivery account. Supply
`group_id_hex` and at least one field. Omit a field to keep it; an empty string
clears it. Names are bounded to 256 UTF-8 bytes and descriptions to 4096 bytes.
MDK requires current group admin authority when committing. Successful replies
include the published commit message ids. Transport timeouts or invalid
acknowledgements have an unknown outcome and are never retried automatically;
check current group details before retrying. This tool preserves the existing
full-control socket authentication boundary.

The tool binds the selected account to the current delivery context but accepts
an explicit target group, like the message tool. This is intentionally not a
per-conversation capability: the selected account must be a current admin of
the target group. Use conversation metadata for the current group, and target
another group only when the user explicitly requests it.

## Install (release)

Versioned `wn-agent` builds and this plugin are published as [`wn-agent-v*`](https://github.com/marmot-protocol/mdk/releases)
GitHub pre-releases. OpenClaw must already be installed with `openclaw` on `PATH`.

Prerequisites:

- OpenClaw host **2026.7.1 or newer**. The installer validates the existing
  host and never installs or upgrades OpenClaw.
- Node ≥ 22.19
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel
- The plugin and `wn-agent` are released as one cohort. Install both from the
  same `wn-agent-v*` release: the plugin calls `stream_finish` with no fallback
  for older connectors.

First copy the [verified installer helper](../../README.md#verified-installer-helper)
into this shell. Then select the release documented here:

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.12.0"
```

Run this example in the same shell where `install_verified` was defined.

```sh
install_verified "$base_url/install-openclaw-marmot.sh" \
  "$base_url/install-openclaw-marmot.sh.sha256"
```

The installer puts `wn-agent` in `~/.local/bin`, downloads and verifies the plugin
tarball, runs `openclaw plugins install`, enables the `marmot` channel, starts a
same-user `wn-agent-openclaw` service where supported, bootstraps or reuses
`~/.marmot-agents/openclaw`, and patches only `channels.marmot` in OpenClaw config.
Supported platforms match the Hermes installer.
Set `MARMOT_RELEASE_REPO`, `MARMOT_RELEASE_TAG`, and `WN_AGENT_VERSION` (or the
legacy `WN_AGENT_SHA` alias) to install a non-default release asset, matching
the Hermes installer.

For repeatable noninteractive setup, pass the allowed inviter/welcomer as either
an `npub` or raw hex public key:

Run this example in the same shell where `install_verified` was defined.

```sh
# Reuse the selected base_url from the same shell above.
install_verified "$base_url/install-openclaw-marmot.sh" \
  "$base_url/install-openclaw-marmot.sh.sha256" \
  --yes --allow-welcomer npub1...
```

Generated-identity onboarding is the default (and can be selected explicitly
with `--generate-identity`). To preserve an existing Nostr identity, place its
`nsec` or raw secret hex in a regular file owned by the current user with mode
`0600`, then use the selected (or a saved, reviewed) release URL:

Run this example in the same shell where `install_verified` was defined.

```sh
# Reuse the selected base_url from the same shell above.
install_verified "$base_url/install-openclaw-marmot.sh" \
  "$base_url/install-openclaw-marmot.sh.sha256" \
  --yes \
  --existing-identity-file "$HOME/.config/example/openclaw-agent.nsec" \
  --expected-npub npub1... \
  --allow-welcomer npub1...
```

The installer passes only the file path, never the secret, in process arguments.
`wn-agent` rejects symlinks, non-regular files, files owned by another user, and
files accessible by group/other users. It verifies `--expected-npub` before
starting the connector or changing OpenClaw configuration, imports idempotently,
then bootstraps the exact account with creation disabled. During interactive
setup, the same identity can instead be entered through a masked `/dev/tty`
prompt, which remains usable when the installer itself arrives through a pipe.
The source credential file is read-only and is not rewritten or removed.
The `--expected-npub` value must be a public `npub` or public-key hex, never an
`nsec` or raw secret key.

OpenClaw keeps its isolated default connector home. Reusing the same identity in
another connector home, such as Hermes's, requires a separate explicit import;
the installers never opt into shared home/socket state silently.

The installer prints restart guidance for your existing OpenClaw gateway. It
does not restart OpenClaw automatically.

The following manual example bootstraps a generated local identity. To reuse
an existing identity instead, follow the connector's
[identity import instructions](../../../crates/agent-connector/README.md#run-locally)
before starting the daemon, then bootstrap with `--no-create` and
`--account-id-hex` set to the verified imported account. Keep that same account
in the OpenClaw channel configuration; do not place a secret key in it.

For manual startup, keep `wn-agent` in terminal 1, using the confirmed
home/socket and the daemon's separate outbound staging root:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/openclaw"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export MARMOT_OUTBOUND_MEDIA_DIR="$MARMOT_HOME/dev/outbound-media"
install -d -m 0700 "$MARMOT_OUTBOUND_MEDIA_DIR"
wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --media-allowed-root "$MARMOT_OUTBOUND_MEDIA_DIR" \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
```

In terminal 2, export the same settings, bootstrap an account with the allowed
phone inviter, configure the target OpenClaw channel/account and sender policy,
then start the gateway only if it is not already managed/running:

```sh
export MARMOT_HOME="$HOME/.marmot-agents/openclaw"
export MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
export MARMOT_OUTBOUND_MEDIA_DIR="$MARMOT_HOME/dev/outbound-media"
wn-agent bootstrap --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" \
  --label openclaw-agent --allow-welcomer npub1... \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat --qr
# After configuring channels.marmot in the confirmed OpenClaw instance:
openclaw gateway run
```

Invite the printed agent account from the phone app. The installer does not
copy `--allow-welcomer` / `dm.allowFrom` into sender policy. Before claiming
chat readiness, set `channels.marmot.senderPolicy` (raw 64-character account
hex, or `allowAll: true`) or export `MARMOT_ALLOWED_USERS` /
`MARMOT_ALLOW_ALL_USERS`, then restart the OpenClaw gateway. Reinstall
preserves an existing `senderPolicy`.

## Dev setup

```sh
just openclaw-dev-test                 # pnpm install + typecheck + vitest
just openclaw-host-compat-test         # build + focused runtime tests on supported beta
# The script installs into a throwaway tree and sets isolated OPENCLAW_HOME /
# OPENCLAW_STATE_DIR so host registry state cannot leak from the operator home.
# Beta send_final uses OpenClaw's SQLite delivery queue. On Node whose embedded
# SQLite is outside OpenClaw's WAL-safe range, that one host-contract check is
# treated as unavailable instead of failing the lane.
just openclaw-dev-script-test          # generated helper/env/installer contract test
just openclaw-dev-setup --print-env    # build + isolated dev root + helper scripts
just openclaw-dev-e2e-connector        # real wn-agent + debug control deterministic E2E
just openclaw-dev-teardown --force     # remove the throwaway dev root
```

`openclaw-dev-setup` builds the plugin, prepares an isolated dev root under
`${TMPDIR:-/tmp}/openclaw-marmot-test`, and generates:

- `env.sh` with isolated `OPENCLAW_HOME`, `MARMOT_HOME`, socket, relay,
  account/group, auth-token, and QUIC-preview environment variables.
- `run-wn-agent.sh` / `start-wn-agent.sh` for the local connector.
- `bootstrap-agent.sh` for `wn-agent bootstrap --qr` against that connector.
- `run-openclaw-gateway.sh` / `start-openclaw-gateway.sh` for the gateway.
- `smoke-plugin.sh` for typecheck + Vitest.
- `control-smoketest.sh` for the real `wn-agent` control socket smoke test.
- `e2e-connector.sh` for a model-free real `wn-agent` connector E2E.
- `stop-dev-processes.sh` for background helper cleanup.

Useful variants:

```sh
# Pin account/group env used by the plugin and smoke helpers.
just openclaw-dev-setup --account-id-hex <agent-account-hex> --group-id-hex <group-hex> --print-env

# Include relay and QUIC preview settings for generated helpers.
just openclaw-dev-setup \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat \
  --quic-candidate quic://quic-broker.ipf.dev:4450 \
  --print-env

# Use a token-gated local control socket for a group-shared OpenClaw/wn-agent setup.
just openclaw-dev-setup --auth-token "$(openssl rand -hex 32)" --socket-dir-mode 0770 --socket-mode 0660 --print-env
```

After setup:

```sh
source "${OPENCLAW_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/openclaw-marmot-test}/env.sh"
"$OPENCLAW_MARMOT_DEV_ROOT/start-wn-agent.sh"
"$OPENCLAW_MARMOT_DEV_ROOT/bootstrap-agent.sh"
"$OPENCLAW_MARMOT_DEV_ROOT/start-openclaw-gateway.sh"
```

The control-socket smoke test is model-free but requires a running `wn-agent`
and a `MARMOT_GROUP_ID_HEX` for send/delete/media steps:

```sh
just openclaw-dev-control-smoke
```

Run the deterministic connector E2E:

```sh
just openclaw-dev-e2e-connector
```

This test starts a real `wn-agent` process with debug controls enabled, injects
one inbound message through its local control socket, runs the OpenClaw Marmot
inbound runtime, and verifies the deterministic reply is sent back through
`wn-agent`. It is model-free and does not need a real Marmot account, group,
relay, phone, or OpenClaw gateway.

## Docker phone test

A Compose profile builds a container with `wn-agent`, OpenClaw, this plugin, and
`qrencode`. It starts `wn-agent` with `MARMOT_AGENT_DEV_ALLOW_ANY_INVITES=1`
and `MARMOT_AGENT_DEBUG_CONTROLS=1` so the first invite from an authenticated
phone lands without pre-seeding an allowlist (use an explicit allowlist and
omit both development options for a real deployment).

```sh
export OPENAI_API_KEY=...        # or ANTHROPIC_API_KEY / OPENROUTER_API_KEY / ...
just openclaw-phone-test-up
just openclaw-phone-test-bootstrap   # prints the agent npub/nprofile + QR
just openclaw-phone-test-logs
just openclaw-phone-test-down        # or -reset to wipe persisted data
```

Set `MARMOT_STREAM_MODE=partial` or `MARMOT_STREAM_MODE=progress` before
`just openclaw-phone-test-up` to exercise OpenClaw's windowed streaming modes
against a real phone; omit it for the default `block` mode.

## Configuration

Configure under `channels.marmot` in the OpenClaw config, or via `MARMOT_*`
environment variables (config wins). Keys mirror the Hermes plugin so an
advanced shared deployment can point both gateways at one `wn-agent`:

| Key (config) | Env | Default |
| --- | --- | --- |
| `home` | `MARMOT_HOME` | `~/.marmot` (the release installer writes `~/.marmot-agents/openclaw`) |
| `socketPath` | `MARMOT_AGENT_SOCKET` | `$MARMOT_HOME/dev/wn-agent.sock` |
| `authToken` | `MARMOT_AGENT_AUTH_TOKEN` | — |
| `authTokenFile` | `MARMOT_AGENT_AUTH_TOKEN_FILE` | — |
| `accountIdHex` | `MARMOT_ACCOUNT_ID_HEX` | sole local account |
| `groupIdHex` | `MARMOT_GROUP_ID_HEX` | — (no filter) |
| `quicCandidates` | `MARMOT_QUIC_CANDIDATES` (or singular `MARMOT_QUIC_CANDIDATE`) | — (final-only); filtered to the `quic://` scheme |
| `streaming.mode` | `MARMOT_STREAM_MODE` | `block` (`off`/`partial`/`block`/`progress`) |
| `blockStreaming` / `streaming.block.enabled` | `MARMOT_BLOCK_STREAMING` | `true` when QUIC candidates are configured and Marmot streaming is not `off` |
| `debounceMs` | `MARMOT_DEBOUNCE_MS` | `0` (off; coalesce rapid same-sender/group messages into one turn) |
| `groupActivation` | `MARMOT_GROUP_ACTIVATION` | `mention` (reply only when addressed in 3+ member groups; `always` replies to every message) |
| — | `MARMOT_OUTBOUND_MEDIA_DIR` | `$MARMOT_HOME/dev/outbound-media` (short-lived connector-approved staging copies) |
| `mentionPatterns` | `MARMOT_MENTION_PATTERNS` | — (extra case-insensitive trigger phrases; the configured agent name is always a trigger) |
| `profileNameOnboarding` | `MARMOT_PROFILE_NAME_ONBOARDING` | `true` |
| `dm.policy` / `dm.allowFrom` | — | `allowlist` (welcomer/inviter admission only) |
| `senderPolicy.allowedUsers` / `senderPolicy.allowAll` | `MARMOT_ALLOWED_USERS` / `MARMOT_ALLOW_ALL_USERS` | missing (deny every sender; not sender-ready) |

The QUIC/streaming settings are still accepted for configuration compatibility,
but inbound agent replies are currently delivered final-only.

`accountIdHex` is the Marmot/wn-agent account id. It is intentionally distinct
from OpenClaw's channel account id (`default`, or a key under
`channels.marmot.accounts`) used for routing, session metadata, and message-tool
target lookup.

The default control socket is same-UID only (parent dir `0700`, socket `0600`,
no TCP listener). If OpenClaw and `wn-agent` run as different local users, start
`wn-agent` with `--auth-token-file` + group-readable socket modes (`0660`) and
set `MARMOT_AGENT_AUTH_TOKEN_FILE`. See
[`crates/agent-connector/README.md`](../../../crates/agent-connector/README.md).
The token grants the full connector API for every hosted account, not only the
configured OpenClaw channel account. Use a separate connector home/socket/token
for any plugin or tenant that is not in the same trust boundary.

## How it works

The shared `message` tool exposes Marmot reaction add/remove through its
`react` action. Reactions target durable message ids; omitting `messageId`
targets the current inbound message. Removal requires explicit `remove: true`:
a non-empty `emoji` removes that exact content, while an omitted or empty
`emoji` removes all of the agent account's active reactions on the target.
Missing, empty, or non-string emoji values never implicitly remove reactions.
Repeating a removal is idempotent. Reaction content follows the
agent-control v2 bound: non-blank, control-free, and at most 64 Unicode scalar
values.

Agents send outbound media through OpenClaw's normal
`message(action="send", channel="marmot", media=..., attachments=...)` interface.
Generated files must be placed under the active agent workspace or an
OpenClaw-managed media store; data URLs are not supported. OpenClaw's
host-provided media reader is the source authorization boundary. The plugin
stages the authorized bytes as a private, short-lived copy under
`MARMOT_OUTBOUND_MEDIA_DIR`, while `wn-agent --media-allowed-root` independently
authorizes that staging path before encrypting and uploading it. Direct
`MarmotAgentControlClient.sendMedia()` calls are reserved for connector tests
and smoketests, not runtime agents.

For each activated inbound turn, the plugin asks `wn-agent` for a bounded recent
materialized chat window and supplies it to OpenClaw with durable message ids,
senders, timestamps, reply links, current reaction summaries, and
delete/invalidation state. Reply context is supplied through both OpenClaw's
native quote fields and a complete structured referenced-message payload.
The model-callable `marmot_history` tool can fetch one exact message id or page
older messages using the returned `(recorded_at, message_id_hex)` cursor.
History reads are best-effort for turn activation, so a temporary read failure
does not suppress the new inbound message.

Inbound dispatch uses a bounded per-group FIFO and a bounded active-group set.
Queue admission is explicit: accepted, debounce-coalesced, onboarding-intercepted,
and overload outcomes remain distinguishable through completion. Queued/running
message ids stay reserved so replay cannot start a second active turn; overload
releases the reservation so a later connector replay can retry. Pressure logs
contain only fixed reason classes and aggregate limits/counts, never identifiers.

- **Inbound → agent turn** (`src/dispatch.ts`): the gateway-owned inbound bridge
  feeds each received Marmot message (`chatId` = Marmot group id, `userId` =
  sender) into OpenClaw's turn kernel via `runChannelInboundEvent` +
  `dispatchReplyWithBufferedBlockDispatcher`. The trusted inbound context owns
  the destination. A nonempty cached group subject is passed only as the
  conversation `label` (native `ConversationLabel` / `GroupSubject`); session
  metadata also binds `record.groupResolution` to the full group id so the host
  session record is not keyed from the sender. A normal assistant final is passed to
  `deliverInboundReplyWithMessageSendContext`, which invokes the registered
  Marmot message adapter and threads the reply to the triggering message. The
  model never has to reconstruct or select the source group.
  Dispatch is serialized per group (distinct groups run concurrently, each group
  stays FIFO), so a slow turn in one group never blocks inbound for others; set
  `debounceMs` to coalesce rapid same-sender bursts into one turn.
- **Inbound sender authorization**: every authenticated inbound message is
  checked against an adapter-owned, account-global sender ACL *before*
  debounce, queue admission, profile onboarding, group-info lookup, media or
  history reads, session/route construction, or the OpenClaw turn kernel.
  Configure `channels.marmot.senderPolicy` (`allowedUsers` and optional
  `allowAll`) or, when that property is absent on the selected account, the
  Hermes-compatible environment fallback `MARMOT_ALLOWED_USERS` /
  `MARMOT_ALLOW_ALL_USERS`. Presence of `senderPolicy` replaces the entire
  environment policy atomically; it never unions with env and never falls
  through on invalid or empty config. Named accounts do not inherit a sibling
  or root policy. IDs are raw 64-character Marmot account hex (trim
  surrounding config whitespace, then require exact hex, lowercase, and
  dedupe). One invalid entry invalidates the whole policy, including
  `allowAll: true`. Envelope identities are stricter: no trimming or prefix
  repair, and self-authored or receiving-account-equal senders are denied
  even under allow-all. Missing policy or an empty list without explicit
  allow-all denies every sender and is not sender-ready. Changes take effect
  on account/gateway restart; this snapshot is not a roster cache. An allowed
  sender is not an OpenClaw owner/admin and does not gain extra tools or
  profiles. Denial is silent (no reply) and privacy-safe (fixed reason
  classes only).
- **Activation gating**: after a sender is authorized, in a multi-party group
  the agent replies only when addressed — it is `p`-tag mentioned, the text
  matches a `mentionPatterns` trigger (or the agent name), or the conversation
  is an effective DM (exactly two members, resolved via the `group_info`
  control op). Set `groupActivation: "always"` to reply to every authorized
  message. Effective DMs always reply. Activation may only narrow
  authorization; mentions, triggers, reply context, display names, and group
  content cannot widen it. A single bounded
  per-(account, group) cache stores both `is_direct` and the normalized
  group subject (display text only) so activation and native conversation
  metadata share one in-flight `group_info` read. The cache holds at most 256
  entries (hits, unnamed groups, label-failure cooldown, and pending lookups),
  evicts least-recently-used settled entries, and never keys, routes, or logs
  by subject. The first turn for a group pays one control-socket lookup; later
  turns reuse the warm named or unnamed hit. A failed label-only lookup keeps
  a 5-second retry-after and leaves that already-admitted turn unlabeled; a
  membership-required lookup ignores that cooldown and still fails **closed**
  (skips the turn) under the `mention` policy, then retries on the next
  message. Membership errors are not cached as `is_direct: false`. The cache
  entry is invalidated on a `group_state_changed` event for that group
  (including rename) and cleared on inbound resync or subscription
  loss/re-establishment, so the next relevant turn re-reads authoritative
  `group_info`. Routing, session keys, reply targets, and the `message` tool
  stay on the full group id; the subject is never an address. OpenClaw's host
  session store may retain a previous display name after a later unlabeled
  turn — that retention is host-owned, not a plugin migration.
- **Durable replies** are sent verbatim as `kind: 9` messages via the registered
  message adapter's `send.text` → `wn-agent send_final` mapping. The adapter
  never merges or rewrites text across sends. A bounded retry reuses one
  per-send idempotency key so a transient control-socket failure does not create
  a second Marmot message.
- **Live-preview retry contract**: `stream_append`, `stream_status`, and
  `stream_progress` use the preview request's 8-second timeout and bounded
  retries. Every retry of one logical mutation reuses its original idempotency
  key and payload. `wn-agent` therefore applies a mutation at most once even
  when it committed the record but its Ack was lost, while the plugin advances
  its append-only text only after an Ack. `stream_finish` checks this text;
  the shared Rust publisher owns transcript hashing and chunk counts.
- **`message`-tool target resolution** (`src/messaging.ts`): a Marmot reply is
  delivered automatically from the assistant's final text, so the agent does not
  need the shared `message` tool to answer. When it *does* call
  `message(action:"send", to:…)`, the target is a Marmot conversation — always an
  MLS **group** id hex (a DM is a two-member group), optionally prefixed
  `marmot:`. The channel's `messaging` adapter exposes `targetResolver.looksLikeId`
  + `resolveTarget` + `inferTargetChatType` (always `group`) so core resolves a
  group id as a first-class target (Marmot has no directory to search).
- **Message deletion**: the control client can retract a prior message via
  `delete_message` (kind-5, `MarmotAppRuntime::delete_message`), and inbound
  kind-5 deletions from other members surface as a `message_deleted` event,
  routed to the agent as quiet ambient context (below). The agent-facing delete
  message action is wired through the channel's `base.actions` adapter: it first
  uses the bounded send-time `messageId → {account, group}` cache, then falls
  back to an explicit `to` group id when the cache misses.
- **Group state changes**: durable, MLS-authenticated changes (member
  add/remove/leave, admin grant/revoke, rename/avatar) surface as a
  `group_state_changed` event carrying only a coarse `change` kind and, for a
  rename, the new group display name — never a member pubkey. The event is
  ambient: it invalidates that group's cached facts and is attached to the
  next triggering user turn, but it never starts an agent turn or writes the
  host session store. The next admitted turn re-reads `group_info`; a rename
  to a blank name omits the plugin label and then follows OpenClaw's native
  session-display retention.
- **Native reply and ambient context**: reply hydration maps to
  `supplemental.quote`; quoted attachment summaries and buffered
  `message_edited`, `message_deleted`, `reaction_added`, `reaction_removed`, and
  group-state facts map to structured `supplemental.untrustedContext`. Mutation
  actors are checked against the same inbound sender ACL before buffering;
  unauthorized edits, deletions, and reactions are denied without entering
  ambient context. Group-state facts still carry no member pubkey and remain
  non-triggering untrusted context. Ambient facts are isolated per
  account/group and attached only to the next triggering user turn; they never
  start a turn and never enter a system prompt.
- **Media**: inbound — an `inbound_message.message` carries non-secret `media` refs
  (the `imeta` mirror); on dispatch the connector calls `download_media` to get
  a host-local decrypted path and passes it to the turn as an OpenClaw
  `InboundMediaFacts` (`{ path, contentType, kind }`), which OpenClaw
  base64-encodes for a vision model. Outbound — the message adapter declares
  `media` and maps an agent reply's `mediaUrl` onto `send_media`. It prefers the
  running host's authorized `mediaReadFile` capability for every source,
  including local paths, and uses connector-side local-root validation only as
  a fallback when the host provides no reader. The adapter stages a short-lived
  copy under `MARMOT_OUTBOUND_MEDIA_DIR` and cleans it up after success or
  failure; `wn-agent` independently requires that path beneath a startup
  `--media-allowed-root` and rejects symlinks and non-regular files. `wn-agent`
  encrypts + uploads to Blossom; the content key never leaves it. The vision
  model actually receiving the image is confirmed on the docker harness.
- **Live QUIC previews** (`src/live.ts`) are temporarily not wired into inbound
  agent turns. Those turns are final-only so durable delivery has one owner: the
  registered OpenClaw message adapter. The transcript and preview primitives
  remain tested for a later reintroduction through OpenClaw's standard live
  message-adapter lifecycle.
  The plugin keeps one stable request id across retries of the initial
  `stream_begin`, retains the returned v2 stream capability in memory, and
  presents it on every later operation. It never logs or persists that bearer.
  - `block` is the best live-preview mode because it naturally maps onto Marmot's
    append-only stream. `partial`/`progress` can emit windowed OpenClaw preview
    text; the plugin treats those modes as best-effort live previews and recovers
    the complete durable answer from OpenClaw's fresh session transcript before
    committing. Tool/progress chatter is written as non-text progress records and
    never becomes durable chat text.
- **Allowlist mirroring**: on startup the plugin mirrors the configured
  `channels.marmot.dm.allowFrom` (hex account ids) into `wn-agent`'s welcomer
  allowlist (a no-op when none is configured, so it never wipes an allowlist
  managed directly on `wn-agent`). `wn-agent` still performs welcomer-based
  post-join accept/decline. This list is **invite admission only**; it does
  not authorize post-join senders to invoke the agent. With `allowFrom` set
  the mirror is *exact reconciliation* of an account-scoped list: entries
  another integration added to the same `wn-agent` account are removed. It
  performs best-effort reconciliation: revocations run before additions, every
  step is attempted even when an earlier one fails, and the effective list is
  read back afterward. `wn-agent` has no atomic replace, so a partial
  control-plane failure is reported, not repaired: the connector logs
  `welcomer allowlist revocation failed …` (entries still authorized) or
  `welcomer allowlist not reconciled …`, and inbound still starts. Healthy
  channel status requires the inbound subscription acknowledgement, an
  acceptable welcomer state (reconciled or unmanaged), *and* an active sender
  policy (`allowlist` or explicit `allow_all`). Missing or invalid sender
  policy publishes `lastError: "marmot_sender_policy_missing"` or
  `"marmot_sender_policy_invalid"` and is not masked by a successful socket
  probe. A failed managed welcomer sync publishes
  `lastError: "marmot_allowlist_sync_failed"` and retries in the running
  gateway task (1s base, exponential backoff with jitter, 30s cap) until a
  later verified or unmanaged result. That welcomer degradation is diagnostic
  only for invitations; inbound sender authorization still fail-closes.
  Status snapshots identify the affected OpenClaw channel account and never
  include Marmot account ids, allowlist members, token/path values, raw
  policy values, or exception text. A failed revocation leaves that welcomer
  authorized until a later successful sync.
- **Profile-name onboarding** (`src/profile-onboarding.ts`, on by default;
  disable with `profileNameOnboarding: false`): when the agent joins a group it
  asks, on its own, whether to publish a public Nostr profile (`kind:0`) name —
  offering the configured OpenClaw agent `name` as the default ("reply `yes`, a
  different name, or `skip`"), or asking for a name when none is configured.
  Nothing is published until the user replies (that reply is the consent). A
  first message in a group the agent already joined triggers the same prompt as a
  fallback. Per-account status is persisted (`$MARMOT_HOME/dev/profile-onboarding.json`,
  override with `MARMOT_PROFILE_ONBOARDING_STATE`) so it never re-asks.

The inbound→agent and live-preview paths are typechecked against the SDK and
their Marmot-side mappings are unit-tested; their end-to-end behavior is
validated by running the local `openclaw-gateway` harness (below).

## Local gateway harness

`just openclaw-gateway-up` brings up a fully local stack — the in-repo
`nostr-rs-relay` + QUIC broker + `wn-agent` (with `--dev-allow-any-invites` and
`--debug-controls`) + a real OpenClaw gateway with this plugin installed — with
no public relays and no phone required. This is the harness for wiring and
validating the inbound and live-preview paths above: inject an inbound message
over the `wn-agent` control socket (`debug_inject_inbound`), then observe the
agent turn and the reply.

```sh
export OPENAI_API_KEY=...           # or another provider key the gateway uses
just openclaw-gateway-up
just openclaw-gateway-bootstrap     # prints the agent npub/nprofile
just openclaw-gateway-logs
just openclaw-gateway-down          # or openclaw-gateway-reset to wipe data
```

## Tests

```sh
cd integrations/openclaw/marmot
pnpm install
pnpm typecheck
pnpm test
```
