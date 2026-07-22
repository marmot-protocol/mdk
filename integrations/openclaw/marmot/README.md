# OpenClaw Marmot Plugin

This directory is an [OpenClaw](https://docs.openclaw.ai) **channel plugin** for the
local `wn-agent` connector. OpenClaw runs the agent, model, tools, and channel
routing. `wn-agent` owns the Marmot account, MLS group state, Nostr transport,
durable encrypted sends, and QUIC live-preview stream records.

The plugin is intentionally thin and **control-plane only**: it speaks the
`marmot.agent-control.v1` newline-delimited JSON protocol to `wn-agent` over a
local Unix socket. It never opens a QUIC connection, encrypts a record, or talks
to a relay — all of that stays in `wn-agent`. It is the OpenClaw counterpart of
the Python Hermes plugin in [`../../hermes/marmot/`](../../hermes/marmot).

- Pinned OpenClaw SDK: **`openclaw@2026.6.11`** (`openclaw/plugin-sdk/*`).
- Toolchain: TypeScript, pnpm, Node ≥ 22.19, Vitest.

## Install (release)

Versioned `wn-agent` builds and this plugin are published as [`wn-agent-v*`](https://github.com/marmot-protocol/mdk/releases)
GitHub pre-releases. OpenClaw must already be installed with `openclaw` on `PATH`.

Prerequisites:

- OpenClaw **2026.6.11** or compatible (this plugin pins `openclaw@2026.6.11`)
- Node ≥ 22.19
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-openclaw-marmot.sh" | bash
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

```sh
curl -fsSL "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-openclaw-marmot.sh" | \
  bash -s -- --yes --allow-welcomer npub1...
```

Use a versioned `wn-agent-v<version>` release URL when you need a pinned install.

The installer prints restart guidance for your existing OpenClaw gateway. It
does not restart OpenClaw automatically. Manual equivalent:

```sh
wn-agent --home ~/.marmot-agents/openclaw \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
wn-agent bootstrap --home ~/.marmot-agents/openclaw --label openclaw-agent --qr
openclaw gateway run
```

Invite the printed agent account from the phone app.

## Dev setup

```sh
just openclaw-dev-test                 # pnpm install + typecheck + vitest
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
| `home` | `MARMOT_HOME` | `~/.marmot` |
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
| `dm.policy` / `dm.allowFrom` | — | `allowlist` |

`accountIdHex` is the Marmot/wn-agent account id. It is intentionally distinct
from OpenClaw's channel account id (`default`, or a key under
`channels.marmot.accounts`) used for routing, session metadata, and message-tool
target lookup.

The default control socket is same-UID only (parent dir `0700`, socket `0600`,
no TCP listener). If OpenClaw and `wn-agent` run as different local users, start
`wn-agent` with `--auth-token-file` + group-readable socket modes (`0660`) and
set `MARMOT_AGENT_AUTH_TOKEN_FILE`. See
[`crates/agent-connector/README.md`](../../../crates/agent-connector/README.md).

- **Inbound → agent turn** (`src/dispatch.ts`): the inbound bridge feeds each
  received Marmot message (`chatId` = Marmot group id, `userId` = sender) into
  OpenClaw's turn kernel via `runChannelInboundEvent` + `dispatchReplyWithBufferedBlockDispatcher`,
  **modeled on the bundled Telegram channel**. The agent's reply is delivered
  back through the message adapter and threads to the triggering message.
  Dispatch is serialized per group (distinct groups run concurrently, each group
  stays FIFO), so a slow turn in one group never blocks inbound for others; set
  `debounceMs` to coalesce rapid same-sender bursts into one turn.
- **Activation gating**: in a multi-party group the agent replies only when
  addressed — it is `p`-tag mentioned, the text matches a `mentionPatterns`
  trigger (or the agent name), or the conversation is an effective DM (exactly
  two members, resolved via the `group_info` control op). Set
  `groupActivation: "always"` to reply to every message. Effective DMs always
  reply. Membership is queried lazily — only for otherwise-unaddressed messages,
  so the common addressed case never pays the round-trip — and the resulting
  `is_direct` fact is cached per (account, group), since it only changes when
  membership changes. The cache entry is invalidated on a `group_state_changed`
  event for that group (and cleared entirely on an inbound resync), so the next
  unaddressed message re-reads fresh membership. On a membership-lookup error
  the gate fails **closed** (skips the turn) under the `mention` policy: an
  unaddressed message in a group whose membership can't be resolved is more
  likely a multi-party conversation the agent wasn't addressed in, and an
  unrecallable barge-in there is worse than dropping a single reply in a true
  two-party DM (where the user can re-send or address the agent explicitly). The
  error is not cached, so the next message retries the lookup.
- **Durable replies** are sent verbatim as `kind: 9` messages via `send_final`;
  the adapter never merges or rewrites text across sends. Each durable reply is
  **idempotent + retried**: the sink generates one `idempotency_key` per reply
  and retries the send a few times (with a short backoff) on retryable errors,
  reusing the same key so `wn-agent` dedups instead of double-posting. A repeated
  key returns the original message ids without a second send, so a retry after a
  post-write timeout cannot double-post an unrecallable encrypted message.
  Live-preview `stream_finalize` uses the same posture: one idempotency key per
  preview stream, bounded retry on retryable failures, and connector-side cached
  final message ids for post-success retries.
- **`message`-tool target resolution** (`src/messaging.ts`): a Marmot reply is
  delivered automatically from the assistant's final text, so the agent does not
  need the shared `message` tool to answer. When it *does* call
  `message(action:"send", to:…)`, the target is a Marmot conversation — always an
  MLS **group** id hex (a DM is a two-member group), optionally prefixed
  `marmot:`. The channel's `messaging` adapter exposes `targetResolver.looksLikeId`
  + `resolveTarget` + `inferTargetChatType` (always `group`) so core resolves a
  group id as a first-class target (Marmot has no directory to search). Without
  it the generic resolver rejected a Marmot group id with an "unknown target"
  error before the durable send could run.
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
  rename, the new group display name — never a member pubkey.
- **Ambient context** (`index.ts` ambient surfacer): `message_deleted` and
  `group_state_changed` are surfaced to the agent's session as quiet,
  next-turn context via `api.runtime.system.enqueueSystemEvent(text, {
  sessionKey, contextKey })` (sessionKey from `resolveAgentRoute`). It is
  feature-detected (no-ops on a runtime without the system-event surface). The
  agent sees the event as context without being forced to reply; confirmed on
  the docker harness.
- **Media**: inbound — an `inbound_message` carries non-secret `media` refs
  (the `imeta` mirror); on dispatch the connector calls `download_media` to get
  a host-local decrypted path and passes it to the turn as an OpenClaw
  `InboundMediaFacts` (`{ path, contentType, kind }`), which OpenClaw
  base64-encodes for a vision model. Outbound — the message adapter declares
  `media` and maps an agent reply's `mediaUrl` (resolved to a local path via
  `mediaReadFile` when needed) onto `send_media`. The adapter retains OpenClaw's
  local-root check, stages a short-lived copy under `MARMOT_OUTBOUND_MEDIA_DIR`,
  and cleans it up after the response; `wn-agent` independently requires that
  path beneath a startup `--media-allowed-root` and rejects symlinks and
  non-regular files. `wn-agent` encrypts + uploads to Blossom; the content key
  never leaves it. The vision model actually
  receiving the image is confirmed on the docker harness.
- **Live QUIC previews** (`src/live.ts`): progressive agent reply blocks drive an
  append-only preview (`stream_begin`/`append`/`finalize`); a non-append-only
  update cancels the preview and sends the final verbatim. The transcript hash +
  chunk count match `wn-agent` byte-for-byte (Rust-anchored parity test in
  `test/transcript.test.ts`). Previews run whenever `streaming.mode` is not
  `off` and `quicCandidates` are set, and OpenClaw is emitting progressive
  blocks. Marmot enables OpenClaw block delivery automatically when
  `quicCandidates` are configured and `streaming.mode` is not `off`; operators
  can override it with `blockStreaming`, `streaming.block.enabled`, or
  `MARMOT_BLOCK_STREAMING`. Like a Telegram preview,
  this is driven by the channel's reply `deliver` callback, not a core-driven
  live adapter (that SDK seam does not exist yet).
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
  post-join accept/decline.
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
