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

- Pinned OpenClaw development SDK: **`openclaw@2026.7.1-2`**.
- Toolchain: TypeScript, pnpm, Node ≥ 22.19, Vitest.

## Install (release)

Versioned `wn-agent` builds and this plugin are published as [`wn-agent-v*`](https://github.com/marmot-protocol/mdk/releases)
GitHub pre-releases. OpenClaw must already be installed with `openclaw` on `PATH`.

Prerequisites:

- OpenClaw host **2026.7.1 or newer**. The installer validates the existing
  host and never installs or upgrades OpenClaw.
- Node ≥ 22.19
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel

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

base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.15"
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

Run this example in the same shell where `install_verified` above was defined.

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.15"
install_verified "$base_url/install-openclaw-marmot.sh" \
  "$base_url/install-openclaw-marmot.sh.sha256" \
  --yes --allow-welcomer npub1...
```

Generated-identity onboarding is the default (and can be selected explicitly
with `--generate-identity`). To preserve an existing Nostr identity, place its
`nsec` or raw secret hex in a regular file owned by the current user with mode
`0600`, then use a pinned release URL:

Run this example in the same shell where `install_verified` above was defined.

```sh
base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.9.15"
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
does not restart OpenClaw automatically. Manual equivalent:

```sh
wn-agent import-identity --json \
  --home ~/.marmot-agents/openclaw \
  --label openclaw-agent \
  --identity-file "$HOME/.config/example/openclaw-agent.nsec" \
  --expected-identity npub1...
wn-agent --home ~/.marmot-agents/openclaw \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
wn-agent bootstrap --home ~/.marmot-agents/openclaw --label openclaw-agent \
  --no-create --account-id-hex <imported-account-hex> --qr
openclaw gateway run
```

Invite the printed agent account from the phone app.

## Dev setup

```sh
just openclaw-dev-test                 # pnpm install + typecheck + vitest
just openclaw-host-compat-test         # build + focused runtime tests on supported beta
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

- **Inbound → agent turn** (`src/dispatch.ts`): the gateway-owned inbound bridge
  feeds each received Marmot message (`chatId` = Marmot group id, `userId` =
  sender) into OpenClaw's turn kernel via `runChannelInboundEvent` +
  `dispatchReplyWithBufferedBlockDispatcher`. The trusted inbound context owns
  the destination. A normal assistant final is passed to
  `deliverInboundReplyWithMessageSendContext`, which invokes the registered
  Marmot message adapter and threads the reply to the triggering message. The
  model never has to reconstruct or select the source group.
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
  its local transcript only after an Ack; the client and server transcript
  hashes remain aligned for `stream_finalize`.
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
- **Native reply and ambient context**: reply hydration maps to
  `supplemental.quote`; quoted attachment summaries and buffered
  `message_edited`, `message_deleted`, `reaction_added`, `reaction_removed`, and
  group-state facts map to structured `supplemental.untrustedContext`. Ambient
  facts are isolated per account/group and attached only to the next triggering
  user turn; they never start a turn and never enter a system prompt.
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
  post-join accept/decline. With `allowFrom` set the mirror is *exact
  reconciliation* of an account-scoped list: entries another integration added
  to the same `wn-agent` account are removed. It runs fail-closed — revocations
  before additions, every step attempted even when an earlier one fails, and the
  effective list read back afterwards. `wn-agent` has no atomic replace, so a
  partial control-plane failure is reported, not repaired: the connector logs
  `welcomer allowlist revocation failed …` (entries still authorized) or
  `welcomer allowlist not reconciled …`, and startup continues.
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
