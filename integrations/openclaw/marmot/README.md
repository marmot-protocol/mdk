# OpenClaw Marmot Plugin

This directory is an [OpenClaw](https://docs.openclaw.ai) **channel plugin** for the
local `dm-agent` connector. OpenClaw runs the agent, model, tools, and channel
routing. `dm-agent` owns the Marmot account, MLS group state, Nostr transport,
durable encrypted sends, and QUIC live-preview stream records.

The plugin is intentionally thin and **control-plane only**: it speaks the
`marmot.agent-control.v1` newline-delimited JSON protocol to `dm-agent` over a
local Unix socket. It never opens a QUIC connection, encrypts a record, or talks
to a relay — all of that stays in `dm-agent`. It is the OpenClaw counterpart of
the Python Hermes plugin in [`../../hermes/marmot/`](../../hermes/marmot).

- Pinned OpenClaw SDK: **`openclaw@2026.6.8`** (`openclaw/plugin-sdk/*`).
- Toolchain: TypeScript, pnpm, Node ≥ 22.19, Vitest.

## Install (release)

Versioned `dm-agent` builds and this plugin are published as `dm-agent-v*`
GitHub pre-releases. OpenClaw must already be installed with `openclaw` on `PATH`.

```sh
DM_AGENT_VERSION=0.1.0
curl -fsSL "https://github.com/marmot-protocol/darkmatter/releases/download/dm-agent-v${DM_AGENT_VERSION}/install-openclaw-marmot.sh" | bash
# or install + bootstrap the agent account in one step:
curl -fsSL ".../install-openclaw-marmot.sh" | bash -s -- --bootstrap
```

The installer puts `dm-agent` in `~/.local/bin`, downloads the plugin tarball,
runs `openclaw plugins install`, and enables the `marmot` channel.

Then start the connector and bootstrap (same public relays as the phone app):

```sh
dm-agent --home ~/.marmot-agent \
  --relay wss://relay.eu.whitenoise.chat \
  --relay wss://relay.us.whitenoise.chat
dm-agent bootstrap --home ~/.marmot-agent --qr
openclaw gateway run
```

Invite the printed agent account from the phone app.

## Dev setup

```sh
just openclaw-dev-test                 # pnpm install + typecheck + vitest
just openclaw-dev-setup --print-env    # build + isolated dev root + helper scripts
just openclaw-dev-teardown --force     # remove the throwaway dev root
```

`openclaw-dev-setup` builds the plugin, prepares an isolated dev root under
`${TMPDIR:-/tmp}/openclaw-marmot-test`, and generates `run-dm-agent.sh`,
`run-openclaw-gateway.sh`, `smoke-plugin.sh`, and `env.sh`.

## Docker phone test

A Compose profile builds a container with `dm-agent`, OpenClaw, this plugin, and
`qrencode`. It starts `dm-agent` with `MARMOT_AGENT_ALLOW_ANY=1` so the first
phone invite lands without pre-seeding an allowlist (use an explicit allowlist
for a real deployment).

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
environment variables (config wins). Keys mirror the Hermes plugin so one
`dm-agent` deployment can serve both gateways:

| Key (config) | Env | Default |
| --- | --- | --- |
| `home` | `MARMOT_HOME` | `~/.marmot` |
| `socketPath` | `MARMOT_AGENT_SOCKET` | `$MARMOT_HOME/dev/dm-agent.sock` |
| `authToken` | `MARMOT_AGENT_AUTH_TOKEN` | — |
| `authTokenFile` | `MARMOT_AGENT_AUTH_TOKEN_FILE` | — |
| `accountIdHex` | `MARMOT_ACCOUNT_ID_HEX` | sole local account |
| `groupIdHex` | `MARMOT_GROUP_ID_HEX` | — (no filter) |
| `quicCandidates` | `MARMOT_QUIC_CANDIDATES` | — (final-only) |
| `streaming.mode` | `MARMOT_STREAM_MODE` | `block` (`off`/`partial`/`block`/`progress`) |
| `blockStreaming` / `streaming.block.enabled` | `MARMOT_BLOCK_STREAMING` | `true` when QUIC candidates are configured and Marmot streaming is not `off` |
| `profileNameOnboarding` | `MARMOT_PROFILE_NAME_ONBOARDING` | `true` |
| `dm.policy` / `dm.allowFrom` | — | `allowlist` |

`accountIdHex` is the Marmot/dm-agent account id. It is intentionally distinct
from OpenClaw's channel account id (`default`, or a key under
`channels.marmot.accounts`) used for routing, session metadata, and message-tool
target lookup.

The default control socket is same-UID only (parent dir `0700`, socket `0600`,
no TCP listener). If OpenClaw and `dm-agent` run as different local users, start
`dm-agent` with `--auth-token-file` + group-readable socket modes (`0660`) and
set `MARMOT_AGENT_AUTH_TOKEN_FILE`. See
[`crates/agent-connector/README.md`](../../../crates/agent-connector/README.md).

- **Inbound → agent turn** (`src/dispatch.ts`): the inbound bridge feeds each
  received Marmot message (`chatId` = Marmot group id, `userId` = sender) into
  OpenClaw's turn kernel via `runChannelInboundEvent` + `dispatchReplyWithBufferedBlockDispatcher`,
  **modeled on the bundled Telegram channel**. The agent's reply is delivered
  back through the message adapter.
- **Durable replies** are sent verbatim as `kind: 9` messages via `send_final`;
  the adapter never merges or rewrites text across sends.
- **Live QUIC previews** (`src/live.ts`): progressive agent reply blocks drive an
  append-only preview (`stream_begin`/`append`/`finalize`); a non-append-only
  update cancels the preview and sends the final verbatim. The transcript hash +
  chunk count match `dm-agent` byte-for-byte (Rust-anchored parity test in
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
  `channels.marmot.dm.allowFrom` (hex account ids) into `dm-agent`'s welcomer
  allowlist (a no-op when none is configured, so it never wipes an allowlist
  managed directly on `dm-agent`). `dm-agent` still performs welcomer-based
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
`nostr-rs-relay` + QUIC broker + `dm-agent` (with `--allow-any` and
`--debug-controls`) + a real OpenClaw gateway with this plugin installed — with
no public relays and no phone required. This is the harness for wiring and
validating the inbound and live-preview paths above: inject an inbound message
over the `dm-agent` control socket (`debug_inject_inbound`), then observe the
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
