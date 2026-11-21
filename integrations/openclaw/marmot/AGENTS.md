# AGENTS.md - integrations/openclaw/marmot

OpenClaw channel plugin for Marmot through the local `wn-agent` control socket.
The OpenClaw counterpart of `integrations/hermes/marmot`. Read `README.md` and `../../AGENTS.md` first.

## Scope

- A thin, **control-plane-only** OpenClaw channel plugin. `wn-agent` owns the
  Marmot account, MLS state, Nostr transport, and durable sends; this plugin
  only speaks `marmot.agent-control.v2` (NDJSON over a Unix socket).
- Replies are final-only: each answer is one durable `send_final` through the message adapter. Live previews were
  removed; the legacy `quicCandidates`/`streaming`/`blockStreaming` config keys stay in the schema only so existing
  configs keep loading, and are ignored.
- No crypto, relay, or MLS logic here.
- Privacy-safe logging only: no account ids, group ids, message ids, pubkeys,
  relay URLs, payloads, ciphertext, plaintext, or key material.
- Runtime agents send media through OpenClaw's normal `message` tool with
  `media`/`attachments`, using files beneath the active workspace or an
  OpenClaw-managed media store; data URLs are unsupported. Treat the host's
  media reader as source authorization and `wn-agent --media-allowed-root` as
  independent staging authorization. Direct control-client `sendMedia()` calls
  are for connector tests and smoketests only.

## Key files

- `src/client.ts` — agent-control NDJSON client (request/response + `subscribe_inbound` stream).
- `src/inbound.ts` — inbound subscription bridge (reconnect, dedupe, resync).
- `src/gateway.ts` — OpenClaw-owned account lifecycle and inbound subscription.
- `src/inbound-runtime.ts` — the inbound→agent dispatch seam.
- `src/dispatch.ts` — inbound → agent turn dispatch; builds the OpenClaw route and sends the final through the durable
  message context.
- `src/group-info-cache.ts` — bounded per-(account, group) cache for `is_direct` activation and display subject.
- `src/durable-final-idempotency.ts` — idempotency keys for durable final sends.
- `src/history-tool.ts` — `marmot_history` agent tool.
- `src/profile-onboarding.ts` — one-time public profile (kind:0) name consent flow.
- `src/runtime-state.ts` — process-local channel subscription status snapshots.
- `src/bounded-keyed-async-queue.ts` — per-group inbound dispatch with a depth cap.
- `src/outbound.ts` — `defineChannelMessageAdapter` durable send → `send_final`.
- `src/messaging.ts` — `messaging` target-resolution adapter so the shared `message` tool can resolve a Marmot conversation (group id hex).
- `src/config.ts` — channel config schema + `MARMOT_*` resolution.
- `src/account.ts` — single agent-account resolution (`account_list`).
- `src/security.ts` — OpenClaw `dm.allowFrom` → `wn-agent` welcomer allowlist sync.
- `src/sender-policy.ts` — account-global inbound sender ACL (distinct from welcomers).
- `src/channel.ts` — `createChatChannelPlugin` (meta, capabilities, config, message, security, threading).
- `index.ts` / `setup-entry.ts` — source entries; package metadata pairs them with built `dist/` runtime entries.
- `doctor-contract-api.ts` — OpenClaw Doctor contract, built to `dist/doctor-contract-api.js` (the path the host's
  Doctor loader resolves); declares no state migrations.
- `src/openclaw-file-access.d.ts` — narrow declarations for the SDK’s public, untyped file-access runtime export.
- `test/openclaw-loader.ts` — typed test facade over the host’s private loader; no production imports.
- `scripts/wn-agent-smoketest.ts` — standalone control-plane smoke test (not built or type-checked).
- `test/packaged-install.ts` — packed-tarball install/upgrade acceptance through the real `openclaw` CLI (run by the
  release workflow; Node type stripping, not Vitest).
- `test/release-acceptance.ts` — live tarball acceptance: local relay, `wn-agent`, `wnd` client, OpenClaw gateway,
  scripted loopback model.
- `test/` — Vitest unit and connector tests; `test/readme-version.test.ts` requires README.md to state the pinned SDK
  and host minimum derived from `package.json` (keep those README sentences verbatim when editing).

## Rules

- Declare every agent tool the entry registers in `openclaw.plugin.json` `contracts.tools`; the host rejects
  undeclared tool registrations. Keep `doctorContract.stateMigrations` identical (ids, order, authority) to the
  `stateMigrations` export of `doctor-contract-api.ts`, and keep that module free of runtime SDK imports. It is empty
  because the plugin owns no OpenClaw state; if the plugin ever stores state under OpenClaw's state directory or
  config, declare and implement a real migration instead.
- Keep the `openclaw` dependency pinned; before bumping, verify the
  `openclaw/plugin-sdk/*` subpath exports against the new version's types, and
  re-verify the deliberate test-only `dist/plugins/loader.js` import used by the
  connector E2E through `test/openclaw-loader.ts` (the SDK exposes no supported typed plugin-loader subpath).
- Keep `test/plugin-sdk-surface.test.ts` in sync when adding or removing a
  runtime (non-type) `openclaw/plugin-sdk/*` import. A named import the host SDK
  no longer exports is an ESM link error that fails the *whole* plugin load, not
  just the feature using it, so the channel disappears from OpenClaw entirely.
  Prefer subpaths that carry the symbol on both the `latest` and `beta` release
  channels; the SDK's barrels get re-cut between them (2026.7.2-beta moved
  `getDefaultLocalRoots` out of `plugin-sdk/media-runtime` and dropped
  `assertLocalMediaAllowed` from the public surface altogether).
- The inbound→agent seam uses OpenClaw gateway runtime
  internals and is validated by the deterministic connector E2E plus the docker
  phone test, not the unit tests alone.

## Verification

```sh
cd integrations/openclaw/marmot && pnpm install && pnpm typecheck && pnpm test
integrations/openclaw/marmot/test/dev-scripts.sh
# or from the repo root:
just openclaw-dev-test
just openclaw-host-compat-test
just openclaw-dev-script-test
just openclaw-dev-e2e-connector
just openclaw-packaged-install-test            # after packaging, manifest, or build changes
just openclaw-release-acceptance <tarball>     # release acceptance; needs Docker
```

After changing OpenClaw plugin dependencies, regenerate the committed beta lock
with `integrations/openclaw/marmot/test/openclaw-host-compat.sh --update-lock`.
