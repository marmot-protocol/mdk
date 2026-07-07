# AGENTS.md - integrations

Top-level guidance for Marmot host integrations. Read `README.md` first, then
the integration-specific `AGENTS.md` in the directory you touch.

## Scope

This directory contains host-runtime integrations that connect external agent
systems to Marmot through `wn-agent`.

- `hermes/marmot` - Hermes platform plugin.
- `openclaw/marmot` - OpenClaw channel plugin.
- `opencode/marmot` - `wn-opencode` harness binary.

The shared boundary is the `marmot.agent-control.v1` NDJSON protocol over a
local Unix socket. `wn-agent` owns Marmot account state, MLS state, Nostr
transport, relay interaction, QUIC preview records, durable encrypted sends,
deletes, invite policy, and local storage.

## Shared Invariants

- Keep integrations control-plane only. Do not add MLS, Nostr relay, encryption,
  storage-engine, or QUIC broker logic under `integrations/`; put that in
  `wn-agent`, `marmot-app`, transport crates, or shared crates as appropriate.
- Treat `MARMOT_HOME`, `MARMOT_AGENT_SOCKET`, `MARMOT_AGENT_AUTH_TOKEN_FILE`,
  `MARMOT_AGENT_AUTH_TOKEN`, and `MARMOT_ACCOUNT_ID_HEX` as the common connector
  vocabulary. Use integration-specific prefixes only for integration-specific
  behavior, for example `WN_OPENCODE_*`.
- Prefer explicit account ids in production configuration. Auto-select only the
  sole local-signing account; fail closed when multiple local-signing accounts
  are available.
- Keep logging privacy-safe: no account ids, group ids, message ids, relay URLs,
  pubkeys, payloads, prompts, model output, ciphertext, plaintext, key material,
  or local sensitive paths.
- Preserve host-runtime configuration outside the Marmot section. Installers and
  setup scripts should patch only the Marmot plugin/channel entries they own.
- Default release installs share one `wn-agent` service, one `MARMOT_HOME`, one
  socket, and one Marmot/Nostr identity. Document and test any departure from
  that model.

## Gateway Versus Harness

Hermes and OpenClaw are gateway/channel integrations. They adapt a full agent
runtime to Marmot and may own activation policy, message-tool routing, live
preview adaptation, media staging policy, profile onboarding, and gateway
session behavior.

`wn-opencode` is a pure harness. It subscribes to allowed Marmot prompts and
invokes `opencode`; it should stay narrower than the gateway integrations unless
there is a concrete product reason to broaden it.

Do not force every feature from Hermes/OpenClaw onto harnesses. Borrow shared
hardening patterns where they fit: strict account selection, socket auth,
allowlist handling, reconnect/resync behavior, bounded queues, chunking,
idempotent sends, installer safety, and privacy-safe diagnostics.

## Coexistence Model

Multiple integrations can run on the same machine and connect to the same
`wn-agent` socket. The socket supports multiple clients and `SubscribeInbound`
streams. There is no global dispatch lease or "one integration claimed this
message" mechanism.

Each integration must make its own activation decision. If two integrations are
eligible for the same inbound message, both may reply. Design activation
defaults conservatively:

- Hermes/OpenClaw default to mention-style activation in multi-party groups and
  always reply in effective DMs.
- `wn-opencode` currently supports only always-on activation for explicitly
  allowed senders.

When changing activation or allowlist semantics, reason about shared installs
first: Hermes, OpenClaw, and opencode may all be installed on the same host,
using the same account and group stream.

## Allowlists

The `wn-agent` welcomer allowlist is account-scoped. It is not scoped per
integration. A connector that reconciles allowlists for a shared account can
affect every other integration on that account.

When adding or changing allowlist behavior:

- Be explicit about whether the integration performs exact reconciliation or
  add-only updates.
- Avoid silent broadening of who can invite or prompt the agent.
- Avoid silently removing entries owned by another integration unless the config
  model clearly declares this integration as the source of truth.
- Keep npub/hex normalization in one small helper and test invalid inputs.

## Release Installers

All production-shaped installers for these integrations should stay in the
`wn-agent-v*` release family. Do not create a separate release track for a new
integration unless the distribution model is intentionally different.

Installer expectations:

- Verify downloaded release assets with SHA256 files.
- Use bounded curl/network timeouts.
- Start same-user services where supported, with private service files and
  owner-only connector state.
- Use the shared default home/socket unless the user explicitly overrides them.
- Preserve existing host-runtime config outside the Marmot section.
- Do not restart Hermes or OpenClaw gateways automatically; print restart
  guidance instead.
- Make dry-runs useful enough to validate release-asset names and config intent.

The default service names are shared (`wn-agent.service`,
`org.marmot.wn-agent`) and are not suitable for multiple isolated identities on
the same login. For isolated identities, document separate homes, sockets,
account ids, and service names.

## Tests And Validation

Use the local integration tests for the directory you touch, plus installer
tests when changing release setup.

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

For shared connector or release-workflow changes, run `just fast-ci` before
pushing and let GitHub run the full CI matrix.

## Adding A New Integration

New integrations should follow the existing shape:

- place code under `integrations/<runtime>/marmot`;
- add local `README.md`, `AGENTS.md`, and a sibling `CLAUDE.md` symlink;
- use `wn-agent` and `agent-control` instead of reimplementing Marmot protocol
  behavior;
- share installer/release conventions with the existing scripts;
- document whether the integration is a gateway/channel plugin or a pure
  harness;
- document coexistence with Hermes, OpenClaw, and opencode before landing
  production install support.
