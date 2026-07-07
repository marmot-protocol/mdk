# AGENTS.md - integrations

Top-level guidance for Marmot host integrations. Read `README.md` first, then
the integration-specific `AGENTS.md` in the directory you touch.

## Scope

This directory contains host-runtime integrations that connect external agent
systems to Marmot through `wn-agent`.

- `hermes/marmot` - Hermes platform plugin.
- `openclaw/marmot` - OpenClaw channel plugin.
- `opencode/marmot` - `wn-opencode` OpenCode harness binary.

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
- Default Hermes and OpenClaw release installs use connector-specific
  `wn-agent` homes, sockets, services, bootstrap labels, and Marmot/Nostr
  identities. Shared-account deployments are opt-in and must be documented
  alongside the required service/socket overrides.

## Gateway Versus Harness

Hermes and OpenClaw are gateway/channel integrations. They adapt a full agent
runtime to Marmot and may own activation policy, message-tool routing, live
preview adaptation, media staging policy, profile onboarding, and gateway
session behavior.

`wn-opencode` is a pure OpenCode harness. It subscribes to allowed Marmot
prompts and invokes the `opencode` binary; it should stay narrower than the
gateway integrations unless there is a concrete product reason to broaden it.

Do not force every feature from Hermes/OpenClaw onto harnesses. Borrow shared
hardening patterns where they fit: strict account selection, socket auth,
allowlist handling, reconnect/resync behavior, bounded queues, chunking,
idempotent sends, installer safety, and privacy-safe diagnostics.

## Coexistence Model

Multiple integrations can run on the same machine. The default Hermes and
OpenClaw installers give each connector its own `wn-agent` process, local home,
socket, service identity, and Marmot/Nostr identity, so their chats are isolated
from each other.

Multiple integrations may also be configured to connect to the same `wn-agent`
socket. The socket supports multiple clients and `SubscribeInbound` streams.
There is no global dispatch lease or "one integration claimed this message"
mechanism.

Each integration must make its own activation decision. If two integrations are
eligible for the same inbound message, both may reply. Design activation
defaults conservatively:

- Hermes/OpenClaw default to mention-style activation in multi-party groups and
  always reply in effective DMs.
- `wn-opencode` currently supports only always-on activation for explicitly
  allowed senders.

When changing activation or allowlist semantics, reason about both default
isolated installs and explicit shared-account installs: Hermes, OpenClaw, and
OpenCode may all be installed on the same host, and advanced operators can point
them at the same account and group stream.

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
- Use connector-specific default homes, sockets, service names, and bootstrap
  labels unless a shared deployment is intentionally configured.
- Preserve existing host-runtime config outside the Marmot section.
- Do not restart Hermes or OpenClaw gateways automatically; print restart
  guidance instead.
- Make dry-runs useful enough to validate release-asset names and config intent.

The default Hermes and OpenClaw service names are connector-specific
(`wn-agent-hermes.service`, `wn-agent-openclaw.service`,
`org.marmot.wn-agent.hermes`, and `org.marmot.wn-agent.openclaw`). If you add a
new production installer, choose names that can coexist with the existing
integrations on the same login.

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
- document coexistence with Hermes, OpenClaw, and OpenCode before landing
  production install support.
