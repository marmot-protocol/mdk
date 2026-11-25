---
title: "Hermes And OpenClaw Agent Integration Plan"
created: 2026-06-06
updated: 2026-11-21
tags: [marmot, architecture, agents, hermes, openclaw]
status: working-plan
---

# Hermes And OpenClaw Agent Integration Plan

This note describes how MDK/Marmot can host a server-side agent account that appears in the iOS, Android, CLI,
and daemon surfaces as a normal Marmot member.

The first target is NousResearch Hermes Agent. The second target is OpenClaw. The shared shape is a headless Rust
connector that owns Marmot account state, MLS group state, and durable encrypted sends. Hermes and OpenClaw get small
channel shims that talk to the connector over a local control socket.

This is implementation architecture. Protocol rules and wire formats stay in `github.com/marmot-protocol/marmot`.

## Goal

The user can invite an agent account into a Marmot direct chat or group. The agent can read encrypted messages through
Marmot and publish a final durable kind-9 app message.

For v1:

- Hermes Agent is the first gateway.
- OpenClaw follows after the connector contract is stable.
- The connector runs on the server with its own Marmot account database and secret store.
- The connector only accepts welcomes from allowed Marmot account pubkeys unless a dev-only flag is set.
- Replies are final-only. The durable kind-9 message is the source of truth; live previews were removed.

## Product Model

The agent is a Marmot account-device identity. It has a Nostr pubkey, publishes a Marmot kind `30443` KeyPackage, joins
groups through welcomes, and sends app messages through `marmot-app`.

Hermes and OpenClaw are gateway runtimes. They own model execution, sessions, tools, and their own platform policy. The
Rust connector owns all Marmot, MLS, and Nostr transport work.

```text
Hermes platform shim
OpenClaw channel shim
        |
        | local JSON control socket
        v
wn-agent connector
  - MarmotAppRuntime host
  - agent account home and SQLCipher session DB
  - KeyPackage publish and relay setup
  - allowlist-driven invite confirmation
  - final encrypted sends
        |
        +-- Nostr relays for durable Marmot traffic
```

## Boundary Decisions

1. Keep policy above the engine.

   `cgka-engine` should expose enough authenticated data for callers to make policy decisions. It should not decide who
   is allowed to invite an agent.

2. Treat welcome authorization as post-join confirmation in v1.

   Today the app runtime joins MLS state when a welcome is ingested, then records the group as pending confirmation in
   app projection state. The connector can auto-accept or auto-decline after observing the joined event. True pre-join
   rejection would require a larger app/runtime ingest gate.

3. Reuse cached KeyPackages on startup.

   `marmot-app` treats kind `30443` KeyPackages as cached last-resort packages. Connector startup should publish or
   repair the cached package. It should rotate when explicitly asked or when validation rejects the cached package.

4. Keep the local socket deployment explicit.

   Same-UID Unix socket auth is a good v1 default when the connector and gateway run as the same Unix user. Docker,
   separate service users, or remote gateway hosts need explicit control-plane auth. The implemented v1 production path is
   a token-gated local Unix socket with group-readable socket permissions. Remote gateway hosts still need a later
   TLS-authenticated control plane.

## Workstream 1: Connector Control Protocol

Create a new Rust library crate:

- `crates/agent-control`

Use newline-delimited JSON over a Unix socket. Match the daemon framing style where possible.

Initial requests:

- `SubscribeInbound`
- `SendFinal`
- `AccountList`
- `AccountCreate`
- `AccountPublishKeyPackage`
- `AllowlistList`
- `AllowlistAdd`
- `AllowlistRemove`

## Workstream 2: Connector Daemon

Create a new binary crate:

- `crates/agent-connector`
- binary name: `wn-agent`

Responsibilities:

- open a Marmot app home;
- host a `MarmotAppRuntime`;
- create or import local agent accounts;
- publish or repair KeyPackages;
- subscribe to runtime events;
- expose the local control socket;
- keep an allowlist per agent account;
- map gateway output to final Marmot sends.

The connector should reuse code patterns from `wnd`, but shared helpers must move into a library crate before another
crate can use them. Useful candidates:

- Unix socket permission hardening;
- same-UID peer credential check;
- newline JSON framing;
- private file and directory creation helpers.

Default auth mode:

- Unix socket;
- mode `0600`;
- same effective UID required;
- no TCP listener.

Deployment constraint:

- Hermes/OpenClaw and `wn-agent` must run as the same Unix user with mode `0600`, or as local users in a shared Unix group
  with a configured auth token, mode `0660`, and a non-world-accessible parent directory.
- The configured token replaces peer-UID authorization and grants every control operation for every hosted account. It
  has no read-only, command, or per-account scopes; separate trust domains require separate connector instances.
- No TCP control listener exists in v2. Split-host gateways require a later TLS-authenticated control plane.

## Workstream 3: Invite Authorization And Welcomer Metadata

Add the exact engine data needed for app policy:

```rust
GroupEvent::GroupJoined {
    group_id,
    via_welcome,
    welcomer: Option<MemberId>,
}
```

Populate `welcomer` from `PeeledMessage.sender` returned by `InboxSealer::unseal`.

Do not infer welcomer from `marmot_members(&mls_group)`. The post-welcome group member set proves membership, not which
account sent the welcome. For the Nostr transport, `NostrInboxSealer::unseal` already extracts the NIP-59 rumor
sender, and that is the value the connector should authorize.

App/runtime updates:

- copy `welcomer` into `AppGroupRecord.welcomer_account_id_hex`;
- keep `via_welcome_message_id_hex`;
- preserve pending confirmation for user-facing clients;
- broadcast enough data for a connector to make the allowlist decision.

The runtime already broadcasts `MarmotAppEvent::GroupEvent` for each summary event. The connector can listen there. A
wider `MarmotAppEvent::GroupJoined` payload is optional if it makes connector code cleaner.

Connector policy:

- if `welcomer` is in the account allowlist, call `accept_group_invite`;
- if `welcomer` is absent or not allowed, call `decline_group_invite`;
- if the development-only `--dev-allow-any-invites` and `--debug-controls` flags are both set, accept welcomes from
  any authenticated welcomer and emit a privacy-safe warning;
- a missing authenticated welcomer always fails closed, including in development mode;
- empty allowlist means reject all welcomes.

Decline currently means leave the group and archive local projection state. That is acceptable for v1, but the plan
should name it as post-join auto-decline.

## Workstream 4: Pairing And Discovery

On startup, the connector should ensure each agent account has relay state and a usable KeyPackage:

- NIP-65 relay list;
- Marmot inbox relay list;
- kind `10051` KeyPackage relay list;
- cached kind `30443` KeyPackage.

Publish or repair the cached KeyPackage with `AppClient::publish_key_package`. Use
`AppClient::rotate_key_package` only for explicit rotation or repair when reuse is impossible.

The app side invites the agent by pubkey. The connector accepts or declines by welcomer allowlist after it observes the
joined event.

## Workstream 5: Hermes Platform Shim

Hermes supports gateway platform adapters through `BasePlatformAdapter` and `ctx.register_platform`. Current Hermes
loads third-party platform plugins as user-installed plugin directories under `~/.hermes/plugins/<name>/`, each
containing `plugin.yaml`, `__init__.py`, and adapter implementation files. The MDK source copy lives at
`integrations/hermes/marmot/` and can be copied or symlinked to `~/.hermes/plugins/marmot/`.

Shim responsibilities:

- connect to `agent.sock`;
- call `SubscribeInbound`;
- convert inbound Marmot messages into Hermes `MessageEvent`s;
- call Hermes gateway handling for inbound messages;
- map final gateway sends to `SendFinal`.

Marmot cannot edit a sent message, so the shim keeps Hermes token streaming off and sends one final reply per answer.

## Workstream 6: OpenClaw Channel Shim

Status (2026-06-17): implemented at `integrations/openclaw/marmot` as a TypeScript channel plugin pinned to
`openclaw@2026.6.8`, using `openclaw/plugin-sdk/channel-outbound` for the durable message adapter. The Marmot-side
logic (control client, durable send, inbound bridge, config / account / allowlist resolution) is unit-tested. The
inbound→agent turn dispatch uses OpenClaw gateway runtime internals and is validated by the docker phone test rather
than unit tests. The path drift below is resolved: `channel-outbound` is the current message-lifecycle surface.

OpenClaw is second because its SDK docs currently show some path drift.

As of 2026-06-06, the docs mention both:

- newer `openclaw/plugin-sdk/channel-outbound` docs for outbound message lifecycle;
- older `openclaw/plugin-sdk/channel-message` references for live preview helpers and compatibility facades.

Before implementation, pin the OpenClaw version and verify the actual exported subpaths in `package.json` and local type
definitions. Write the shim against the supported path for that version.

Shim responsibilities:

- register a Marmot channel;
- expose durable text-send capability only when `SendFinal` returns a receipt;
- use OpenClaw ingress helpers for DM policy and mention gating where they fit;
- mirror OpenClaw setup allowlist state into the connector allowlist through the control API.

## Suggested Sequence

1. Add welcomer threading from `PeeledMessage.sender` to `GroupEvent::GroupJoined` and app projection.
2. Add `agent-control` and a minimal `wn-agent` with account list, KeyPackage publish, inbound subscription, and final
   send.
3. Add connector allowlist and post-join auto-accept/auto-decline.
4. Build the Hermes platform shim and run an end-to-end local relay test.
5. Build the OpenClaw channel shim after pinning the SDK version and import paths.

## Verification

Focused Rust checks:

```sh
cargo test -p cgka-traits
cargo test -p cgka-engine
cargo test -p marmot-app
cargo test -p wn-cli
```

Connector checks:

- allowlist accepts an invite from an allowed welcomer;
- allowlist declines an invite from an unknown welcomer;
- missing welcomer always fails closed, including with `--dev-allow-any-invites`;
- decline leaves and archives the pending group projection;
- `SubscribeInbound` filters by account and group;
- final send produces a normal projected received message on another client.

Gateway checks:

- Hermes plugin loads and appears in gateway setup;
- Hermes inbound message reaches the agent;
- Hermes final response produces a durable kind-9 message;
- OpenClaw channel plugin declares only capabilities backed by tests.

End-to-end check:

1. Start local Nostr relays.
2. Start `wn-agent`.
3. Start Hermes with the Marmot platform shim.
4. Invite the agent account by pubkey.
5. Confirm the connector accepts only the allowed welcomer.
6. Send a user message from a MDK client.
7. Confirm the final encrypted message lands in history.

## Main Risks

- Welcomer metadata is transport-authenticated for Nostr welcomes, but other transports may not supply a sender. The
  policy must fail closed for `None`.
- Same-UID socket auth is simple and local. It needs a new design for split-user or remote deployments.
