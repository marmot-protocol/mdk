---
title: "Hermes And OpenClaw Agent Integration Plan"
created: 2026-06-06
updated: 2026-06-07
tags: [marmot, architecture, agents, hermes, openclaw, quic]
status: working-plan
---

# Hermes And OpenClaw Agent Integration Plan

This note describes how Darkmatter/Marmot can host a server-side agent account that appears in the iOS, Android, CLI,
daemon, and TUI surfaces as a normal Marmot member.

The first target is NousResearch Hermes Agent. The second target is OpenClaw. The shared shape is a headless Rust
connector that owns Marmot account state, MLS group state, durable encrypted sends, and live QUIC previews. Hermes and
OpenClaw get small channel shims that talk to the connector over a local control socket.

This is implementation architecture. Protocol rules and wire formats stay in `spec/`.

## Goal

The user can invite an agent account into a Marmot direct chat or group. The agent can read encrypted messages through
Marmot, produce live provisional output through the existing agent text stream profile, and publish a final durable
kind-9 app message.

For v1:

- Hermes Agent is the first gateway.
- OpenClaw follows after the connector and stream contract are stable.
- The connector runs on the server with its own Marmot account database and secret store.
- The connector only accepts welcomes from allowed Marmot account pubkeys unless a dev-only flag is set.
- Live previews are best-effort. The durable kind-9 final remains the source of truth.

## Product Model

The agent is a Marmot account-device identity. It has a Nostr pubkey, publishes a Marmot kind `30443` KeyPackage, joins
groups through welcomes, and sends app messages through `marmot-app`.

Hermes and OpenClaw are gateway runtimes. They own model execution, sessions, tools, and their own platform policy. The
Rust connector owns all Marmot, MLS, Nostr transport, and QUIC broker work.

```text
Hermes platform shim
OpenClaw channel shim
        |
        | local JSON control socket
        v
dm-agent connector
  - MarmotAppRuntime host
  - agent account home and SQLCipher session DB
  - KeyPackage publish and relay setup
  - allowlist-driven invite confirmation
  - final encrypted sends
  - live stream composition to QUIC broker
        |
        +-- Nostr relays for durable Marmot traffic
        +-- QUIC broker for provisional preview records
```

## Boundary Decisions

1. Keep policy above the engine.

   `cgka-engine` should expose enough authenticated data for callers to make policy decisions. It should not decide who
   is allowed to invite an agent.

2. Treat welcome authorization as post-join confirmation in v1.

   Today the app runtime joins MLS state when a welcome is ingested, then records the group as pending confirmation in
   app projection state. The connector can auto-accept or auto-decline after observing the joined event. True pre-join
   rejection would require a larger app/runtime ingest gate.

3. Keep gateway edit semantics out of Marmot unless they are encoded.

   The current QUIC preview path is append-oriented. Hermes/OpenClaw update callbacks may send replacement text or block
   edits. The shim must convert those updates to append-only deltas, or the stream protocol/runtime must gain an explicit
   replace/checkpoint rendering contract.

4. Reuse cached KeyPackages on startup.

   `marmot-app` treats kind `30443` KeyPackages as long-lived last-resort packages. Connector startup should publish or
   repair the cached package. It should rotate only when explicitly asked or when the cached package is unusable.

5. Keep the local socket deployment explicit.

   Same-UID Unix socket auth is a good v1 default when the connector and gateway run as the same Unix user. Docker,
   separate service users, or remote gateway hosts need a different control-plane auth story before production use.

## Workstream 1: Reusable Stream Composition

Create a new Rust library crate:

- `crates/agent-stream-compose`

Move the stream composition worker out of `crates/cli/src/daemon.rs`:

- `StreamComposeSession`
- `StreamComposeCommand`
- `run_stream_compose_session`
- local transcript accounting
- append and finish report helpers

Move stream crypto derivation out of `crates/cli/src/lib.rs` into a reusable app-facing helper. The current logic derives
`AgentTextStreamCrypto` from:

- `MarmotAppRuntime::agent_text_stream_exporter_secret`
- current group MLS epoch
- group id
- stream id
- start event id
- start-event sender member id

That sender id is part of the AEAD key context. If the connector derives a context with the wrong sender, apps will fail
to decrypt preview records.

Add a generic record append API to `BrokerTextPublisher` alongside `append_text`. `AGENT_TEXT_STREAM_RECORD_STATUS`
already exists in `cgka-traits`; the missing pieces are:

- publisher support for record types other than text deltas;
- local transcript support for those record types;
- runtime and app update types that expose record type and payload where needed;
- UI policy for showing or ignoring status records.

Keep the current text-only path working for `dm stream compose`.

## Workstream 2: Connector Control Protocol

Create a new Rust library crate:

- `crates/agent-control`

Use newline-delimited JSON over a Unix socket. Match the daemon framing style where possible.

Initial requests:

- `SubscribeInbound`
- `SendFinal`
- `StreamBegin`
- `StreamAppend`
- `StreamStatus`
- `StreamFinalize`
- `StreamCancel`
- `AccountList`
- `AccountCreate`
- `AccountPublishKeyPackage`
- `AllowlistList`
- `AllowlistAdd`
- `AllowlistRemove`

Important protocol rule: `StreamAppend` carries append-only text. If a gateway has full replacement text, the shim must
compute the suffix before it calls `StreamAppend`.

If suffix computation fails, the shim has two v1 choices:

- cancel the preview and send only a final message;
- use a future `StreamReplace` operation once the Marmot preview runtime knows how to render replacement records.

Do not fake replacement output by appending a complete rewritten draft.

## Workstream 3: Connector Daemon

Create a new binary crate:

- `crates/agent-connector`
- binary name: `dm-agent`

Responsibilities:

- open a Marmot app home;
- host a `MarmotAppRuntime`;
- create or import local agent accounts;
- publish or repair KeyPackages;
- subscribe to runtime events;
- expose the local control socket;
- keep an allowlist per agent account;
- map gateway output to final Marmot sends and QUIC previews.

The connector should reuse code patterns from `dmd`, but shared helpers must move into a library crate before another
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

- Hermes/OpenClaw and `dm-agent` must run as the same Unix user for v1, or the operator must opt into a later token or
  TLS-authenticated control plane.

## Workstream 4: Invite Authorization And Welcomer Metadata

Add the exact engine data needed for app policy:

```rust
GroupEvent::GroupJoined {
    group_id,
    via_welcome,
    welcomer: Option<MemberId>,
}
```

Populate `welcomer` from `PeeledMessage.sender` returned by `TransportPeeler::peel_welcome`.

Do not infer welcomer from `marmot_members(&mls_group)`. The post-welcome group member set proves membership, not which
account sent the welcome. For the Nostr transport, `NostrMlsPeeler::peel_welcome` already extracts the NIP-59 rumor
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
- if `--allow-any` is set, accept all welcomes and log only aggregate counts;
- empty allowlist means reject all welcomes.

Decline currently means leave the group and archive local projection state. That is acceptable for v1, but the plan
should name it as post-join auto-decline.

## Workstream 5: Pairing And Discovery

On startup, the connector should ensure each agent account has relay state and a usable KeyPackage:

- NIP-65 relay list;
- Marmot inbox relay list;
- kind `10051` KeyPackage relay list;
- cached kind `30443` KeyPackage.

Publish or repair the cached KeyPackage with `AppClient::publish_key_package`. Use
`AppClient::rotate_key_package` only for explicit rotation or repair when reuse is impossible.

The app side invites the agent by pubkey. The connector accepts or declines by welcomer allowlist after it observes the
joined event.

## Workstream 6: Hermes Platform Shim

Hermes supports gateway platform adapters through `BasePlatformAdapter` and `ctx.register_platform`. Current Hermes docs
show third-party platform plugins as user-installed plugin directories under `~/.hermes/plugins/<name>/`, each containing
`PLUGIN.yaml` and `adapter.py`. The Darkmatter source copy lives at `integrations/hermes/marmot/` and can be copied or
symlinked to `~/.hermes/plugins/marmot/`.

Shim responsibilities:

- connect to `agent.sock`;
- call `SubscribeInbound`;
- convert inbound Marmot messages into Hermes `MessageEvent`s;
- call Hermes gateway handling for inbound messages;
- map final gateway sends to `SendFinal`;
- map progressive output to `StreamBegin`, append-only `StreamAppend`, optional `StreamStatus`, and `StreamFinalize`.

The shim must understand Hermes edit behavior:

- if Hermes calls `edit_message` with full replacement text, compute the suffix before `StreamAppend`;
- if the new text is not an extension of the previous text, cancel live preview and keep only the final send for v1;
- pass `finalize=True` to `StreamFinalize` with the final text and transcript data.

Do not require per-token output for v1. Block-level or edit-level progress is enough if the shim enforces append-only
records.

## Workstream 7: OpenClaw Channel Shim

OpenClaw is second because its SDK docs currently show some path drift.

As of 2026-06-06, the docs mention both:

- newer `openclaw/plugin-sdk/channel-outbound` docs for outbound message lifecycle;
- older `openclaw/plugin-sdk/channel-message` references for live preview helpers and compatibility facades.

Before implementation, pin the OpenClaw version and verify the actual exported subpaths in `package.json` and local type
definitions. Write the shim against the supported path for that version.

Shim responsibilities:

- register a Marmot channel;
- expose durable text-send capability only when `SendFinal` returns a receipt;
- expose live preview capabilities only after contract tests prove begin, append/update, finalization, fallback, and
  receipt behavior;
- use OpenClaw ingress helpers for DM policy and mention gating where they fit;
- mirror OpenClaw setup allowlist state into the connector allowlist through the control API.

For live previews, the same append-only rule applies. If OpenClaw supplies block updates or full replacements, the shim
must produce suffixes or fall back to final-only delivery.

## Workstream 8: QUIC Broker Production Shape

The broker already supports:

- memory-only rooms;
- bounded backlog and room limits;
- connection and stream limits;
- PEM TLS config;
- self-signed local config;
- certificate fingerprint reporting;
- `run_until` shutdown.

The production work is mostly configuration and operator guidance:

- expose `max_rooms`, `max_backlog_bytes`, `max_connections`, stream limit, read timeout, idle timeout, and keepalive in
  `marmot-quic-broker`;
- use PEM TLS for public deployment;
- distribute either platform-trusted broker names or explicit cert DER/fingerprints in kind-1200 stream candidates;
- keep `InsecureLocal` loopback-only and dev-only;
- document that broker payload confidentiality rests on `AgentTextStreamCrypto`;
- document that the broker has no durable storage and final kind-9 messages are the durable record;
- consider per-room publish tokens after the first public deployment slice.

Do not add account storage, relay integration, or MLS logic to the broker.

## Stream Capability Fallback

New groups created by the current app path include the agent text stream component by default. Existing or imported
groups may not.

Before `StreamBegin`, the connector should check the group projection:

- if the group supports agent text streams, use live preview plus final message;
- if it does not, send final-only;
- if the agent account is allowed to propose an upgrade, expose a separate repair or upgrade operation.

Do not silently start a stream in a group that cannot derive the stream exporter or render the kind-1200 start.

## Suggested Sequence

1. Add welcomer threading from `PeeledMessage.sender` to `GroupEvent::GroupJoined` and app projection.
2. Extract stream compose and stream crypto into reusable crates/helpers.
3. Add `agent-control` and a minimal `dm-agent` with account list, KeyPackage publish, inbound subscription, and final
   send.
4. Add connector allowlist and post-join auto-accept/auto-decline.
5. Wire stream begin, append, status, finalize, and cancel.
6. Harden broker CLI config for public deployment.
7. Build the Hermes platform shim and run an end-to-end local relay test.
8. Build the OpenClaw channel shim after pinning the SDK version and import paths.

## Verification

Focused Rust checks:

```sh
cargo test -p cgka-traits
cargo test -p cgka-engine
cargo test -p marmot-app
cargo test -p transport-quic-broker
cargo test -p darkmatter-cli
```

Connector checks:

- allowlist accepts an invite from an allowed welcomer;
- allowlist declines an invite from an unknown welcomer;
- missing welcomer fails closed unless `--allow-any` is set;
- decline leaves and archives the pending group projection;
- `SubscribeInbound` filters by account and group;
- final send produces a normal projected received message on another client;
- stream begin, append, status, finalize, and cancel keep transcript hashes consistent;
- append-only violation falls back to final-only or explicit cancel.

Gateway checks:

- Hermes plugin loads and appears in gateway setup;
- Hermes inbound message reaches the agent;
- Hermes progressive edits become append-only stream records;
- Hermes final response produces a durable kind-9 message;
- OpenClaw channel plugin declares only capabilities backed by tests;
- OpenClaw live preview tests cover final edit, fallback, receipt, and cleanup behavior for the pinned SDK version.

End-to-end check:

1. Start local Nostr relays.
2. Start `marmot-quic-broker` with TLS config.
3. Start `dm-agent`.
4. Start Hermes with the Marmot platform shim.
5. Invite the agent account by pubkey.
6. Confirm the connector accepts only the allowed welcomer.
7. Send a user message from a Darkmatter client.
8. Confirm live preview records arrive and the final encrypted message lands in history.

## Main Risks

- Welcomer metadata is transport-authenticated for Nostr welcomes, but other transports may not supply a sender. The
  policy must fail closed for `None`.
- Same-UID socket auth is simple and local. It needs a new design for split-user or remote deployments.
- Gateway edit streams are not guaranteed to be append-only. The shims must enforce that contract.
- Status records are protocol-valid, but current app/UI code mostly treats non-text records as empty text. Runtime event
  types and UI policy need small additions before users see useful status.
- Public QUIC broker deployment must avoid `InsecureLocal`; it is for loopback development only.
