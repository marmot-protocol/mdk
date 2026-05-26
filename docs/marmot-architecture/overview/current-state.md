---
title: "Current State — Implementations & Spec"
created: 2026-04-19
updated: 2026-05-25
tags: [marmot, overview, current-state, implementations]
status: overview
---

> **2026-05-09 audit pass:** A line-by-line engine review surfaced and closed correctness bugs in recipient
> required-capability refresh, group profile refresh, and the `GroupContext::exporter_secret` over-length contract,
> tightened seven smells (welcome
> dedup at the API surface, atomic `EpochState` transitions, replay error classification, more honest convergence ingest
> outcomes, capability-cache self-id assertion, fail-closed auto-committer admin guard, registry-overwrite warning), and
> added a `SnapshotRollbackGuard` so the snapshot dance is panic-safe. Snapshot names no longer carry plaintext group
> ids. The canonicalization contract now distinguishes `Resolving`, `Settled`, and `Blocked` convergence statuses from
> lifecycle `Stable`. The old auto-commit exception to publish-before-apply is closed: auto-publish work now carries a
> pending ref and confirms or rolls back like
> explicit group evolution.

# Current State — Implementations & Spec

Where Marmot is today: the merged MIPs define the deployed protocol shape, MDK and Marmot-TS give us independent
implementations, and this repository now contains the candidate CGKA engine/convergence workspace that is being shaped
into spec text.

## The spec

**Merged MIPs:**

- **MIP-00** — Credentials & KeyPackages
- **MIP-01** — Group Construction
- **MIP-02** — Welcomes
- **MIP-03** — Group Messages and SelfRemove
- **MIP-04** — Encrypted Media
- **MIP-05** — Push Notifications

**In PR / design:**

- **MIP-06** — Multi-Device Support
- **Marmot v2 protocol draft** — protocol principles, publish lifecycle, and MLS app components in
  [`../../../spec/README.md`](../../../spec/README.md)
- **CGKA engine canonicalization** — post-peeling commit/proposal/app-message contract in
  [`../cgka-engine-canonicalization-contract.md`](../cgka-engine-canonicalization-contract.md)
- **Distributed convergence** — deterministic branch selection for unordered transport input in
  [`../distributed-convergence.md`](../distributed-convergence.md)

The current spec pressure point is commit ordering. MLS wants one ordered commit log; Nostr and other transports may
deliver unordered, duplicated, delayed input. The engine contract is where that mismatch gets resolved.

## Protocol implementations

### MDK (Rust)

MDK is the deployed Rust protocol implementation. It still carries Nostr-aware API surface in places, but it remains the
main source of production experience: persistent storage, OpenMLS integration, group operations, and current MIP
coverage.

### Marmot-TS (TypeScript)

Marmot-TS is an independent implementation. It is valuable because it catches spec ambiguity that a single reference
implementation would normalize.

## Client reference implementation

### whitenoise-rs + whitenoise

whitenoise-rs is the application core for the Flutter client. It owns account management, relay control, event
processing, chat projection, push notifications, and other app-layer work that should stay above the CGKA engine
boundary.

Known architecture pressure remains in the application layer: large database surface, relay-control migration, and
event-processing complexity. Those are separate from the CGKA engine convergence work.

## Current CGKA engine workspace

This repository now has the main engine candidate:

- `crates/traits` — cross-boundary value types and traits, including the account-aware `TransportAdapter` boundary.
- `crates/cgka-engine` — OpenMLS-backed engine implementation.
- `crates/cgka-session` — production-shaped account-device session wrapper over `Engine<SqliteStorage>`.
- `crates/marmot-account` — account/session orchestration over a session and transport adapter. It activates the transport
  account, uses static transport routing for early harnesses, publishes fresh KeyPackages through an injected boundary,
  and confirms or rolls back pending session work from adapter publish reports.
- `crates/marmot-app` — first multi-account app runtime over account home, per-account projections, shared
  relay/directory cache, relay-list setup, KeyPackage lookup, runtime subscriptions, and app-facing
  group/message/member methods.
- `crates/cli` — first real CLI, daemon, and TUI surface over `marmot-app`. It is intentionally product-facing rather
  than a lab harness, and its JSON envelope is shaped for daemon/TUI/testing callers.
- `crates/storage-sqlite` — SQLCipher-backed SQLite storage for Marmot and custom OpenMLS state, with Rust migrations
  for schema/data evolution. Tests and the simulator use its in-memory SQLite mode by default.
- `crates/transport-nostr-adapter` — Nostr transport adapter core for account activation, group subscription sync,
  relay-event routing, and endpoint-level publish reports behind an injectable relay-client boundary. It also has the
  first Marmot kind `30443` KeyPackage event builder/publisher boundary, with MIP-00 metadata supplied explicitly. Its
  optional `sdk` feature provides the first `nostr-sdk` backed relay client.
- `crates/transport-nostr-peeler` — Nostr boundary mapping for kind `445` / `1059` events, kind `445` group envelope
  peeling, and NIP-59 welcome wrap/peel with injected local signer/decrypter.
- `crates/transport-quic-stream` — raw QUIC transport binding for transient agent text stream previews over reliable
  ordered QUIC streams, with transcript hashes tied to durable MLS start/final app-message payloads.
- `crates/transport-quic-broker` — memory-only QUIC pub/sub broker for forwarding live preview records by
  `stream_id + start_event_id` without account state, relay integration, or payload persistence.
- `crates/cgka-conformance-simulator` — multi-client simulator, vectors, generated scenarios, and property tests.
- `formal/tamarin` — formal models for the convergence selector, delivery-order robustness, lifecycle cases, and
  proof/test mapping.
- `spec` — Marmot v2 protocol draft by stable surface, including protocol principles and app components.

The current workspace can exercise the peeler-ingest boundary through in-memory clients, reopen encrypted
SQLCipher-backed account-device sessions, preserve MLS signing identity across those reopens, drive a real
`AccountDeviceSession` + `NostrTransportAdapter` + `NostrMlsPeeler` stack over an in-memory relay client, cover publish
ack/fail resolution and delivery/invite-lifecycle chaos cases at that stack boundary, exercise a transport-generic
account runtime for activation, KeyPackage publication, and publish confirmation/rollback, converge stored OpenMLS
messages, emit application-visible group events, model losing-branch invalidations, and test generated delivery
variants.

## Known gaps

- **Production persistence hardening** — `storage-sqlite` provides encrypted persistence, atomic group snapshots,
  retained-anchor pruning, and privacy-oriented SQLite defaults. `cgka-session` opens one encrypted database per
  account-device identity. App key-management integration, packaging, and longer-term rekey/vacuum/checkpoint policy
  still need production wiring.
- **App-core hardening** — `marmot-app` and `dm` now exercise real account setup, key storage, relay-list repair,
  KeyPackage publication/fetch, directory cache, group membership, group profile projection, message projection, local
  archive state, and sync. The next hardening pass should keep app policy in `marmot-app`/`marmot-account` and keep
  `dm` focused on command presentation and stable JSON output. The current boundary is summarized in
  [`app-core-boundary.md`](./app-core-boundary.md).
- **Production transport adapters** — `transport-nostr-adapter` now implements the Nostr adapter core over an injectable
  relay-client boundary, with an optional `nostr-sdk` relay client, exact stale group subscription cleanup,
  adapter-local metrics, privacy-safe tracing, and redacted SDK relay-health summaries. The SDK owns reconnect/backoff,
  retry interval adjustment, jitter, and relay status mechanics. The session crate now has an in-memory relay
  integration harness that drives NIP-59 welcomes, `marmot.transport.nostr.routing.v1`-backed kind `445` group messages,
  invite group evolution, insufficient acks, publish errors, subscription gating, duplicate delivery, reordered delivery,
  invite commit/welcome order variants, and terminal stale-epoch invite commits through the real session, adapter, and
  peeler stack. Production relay auth, relay safety policy, full KeyPackage metadata derivation through the transport
  layer, richer telemetry export, and account key-management wiring still need integration.
- **Nostr account transport shape** — the likely production shape includes a Nostr user directory, account bootstrap for
  relay-list events, a shared multi-account relay plane, `marmot.transport.nostr.routing.v1` group routing, and explicit
  relay URL safety policy. This is captured as a working note in
  [`nostr-account-transport.md`](./nostr-account-transport.md), but it should not pull focus away from the engine work.
- **Byte-level and scenario vector maturity** — the simulator has a growing portable scenario fixture set, generated
  chaos families, and a runner that writes JSON reports with expectation failures plus generated fixture candidates.
  `convergence-chaos/v1` is the first convergence-focused generated family with built-in semantic expectations, 20+
  client stress cases, mixed message/commit storms, and conservative generated-failure minimization. The byte-level
  vector plan is still thin beyond the first app-component encoding fixtures.
- **whitenoise-rs integration map** — the first integration path is likely a shim over `cgka-session` /
  `marmot-account`, with whitenoise-rs keeping account setup, Nostr directory state, relay-list repair, and shared relay
  plane ownership. The current friction points are tracked in
  [`whitenoise-integration-map.md`](./whitenoise-integration-map.md).
- **Deep same-epoch app-message reordering** — the seeded stack-chaos runner keeps generated app-message reordering
  shallow. A deeper generated reversal exposed OpenMLS `TooDistantInThePast` behavior in the message generation secret
  tree. We need an explicit policy for how much same-epoch app-message reordering the transport/session layer promises
  to tolerate, and how to classify messages outside that window.
- **Portable fork-recovery vectors** — `group-data-fork-recovery/v1` and `concurrent-invite-fork-recovery/v1` are
  semantic fixtures. They check recovery outcomes without requiring exact randomized MLS commit bytes. Exact byte
  fixtures remain for deterministic encodings and transport shapes.
- **Safe Extensions framework support** — still gated on backend library support and migration design.
- **`IdentityRemove` proposal type** — identified as the first likely Marmot-custom proposal, not specified or
  implemented.
- **KeyPackage refresh/expiry policy** — still a higher-layer production scheduling concern. The transport adapter can
  publish a Marmot kind `30443` KeyPackage event when supplied with the required MIP-00 metadata, but deriving that
  metadata from a fresh engine KeyPackage is still follow-up work.

## See also

- Target architecture: [`target-architecture.md`](./target-architecture.md)
- Direction: [`direction.md`](./direction.md)
- Engine quality and vectors: [`cgka-engine-quality-and-vectors.md`](./cgka-engine-quality-and-vectors.md)
- Nostr account transport notes: [`nostr-account-transport.md`](./nostr-account-transport.md)
- whitenoise-rs integration map: [`whitenoise-integration-map.md`](./whitenoise-integration-map.md)
- Canonicalization contract:
  [`../cgka-engine-canonicalization-contract.md`](../cgka-engine-canonicalization-contract.md)
- Distributed convergence: [`../distributed-convergence.md`](../distributed-convergence.md)
