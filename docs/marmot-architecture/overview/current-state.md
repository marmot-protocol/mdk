---
title: "Current State — Implementations & Spec"
created: 2026-04-19
updated: 2026-05-09
tags: [marmot, overview, current-state, implementations]
status: overview
---

# Current State — Implementations & Spec

Where Marmot is today: the merged MIPs define the deployed protocol shape,
MDK and Marmot-TS give us independent implementations, and this repository now
contains the candidate CGKA engine/convergence workspace that is being shaped
into spec text.

## The spec

**Merged MIPs:**
- **MIP-00** — Credentials & KeyPackages
- **MIP-01** — Group Construction & `marmot_group_data`
- **MIP-02** — Welcomes
- **MIP-03** — Group Messages and SelfRemove
- **MIP-04** — Encrypted Media
- **MIP-05** — Push Notifications

**In PR / design:**
- **MIP-06** — Multi-Device Support
- **CGKA engine canonicalization** — post-peeling commit/proposal/app-message
  contract in [`../cgka-engine-canonicalization-contract.md`](../cgka-engine-canonicalization-contract.md)
- **Distributed convergence** — deterministic branch selection for unordered
  transport input in [`../distributed-convergence.md`](../distributed-convergence.md)

The current spec pressure point is commit ordering. MLS wants one ordered commit
log; Nostr and other transports may deliver unordered, duplicated, delayed
input. The engine contract is where that mismatch gets resolved.

## Protocol implementations

### MDK (Rust)

MDK is the deployed Rust protocol implementation. It still carries Nostr-aware
API surface in places, but it remains the main source of production experience:
persistent storage, OpenMLS integration, group operations, and current MIP
coverage.

### Marmot-TS (TypeScript)

Marmot-TS is an independent implementation. It is valuable because it catches
spec ambiguity that a single reference implementation would normalize.

## Client reference implementation

### whitenoise-rs + whitenoise

whitenoise-rs is the application core for the Flutter client. It owns account
management, relay control, event processing, chat projection, push
notifications, and other app-layer work that should stay above the CGKA engine
boundary.

Known architecture pressure remains in the application layer: large database
surface, relay-control migration, and event-processing complexity. Those are
separate from the CGKA engine convergence work.

## Current CGKA engine workspace

This repository now has the main engine candidate:

- `crates/traits` — cross-boundary value types and traits, including the
  account-aware `TransportAdapter` boundary.
- `crates/cgka-engine` — OpenMLS-backed engine implementation.
- `crates/cgka-session` — production-shaped account-device session wrapper
  over `Engine<SqliteStorage>`.
- `crates/storage-memory` — in-memory storage and snapshot backend for tests.
- `crates/storage-sqlite` — SQLCipher-backed SQLite storage for Marmot and
  custom OpenMLS state, with Rust migrations for schema/data evolution.
- `crates/transport-nostr-adapter` — Nostr transport adapter core for account
  activation, group subscription sync, relay-event routing, and endpoint-level
  publish reports behind an injectable relay-client boundary. Its optional
  `sdk` feature provides the first `nostr-sdk` backed relay client.
- `crates/transport-nostr-peeler` — Nostr boundary mapping for kind `445` /
  `1059` events, kind `445` group envelope peeling, and NIP-59 welcome
  wrap/peel with injected local signer/decrypter.
- `crates/cgka-conformance-simulator` — multi-client simulator, vectors,
  generated scenarios, and property tests.
- `formal/tamarin` — formal models for the convergence selector, delivery-order
  robustness, lifecycle cases, and proof/test mapping.

The current workspace can exercise the peeler-ingest boundary through
in-memory clients, reopen encrypted SQLCipher-backed account-device sessions,
drive a real `AccountDeviceSession` + `NostrTransportAdapter` +
`NostrMlsPeeler` stack over an in-memory relay client, cover publish ack/fail
resolution and basic delivery-chaos cases at that stack boundary, converge
stored OpenMLS messages, emit application-visible group events, model
losing-branch invalidations, and test generated delivery variants.

## Known gaps

- **Production persistence hardening** — `storage-sqlite` provides encrypted
  persistence, atomic group snapshots, retained-anchor pruning, and
  privacy-oriented SQLite defaults. `cgka-session` opens one encrypted
  database per account-device identity. App key-management integration,
  packaging, and longer-term rekey/vacuum/checkpoint policy still need
  production wiring.
- **Production transport adapters** — `transport-nostr-adapter` now implements
  the Nostr adapter core over an injectable relay-client boundary, with an
  optional `nostr-sdk` relay client, exact stale group subscription cleanup,
  adapter-local metrics, privacy-safe tracing, and redacted SDK relay-health
  summaries. The SDK owns reconnect/backoff, retry interval adjustment, jitter,
  and relay status mechanics. The session crate now has an in-memory relay
  integration harness that drives NIP-59 welcomes, kind `445` group messages,
  invite group evolution, insufficient acks, publish errors, subscription
  gating, duplicate delivery, and reordered delivery through the real session,
  adapter, and peeler stack. Production relay auth, app-level relay policy,
  richer telemetry export, and account key-management wiring still need
  integration.
- **Deep same-epoch app-message reordering** — the seeded stack-chaos runner
  keeps generated app-message reordering shallow. A deeper generated reversal
  exposed OpenMLS `TooDistantInThePast` behavior in the message generation
  secret tree. We need an explicit policy for how much same-epoch app-message
  reordering the transport/session layer promises to tolerate, and how to
  classify messages outside that window.
- **Late invite commits for new members** — invite lifecycle chaos shows that a
  member who joined from the welcome cannot decrypt the earlier group commit
  that invited them. The stack currently fails closed with `PeelFailed` and
  treats replay as another deferred peel attempt. We should decide whether that
  class should become terminal once the welcome has already landed the member
  at the post-invite epoch.
- **Portable fork-recovery vectors** — fork recovery is tested in Rust, but
  OpenMLS commit randomness makes stable external vectors harder.
- **Safe Extensions framework support** — still gated on backend library
  support and migration design.
- **`IdentityRemove` proposal type** — identified as the first likely
  Marmot-custom proposal, not specified or implemented.
- **KeyPackage refresh/expiry policy** — still a higher-layer production
  scheduling concern.

## See also

- Target architecture: [`target-architecture.md`](./target-architecture.md)
- Direction: [`direction.md`](./direction.md)
- Canonicalization contract: [`../cgka-engine-canonicalization-contract.md`](../cgka-engine-canonicalization-contract.md)
- Distributed convergence: [`../distributed-convergence.md`](../distributed-convergence.md)
