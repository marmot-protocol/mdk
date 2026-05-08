---
title: "Current State — Implementations & Spec"
created: 2026-04-19
updated: 2026-05-08
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

- `crates/traits` — cross-boundary value types and traits.
- `crates/cgka-engine` — OpenMLS-backed engine implementation.
- `crates/storage-memory` — in-memory storage and snapshot backend for tests.
- `crates/storage-sqlite` — SQLCipher-backed SQLite storage for Marmot and
  custom OpenMLS state, with Rust migrations for schema/data evolution.
- `crates/cgka-conformance-simulator` — multi-client simulator, vectors,
  generated scenarios, and property tests.
- `formal/tamarin` — formal models for the convergence selector, delivery-order
  robustness, lifecycle cases, and proof/test mapping.

The current engine can exercise the peeler-ingest boundary through in-memory
clients, converge stored OpenMLS messages, emit application-visible group
events, model losing-branch invalidations, and test generated delivery variants.

## Known gaps

- **Production persistence hardening** — `storage-sqlite` provides encrypted
  persistence, atomic group snapshots, retained-anchor pruning, and
  privacy-oriented SQLite defaults. App key-management integration, packaging,
  and longer-term rekey/vacuum/checkpoint policy still need production wiring.
- **Production transport adapters** — the simulator uses an in-memory bus and
  `MockPeeler`. Nostr/FIPS adapters live outside this engine workspace.
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
