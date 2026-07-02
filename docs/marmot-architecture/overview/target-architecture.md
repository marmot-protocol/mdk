---
title: "Target Architecture — Four Components"
created: 2026-04-19
tags: [marmot, overview, architecture, components]
status: overview
updated: 2026-06-07
---

# Target Architecture — Four Components

Inside the protocol package, responsibilities split into four pieces with explicit trait boundaries. Every piece above
the trait is the protocol's concern; every piece below is swappable technology.

---

## The four components

```
┌─────────────────────────────────────────────────────┐
│  Application layer                                  │
│  (intent in, events out; no crypto or transport)    │
├─────────────────────────────────────────────────────┤
│  CgkaEngine                                         │
│  (coordinator + CGKA backend + capability system    │
│   + opinionated defaults over the backend)          │
│  ┌─────────────────────────────────────────────┐    │
│  │  TransportPeeler  (injected, pluggable)     │    │
│  │  — one impl per transport+CGKA pair         │    │
│  └─────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────┤
│  TransportAdapter                                   │
│  (moves opaque encrypted blobs over a network)      │
└─────────────────────────────────────────────────────┘
```

### 1. Application layer

One job: **express intent, consume events.** Sends `SendIntent` (a message, an invite, a leave). Receives a stream of
`GroupEvent`s (message arrived, member added, epoch advanced). Never touches crypto, wire formats, or transports
directly.

### 2. CgkaEngine

The heart. Wraps the CGKA backend (MLS/OpenMLS today, swappable), drives commit sequencing (the "coordinator"), enforces
capability negotiation, and supplies opinionated defaults where the backend is unopinionated (e.g. "leave a group via
SelfRemove proposal, not legacy Remove-self").

Takes `TransportMessage` in from the transport layer; produces `GroupEvent` out. Takes `SendIntent` in from the app;
produces `TransportMessage` (one or more) out.

### 3. TransportPeeler

The explicit seam where a specific transport format meets a specific CGKA backend. For MLS-over-Nostr there's one peeler
(`NostrMlsPeeler`); for MLS-over-FIPS-mesh there'd be a different one. Its job: wrap CGKA ciphertext with the transport
envelope (outbound), unwrap the transport envelope to get CGKA ciphertext (inbound).

Two-path interface: group messages use group/epoch material; welcomes use recipient-addressed encryption. Same trait,
two crypto paths.

### 4. TransportAdapter

Moves opaque blobs. Publishes `TransportMessage`s; subscribes to inbound streams. Never sees plaintext. For Nostr, this
is the relay-control layer: activate an account against its inbox relays, keep group subscriptions synced from the
active group set, publish group messages to group relays, publish welcomes to recipient inbox relays, and deliver
account-scoped `TransportMessage`s back to the coordinator. It should remove stale subscriptions when the active group
set changes and expose diagnostics without feeding those diagnostics into convergence. A concrete adapter should use its
transport library's native connection lifecycle when available; for Nostr, the SDK owns reconnect/backoff, retry
interval adjustment, jitter, and relay status mechanics. For FIPS: wraps in mesh frames. For HTTP/P2P/BLE: whatever's
appropriate.

Multiple transports can run simultaneously for the same group — the engine deduplicates by MessageId.

---

## Why the split matters

- **CGKA is the interoperability boundary.** Two clients can use different transports (one on Nostr, one on FIPS mesh)
  and still share a group, as long as they share the same CGKA backend. But they cannot interop across different CGKA
  backends — that's a different group type.
- **Transport is orthogonal to the CGKA.** Swapping transport doesn't affect group state or crypto.
- **Peeler is the explicit pair-wise seam.** Not a way to pretend transport and CGKA are independent — they're not — but
  an honest acknowledgment of the coupling point.
- **Storage is pluggable below the blob layer.** Blossom today for media; S3, filesystem, IPFS, self-hosted all
  plausible. Orthogonal to the four components above.

---

## Two-layer message model

Every message has two encryption layers, always:

```
  Outer: transport envelope (kind 445 wrap with group exporter secret, or 1059 gift-wrap for welcomes)
    ↓
  Inner: CGKA ciphertext (MLS commit, proposal, application message, or welcome)
    ↓
  Plaintext: unsigned Nostr rumor or control primitive
```

The outer is the TransportPeeler's concern; the inner is the CgkaEngine's; the plaintext is the application's.

---

## Publish-before-apply contract

Group-evolution operations (commits, adds, removes, rotations) follow a two-step flow:

1. Engine produces a `SendResult::GroupEvolution { msg, welcomes, pending }`.
2. Application publishes the commit + any welcomes via the adapter.
3. On successful publish confirmation, application calls `engine.confirm_published(pending)`.
4. Engine merges pending state and emits the corresponding `GroupEvent`.

This prevents the engine from advancing past a commit that never made it to the network.

Auto-publish work created while ingesting inbound messages follows the same rule. The current example is a SelfRemove
auto-commit: the engine stages the commit, returns a publish obligation with a pending reference, and waits for
`confirm_published` or `publish_failed` before applying or discarding it.

---

## Current implementation status

The active workspace proves the shape without the old prototype tree:

- `crates/traits` defines the cross-boundary types, including the account-aware `TransportAdapter` boundary: activation,
  group sync, publish requests/reports, and delivery metadata.
- `crates/cgka-engine` implements the OpenMLS-backed engine candidate.
- `crates/cgka-session` wires the engine to encrypted account-device storage.
- `crates/marmot-account` owns account/session orchestration: it combines an account-device session, a `TransportAdapter`,
  transport routing policy, KeyPackage publication, and pending publish confirmation.
- `crates/storage-sqlite` provides SQLCipher-backed persistence for Marmot metadata and group-scoped OpenMLS state, plus
  an in-memory SQLite mode for tests and simulator runs.
- `crates/transport-nostr-adapter` implements the Nostr adapter core: account-scoped activation, group subscription
  sync, stale subscription cleanup, relay-event routing, diagnostics, redacted relay-health summaries, and publish
  reports over an injectable relay-client boundary. Its optional `sdk` feature provides the first `nostr-sdk` backed
  relay client.
- `crates/transport-nostr-peeler` maps Nostr kind `445` / `1059` events into engine transport messages, peels Nostr/MLS
  group envelopes, and handles NIP-59 welcomes when supplied with a local signer/decrypter.
- `crates/cgka-conformance-simulator` drives multi-client scenarios, generated delivery variants, and property tests
  over the engine.

The production perimeter is still partly outside this workspace: relay auth, relay safety policy, account
key-management integration, persistence operations policy, and packaging.

The Nostr routing source of truth is the signed `marmot.transport.nostr.routing.v1` app component for group routes and
the user's kind `10002` NIP-65 relay list for KeyPackage publication. The generic account runtime remains
transport-agnostic; Nostr-specific relay safety and full KeyPackage event publication should stay with the Nostr
transport/app-runtime layer.

---

## See also

- Deep reference: [`../further-context/target-architecture.md`](../further-context/target-architecture.md)
- CGKA engine trait specifics: [`../further-context/cgka-engine-design.md`](../further-context/cgka-engine-design.md)
- Canonicalization contract:
  [`../cgka-engine-canonicalization-contract.md`](../cgka-engine-canonicalization-contract.md)
