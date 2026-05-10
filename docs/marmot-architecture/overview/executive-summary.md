---
title: "Marmot — Executive Summary"
created: 2026-04-19
tags: [marmot, overview, executive-summary]
status: overview
updated: 2026-05-10
---

# Marmot — Executive Summary

Marmot is an end-to-end encrypted group messaging protocol built on Nostr identity and RFC 9420 MLS (Messaging Layer Security). It's designed as an **interoperable protocol**, not a product — the goal is that independent clients and devices can join the same group and exchange encrypted messages correctly, without all implementing the same code.

---

## The problem we're solving

Existing encrypted messengers (Signal, Wire, WhatsApp) bundle protocol, UI, key management, storage, and social graph into one shippable product. They work well but lock users into one vendor and one codebase.

**Marmot instead defines just the interop-required substrate** — group state, wire formats, identity binding, capability negotiation — and leaves everything above that line to client freedom. A Marmot group can include users on multiple independently-built clients, across multiple devices per user, without feature drift breaking the group.

The core technical challenge: **MLS requires total linear ordering of group-state commits, but Nostr is unordered, unreliable pub/sub**. Bridging that mismatch safely — without forking, losing messages, or leaking forward secrecy — is what the protocol has to get right.

---

## What we're optimizing for

1. **Cross-client and cross-device feature parity.** Two users on different Marmot clients should experience the same features in the same group.
2. **Multiple independent implementations.** MDK (Rust) and Marmot-TS (TypeScript) are two today; at least one more planned. Independent implementations catch spec ambiguities that a single codebase would normalize silently.
3. **Technology pluggability.** CGKA backend, transport, and blob storage are all meant to be swappable. MLS over Nostr relays + Blossom is today's instantiation, not the definition of Marmot.
4. **Forward security and post-compromise security.** Both are non-negotiable — that's why MLS is the CGKA. Sender Keys and weaker schemes are off the table.
5. **Progressive enhancement at the group level.** Groups form at the best capability set all members can support. Groups upgrade over time as member capabilities improve. No hard-fork migrations.
6. **Durable patterns.** The goal is a design that lasts 10+ years. Decisions are made slowly and deliberately.

---

## What we're explicitly NOT optimizing for

1. **Being a product.** Marmot is a protocol; MDK is a reference implementation. whitenoise-rs is the application core. Shipping "a better messenger app" is not the goal.
2. **Consensus across a global network.** Marmot groups are independent of each other — no global ledger, no blockchain-style agreement. A protocol bug affects one group, not the network.
3. **Interop at layers where Marmot isn't currently aiming.** We don't target cross-MLS-implementation interop for every primitive; Marmot owns its own extensions, proposal types (when needed), and event kinds.
4. **Speed of spec iteration at the cost of correctness.** Protocol changes coordinate across multiple clients, so they're deliberately slower than single-product feature shipping.
5. **Minimal protocol surface for its own sake.** Where cross-client feature parity requires protocol-level agreement, we agree at the protocol level. Thin-protocol purism (Matrix-style, where features drift per-client) is explicitly rejected.

---

## The target state we're building toward

**A thick-protocol, thin-application architecture, structured like Bitcoin or Lightning:**

- **The protocol package** (MDK and equivalent implementations) defines group state evolution, wire formats, identity binding, capability negotiation, and the interface to swappable technology (CGKA, transport, storage).
- **Clients** build UX, storage, notifications, key custody, and integrations on top. Clients differentiate freely above the protocol line.
- **Multiple reference implementations** keep the spec honest. One codebase is never the whole definition.

**Four components with explicit trait boundaries inside the protocol package:**

- **CgkaEngine** — group key agreement (MLS today, swappable)
- **TransportPeeler** — the explicit seam between a CGKA backend and a transport (one per pair)
- **TransportAdapter** — moves opaque encrypted blobs over a network (Nostr relays today, swappable)
- **Application layer** — intent in, events out

**MLS Extensions Safe Framework as the default** for new custom data going forward, once backend libraries support it (draft-ietf-mls-extensions-09). Classical custom extensions (our current `0xF2EE`, `0xF2EF`, `0xF2F0`) stay as-is.

**Capability negotiation baked into every client** so groups form correctly regardless of which clients the members are on, and evolve as capabilities improve.

---

## How far along we are

- ✅ Spec merged for MIP-00 through MIP-05; MIP-06 multi-device in PR.
- ✅ MDK (Rust) and Marmot-TS (TypeScript) both implement the merged spec.
- ✅ whitenoise-rs client reference implementation running against real Nostr relays.
- ✅ Current CGKA engine workspace implements the OpenMLS-backed engine
  candidate, convergence model, simulator harness, generated delivery variants,
  no-network Nostr stack chaos, property tests, and Tamarin proofs for the
  branch-selection core.
- 🚧 MDK (~66K LOC) and whitenoise-rs (~100K LOC) are larger than their target shapes — decomposition follow-up needed.
- 🚧 MIP structure being reworked in `spec/` — the new draft is organized by
  stable protocol surfaces and small MLS app data dictionary components.
- 🚧 Safe framework adoption blocked on backend library support; needs investigation.
- 🚧 `IdentityRemove` custom proposal type identified as the first needed Marmot-custom MLS proposal.
- 🚧 Production app integration remains outside the current engine simulator;
  the Nostr adapter core, optional SDK client, stale subscription cleanup, and
  adapter diagnostics exist. The adapter relies on `nostr-sdk` for
  reconnect/backoff and relay status mechanics, but relay auth, app-level relay
  policy, telemetry export, and account key-management integration still need
  production work.

---

## Where to go next

- One-page overviews of each major theme: see sibling docs in this `overview/` directory.
- Deep reference material: [`../index.md`](../index.md) has the full map.
