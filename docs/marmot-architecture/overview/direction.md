---
title: "Direction — Where We're Going"
created: 2026-04-19
tags: [marmot, overview, direction, conclusions]
status: overview
updated: 2026-05-11
---

# Direction — Where We're Going

Current architectural direction after the CGKA engine/convergence work, draft-ietf-mls-extensions-09 review, full MIP
walk, and identity-scoped removal discussion.

This is a snapshot of consensus. Major rework decisions are deliberately deferred until cost/benefit is clearer.

---

## What we've concluded (higher confidence)

### 1. Thick protocol with explicit interop/application boundary — embraced.

Cross-client feature parity is worth the protocol-evolution cost. Every future feature gets a conscious "protocol-level
or client-level" decision at design time using the test in [`protocol-boundary.md`](./protocol-boundary.md).

### 2. Reference-implementation + multiple implementations + clients — the durable pattern.

Matches Bitcoin (Core + wallets) and Lightning (LND/LDK/Eclair/CLN + apps). Marmot is already on this path with MDK
(Rust) + Marmot-TS (TypeScript). Marmot-TS has already surfaced real stress points MDK-alone missed — this principle
works. Target at least one more independent implementation in the 12–24-month window.

### 3. The four-component target architecture is holding.

The active engine workspace maps cleanly onto the Application / CgkaEngine / TransportPeeler / TransportAdapter split.
The main refinement since the first architecture docs is that convergence belongs inside the engine, after peeling and
before application-visible output.

### 4. MLS Extensions Safe Framework as default for new customs.

Draft-09's Components + AppDataDictionary + SafeExportSecret + SafeAAD toolkit is the right architectural home for new
protocol-level data going forward. Existing classical extensions don't need emergency migration. **Gated on backend
library support** — OpenMLS's Safe framework support still needs a concrete backend investigation.

### 5. Custom proposal types stay outside the Safe framework.

The framework covers component data (persistent + ephemeral) but not custom proposal semantics. `IdentityRemove`
(Marmot's first custom proposal type) will be a classical `ProposalType::Custom(u16)`.

### 6. `IdentityRemove` is Marmot's first needed custom proposal type.

Addresses the MIP-06 multi-device "leave all my devices" gap, admin-kicks-user-entirely races, and lost-device
scenarios. Recommended shape: commit-time resolution, same-identity authorization, and auto-commit by the lowest-index
remaining non-target identity. Full design in
[`../further-context/custom_extensions.md`](../further-context/custom_extensions.md) §7.

### 7. MIP-01 group image encryption stays Marmot-custom as-is.

Epoch-independent image key is a deliberate operational trade-off, not a flaw. MIP-04 per-file media encryption is
different and is a Safe framework candidate.

---

## Directions we're leaning toward (needs more work)

### 1. The MIP structure itself may be wrong.

Per-feature MIPs cause scatter — landing one feature touches many MIPs. A better structure might be **reference docs for
components, patterns, and primitives** with feature MIPs that reference them.

- Wire-format reference docs (per Nostr event kind, per extension, per proposal type).
- Pattern reference docs (`kind: 450` identity proof; SelfRemove auto-commit rule; gossip-inside-MLS pattern).
- Primitive reference docs (ComponentID namespace; exporter conventions; capability registry).
- Feature MIPs compose these building blocks — shorter, more focused.

**NOT a strict Bitcoin/BIP one-number-per-feature model** — overlap between features is too real. Needs a concrete pilot
before committing.

### 2. App components are now the group-state shape.

Group profile, admin policy, and Nostr routing now live in `app_data_dictionary`, and KeyPackages advertise supported
component ids through the upstream `app_components` component. Keep pushing new group-state work into small component
documents.

### 3. MDK and whitenoise-rs need their own decomposition review.

Three postures worth naming: **evolution** (keep, land incremental changes), **refactor** (move toward the target
boundaries while keeping protocol as-is), and **rebuild** (new protocol library built on Safe framework from day one).
The likely answer is phased, but it still deserves its own cost/benefit proposal.

---

## Investigation items

- Does OpenMLS (or the MLS library Marmot-TS uses) support draft-09's Safe Extensions framework? If not, what's the
  upstream timeline?
- What does a component-based Marmot spec structure look like concretely? Which existing feature is the right pilot?
- Should `IdentityRemove` be gated on multi-device being active, or available universally?
- Should the `kind: 450` identity proof pattern be elevated to a first-class Marmot primitive (a
  `MarmotNostrIdentityProof` reference doc) that multiple MIPs reference?

---

## Immediate next steps (concrete, near-term)

Each small enough to actually do, each produces an artifact that makes bigger decisions cheaper:

1. **Build the CGKA engine vector plan.** Write a vector manifest, define the byte-level fixture schema, and promote the
   best chaos cases into portable scenario vectors where the OpenMLS randomness model allows it.
2. **Map the whitenoise-rs integration boundary.** Decide whether the first path is a direct interface change or a shim,
   and list the exact methods the app core needs from `cgka-session` / `marmot-account`.
3. **Draft a spec-structure reorganization proposal.** Walk one existing feature (MIP-03 SelfRemove or MIP-06
   multi-device) through a component-based structure. Decide whether to pilot.
4. **Investigate OpenMLS + Marmot-TS Safe framework support.** Gate for §1.4 above.
5. **Sketch `IdentityRemove` as a full MIP-sized design.** First concrete data point for how any new spec structure
   handles a new custom proposal.
6. **Start an MDK/whitenoise-rs decomposition exploration.** Use the current target architecture and engine contract as
   the baseline for deciding what is evolution-compatible, refactor-required, or rebuild-only.

---

## The 10-year durability test

| Decision | Durability | Reasoning |
| --- | --- | --- |
| Thick protocol with explicit interop/app boundary | **High** | Matches Bitcoin (15 yrs) + Lightning (7+ yrs). |
| Reference-impl + multi-impl + clients | **High** | Same pattern; already on this path. |
| Four-component target architecture | **High** | Boundaries align with real concerns. |
| Safe framework as default for new customs | **Medium** | Contingent on MLS ecosystem and backend adoption. |
| App-component group state | **High** | Matches the current engine path and keeps profile/admin/routing concerns separable. |
| Component-based spec structure | **Unknown** | Novel for Marmot; needs piloting. |
| `IdentityRemove` as first custom proposal | **High** | Real gap; once shipped, stable. |

High-confidence decisions are about **shape** (thick protocol, reference-impl, crate boundaries). Lower-confidence
decisions are about **ecosystem timing** (Safe framework adoption and component-backed routing details). Commit to shape now; defer
timing-dependent decisions until external work resolves.

---

## See also

- Target architecture: [`target-architecture.md`](./target-architecture.md)
- Current state: [`current-state.md`](./current-state.md)
- Canonicalization contract:
  [`../cgka-engine-canonicalization-contract.md`](../cgka-engine-canonicalization-contract.md)
