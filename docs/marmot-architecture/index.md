---
title: "Marmot Architecture — Index"
created: 2026-04-15
updated: 2026-05-10
tags: [marmot, architecture, index]
---

# Marmot Architecture — Index

A technical reference for the Marmot stack: where the current architecture
stands, which contracts are becoming spec text, and which older notes are kept
only for background.

This wiki is organized in two tiers:

1. **`overview/`** — **short, one-page docs**. Each covers one theme. Read these first; these are the docs to share with a new engineer.
2. **`further-context/`** — **deep reference material**. Longer design docs,
   historical decision tracking, codebase surveys, and older exploration notes.
   Check the status banner before treating a further-context doc as current.

---

## Start here — overview (one page each)

Written to be readable in 5 minutes each, shareable as a package.

| Doc | What it covers |
|---|---|
| [**`overview/executive-summary.md`**](./overview/executive-summary.md) | **The one-pager.** Problem, what we're optimizing for, what we're NOT optimizing for, target state. Share this with a new engineer. |
| [`overview/protocol-boundary.md`](./overview/protocol-boundary.md) | Where the line is between protocol and application. The test for putting new features on the correct side. |
| [`overview/target-architecture.md`](./overview/target-architecture.md) | The four components (CgkaEngine, TransportPeeler, TransportAdapter, application) and their trait boundaries. |
| [`overview/capability-negotiation.md`](./overview/capability-negotiation.md) | Why the capability system is load-bearing and what every client must implement. |
| [`overview/custom-extensions.md`](./overview/custom-extensions.md) | The inherit-vs-define decision framework. The MLS Safe Extensions framework (draft-09). |
| [`overview/nostr-role.md`](./overview/nostr-role.md) | Nostr's three distinct roles — identity, app message format, transport — and which are pluggable. |
| [`overview/observability.md`](./overview/observability.md) | Privacy-safe tracing/logging rules and the repo-wide tracing audit guardrail. |
| [`overview/current-state.md`](./overview/current-state.md) | Implementations, merged MIPs, the current CGKA engine workspace, and known gaps. |
| [`overview/direction.md`](./overview/direction.md) | Where we're going after the CGKA engine/convergence work. |

**Read order for a new engineer:** executive-summary → protocol-boundary → target-architecture → capability-negotiation → nostr-role → observability → custom-extensions → current-state → direction.

---

## Deeper reference — further-context

These are longer working documents. Go here when you need depth, not orientation.

### Protocol & architecture reference

| Doc | What it covers |
|---|---|
| [`cgka-engine-spec.md`](./cgka-engine-spec.md) | Draft normative CGKA engine spec: boundary, state, convergence, storage, conformance requirements. |
| [`cgka-engine-canonicalization-contract.md`](./cgka-engine-canonicalization-contract.md) | Draft CGKA engine canonicalization contract: post-peeling inputs, candidate-state graph, sync state, outputs, storage, conformance scenarios. |
| [`distributed-convergence.md`](./distributed-convergence.md) | Draft convergence model for selecting one MLS branch from unordered multi-relay input. |
| [`../../spec/README.md`](../../spec/README.md) | Experimental Marmot spec rewrite by stable protocol surface and app component. |
| [`further-context/target-architecture.md`](./further-context/target-architecture.md) | Older long-form target architecture with illustrative trait sketches. Current orientation lives in `overview/target-architecture.md`. |
| [`further-context/cgka-engine-design.md`](./further-context/cgka-engine-design.md) | Older long-form `CgkaEngine` design. Current contract lives in the canonicalization and convergence docs. |
| [`further-context/capability-negotiation.md`](./further-context/capability-negotiation.md) | Full capability negotiation design. The three queries, group creation, upgrade, admin action, MIP checklist. |
| [`further-context/nostr-role-in-marmot.md`](./further-context/nostr-role-in-marmot.md) | Deep version of Nostr's three roles. What's spec-stable and what's transport-specific. |
| [`further-context/custom_extensions.md`](./further-context/custom_extensions.md) | Full decision framework + per-MIP review + MLS Extensions Safe framework teaching + `IdentityRemove` design space. |

### Current state — facts and analysis

| Doc | What it covers |
|---|---|
| [`further-context/codebase-survey.md`](./further-context/codebase-survey.md) | Raw metrics — LOC counts, dependency graphs, module structures. |
| [`further-context/whitenoise-rs-deep-dive.md`](./further-context/whitenoise-rs-deep-dive.md) | Detailed analysis of the whitenoise-rs client layer — major subsystems, known complexity hotspots, refactor plan. |
| [`../learnings.md`](../learnings.md) | Historical engineering notes. Useful for archaeology, not a current contract. |

### Historical context

| Doc | What it covers |
|---|---|
| [`further-context/architectural-alternatives.md`](./further-context/architectural-alternatives.md) | The six architectural alternatives considered before landing on the target. Useful for understanding *why* the target looks the way it does. |
| [`further-context/decision-points.md`](./further-context/decision-points.md) | Seven key architectural decisions with explicit recommendations. Several marked ✅ resolved. |

### Principles (lives at `docs/` top level)

| Doc | What it covers |
|---|---|
| [`../required-features.md`](../required-features.md) | Full principles statement for what Marmot the protocol defines and what it doesn't. The long-form version of `overview/protocol-boundary.md`. |

---

## Current state vs. target state, at a glance

| Layer | Today | Target |
|---|---|---|
| Presentation | Flutter (whitenoise) | Unchanged |
| FFI bridge | flutter_rust_bridge | **whitenoise-ffi** — transport-agnostic, Dart + Swift |
| Application | whitenoise-rs singleton | **whitenoise-core** — thin facade, per-account sessions |
| Transport | Nostr relay control planes, embedded | `TransportAdapter` trait plus `transport-nostr-adapter` core, stale subscription cleanup, diagnostics, redacted SDK relay health, and optional SDK client; relay auth/policy next |
| CGKA Engine | `crates/cgka-engine` implements the current OpenMLS-backed engine candidate; `crates/cgka-session` wraps it in an encrypted account-device lifecycle | Spec-level `CgkaEngine` contract with production persistence and packaging |
| Crypto | OpenMLS behind `CgkaEngine` | OpenMLS first, with the trait boundary preserving future CGKA swap room |
| Storage | `storage-memory` for tests/simulator work; `storage-sqlite` for SQLCipher-backed persistence | MLS app-component policy negotiation, app key-management integration, packaging |

---

## Key decisions already made

- **PCS is non-negotiable.** Both FS and PCS required. Sender Keys off the table.
- **MLS stays.** BeeKEM and other CGKAs interesting but immature; `CgkaEngine` trait makes them swappable in future.
- **Transport is pluggable.** FIPS mesh and others are first-class future targets.
- **Commit convergence is engine-owned.** Transport ordering is advisory; the engine canonicalizes commits before releasing app-visible output.
- **whitenoise-ffi, not whitenoise-frb.** FFI bridge outputs Swift bindings too.
- **Nostr has three distinct roles** — identity (always), app message format (always), transport (pluggable).
- **One capability per feature.** Flat feature registry, no dependency graph.
- **Progressive enhancement, not hard breaks.** Create the best group possible, upgrade gracefully, never block communication.
