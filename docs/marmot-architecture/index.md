---
title: "Marmot Architecture — Index"
created: 2026-04-15
updated: 2026-06-10
tags: [marmot, architecture, index]
---

# Marmot Architecture — Index

A technical reference for the Marmot stack: where the current architecture stands, which contracts are becoming spec
text, and which older notes are kept only for background.

This wiki is organized in two tiers:

1. **`overview/`** — **short, one-page docs**. Each covers one theme. Read these first; these are the docs to share with
   a new engineer.
2. **`further-context/`** — **deep reference material**. Longer design docs, historical decision tracking, codebase
   surveys, and older exploration notes. Check the status banner before treating a further-context doc as current.

---

## Start here — overview (one page each)

Written to be readable in 5 minutes each, shareable as a package.

- **Doc:** [**`overview/executive-summary.md`**](./overview/executive-summary.md)
  - **What it covers:** **The one-pager.** Problem, what we're optimizing for, what we're NOT optimizing for, target
    state. Share this with a new engineer.

- **Doc:** [`overview/protocol-boundary.md`](./overview/protocol-boundary.md)
  - **What it covers:** Where the line is between protocol and application. The test for putting new features on the
    correct side.

- **Doc:** [`overview/target-architecture.md`](./overview/target-architecture.md)
  - **What it covers:** The four components (CgkaEngine, TransportPeeler, TransportAdapter, application) and their trait
    boundaries.

- **Doc:** [`overview/capability-negotiation.md`](./overview/capability-negotiation.md)
  - **What it covers:** Why the capability system is load-bearing and what every client must implement.

- **Doc:** [`overview/custom-extensions.md`](./overview/custom-extensions.md)
  - **What it covers:** The inherit-vs-define decision framework. The MLS Safe Extensions framework (draft-09).

- **Doc:** [`overview/nostr-role.md`](./overview/nostr-role.md)
  - **What it covers:** Nostr's three distinct roles — identity, app message format, transport — and which are
    pluggable.

- **Doc:** [`overview/nostr-account-transport.md`](./overview/nostr-account-transport.md)
  - **What it covers:** Working note on Nostr user directory, account bootstrap, relay plane, group routing, and relay
    safety policy.

- **Doc:** [`overview/app-core-boundary.md`](./overview/app-core-boundary.md)
  - **What it covers:** The boundary between `dm`, `marmot-app`, `marmot-account`, sessions, and future Swift/TUI
    bindings.

- **Doc:** [`overview/marmot-app-runtime.md`](./overview/marmot-app-runtime.md)
  - **What it covers:** The implemented first slice of the multi-account `marmot-app` runtime, its shared Nostr relay
    plane, and the daemon, CLI, TUI boundary.

- **Doc:** [`hermes-openclaw-agent-integration-plan.md`](./hermes-openclaw-agent-integration-plan.md)
  - **What it covers:** Working plan for hosting Hermes Agent and OpenClaw as server-side Marmot members with a
    `dm-agent` connector, local gateway shims, invite allowlists, and QUIC previews.

- **Doc:** [`hermes-agent-production-runbook.md`](./hermes-agent-production-runbook.md)
  - **What it covers:** Supervised deployment path for Hermes Agent with `dm-agent`, token-gated local control sockets,
    systemd templates, and a Docker-to-phone manual test.

- **Doc:** [`overview/cgka-engine-quality-and-vectors.md`](./overview/cgka-engine-quality-and-vectors.md)
  - **What it covers:** Near-term engine quality target: whitenoise-rs integration, chaos coverage, scenario vectors,
    and byte-level vectors.

- **Doc:** [`overview/whitenoise-integration-map.md`](./overview/whitenoise-integration-map.md)
  - **What it covers:** First shim map from whitenoise-rs account/relay flows to the current engine/session/account
    boundary.

- **Doc:** [`overview/observability.md`](./overview/observability.md)
  - **What it covers:** Privacy-safe tracing/logging rules and the repo-wide tracing audit guardrail.

- **Doc:** [`overview/current-state.md`](./overview/current-state.md)
  - **What it covers:** Implementations, merged MIPs, the current CGKA engine workspace, and known gaps.

- **Doc:** [`overview/direction.md`](./overview/direction.md)
  - **What it covers:** Where we're going after the CGKA engine/convergence work.

**Read order for a new engineer:** executive-summary → protocol-boundary → target-architecture → capability-negotiation
→ nostr-role → app-core-boundary → marmot-app-runtime → cgka-engine-quality-and-vectors → whitenoise-integration-map →
observability → custom-extensions → current-state → direction.

---

## Deeper reference — further-context

These are longer working documents. Go here when you need depth, not orientation.

### Protocol & architecture reference

- **Doc:** [`cgka-engine-spec.md`](./cgka-engine-spec.md)
  - **What it covers:** Draft normative CGKA engine spec: boundary, state, convergence, storage, conformance
    requirements.

- **Doc:** [`cgka-engine-canonicalization-contract.md`](./cgka-engine-canonicalization-contract.md)
  - **What it covers:** Draft CGKA engine canonicalization contract: post-peeling inputs, candidate-state graph, sync
    state, outputs, storage, conformance scenarios.

- **Doc:** [`distributed-convergence.md`](./distributed-convergence.md)
  - **What it covers:** Draft convergence model for selecting one MLS branch from unordered multi-relay input.

- **Doc:** [`relay-delivery-telemetry.md`](./relay-delivery-telemetry.md)
  - **What it covers:** Measuring relay delivery behavior to tune convergence quiescence; cross-relay arrival spread,
    quiescence regimes, and the backfill/reconciliation backstop.

- **Doc:** [`relay-observability.md`](./relay-observability.md)
  - **What it covers:** Export contract for client-side relay performance telemetry: the opt-in/aggregate/k-anonymous
    privacy contract, metric catalogue, collection architecture, and the proposed observability.md amendment.

- **Doc:** [`telemetry.md`](./telemetry.md)
  - **What it covers:** Current implementation inventory for relay telemetry, OTLP export, engine reorg metrics,
    tracing/logging guardrails, local surfaces, and exactly what fields are collected or exported.

- **Doc:** [`audit-logging.md`](./audit-logging.md)
  - **What it covers:** Current implementation inventory for opt-in forensic JSONL logs, file identity, every event
    kind and metadata field, upload/tracker behavior, and downstream tooling guidance.

- **Doc:** [`../../spec/README.md`](../../spec/README.md)
  - **What it covers:** Marmot v2 protocol draft by stable protocol surface and app component.

- **Doc:** [`../quic-broker-deployment.md`](../quic-broker-deployment.md)
  - **What it covers:** Local Compose, GHCR image, and VM deployment notes for the memory-only QUIC broker.

- **Doc:** [`further-context/target-architecture.md`](./further-context/target-architecture.md)
  - **What it covers:** Older long-form target architecture with illustrative trait sketches. Current orientation lives
    in `overview/target-architecture.md`.

- **Doc:** [`further-context/cgka-engine-design.md`](./further-context/cgka-engine-design.md)
  - **What it covers:** Older long-form `CgkaEngine` design. Current contract lives in the canonicalization and
    convergence docs.

- **Doc:** [`further-context/capability-negotiation.md`](./further-context/capability-negotiation.md)
  - **What it covers:** Full capability negotiation design. The three queries, group creation, upgrade, admin action,
    MIP checklist.

- **Doc:** [`further-context/nostr-role-in-marmot.md`](./further-context/nostr-role-in-marmot.md)
  - **What it covers:** Deep version of Nostr's three roles. What's spec-stable and what's transport-specific.

- **Doc:** [`further-context/custom_extensions.md`](./further-context/custom_extensions.md)
  - **What it covers:** Full decision framework + per-MIP review + MLS Extensions Safe framework teaching +
    `IdentityRemove` design space.

### Current state — facts and analysis

- **Doc:** [`further-context/codebase-survey.md`](./further-context/codebase-survey.md)
  - **What it covers:** Raw metrics — LOC counts, dependency graphs, module structures.

- **Doc:** [`further-context/whitenoise-rs-deep-dive.md`](./further-context/whitenoise-rs-deep-dive.md)
  - **What it covers:** Detailed analysis of the whitenoise-rs client layer — major subsystems, known complexity
    hotspots, refactor plan.

- **Doc:** [`../learnings.md`](../learnings.md)
  - **What it covers:** Historical engineering notes. Useful for archaeology, not a current contract.

### Historical context

- **Doc:** [`further-context/architectural-alternatives.md`](./further-context/architectural-alternatives.md)
  - **What it covers:** The six architectural alternatives considered before landing on the target. Useful for
    understanding _why_ the target looks the way it does.

- **Doc:** [`further-context/decision-points.md`](./further-context/decision-points.md)
  - **What it covers:** Seven key architectural decisions with explicit recommendations. Several marked ✅ resolved.

### Principles (lives at `docs/` top level)

- **Doc:** [`../required-features.md`](../required-features.md)
  - **What it covers:** Full principles statement for what Marmot the protocol defines and what it doesn't. The
    long-form version of `overview/protocol-boundary.md`.

---

## Current state vs. target state, at a glance

- **Layer:** Presentation
  - **Today:** Flutter (whitenoise)
  - **Target:** Unchanged

- **Layer:** FFI bridge
  - **Today:** flutter_rust_bridge
  - **Target:** **whitenoise-ffi** — transport-agnostic, Dart + Swift

- **Layer:** Application
  - **Today:** whitenoise-rs singleton
  - **Target:** **whitenoise-core** — thin facade, per-account sessions

- **Layer:** Transport
  - **Today:** Nostr relay control planes, embedded
  - **Target:** `TransportAdapter` trait plus `transport-nostr-adapter` core, stale subscription cleanup, diagnostics,
    redacted SDK relay health, and optional SDK client; relay auth/policy next

- **Layer:** CGKA Engine
  - **Today:** `crates/cgka-engine` implements the current OpenMLS-backed engine candidate; `crates/cgka-session` wraps
    it in an encrypted account-device lifecycle
  - **Target:** Spec-level `CgkaEngine` contract with production persistence, whitenoise-rs integration mapping, chaos
    coverage, and portable vectors

- **Layer:** Crypto
  - **Today:** OpenMLS behind `CgkaEngine`
  - **Target:** OpenMLS first, with the trait boundary preserving future CGKA swap room

- **Layer:** Storage
  - **Today:** `storage-sqlite` for SQLCipher-backed persistence plus in-memory SQLite test/simulator runs
  - **Target:** MLS app-component policy negotiation, app key-management integration, packaging

---

## Key decisions already made

- **PCS is non-negotiable.** Both FS and PCS required. Sender Keys off the table.
- **MLS stays.** BeeKEM and other CGKAs interesting but immature; `CgkaEngine` trait makes them swappable in future.
- **Transport is pluggable.** FIPS mesh and others are first-class future targets.
- **Commit convergence is engine-owned.** Transport ordering is advisory; the engine canonicalizes commits before
  releasing app-visible output.
- **whitenoise-ffi, not whitenoise-frb.** FFI bridge outputs Swift bindings too.
- **Nostr has three distinct roles** — identity (always), app message format (always), transport (pluggable).
- **One capability per feature.** Flat feature registry, no dependency graph.
- **Progressive enhancement, not hard breaks.** Create the best group possible, upgrade gracefully, never block
  communication.
