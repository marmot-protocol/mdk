---
title: "MDK Architecture Review (2026-10)"
created: 2026-10-15
updated: 2026-10-15
tags: [marmot, architecture, review]
status: in-progress
---

# MDK Architecture Review (2026-10)

A system-by-system review of how MDK's crates fit together. It asks whether the architecture can run safely, fast and
predictably on every platform we ship, and where structure has grown by addition rather than by design.

This is a review, not a refactor. Findings and recommendations land here first and are discussed before any code
changes. Structural changes, including splitting `marmot-app` into smaller crates, are in scope as recommendations.

## Scope

In scope: every crate under `crates/` except the conformance simulator, the convergence campaign runner and the
incident replay adapter. The simulator is considered only to ask whether our test infrastructure can verify a given
architectural claim.

Out of scope for now: `integrations/` (reviewed separately later) and the Marmot protocol itself
(`github.com/marmot-protocol/marmot`). The exception is large-group event sizes: commit and Welcome sizes against
relay event-size limits are measured and tracked here, because this repository has the tests and real data.
Protocol-level fixes are then proposed in the spec repository.

## Platform constraint

The same Rust core ships to:

- iOS and macOS, as MarmotKit Swift over UniFFI;
- Android, as MarmotKit Kotlin over UniFFI;
- the Linux desktop app, over the C ABI;
- `wn`, `wnd` and `wn-agent` on Linux.

Windows has no bindings and none are planned. The Linux desktop app may cross-compile to Windows, but that is
untested, so Windows is kept in mind but is not a target. Every finding and recommendation must hold for:

- mobile processes that the OS suspends or kills without warning, with tight memory and background-time budgets;
- desktop hosts that stay running for a long time;
- the `wnd` and `wn-agent` daemons on Linux servers.

## Scale targets

Product guidance as of 2026-10-15. Pass 1 judges every cost model against these numbers.

| Dimension | Today | Design target |
| --- | --- | --- |
| Accounts per device | One is by far the most common; two to five is uncommon; more than five is rare | The same |
| Group size | Most groups have 2 to 5 members, some up to 15; a handful have hundreds | Thousands of members |
| History per group | Weeks (the app launched in August 2026) | Years, with some very busy groups |

So costs that grow with history or group size matter far more than costs that grow with account count. Concurrency
work should target groups within one account, not parallelism across accounts.

[`map-platforms.md`](map-platforms.md) records what each platform requires today.

## Plan

Progress on the review, the structural plan and the fixes it produced is tracked in
[#2360](https://github.com/marmot-protocol/mdk/issues/2360).

| Pass | Output | Status |
| --- | --- | --- |
| 0. System map | [`00-system-map.md`](00-system-map.md) plus the `map-*.md` pages it links | Done (#2325) |
| 1. System reviews | One page per system, A to H below | B [`b-runtime-concurrency.md`](b-runtime-concurrency.md) and E [`e-transport.md`](e-transport.md) done (#2325). The other systems are covered by extraction briefs as their steps come up. |
| 2. Synthesis | Ranked findings and an evolve/refactor/rebuild posture per system | Structural part drafted: [`core-structure.md`](core-structure.md). Extraction briefs: [relay plane](brief-relay-plane.md) |

Pass 1 systems:

| # | System | Main crates and modules |
| --- | --- | --- |
| A | Engine state machine and the contract it exposes upward | `cgka-engine`, `traits` |
| B | App runtime concurrency and ownership | `marmot-app` `runtime/`, `client/`, `lib.rs` |
| C | Storage authority versus projections | `storage-sqlite`, `marmot-app` `sqlcipher.rs`, shared and cache databases |
| D | Publish-before-apply across crash boundaries | `cgka-session`, `marmot-account`, the account worker |
| E | Transport plane, including large-group event sizes against relay limits | `transport-nostr-adapter`, `transport-nostr-peeler`, `marmot-app` `relay_plane/`, dial safety |
| F | Content acquisition | `marmot-app` `media/` and attachment/avatar runtime, `storage-sqlite` attachment and avatar stores |
| G | Product surfaces | `marmot-uniffi`, `marmot-c`, `cli`, `agent-connector`, QUIC stream crates |
| H | Cross-cutting sidecars | audit logging, telemetry, product analytics, `marmot-forensics` |

## Lenses

Every system review answers the same six questions:

1. **Ownership.** What state does it hold, who is the single writer, where is it persisted, and is it authoritative
   or derived?
2. **Concurrency.** What runs where, what serializes what, where can work queue behind unrelated work, and how do
   backpressure and cancellation behave?
3. **Failure and restart.** Where can a crash land mid-operation, what is idempotent, and can in-memory state diverge
   from what is on disk?
4. **Coupling.** Which boundaries leak, which concepts are implemented twice, and which changes routinely touch
   several systems at once?
5. **Cost model.** What is O(accounts), O(groups) or O(messages) on hot paths, at startup and in steady state?
6. **Invariants in prose versus in structure.** Which rules exist only as `AGENTS.md` or doc text that a type,
   module boundary or test could enforce instead?

## Evidence rules

- Every finding cites source (`path:line`) or a cluster of past fixes, and is marked **observed** or **hypothesis**.
- Performance claims need measurement (existing telemetry, benchmarks, audit data), not only code reading.
- Docs are leads, not evidence. Several architecture pages are out of date; the source is the authority.
- Nothing is fixed during the review. Defects found along the way are filed as issues and linked here.
