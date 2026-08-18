---
title: "Multi-Step State Changes"
created: 2026-07-04
updated: 2026-08-18
tags: [marmot, overview, state, atomicity, error-paths]
status: overview
---

# Multi-Step State Changes

After any multi-step operation, local state must reflect what actually happened — especially on the error path. A
failure in the middle of a sequence must never leave a torn record, an unreachable retry, or a stale marker that
disagrees with the step that actually failed. This generalizes the engine's atomic snapshot/rollback rule
("Snapshot and rollback MUST be atomic across Marmot metadata and OpenMLS state" — `cgka-engine-spec.md`, Engine State
Snapshots and Horizons) to every crate in the workspace. Tracking issue: mdk#711.

## Rules

1. **Validate before you mutate.** An operation that both validates input (client-supplied or derived) and tears down
   or advances durable state runs the validation first and mutates only on success. If teardown and validation cannot
   be separated, move the validation to where it is atomic with the teardown decision (the agent stream finalize path
   validates inside the compose task's `Finish` handling — mdk#366).

2. **Compensation covers every applied step.** Where staging must precede a fallible step, the error path restores
   *all* state the operation already advanced — not just one layer of it. Prefer restructuring so the hard-to-undo
   step runs last (swap-then-assign in the forensic recorder — mdk#358; record projection after `begin_pending` in
   auto-commit staging — mdk#333). Where an RAII guard provides the compensation, it must cover everything the guarded
   window applied (`PendingCommitCleanupGuard` clears the staged commit, releases the snapshot, and removes the stored
   proposal).

3. **Record intent before external side effects.** Reconciliation against an external system (relays, brokers)
   persists the desired state first, then drives the side effects, re-enqueueing failures for retry instead of
   abandoning the state update (the Nostr adapter's group sync updates routing state before unsubscribing and queues
   failed unsubscribes — mdk#337). Purely local observable state that exists to mirror a successful external effect
   advances only after that effect succeeds (the chat read marker advances post-publish — mdk#338).

4. **Confirmation reflects reality.** Never confirm work that reached no one: zero accepted endpoints is a failure
   regardless of the acknowledgement policy (mdk#375). When a confirmed operation leaves a partial failure behind
   (a confirmed commit with an undelivered welcome), surface it with structured context that makes targeted repair
   possible without redoing the confirmed part (`WelcomeDeliveryFailure` + `redeliver_welcome` — mdk#352).

## Create-group durability ownership (mdk#1487)

The current-profile create path crosses three deliberately separate ownership layers:

| State | Classification | Create-path rule | Crash recovery |
| --- | --- | --- | --- |
| MLS group plus exact founding Welcome bytes/destinations | Authoritative | The engine commits these atomically before app projection work. | Session open reloads the group and retained outbound Welcomes. |
| Account group plus materialized chat-list row | Derived, durable host projection | One app SQLCipher transaction writes both; the detailed create result returns that exact committed row. | Account-open reconciliation derives the group projection from the engine. |
| `app_pending_welcome_delivery` | Convenience-only repair index | Founding create does not write it synchronously. Actual delivery failures populate it, and an explicit pending query reconciles it from engine obligations. | Account open and pending-delivery enumeration rebuild missing rows and remove completed tracked rows. |

The engine transaction remains the authoritative point of no return. The app transaction does not widen or nest the
engine transaction across components, so lock ordering is unchanged. Removing the eager convenience-index commit cuts
the synchronous post-canonical app commits from two to one. That remaining commit also materializes the chat-list row,
so `CreatedGroup`/`CreatedGroupFfi` can hand the host the durable row without a read-after-create transaction. Founding
Welcome publication and subscription refresh remain after the managed worker response, preserving mdk#1451.
If the app transaction fails after the engine commit, the detailed API returns the typed
`CreatedGroupProjectionUnavailable` result with the canonical group id so the host refreshes instead of creating a
duplicate. The legacy group-id API preserves its historical post-canonical success and recovery still drives Welcome
delivery.

### File-backed SQLCipher measurements

The ignored benchmark `file_backed_create_group_tail_benchmark_matrix` is repeatable with:

```sh
MDK_CREATE_TAIL_SAMPLES=50 cargo test -p storage-sqlite \
  file_backed_create_group_tail_benchmark_matrix --release -- --ignored --nocapture
```

Measurement on 2026-08-18 used base `a5bbb45967286761cf8d2fb74e4cdcb73347d385`, Rust 1.96.1, macOS Darwin
25.6.0, and an Apple M4 Max. Each cell is 50 optimized samples over encrypted file-backed SQLCipher storage. “Legacy
return” is the former pending-index commit plus projection commit and does not provide a response row. “Legacy + row”
adds the immediate materialization/read transaction a host needed for navigation. “Combined” is the new single app
transaction and returns its row.

| Invitees | Legacy return p50 / p95 | Legacy + row p50 / p95 | Combined p50 / p95 |
| ---: | ---: | ---: | ---: |
| 1 | 639 / 946 us | 1,434 / 2,418 us | 1,109 / 1,705 us |
| 8 | 724 / 1,451 us | 1,522 / 3,079 us | 1,046 / 1,894 us |
| 32 | 934 / 1,552 us | 1,742 / 2,725 us | 1,104 / 2,261 us |

The combined path intentionally performs more host-visible work than the old bare return, so the 1- and 8-invitee
bare-tail p50 is higher. Against the equivalent host-ready boundary, it removes two commits and improves both p50 and
p95 at all three sizes. The structured runtime metrics below remain the source for production-device attribution.

## Checklist for new multi-step flows

- What does each step mutate (durable storage, in-memory state machines, external systems, user-visible projections)?
- For every fallible step: what has already been applied at that point, and what compensates it on failure?
- Can the sequence be reordered so validation and pure reads come first and the irreversible step comes last?
- What does a crash between steps leave behind, and does the recovery path (hydrate, retry, next sync) converge on it?
- Does the error path have a regression test that injects the failure at the widest window?

## Existing anchors

- Engine snapshot/rollback atomicity: `docs/marmot-architecture/cgka-engine-spec.md`, "Engine State Snapshots and
  Horizons".
- Publish-before-apply: `crates/cgka-engine/src/publish.rs` module docs (stage, publish, then confirm/fail).
- Exposure-aware confirmation: mdk#483 / mdk#499 (a message any endpoint accepted is externally visible; never roll it
  back).
