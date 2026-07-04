---
title: "Multi-Step State Changes"
created: 2026-07-04
updated: 2026-07-04
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
