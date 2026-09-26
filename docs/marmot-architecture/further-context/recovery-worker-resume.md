---
title: Account recovery comparison result ownership
updated: 2026-09-25
status: First extraction slice; periodic comparison follow-up implemented
---

# Account recovery comparison result ownership

The later periodic-maintenance off-worker slice is recorded in
[`recovery-worker-comparison-resume.md`](recovery-worker-comparison-resume.md).
Its worker-join memory cursor handoff supersedes the pre-fetch durable cursor
recommendation below. This page describes the earlier inline state.

This slice prepares the owner-frozen, bounded reconciliation pass for a later
off-worker wait. Production bounded recovery remains disabled. The existing
account worker still awaits the comparison and subsequent transport drain; this
change does not resolve the broad `#h` wait demonstrated in
`recovery-worker-wait-attribution.md`.

## Current path and changed boundary

`authorize_account_recovery` synchronizes delivery loss and receipts, captures
route and obligation revisions, freezes the retained-event inventory, and
durably reserves one grant. `execute_recovery_grant_inner` installs the grant's
live and maintenance interests, calls `reconcile_transport_history`, drains
delivery, and checkpoints the exact grant. `sync_inner` reaches this executor at
startup, explicit catch-up, and key-package maintenance catch-up. The worker's
receive, scheduled-convergence, and periodic-maintenance arms also reach it
through `run_pending_epoch_backfill_reporting_arm`.

Before this slice, `MarmotRelayPlaneAccountAdapter::reconcile_inbox_history`
and `reconcile_group_history` injected returned NIP-77 candidate events into
the ordinary account queue before returning their aggregate outcome. They now
return `(summary, events)` to the sole caller. The serialized client executor
submits each returned event through the same account-scoped adapter routing
path before its existing drain. This removes the implicit relay-plane delivery
side effect and makes the network result an owned value. It does not bypass the
existing account queue or change durable admission, cursor, or completion rules.
Explicit queue submission remains inside the existing per-route comparison
deadline and error classification. A blocked queue consumes that route's
remaining quantum; a submission error marks that route transient while later
routes retain their normal opportunity. Already submitted events remain queued
for the normal drain.
An unsupported backend still returns `None`; an empty supported result remains
empty; route errors retain their existing transient classification. The SDK
continues to limit each reconciliation's selected candidates, and partial
endpoint summaries keep `relays_failed > 0` while returned events are handed to
the worker.

The current SDK fetch used after NIP-77 returns an error when a missing event
must be fetched through a mixed healthy/unavailable endpoint set. This slice
does not claim partial useful bytes for that case. The separate bounded SDK
missing-ID acquisition change must land and be composed with this return seam
before that behavior is qualified.

## Storage and lifetime ownership

The worker still owns `freeze_recovery_inventory`, the grant and its revision
fence, live subscription identity, the mutable engine, receipt synchronization,
all event ingestion, and the final checkpoint. The frozen inventory contains
route, endpoint, time-window, and retained-ID snapshots used for the comparison;
it is not itself a completion certificate. The SDK's request-local result does
not admit anything durably. EOSE and a successful comparison are endpoint
observations, not proof that all eligible events reached SQLCipher.

`StoredReconciliationProgress` currently reads and advances the per-route
advisory rotation cursor through a storage reference during the **inline** SDK
call. This is the only comparison-related storage write inside that wait. It
occurs before missing-ID fetch so a refused prefix cannot monopolize retries.
The cursor must not move into a detached task through a cloned storage handle:
the next slice needs a worker-acknowledged cursor handoff before fetch, and must
prove cancellation or process interruption cannot skip unretained candidate
IDs. The cursor is not the durable event inventory and does not discharge a
recovery obligation.

## Next execution slice

For a selected comparison grant, retain the same owner lease while the frozen
comparison request runs outside the worker. Return the bounded event batch and
endpoint outcomes, then admit at most a bounded number of events per worker
turn. The worker must finish ingestion and receipt/checkpoint work before it
settles the grant. Activation and group-subscription registration currently
rebuild live and temporary maintenance interests; the SDK drain currently
waits with the mutable client. Those phases require their own split that
preserves subscription identity, generation fencing, command order, and
maintenance prerequisite clocks. A comparison-only off-worker change must not
claim that it also fixes the held broad `#h` worker wait.
