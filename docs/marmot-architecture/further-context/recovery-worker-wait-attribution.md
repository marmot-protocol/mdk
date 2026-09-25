---
title: Account recovery worker wait attribution
updated: 2026-09-24
status: Controlled legacy-path witness; correction pending
---

# Account recovery worker wait attribution

This note records one controlled worker-held network wait at base
`aae20359d4a669b32ca53a068ac2d3214eefdfcd` with the pinned Nostr SDK
revision `63384e485d55097cb3d9e57a2146f453a5742570`. It addresses the
worker-occupancy part of [#1976 P5/P7](https://github.com/marmot-protocol/mdk/issues/1976)
and [#1947](https://github.com/marmot-protocol/mdk/issues/1947). It does not
generalize a delayed relay into account-wide or permanent starvation.

## Ownership and call path

The serialized account worker owns one mutable `AppClient`. Its periodic
maintenance arm in `runtime/account_worker.rs` invokes
`run_pending_epoch_backfill_reporting_arm(&mut client, Maintenance)` after the
key-package catch-up leg. That helper invokes `AppClient::run_pending_epoch_backfill`
in `client/sync.rs`, which asks the existing recovery owner for a grant and awaits
`execute_recovery_grant`. `execute_recovery_grant_inner` activates the transport,
registers group interests, optionally reconciles retained inventory, and drains
the SDK relay until its bounded EOSE/quantum outcome. The owner reservation and
frozen scope are durable before these network effects. The broad executor retains
the worker's mutable client throughout its awaits.

The same reporting helper is reached after a receive and after scheduled local
convergence. `sync_inner` also executes a grant inline for startup, explicit
catch-up and key-package maintenance catch-up. Post-join subscription advancement
and `run_due_maintenance` remain domain-owned maintenance steps. Their protocol
grace and quiet clocks must not be replaced by transport coverage.

The existing `runtime/account_worker/bounded_recovery.rs` job is a separate,
test-enabled exact known-event path. It runs its owned SDK acquisition outside
the worker and requeues admission. Its current eligibility and resource claims
are narrower than the broad maintenance path observed here.

## Controlled witness

`worker_wait_attribution_tests::owner_granted_broad_recovery_wait_holds_queued_worker_command`
uses a real local relay and the configured SDK. It finishes startup catch-up and
publishes a real group ciphertext before arming the relay query gate. The gate
selects only a broad, no-ID `#h` request for that group's routing handle.

The test records a durable known-event ticket, advances the worker's recovery
clock, and advances its timers by 16 seconds. A due scheduled-convergence arm or
the periodic maintenance arm can invoke the same backfill reporting helper with
the `Maintenance` seam; the fixture does not distinguish those two timer callers.
When the matching relay request enters the gate, the test verifies that the
recovery attempt serial advanced and that the ticket's frozen scope carries
both that serial and the selected event ID.
It then enqueues `GroupRecoveryStatus` through the same account worker's command
sender. The reply remains pending during a 150 ms held-request window and
completes within two seconds after the relay releases the request, before the
configured 30-second EOSE/quantum limit could end the attempt. This ties the
relay wait to an owner-granted attempt and a queued command at the actual
worker. The test passes with `cargo test -p marmot-app --lib --features test-policy-overrides
owner_granted_broad_recovery_wait_holds_queued_worker_command`.

The fixture has one account and one group. It publishes a current KeyPackage
and checks the lifecycle fields that make key-package catch-up unnecessary.
Startup and the published event's live echo settle before the new demand is
recorded. It performs no explicit catch-up, incoming peer delivery or group
convergence after arming the gate.
The exact-ID bounded job remains disabled. The two timer callers of the shared
helper are the possible history entry points in this fixture, and the gate
matches the group's `#h` route rather than an unrelated inbox or inspector
request. It blocks only the first matching request; a second matching request
cannot explain the pending command.
`try_send` confirms queue admission before the pending check. The shared fixture
mutex serializes tests only; it is not held by the account worker or command
receiver. The same status command completes before the demand and gate are
armed. A drop guard releases the relay gate if the assertion fails.

The held relay query is a test control, not a production scheduling policy.
The bounded pending window shows an occupied worker in this fixture. It does not
measure natural-arrival fairness, all other worker operations, device latency,
wire-byte limits or process RSS. A new SDK request that merely stays open would
not establish the worker relationship; the frozen owner attempt and queued
command are essential to this witness. QueryPolicy exposes the parsed filter,
not the wire subscription ID, so the correlation uses the unique target route,
the owner attempt, the absence of competing fixture activity and the command
completion order.

## Correction boundary

The [P5/P7 contract in #1976](https://github.com/marmot-protocol/mdk/issues/1976)
requires off-worker acquisition and bounded admission while local work remains
serviceable. This witness identifies the shared reporting helper as one legacy
entry and the concrete split seam between `authorize_account_recovery` and the
network awaits in `execute_recovery_grant_inner`.

The worker must still own receipt-journal synchronization,
`freeze_recovery_inventory`, route and obligation revision
capture, MLS ingestion, progress checkpointing, and generation-checked finish.
The relay plane/adapter may own an immutable request and endpoint outcomes while
the worker services other turns. Transport activation currently also installs
live and temporary maintenance subscriptions through the mutable client; a split
must preserve their identity and lifetime instead of moving the whole client to
another task. `advance_post_join_maintenance_subscriptions` and
`run_due_maintenance` retain maintenance policy, protocol timers and publication
ownership, and may resume only after their qualified prerequisite is available.

The current exact-ID job has narrower eligibility and resource guarantees than
this broad path. The legacy broad executor still runs on the worker until a
scoped replacement proves route, endpoint, admission and lifecycle behavior.
