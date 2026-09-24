# #1946 amendment: bounded comparison with independent history debt

Prepared 2026-09-23 against owner checkpoint
`36442cd2e62883d0290c5fc6145e7af04ec7ea08`. The user approved this amendment,
including the cutoff, mixed-result and repeated-start clarifications below. Implementation is complete within #1992; the
acceptance ledger records exact tested revisions and remaining backend limitations.
The rest of `account-recovery-ownership.md` remains unchanged.

## Approved clarifications

The live subscription timestamp cutoff and the retained-inventory comparison
floor are different. The restart regressions recover late events older than the
live cutoff **but within** the inventory retention/compaction window. This does
not promise recovery of arbitrary history older than that comparison floor.

Settlement is per selected route. A serviced route cannot consume a transiently
failed route's retry opportunity. Persist the failed subset (at most the selected
route budget) in the same comparison slot; retry that subset under the shared
account deadline before considering the opportunity serviced. Where only aggregate
endpoint results are available, conservatively retry the whole affected route;
retained IDs prevent needless payload reacquisition. Successful routes need not
be compared again merely because a sibling failed. Unattempted routes are distinct
from failed routes: their coverage debt remains, without inventing an unbounded
continuation sweep. Backend-wide unsupported requires affirmative capability
evidence and is never inferred from one failed endpoint or missing exhaustive proof.

Repeated startup is an automatic request, never an override: it preserves the
retry ordinal/deadline and ordinary live cutoff. Reconnects, ticks, maintenance and
polling do not create requests. Frozen wake remains excluded. Tests must cover
multiple restarts, exact persisted pacing, and retained-payload no-redownload.

## Contract change and evidence

An ordinary cold start may request one bounded comparison of retained transport
inventory, even when older history coverage is parked. It must use the same
`AccountRecoveryOwner`, durable attempt sequence and cooldown as every other
history trigger. Servicing this request does not complete any coverage obligation.
An unchanged reconnect, timer tick, local maintenance pass or repeated polling
cannot create another request. This is the narrow exception to the blanket
unchanged-reopen quiescence rule; broad historical replay remains quiescent.

The combined run at `3fcb823652b3bfe4f294423dc452994c16443c18` had 2,865 passes
and three failures among 2,868 tests. At proposal time the frozen-cursor failure
was fixed in `36442cd2`, while both unchanged `since_floor` journeys still failed.
Restoring comparison inside the executor alone also failed: parked demand does not authorize it, and
cold-start timing must now respect persisted cooldown. The exact mixture of these
two effects in each failed boot has not been instrumented; neither should be
presented as an observed database trace from that run.

The source requires a distinct operational request: `reserve_recovery_attempt`
requires a nonempty selected coverage fence, `AttemptGrant::plan` rejects an empty
coverage plan, and joining pending `IncrementalHistory` deliberately does not
rearm it. Removing those checks globally would weaken existing guarantees.

## One durable comparison slot

Append migration **0095**, leaving published migrations 0092–0094 unchanged. Add
`account_recovery_comparison`, containing exactly one row (`singleton = 1`). Do
not rebuild the obligations table or extend its coverage-predicate enum. Use
checked nonnegative SQLite integers, checked states and artifact-local format
validation, consistent with the existing ledger.

| Column group | Proposed representation and purpose |
| --- | --- |
| Request | `revision`, `settled_revision`, `request_key`, `requested_at_ms`, `requested_until_seconds`; pending means revision exceeds settled revision. A pending join extends the upper bound monotonically and invalidates an older request token only when its intent changes. No row per boot, caller or attempt. |
| Eligibility | Ready / waiting-capability is derived from nullable `blocked_route_revision` and `blocked_capability_key` bind a known backend-wide unsupported result. Reopen alone cannot clear this block. |
| Frozen attempt | `attempt_serial` and `frozen_revision` are zero until first freeze; `plan_format` defaults to 1 and `plan_payload` is nullable until then. The version-1 payload holds the live activation floor and at most four selected route descriptors, admitted endpoints, comparison windows and the loss/route/inventory fence. Persist the retryable route subset here after mixed outcomes. It contains no receipt list or event payload. |
| Last observation | Nullable `last_outcome` = serviced-unknown / partial / unsupported / transient-failure. It is diagnostic operational state, never a coverage certificate. No per-attempt outcome history. |

The row has **no deadline, ordinal, lease owner or independent attempt counter**.
Those remain exclusively in `account_recovery_state`. Migration creates an idle
slot and leaves all existing evidence, retry state, scopes and eligibility intact.
An upgraded account joins its startup request through the owner. A failed migration
must roll back completely; older binaries reject schema 0095. Same-schema
conservative mode reads this exact slot. Binary rollback still requires the
pre-upgrade backup.

A fresh cold startup joins once after route hydration; an explicit ordinary
catch-up may also join. Repeated calls within that startup/caller reuse the same
request. Joins while pending coalesce and preserve the account retry state. A
request arriving after a frozen revision cannot be erased by settlement of that
older revision. Startup with `CursorPersistence::Frozen` does not join or spend
this request; its existing explicit full-history API remains supported.

## Internal operations and transaction boundaries

The following names describe specific internal contracts, not a new generic job
framework or public app API:

1. **Join comparison:** atomically update the singleton intent and join/extend the
   existing incremental coverage debt. Preserve the oldest unresolved lower
   bound, extend `until` monotonically, union required endpoints and retain old
   route scopes under their existing scope IDs. Invalidate prior completion proof
   for an expanded goal. Preserve parked eligibility and retry cost. The immutable
   scope preparation/merge already in `authorize_account_recovery` supplies these
   facts; factor it so coverage debt can be persisted without authorizing its
   replay. Never shrink an old goal to the comparison inventory floor. No I/O may
   start before this debt checkpoint succeeds.
2. **Reserve owner work:** add a typed selection containing coverage tickets,
   a comparison revision, or both. Validate global loss/route/inventory revisions,
   absence of unimported loss, and eligibility of every selected item. Spend the
   existing account reservation once. Preserve the current storage reservation
   method as a coverage-only wrapper; an empty legacy fence stays invalid.
3. **Freeze owner work:** after receipt synchronization and bounded inventory
   preparation, atomically install all selected scope snapshots and the comparison
   descriptor against that reservation. Advance the existing route rotation claim
   with this successful freeze, rather than on rejected preparation. Failed freeze
   retains spent cost and pending intent, performs no network I/O, and consumes
   neither the caller's override nor live maintenance observations.
4. **Record productive admission:** a comparison-only grant may reset pacing only
   for a new durably retained event inside its frozen route/window, under current
   attempt and loss/route/inventory fences. Its bounded in-memory receipt snapshot
   lives exactly as long as the grant. Duplicates, engine progress, EOSE and SDK
   counters do not qualify. Keep the existing minimum activation delay. Do not
   make a comparison token acceptable to any coverage-completion API.
5. **Settle comparison:** after its bounded execution and admission checkpoint,
   CAS the frozen request revision/attempt and current safety fences. A serviced unknown/partial route is removed from the retry subset. A transient
   failure remains pending; a mixed result never settles that failed work. Routes
   not started before the comparison quantum expires remain coverage debt, while
   a started operation interrupted by the quantum remains retryable. Once no
   selected route is retryable, settle only this operational opportunity. Its unresolved coverage
   was already persisted in step 1. Stale settlement cannot consume a successor
   request or acknowledge live loss. A storage failure or dropped future leaves
   pending intent and spent cost; no asynchronous cleanup is needed to retain it.

Unknown payload formats fail closed. Reservations and freeze use the same
transactions in normal and conservative mode. These operations are implemented
with their first runtime consumer in #1992, not extracted into another storage PR.

## Selection, bounds and outcomes

Normal mode may coalesce a comparison with eligible coverage in one reservation.
A **comparison-only** grant uses the ordinary floored live subscription and the
bounded set-comparison path; parked coverage cannot widen that activation to
`since = None`. An unchanged previously investigated broad goal cannot widen
automatic startup comparison. Independently new loss, missing-input or relevant route evidence can
still require the broader activation, coalesced in the same reservation. A live
explicit catch-up also retains its supported prearmed recovery pass; explicit
full-history repair keeps its separately authorized range. Freeze that decision
before I/O. This preserves both the cold-restart/no-redownload journeys and the
existing new-loss/explicit-catch-up guarantees without clearing old epoch debt to
suppress traffic. All unqualified history remains pending. Maintenance retains its
existing limited boundary, session restoration and grace timing.

Conservative mode selects one work item, treating the comparison slot as one item
alongside individual coverage obligations. Use last-attempt ordering already used
by conservative coverage selection, with the existing explicit-caller precedence,
so neither class buys extra attempts or starves the other. Normal mode can
coalesce, but cannot reset or shorten the shared deadline by doing so.

Reuse the existing limits without introducing new tuning constants:

- Four routes per comparison pass (`TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS`),
  using the durable route rotation and existing epoch-gap priority.
- At most 16,384 retained IDs per route and the existing 30-day retention window;
  the actual comparison floor may be later after inventory compaction. Freeze
  IDs in memory after compaction and filter to the request's frozen upper bound.
- Existing 10-second comparison quantum and existing drain/setup behavior.
  These bound this comparison stage; they do not claim to bound total backend
  memory, wire bytes or all worker occupancy. Acquisition remains blocking.
- Existing account retry base/cap: 15/30/60/120/240/300 seconds. No progress and
  repeated reopens never reset that sequence. A live explicit caller retains its
  one immediate override; automatic startup has none.

Do not treat the current aggregate backend result as complete coverage. Replace
`reconcile_transport_history`'s discarded aggregate result with a private typed
operational observation: attempted/omitted routes, partial or transient outcome,
and backend-wide unsupported only when actually known. This is not an SDK upgrade.
Missing endpoint proof stays unknown. Endpoint-specific failure must not label
all other endpoints unsupported. Known backend-wide unsupported blocks the slot
until a relevant route/capability change or one explicit override; unknown must
not be mislabeled unsupported merely to suppress traffic.

Transient failure/unavailability keeps the request pending under capped pacing.
A completed bounded unknown/partial pass with no transiently failed route settles
the opportunity and does not repeat on timer ticks. Mixed outcomes preserve only
the retryable selected subset; unrelated successful routes are not reissued. Unattempted routes, omitted endpoints and history outside
the inventory window remain represented by coverage debt. This amendment promises
the existing bounded comparison opportunity, not exhaustive recovery for arbitrary
older history or all routes in one boot. Cancellation retains the request for a
later paced retry and does not manufacture completed work.

The existing worker maintenance tick services pending owner work even when local
engine maintenance is paused. Update the pending-work probe to include this slot;
do not add a timer, dispatcher, detached task, connection allocator or #1947
scheduler. A tick may service a request, never create one.

## Implementation and acceptance inventory

These behaviors are implemented. The names below identify actual regressions;
the adjacent integration ledger records the final combined verification results.

| Behavior and affected files | Required acceptance |
| --- | --- |
| Singleton, coverage-debt join, shared reserve/freeze/settle: `storage-sqlite/src/account_recovery/{comparison,plan}.rs`, `account_recovery.rs`, `migrations.rs`, new migration 0095 | `comparison_join_persists_debt_before_reserving_and_coalesces_duplicates`; `settlement_preserves_successor_and_rejects_loss_or_inventory_changes`; `recovery_completion_migration_preserves_populated_state_and_rolls_back_interruption`; `comparison_cancellation_and_cost_survive_encrypted_reopen_and_repeated_starts`; unknown-format and unresolved-placeholder regressions. |
| Typed owner work, admission and fair selection: `marmot-app/src/client/recovery.rs` | `comparison_only_grant_preserves_cooldown_cancellation_and_scoped_admission`; `comparison_and_coverage_share_one_cost_and_conservative_fairness`; `comparison_rejected_freeze_rolls_back_coverage_and_preserves_permit`. Servicing comparison cannot acknowledge loss. |
| Startup/catch-up join, bounded execution and existing due tick: `client/sync.rs`, `runtime/account_worker.rs` | `comparison_runtime_retries_failed_route_without_reissuing_successful_sibling`; `comparison_quantum_keeps_interrupted_route_retryable_and_unattempted_coverage_pending`; `absent_comparison_backend_stays_parked_across_new_startup_requests`; `cancelled_comparison_executor_keeps_intent_cost_and_parked_coverage`; storage transaction-failure regressions. |
| Original below-live-cutoff delivery: `marmot-app/tests/since_floor.rs` | Preserve `cold_restart_reconciles_backlog_below_since_floor`: automatic above/below-live-cutoff delivery, persisted cursor, third-boot comparison and no repeated payload download. Preserve `stalled_epoch_backfill_still_arms_after_route_reconciliation`: same guarantees plus independent authenticated epoch-gap demand. |
| Compatibility and replacement audit: cursor/full-history/owner suites and `account-recovery-integration-tests.csv` | Keep the unchanged three-boot frozen-wake test, ordinary quiet catch-up, prompt invite acceptance, maintenance timing and all stale-evidence tests. Add explicit mapping for any changed timing fixtures. No replacement with caller-requested catch-up and no weakened event-count assertions. |

The two restart journeys use a controlled test clock/policy instead of assuming
an automatic attempt before the production 15-second deadline. Assert no
reservation/activation before the deadline, then advance it and assert the same
delivery/inventory outcomes. Default-policy unit tests continue pinning production
spacing; a shorter test delay alone is not evidence of cooldown correctness.

## Checkpoints and exit criterion

Keep two small committed implementation sections inside the existing integration
PR: first the singleton plus typed owner selection/admission with storage/owner
regressions; then runtime triggers/execution with both complete cold-restart
journeys and cancellation. Do not start the second until the first section's
checks pass. Neither is an independently deployable foundation layer.

The signed checkpoints and their applicable storage/owner/runtime regressions
are recorded in the integration ledger, including corrections discovered by the
combined suite. The integration exit remains all #1946 matrix rows, the full four affected crates under the
recorded feature set, default-policy compatibility tests, simulator policy tests,
applicable doctests and `just fast-ci` passing on the final code. Focused green
results alone do not make #1992 ready. Preserve the existing WIP and dependency
heads; no merge, SDK upgrade or #1947 work is authorized by this amendment.
