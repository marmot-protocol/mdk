---
title: Account recovery ownership — issue 1946
updated: 2026-09-22
status: Phase A design; loss-writer exception approved; implementation pending
---

# Account recovery ownership

This is the concrete Phase A design for [#1946](https://github.com/marmot-protocol/mdk/issues/1946),
checked against clean source revision `3db9d29de00222622cd98a9598982457ecb61786`.
It applies the agreed ownership, completion and staged-delivery sections of
[#1976](https://github.com/marmot-protocol/mdk/issues/1976), read on 2026-09-22.
This is not evidence that the new owner is implemented.

Recommendation: one `AccountRecoveryOwner` inside `AppClient`, invoked through the
existing serialized account worker (and the exclusive mutable borrow for supported
direct clients). Storage owns atomic primitives; the owner owns demand, authorization,
retry and completion. The relay plane owns interests/registration; the engine and
account runtime retain convergence and maintenance policy. No additional mutable
client, receipt consumer, engine loop, task scheduler or database is introduced.

Phase B replaces dispatch authority, including indirect dispatch, now. Its legacy
executor may still await network work on the worker. Off-worker acquisition, shared
fair scheduling, paged history and efficient selective execution belong to
[#1947](https://github.com/marmot-protocol/mdk/issues/1947). SDK changes/adoption
belong to #1358. Neither that work nor #1955 is a merge dependency.

## Source ownership and replacement inventory

Short `client/`, `runtime/`, `relay_plane/` and `directory/` paths are relative to
`crates/marmot-app/src/`; expanded crate paths are repository-relative.
Line numbers refer to the inspected base;
symbols are the durable lookup keys. `B1` is schema/state, `B2` is owner integration,
`B3` is policy/completion qualification; all three are focused changes under #1946.
The integration may not activate until B1–B3's relevant safety regressions pass.

| Entry / source | Trigger, existing state and authority; network effect | Replacement / retained owner | Package; regression |
| --- | --- | --- | --- |
| `runtime/account_worker.rs:941`, startup catch-up | `sync_with_stage_telemetry` then `run_pending_epoch_backfill_reporting_arm`; startup rebuild/reconciliation plus epoch and overflow replays | Request startup window and join restored demand; one selection through owner. Live-interest preparation stays plane-owned | B2; startup + restored overflow + group intent start one authorized history attempt |
| `client/sync.rs:1228`, `sync_inner` and public `sync*` wrappers | Always `require_fresh_activation`, prepare, bounded reconciliation, drain, then `recover_delivery_overflow_and_merge` | Separate live preparation/local drain from owner-requested catch-up. Delete independent history preparation/reconciliation/overflow dispatch here; preserve summary and classified partial-failure adapters | B2; repeated sync/maintenance cannot bypass cooldown; direct-client API covered |
| `runtime/account_worker.rs:1397,1472`, receive; `client/sync.rs:1631`, `next_event` | Overflow notification executes recovery directly; ordinary ingestion can arm epoch work and worker helper executes it | Persist/join loss demand before selection; remove direct overflow calls from both receive surfaces. Normal retained delivery/projection still runs | B2; full queue, empty queue with latched loss, repeated receive during cooldown |
| `runtime/account_worker.rs:1338`, scheduled convergence | Calls epoch helper using forensic `Maintenance` seam after local step | Keep `ScheduledConvergence` and engine eligibility; publish local effects, observe evidence/request, then owner may select once. No hidden epoch→overflow call | B2; worker-level convergence/attempt counters prove local progress during cooldown |
| `runtime/account_worker.rs:1805,1882`, maintenance tick | 15-second `sync_with_partial_progress` when key-package catch-up required, followed by epoch helper | Maintenance requests/joins typed prerequisite; history selection is owner-only. Keep 15-second caller budget and domain state; budget expiry leaves demand. Nonblocking resume is P7 | B2; maintenance plus receive joins same demand without resetting deadline |
| `client/mod.rs:1046`, `advance_post_join_maintenance_subscriptions` | Per-group temporary full-history subscription, durable CatchUp/EOSE deadline; `group_maintenance_any_eose` at 1174 | Maintenance owns prerequisite and grace/quiet state; owner authorizes/coalesces history-interest acquisition. Helper becomes install/poll/retire executor for owner grant, never a retry decision | B2/B3; first EOSE advances only protocol prerequisite, never account history; restart keeps deadline |
| `runtime/account_worker.rs:2121` (`handle_account_worker_catch_up`, live dispatcher) and `:3265` (`account_worker_command_future`, currently bypassed by the live dispatcher), explicit catch-up; `client/sync.rs:4269`, `repair_full_history_with_control` | Explicit seam bypasses epoch cooldown, rotates epoch intents, then may run another unfloored repair/overflow leg | Public wrappers request one caller ticket, join compatible plan, use existing cancellation/partial-summary adapter. Remove prearmed epoch loop and autonomous overflow leg | B2; one activation across quanta, cancelled waiter, later durable demand retained |
| `client/sync.rs:4036`, `run_pending_epoch_backfill`; `runtime/account_worker.rs:5402` helper | `PendingEpochBackfill`/queue, `Instant` cooldown, per-intent counters; `activate_transport(None)` and full-history drain, then unpaced overflow chaining at `runtime/account_worker.rs:5467` | Remove execution/retry ownership and queue. Detector supplies facts; one owner grants executor. Keep audit translation and ingestion/checkpoint helpers only as delegates | B2; baseline fixture below changes 2/3 activations to 1/1 |
| `client/sync.rs:1855`, `recover_delivery_overflow*` | Durable marker plus process-local plane generation; no own cooldown; fresh activation each call | Internal executor only, requiring nonconstructible grant. Completion moves to owner transaction; no helper may clear marker independently | B1/B2; overflow cannot bypass owner cooldown from any seam |
| `client/epoch_stall.rs`, `backfill_trigger_for`, `observe_undecryptable`, `observe_resource_refusal` | Threshold, contested fork and refused input currently arm same broad replay | Detector retains authenticated facts and debounce; evidence policy below chooses demand/local work. Arming cannot authorize I/O | B2/B3; mixed evidence and refusal-redelivery tests |
| `epoch_stall.rs`, `rearm_wedged`, `observe_fruitless_completion`; `sync.rs`, `finish_epoch_backfill_execution` | Hourly same-epoch arm buys replay; three EOSE-confirmed fruitless replays can escalate | Replace replay-arm precondition with durable, unique qualified coverage + engine-observation certificates. Timer schedules reassessment only | B3; no repeated certificate count, valid wedge escalation without blanket replay |
| Worker reconnect at `account_worker.rs:1585`; `client/sync.rs:628`, `note_connectivity_restored` | Worker reconstruction/backoff restores subscriptions and live tail; intentionally skips blocking catch-up | Restore owner state locally; reconnect submits readiness/loss facts without executing catch-up in reopen. Keep worker lifecycle and backend connection retry | B2; reconnect replies/live tail service before any maintenance acquisition |
| `client/sync.rs:1105`, `retry_pending_runtime_group_subscription_refresh`; worker `ScheduledRuntimeGroupSubscriptionRefresh` | Deferred route refresh may force activation; plane adapter reuses complete identical incremental activation | Plane retains registration authority. Registration is live-interest installation, not implicit history repair; route changes notify owner and invalidate matching plans | B2 minimal readiness adaptation; P3 isolated registration; route-revision/stale EOSE tests |
| `relay_plane/mod.rs:1610,1748`, notification-consumer lag/exit | 0.44 broadcast `Lagged` exits the consumer; forwarder recovery clears account delivery routes and separately broadcasts directory `RecoveryRequired`. This does not create the account-queue overflow marker | Plane reports an explicit lag exit cause to the worker; the worker records typed receiver-loss evidence and joins distinct unknown-scope demand. Generic closure/reconnect is not evidence. Directory signal remains directory-only | B2; confirmed lag is an intentional new loss trigger; ordinary close, shutdown and reconnect do not request history |
| `relay_plane/mod.rs:1222`, account queue saturation | Router `record_drop` latches a generation and cumulative drop count, reserves a control slot, and starts marker persistence independently of the saturated queue | Keep loss fence; owner joins persisted queue-loss evidence and compares token **and drop count** at completion | B2; later omissions with the same token invalidate old results; other accounts continue |
| `lib.rs:3773`, recovery-marker callback; `relay_plane/mod.rs`, `persist_marker_before_drop` | A separate account-local blocking task persists overflow evidence and retries storage contention every 100 ms while the router continues; this is not the serialized account worker | Retain only this loss-evidence writer, extending it to persist same-token count growth until the generation closes, with an evidence table consumed by the owner. It cannot select/complete recovery or access engine/receipts. The task owner approved this narrow exception on 2026-09-22 | B1/B2, approved exception; block worker, omit delivery, crash before worker resumes, verify durable loss on reopen |
| `client/receipts.rs`, `transport_receipts` / release synchronization | Sole exclusive receipt view; consumes released journal, retires disk and memory receipts, reloads old backfill intents | Keep sole consumer and atomic storage contract. Transaction creates/joins owner demand and invalidates inventory revision instead of writing old intent table | B1/B2; reload failure after journal consumption, released ID fetched despite SDK seen cache |
| `client/mod.rs` / `sync.rs`, `recover_superseded_invites_best_effort` | Invitation recovery/publication state, exact welcome retries | Separate invitation owner, unchanged; any independently justified account-history need uses owner, not blanket migration of invitation jobs | Retain; existing invitation regressions |
| `runtime/onboarding*`, setup readiness/recovery | Durable onboarding stages and publication/preflight | Separate onboarding owner, unchanged | Retain; setup cancellation/reopen tests |
| `directory/sync.rs:386`, `DirectoryRecoveryRebuildQueue` | Directory lag/RecoveryRequired requests coalesced forced `run_directory_sync_once`; block-list reconcile separate | Directory sync owns query-coverage invalidation/rebuild. Per-account `DirectoryCache` owns scoped provenance/records; `SqliteSharedStorage` owns reusable public records. Neither store's record presence certifies query coverage | Retain; directory loss rebuild/coalescing tests. Durable directory coverage redesign is separate P3/P7 work |

The maintenance first-EOSE predicate remains **one current temporary subscription
has reached stored-event boundary at any admitted endpoint**, solely to start its
existing grace/quiet protocol timing. It is not a durable admission certificate or
proof of all-endpoint coverage. Preserve `mark_post_join_subscription_installed`,
`mark_post_join_eose`, EoseTimeout handling, and valid-state-bearing-input quiet
timers in `marmot-account/src/runtime.rs:1404–1450`. The owner records a separate
`MaintenanceFirstBoundary` predicate; it cannot clear a `HistoryAllEndpoints` row.
Sharing a physical acquisition does not merge those predicates. P7 later removes
the worker-held prerequisite wait without changing this protocol interpretation.

### #1955 disposition

Reviewed the PR metadata/file inventory and migration at exact head
`c7b29afe6a1ee60ece96d9442f536c539c0466fa` (open on 2026-09-22).

| Requirement | Decision and destination |
| --- | --- |
| `subscription_replay_obligations` migration 0092, endpoint and admitted-endpoint child tables | Do not import. It models route replay but omits independent causes/predicates, durable retry, explicit caller lifetime and migration of existing pending rows. Reuse generation/floor fencing principles in B1's single ledger |
| Required vs admitted endpoint sets, route-local completion | B1/B3 records both and never treats exclusions as coverage. Efficient independent route execution follows P5/P6 |
| Healthy routes survive unrelated admission/registration failure | Required P3 behavior under #1976; separate focused change, not silently claimed here. B2 does not introduce teardown or new fail-fast behavior |
| Registration backoff/status; 1/2/4/8/16/32/60 seconds, eight registrations, five-second round (A11 in that PR) | Plane-owned P1/P3 contract; not copied into logical recovery retry. B2 adapts existing readiness and never reconstructs clients to beat backend backoff |
| Rust account transport snapshots/subscriptions, UniFFI/C DTOs and generated references | Separate P3 API/binding change with binding documentation/artifact gates. #1946 uses internal outcomes and preserves supported public paths |
| Damus safety eligibility / retired-relay change (#842/#1951 scope) | Separate relay-policy change. No denylist changes here; signed routing bytes remain untouched |
| Hermes pinned checkout `--no-checkout`, queue settlement test | Separate tooling/test change. No import or dependency |
| #1961 connection reuse | P3 after compatible authentication/session allocation; no dependency or closure here |

## Authoritative storage proposal

The existing rows cannot be the new contract unchanged:

| Existing record | Inspected shape / decision |
| --- | --- |
| `account_delivery_recovery` (0053) | Account label, marker token, pending_since, dropped_count. Migrate its demand, preserve token/count/time; no endpoint/scope/retry fields today. Copy the old marker into loss evidence, with no dispatch authority (approved exception below) |
| `app_epoch_backfill_intents` (0052) | Group FK, stalled_epoch, updated_at. Migrate each pending row independently; current epoch compare-and-clear cannot fence a new same-epoch gap |
| `app_epoch_stall_evidence` (0055) | Epoch, fruitless count/reported, last-arm wall time. Retain as detector evidence, not acquisition authority; add observation identity for deduplication |
| `cgka_released_transport_receipts` (0060) | Event/group/epoch release journal. Keep authoritative redelivery evidence. `consume_released_transport_receipts` currently atomically retires receipts and inserts group intents; replace that insert within the same transaction |
| `transport_reconciliation_items`, `_route_state`, `_scheduler` (0054/0061) | Exact retained IDs, compaction floor, route rotation, 32-byte replay-after ID. Keep progress/retained-inventory ownership; neither rotation cursor proves obtained coverage |
| Maintenance obligations / key-package lifecycle | Domain obligations in session storage; keep their state machine and timing. Idempotently link a history prerequisite to its durable obligation identity |

Choose four authoritative records/tables in the account-device SQLCipher database and migrate
the two narrow demand tables into them. This is replacement, not dual writing.
Use the next free migration number (0092 at inspected base; recheck at landing).
No historical migration edits or workspace version bump.

### Physical records

All enum values get explicit integer discriminants and CHECK constraints. Wall
times/durations/revisions are checked nonnegative SQLite INTEGERs with checked
arithmetic; exhaustion fails closed. Random identity tokens are 16-byte BLOBs,
not clock-derived IDs. MLS `group_id` is opaque variable-length bytes, while
transport route IDs and Nostr event IDs are exactly 32 bytes. No identifiers or
endpoint strings leave encrypted storage in diagnostics.

| Table / key | Authoritative columns and constraints |
| --- | --- |
| `account_recovery_state`, singleton `1` | `next_attempt`, `loss_revision`, `route_revision`, `inventory_revision`; `retry_ordinal`, `retry_recorded_at_ms`, `retry_delay_ms`, `retry_not_before_ms`. `inventory_revision` fences reservation and plan installation on release/removal/compaction. Installed scope tokens/proof are invalidated for overlapping route/window removals (exact event for a known-event predicate), so unrelated/out-of-window eviction triggered by positive admission cannot prevent bounded completion. Receipt-journal consumption conservatively invalidates all installed proof when route/time is unavailable. Qualified completion and loss acknowledgment recheck scope proof, rather than rejecting unrelated account inventory churn. Rollback executor selection is process-local configuration, not persisted schema |
| `account_recovery_obligations`, `id` BLOB PK | Unique typed `demand_key`; `cause`, nullable group FK/`stalled_epoch`, legacy account label/loss token/count/time where applicable; `revision`, `predicate`, `urgency`, timestamps, `state` (`pending`, `satisfied`, `retired`), `eligibility` (`ready`, `retry`, `waiting_capacity`, `waiting_capability`, `needs_deep_repair`), `incomplete_reason`, durable/caller origin. Account-wide demand has NULL group |
| `account_recovery_scopes`, `(obligation_id, scope_id)` | FK cascade; route kind/role/MLS group/transport ID, `route_revision`, `since` (NULL = unbounded older request), frozen `until`, optional 32-byte `known_event_id`; `scope_revision`, `snapshot_state` (`unresolved`, `ready`), inventory floor/rotation progress. `scope_format = 1` versions an explicitly decoded plan/outcome blob containing canonical requested/admitted endpoints, endpoint policy, qualified endpoint checkpoints, attempt token and captured revision fences. Unknown versions fail closed. One latest checkpoint per scope, no separate attempt log or known-event table |
| `account_delivery_loss_evidence`, `(account_label, cause, marker_token)` PK | Loss token, first-observed time, max observed count, nullable owner-imported count (NULL means never imported, including zero-count observations) and nullable legacy-retired count. Copy old 0053 rows with imported count equal to observed count because their demand is migrated in the same transaction. The approved off-worker writer may only insert/increase queue-loss evidence; notification evidence is worker-written. Only the owner advances imported count/acknowledges it. Distinct tokens cannot overwrite one another; cause separates queue omissions from notification-consumer loss. No evidence row authorizes I/O or clears demand |

`demand_key` is a typed encoding: overflow + account label (normally one per database);
notification-consumer loss + account label; epoch gap + MLS group; maintenance prerequisite + durable job ID + predicate; explicit repair +
operation token. A known-event demand includes its scope identity. Distinct causes
remain distinct rows. Coalescing operates on plan work, not by flattening causes
into one row. Do not allocate a new row on every receive tick or every timer.
Satisfied caller rows are reclaimed after their reply/waiters release them;
system rows retain bounded current evidence, not an unbounded attempt log. Only
current checkpoint per scope is needed after no active grant can reference an
older revision. Register these bounds in `runtime-state-bounds.md` with B1/B2.

### Join, expansion and satisfaction

* Duplicate observation of the same loss **token and count**, detector evidence or prerequisite
  is a join: preserve revision, oldest created time, progress and retry deadline.
* New loss (including a larger count under the same token), earlier requested floor, additional endpoint/event or different route
  policy increments the affected obligation/scope revision. Preserve compatible
  admitted IDs; invalidate only certificates no longer covering the goal. A new
  same-epoch release is new evidence and increments revision.
* Freeze `until` when creating a historical scope. Live arrivals do not extend it.
  Later demand gets a successor revision/window; old grants can checkpoint but
  cannot clear the successor. Endpoint membership is captured with route revision.
* One plan may cover overflow, several groups and explicit demand; evaluate each
  predicate separately. Partial endpoint satisfaction remains durable only when
  its bounded comparison and admission proof is complete. Reopen cannot resume an
  incomplete EOSE session as though it were covered.
* All required endpoints and the declared window must qualify. Missing, excluded,
  unsupported or truncated coverage is incomplete. A known event may instead use
  one validated durable copy. Empty endpoint sets are not vacuous success.
* Group terminality retires only its group-local demand with a terminal reason;
  account loss/explicit history debt is independent. Epoch movement never clears
  account-history demand. Maintenance domain completion does not delete its
  independently requested history obligation.

### Populated migration, compatibility and rollback

One migration transaction creates tables, inserts owner state and converts every
overflow row and every group-intent row. Overflow preserves marker_token,
pending_since and dropped_count; group demand preserves stalled_epoch/updated_at.
Routes/endpoints are unresolved until hydrated and captured under the worker;
never guess endpoint sets in SQL. Preserve all stall evidence, release journals,
inventory/cursors, maintenance rows, account state and retained bytes unchanged.
Do not consume release journals during migration. A released row without an old
intent still creates demand atomically when the existing receipt consumer runs.

Create the four tables, convert and validate row counts/keys, then remove the two
old demand tables within the same migration transaction. Copy each old loss row
into the evidence table with `imported_count = observed_count`, as well as preserving
its demand in the ledger. Only new loss changes the imported watermark. Changing
which token the compatibility pointer represents also advances loss/obligation
revisions, so a grant cannot keep the same fence across generation adoption;
adopting already-imported evidence does not reset quiescence or retry state.
Already-imported callback duplicates cannot replace that pointer. An unrecognized
token is joined with a changed pointer, making an older token-only clear fail closed;
random token values do not establish generation order. Every generation retains
its own import/legacy-retirement watermark. Retain the current evidence until the
plane confirms its marker writer is finished; reclaim it only after fenced
completion. Reopen has no surviving old callback. Compare unimported evidence
inside the completion transaction; a newer count is not hidden behind the worker
being occupied. Inject both late-writer and same-token-count races in B1/B2.
Retain the old tables' supported Rust
storage methods as adapters into the new authority, not writable legacy SQL tables.
Read adapters select the corresponding causes; mark adapters perform request/join.
Legacy token retirement records its own evidence watermark and restores any other
joined generations atomically, returning incomplete while any remain. Imported
is not retired; retained watermarks suppress late duplicates while count growth
rearms demand. Qualified owner completion remains the only evidence-reclamation path.
Keep the public storage clear signatures and their documented token/epoch-exact
low-level retirement semantics, restricted to the corresponding legacy cause;
legacy retirement retains imported loss watermarks and cannot reclaim them;
they cannot certify qualified completion or clear explicit/maintenance demand.
Add revision-aware CAS primitives for all internal completion. No owner/executor
path may call the old clears. This preserves supported lower-level methods without
mistaking a caller-directed legacy retirement for safe same-epoch recovery
completion. The replacement inventory must verify zero internal old-clear callers.
Compatibility adapters have one backing authority and can be removed only in an
explicitly approved public API migration, not by silently dropping old entry points.

Existing migrations reject unknown future versions. An old binary will reject the
upgraded database; it is not a rollback mechanism. Keep that refusal and test it
against populated schema 0092. Binary downgrade requires a pre-upgrade backup/export
and cannot promise preservation of later writes; no automatic destructive down
migration is proposed. This preserves the existing schema-compatibility contract.

The supported runtime rollback is a **same-schema, single-owner conservative
executor mode**, selected through runtime configuration only while no grant is active.
Normal mode coalesces compatible obligations into one plan; conservative mode disables
that coalescing and selects one obligation per legacy broad-executor grant. This
is a fallback for plan-sharing defects, not a rollback of the ledger or its owner.
It retains every row/revision, account-wide retry deadline, completion predicate and
receipt contract; processing separate obligations cannot buy extra retry overrides. It never resurrects old independent schedulers or old-table
writers. Faults can suspend new authorization while local receive/projection remains
available. B1/B2 must demonstrate normal→conservative→normal on populated pending
state and cancellation during handoff before activation. The fixture must show one
coalesced normal plan versus separate conservative grants for compatible demands,
with unchanged pacing and independent completion; rollback does not claim
to cure the legacy worker-blocking/coverage limitations. Remove the temporary mode
only after #1948/#1945's rollout/rollback gate, not during this consolidation.

## Internal contract and state machine

Implement policy/state transitions in `client/recovery.rs`; store primitives in
`storage-sqlite/src/account_recovery.rs`. Keep wire DTO translation in the adapter
and acquisition in `client/sync.rs` initially. Conceptual private API:

```rust,ignore
request_or_join(request, now) -> DemandTicket
select_authorized_attempt(readiness, budget, now) -> Deferred | AttemptGrant
observe_admission(grant, durable_checkpoint) -> Progress
observe_result(grant, scoped_outcomes) -> QualifiedResult
checkpoint_and_complete(grant, result) -> CompletedScopes | StillPending
cancel_waiter(ticket) -> RemainingDemand
```

`AttemptGrant` has a private constructor and owns an immutable `RecoveryPlan`:
attempt token, obligation revisions, route/endpoint policy, loss/inventory
revisions, bounded historical windows, inventory snapshot, caller cancellation
interest and execution budget. Only the account mutation owner can obtain it.
No borrowed mutable client, second store handle with receipt-consumption rights,
or SDK-specific type escapes into policy. One active history grant per account;
independent accounts remain independent worker tasks.

1. **Request:** validate/persist demand before network side effects. Hydration and
   `transport_receipts()` synchronize releases before snapshot capture. Requesting
   does not authorize execution and joining does not change pacing.
2. **Select:** read current authoritative demand, readiness and fences under the
   existing exclusive account owner; choose compatible scopes, freeze plan;
   persist attempt serial and a conservative retry reservation **before** I/O.
   A cancelled future therefore cannot forget its retry cost. Preserve obligations
   until conditional completion; do not move the only copy into a future.
3. **Execute:** one authorized legacy acquisition. It returns owned result/progress
   and newly observed demand; it cannot start overflow/epoch follow-up itself.
   Quantum continuation uses the same grant/session, preserving subscriptions and
   EOSE evidence. New activation requires another explicit selection.
4. **Admit:** use existing ingestion/receipt/checkpoint paths. Durably retained
   deferred input can support retained inventory/cursor rules; it is not decrypted,
   projected or engine-ready. Refused/unretained input stays eligible for redelivery.
   Release synchronization advances invalidation revision in the same transaction
   that retires receipts and joins recovery demand.
5. **Complete:** persist qualified bounded evidence and CAS each obligation against
   all captured revisions. Checkpoint and pending→satisfied transition are one
   transaction. Commit failure leaves intent pending; positive memory completion
   is published only after commit. Plane generation acknowledgment is a separate
   conditional step; failure or newer loss preserves/rejoins demand, never success.
6. **Cancel/shutdown:** detach only this waiter. Persisted system or other caller
   demand survives; admitted checkpoints remain. Explicit-only abandoned demand
   keeps an incomplete resumable row but loses foreground urgency. Finish safe
   ingest/checkpoint units, cancel acquisition at boundaries, then use existing
   `shutdown_and_close`; no asynchronous destructor writes or implicit store reopen.
7. **Reopen:** rebuild owner from durable state, clear only transient session
   evidence, reacquire route snapshot/readiness and resume pending demand when due.
   No synchronous history call from reconnect. Snapshot reads retain their current
   worker repair service path and mutations retain FIFO ordering.

### Endpoint outcome adaptation and safe progress

Use an internal `ScopeOutcome` with `Covered`, `Partial`, `Unavailable`,
`Unsupported`, `Excluded`, `Cancelled`, `BudgetExhausted`, `LossInvalidated`, and
`Unknown`; attach captured bounds/revisions and worker admission acknowledgment.
`Covered` requires an exhaustive bounded comparison/acquisition and no unadmitted
input. EOSE by itself is a session boundary, not `Covered`.

Current limitations are concrete: `reconcile_transport_history` rotates at most
four routes and discards errors into aggregates; SDK comparison limits the remote
filter to 16,384, fetches a rotating bounded difference, and the app's inventory
retains 30 days/16,384 IDs per route. Automatic overflow lacks the reconciliation
leg unless explicit repair requested it. Therefore its current `Ok(())`, EOSE,
`received_items` or quiet drain cannot be translated to universal `Covered`.

B3 minimally returns scope outcomes/fences from the existing adapter/executor,
including unattempted endpoints/routes and remaining difference. When the current
backend cannot establish exhaustiveness, return `Unknown`/`Unsupported` and retain
debt, rather than synthesizing success. Keep valid retained progress. Do not upgrade
the SDK or solve remote/local paging here. P5/P6 supply the efficient selective
executor and complete bounded comparison contract. Supported explicit repair
continues to report a partial summary plus incomplete/error at its deadline;
it must not return completed solely because the old helper returned `Ok`.

Existing `StoredReconciliationProgress` cursor is a rotation claim saved before
fetch, not an admission checkpoint. Keep that distinction. Transport timestamp
advancement keeps the existing unretained-input fence and future-skew clamp. Do
not derive exhaustive coverage from timestamps, drop same-timestamp event IDs, or
advance past refused work. Goal freezing is a plan property even while legacy
subscriptions remain live; arrivals above `until` go through normal receive and do
not enlarge the grant. Loss invalidates the affected coverage regardless of whether
the dropped IDs are known.

### Three retry responsibilities

| Owner | Retry and readiness contract |
| --- | --- |
| SDK/backend | Socket establishment/authentication/lifecycle; existing reconnect/backoff. Reports ready, unavailable or unknown. Recovery never constructs another client to evade it |
| Plane/worker live-interest service | Registration/reinstall for current generation, pending refresh and registration outcome. No recovery completion from registration acknowledgment; no historical replay floor chosen here |
| AccountRecoveryOwner | Logical acquisition eligibility, attempt reservation, progress/reset, caller urgency. Defer while registration is known not ready; no synthetic acquisition failure for a mere readiness wait. Unknown readiness permits at most one paced probe |

Retain existing recovery policy base 15 seconds, doubling 15/30/60/120/240/300
seconds, cap 300 seconds. Duplicate joins and route/loss invalidation do not reset
the account retry ordinal/deadline. Errors and no-progress attempts increase the
ordinal; only newly durably admitted input from the requested scope resets it.
Local epoch/convergence movement is separate evidence, never network progress.
Productive continuation keeps the same grant; it may resume immediately within its
budget. Any **new automatic activation** still observes the 15-second minimum.
An explicit caller may spend one owner-authorized immediate request (preserving
today's explicit override), but cannot turn each continuation/error into another
override. Multiple compatible explicit callers join the same plan.

For a no-progress workload starting at time zero, earliest starts are
0, 15, 45, 105, 225, 465, 765 seconds. Globally automatic activation spacing is at
least 15 seconds; unavailable steady state is at most one per 300 seconds. These
are attempt-start bounds, not network byte or worker occupancy bounds. Waiting
for network readiness can delay starts, never accelerate them. Keep EOSE and drain
budgets unchanged; setup/reconciliation remain blocking and are not covered by
the five-second drain quantum. Transient unavailable endpoints may keep paced demand indefinitely; capability
failures do not authorize an infinite series of futile broad replays.

After one bounded automatic investigation establishes `Unsupported`, known
unprovable exhaustiveness, or exhaustion of the automatic older-history budget,
retain pending debt with `waiting_capability` or `needs_deep_repair`. Selection
must skip it even when the retry deadline expires. Rearm only on a relevant route/
backend capability change, independently justified new loss/missing-input evidence,
or one explicit caller request. Duplicate joins, ordinary reconnect with unchanged
capabilities and timer ticks do not rearm. A caller request permits one bounded
attempt, then restores quiescence if the limitation remains. Transient timeout/
unavailability stays `retry` with capped pacing; productive same-plan continuation
is distinguished from unsupported scope. `retired` is only group terminality or
explicit authorized withdrawal, never the result of unavailable coverage. No debt
is marked satisfied to stop traffic. Test zero additional activations across
multiple capped retry windows and reopen, followed by each permitted rearm cause.

Approved #1992 amendment: cold startup may join one bounded retained-inventory
comparison even while older coverage is parked. Its durable singleton shares the
same owner, reservation and retry cost. Per-route servicing never completes
coverage or acknowledges loss. The live timestamp cutoff and retained-inventory
floor are distinct; see
[the concrete comparison amendment](account-recovery-incremental-comparison-proposal.md)
for mixed-result settlement, repeated-start behavior and acceptance tests.

Apply that eligibility rule by cause, without changing completion predicates:

- An epoch-gap attempt with no admitted input, transient failure, or a legacy EOSE
  remains `retry` on the capped schedule. EOSE's lack of a coverage certificate is
  not itself proof that acquiring the missing epoch input is unsupported. Explicitly
  established lack of the required acquisition capability can quiesce that scope.
- Unknown-scope overflow, notification loss and below-floor investigations have a
  bounded automatic investigation budget. Proven unsupported coverage or exhaustion
  of that budget preserves debt in `waiting_capability`/`needs_deep_repair`; an
  unchanged unknown result cannot authorize a standing full-history replay loop.
- `Unknown` alone proves neither incapability nor completion. Carry the cause,
  independent missing-input evidence and remaining investigation budget into policy.
  All-endpoint history still requires qualified coverage and admission; only an
  independently declared known-event predicate can complete from one retained copy.
  Epoch movement alone cannot be substituted for either admission or coverage.

Persist `(recorded_at_ms, delay_ms, not_before_ms)` and ordinal, never `Instant`.
On open sample wall time once: if it is within the stored interval, restore its
remaining delay; if beyond due, permit one selection; if before recorded time,
rebase the remaining delay conservatively to the stored delay clamped to the cap
and persist the rebase. Use a monotonic deadline within that process. Subsequent
wall-clock changes cannot repeatedly reopen the gate. Selection atomically records
the next reservation, so repeated crashes/reopen do not buy free probes. Clamp
invalid durations to the cap, report aggregate clock correction, and fail closed
on invalid schema/overflow. With a stable clock, a rebase delays work by at most
300 seconds; indefinite adversarial clock changes cannot guarantee liveness.
Repeated duplicate joins must never rebase the deadline. Tests inject both clocks.

Register the owner retry policy under a new ledger ID (recommend A12, avoiding
#1955's proposed A11) on all five required surfaces: constant inventory; Table 1,
Table 2 and progress log in the reliability plan; `expected_ids`; and simulator
`decision(...)` plus array length. The existing backoff constants are unledgered
at this base. A10 separately changes for B3's wedge evidence semantics; it does
not own the 15-second retry policy.

## Evidence-to-action and escalation

| Evidence (not mutually exclusive) | Owner action / completion and test |
| --- | --- |
| Identified eligible missing ID | Known-event obligation; request bounded selective acquisition, valid retained copy from one relay can satisfy. B2 uses authorized legacy executor; P5/P6 optimize. Test SDK-seen/unretained ID and release after snapshot |
| Contested fork with eligible local work | Keep scheduled convergence runnable; no new broad acquisition solely from fork. Independent missing/loss demand still runs when eligible. Test complete coverage + unresolved fork, and fork + missing event |
| Resource refusal | Preserve journal/redelivery eligibility; join admission-pressure evidence. Defer acquisition until bounded local relief or an owner-paced probe; no immediate replay into the same queue. Test refusal-only and mixed retained/refused batches; engine context-attempt budget is not queue capacity |
| Suspected gap below inventory floor | Keep unknown older-history scope; one bounded legacy broad investigation per new qualified gap observation, paced through owner. Budget/fallback exhaustion records `needs_deep_repair`/incomplete; new timer ticks do not restart it. Explicit deep repair uses same owner and preserves its incomplete status if exhaustiveness cannot be shown. P6 adds paged local and remote windows |
| Coverage qualified, engine blocked | No reflexive new acquisition. Record engine-supported blocked reason or `Unknown`, service eligible local work, and observe qualified stagnation below. Engine readiness stays independent |
| Engine progressed, coverage incomplete | Publish local progress/readiness permitted by engine; keep coverage obligation and its retry deadline. No account-wide disarm |
| Unknown/contradictory evidence | Union justified scoped obligations; record uncertainty; newer release/loss invalidates older coverage. Do not infer missing events from a timer, or complete inventory from fork evidence. Keep paced pending acquisition and eligible local work |

Replace replay-dependent wedge escalation only together with its replacement tests:
an observation certificate contains group stalled epoch, qualified coverage scope
revision, engine observation revision, and monotonically assigned sample sequence.
Persist the last consumed certificate identity with `app_epoch_stall_evidence`.
At most one sample is counted per existing wedge interval, after an eligible local
convergence evaluation, with unchanged epoch and still-valid qualified coverage.
A newly completed qualified acquisition may produce the first sample immediately;
subsequent local reassessments need no replay. Never count repeated polling of the
same engine observation, time bucket, or certificate. Keep the existing threshold
of three qualified fruitless samples and one-shot report semantics.

Epoch movement resets per-epoch sample evidence; authenticated current-epoch peer
traffic, join and terminal state retain their current detector clearing rules.
Arbitrary ciphertext, stale EOSE and a timer alone cannot create qualified coverage,
authenticated progress or an escalation. Unknown coverage retains an unknown
blockage and bounded investigation rather than incrementing a false proof count.
The hourly wedge timer schedules this local reassessment; it no longer purchases
blanket replay. B3 removes `armed_at_epoch` as the prerequisite for counting but
retains stalled-epoch/authenticated evidence checks. P5/P6 improve coverage
certificates; their unavailable capabilities are not faked in B3. This preserves
an escalation path without treating absent backend proof as proof of a wedge.

## Baseline and acceptance matrix

Synthetic baseline fixture:
`runtime::account_worker::tests::recovery_ownership_baseline_overflow_bypasses_epoch_cooldown`.
One account, one group, one scripted endpoint, persisted overflow token + group
intent, no EOSE; 25 ms test silence wait, 300-second cooldown to keep both seams
inside one window independent of CI load. Counts are **new unfloored inbox
subscriptions**, which distinguish account activations from group registrations.
The first Maintenance invocation starts epoch + overflow (2); Receive during the
epoch cooldown starts another overflow (cumulative 3). Both debts remain pending.
After B2, identical workload must produce cumulative **1 then 1**, one owner
attempt and two retained independent obligations. Change this characterization
into the owner regression when integration replaces the old seam; do not leave a
permanent test requiring the defect. This is not a device or bandwidth benchmark.

The existing `tests::epoch_backfill_overflow_retries_back_off_even_after_the_queue_is_empty`
uses 1,040 synthetic known IDs (1,024 queue + 16), demonstrates first/second epoch
attempt spacing 15/30 seconds and skipped counts 1,024 then 0, and verifies that
direct epoch receive calls do not activate during cooldown. It does **not** test
the worker overflow chain; keep both fixtures. Record execution results in the PR.

| Gate / focused regression | Required observation before integration activation |
| --- | --- |
| B1 populated migration | Simultaneous overflow + multiple group intents, release journal, detector evidence, maintenance rows, inventories and cursors survive exactly; empty DB also opens |
| B1 migration/completion fault | Inject failure after conversion and before commit: all-old or all-new transaction, never partial ledger; completion failure leaves retryable intent |
| B1 revision fencing | Same-epoch rearm, new loss, changed endpoint, earlier floor, released receipt during grant cannot be cleared by stale result; compatible checkpoint survives |
| B1 reopen/clocks | Cancellation before activation, after admission and during retry; backward/forward wall jumps; no free hot-loop attempts or permanent suppression after stable time returns |
| B1 rollback | Populated normal/conservative mode handoff preserves state and sole authority; old migration runner refuses newer DB; no claim that old binary reads new schema |
| B2 all-entry interleaving | Startup/receive/maintenance/post-convergence/explicit/direct-client requests join; counters distinguish requests, joins, authorizations, actual activations and resumed drains; zero dispatchers outside owner |
| B2 pacing | Controlled starts 0/15/45/105/225/465/765; cap, scope-admission reset, duplicate joins, refusal, new loss, explicit one-shot override; no seam bypass |
| B2 local eligibility | Worker-level local-convergence/projection counter advances while network cooldown remains; no new forensic seam/schema solely for testing |
| B2 cancellation/lifetime | One waiter cancels while another/system debt remains; repair preserves partial summary, snapshot reads and mutation FIFO; another account remains serviceable |
| B2 maintenance | First EOSE only advances prerequisite; missing endpoint keeps history pending; grace/quiet/EOSE deadline survive restart and unchanged protocol tests pass |
| B3 qualified completion | All endpoints plus admission, same-timestamp IDs, live arrivals past frozen goal, SDK-seen missing ID, partial/unsupported/truncated result; no false cursor or completion |
| B3 evidence matrix | Complete coverage + blocked engine; incomplete coverage + runnable engine; mixed/unknown facts; refusal + fork; one older investigation then honest deep-repair need |
| B3 escalation | Three distinct paced local observations over valid coverage can escalate once without replay; repeated sample, stale route/loss/release, arbitrary ciphertext cannot; authenticated recovery/terminal group retires evidence |
| Existing regression preservation | `client/sync/full_history_tests.rs` cancellation, delayed EOSE/same activation, overflow generation/reopen; `client/receipts.rs` release synchronization; sync cursor tests; epoch terminal/fruitless tests updated only with replacement predicates |

Aggregate instrumentation uses privacy-safe counters and enum outcomes with
explicit tracing target/method. No IDs, endpoint strings, payloads or new forensic
schema in this package. Existing audit event adapters remain truthful about their
legacy seam meaning; worker counters separate post-convergence from maintenance.
Do not equate selected/registered attempts with completed recovery.

## Delivery and design gate

1. Phase A: publish this source-checked proposal and executable baseline. The initial
   schema/outcome review required by #1976 is recorded on the PR; resolve findings before
   adding tables or changing runtime behavior. No implementation acceptance is
   implied by a documentation PR or by the prior architecture discussion.
2. B1: failing-first storage/state-machine tests, populated migration and rollback
   tests, then primitives. New unused primitives are not an ownership-completion
   claim. Land with coordinated integration; do not activate two authorities.
3. B2/B3: one focused integration series moves every mapped dispatch path, retires
   old in-memory retry/queue authority, changes the baseline to the acceptance
   assertion, and qualifies completion/policy before activation. Review supported
   API error/completion behavior explicitly; escalate incompatible changes.
4. Run affected crates and `just fast-ci` before push; changes to policy also run
   `just convergence-ledger-gate` and the simulator `protocol_decision_gate`.
   Bindings remain unchanged unless an independently reviewed additive API is
   necessary, then use the binding gates. Signed commits; CI/device evidence separate.
5. Report replaced symbols, remaining delegated executors, compatibility adapters
   and mode-removal criteria in each PR. Close #1946 only when B1–B3 are implemented
   and demonstrated, not after Phase A.

Routine choices are recommendations above, not unanswered design questions.
Escalate a proposed weakening of endpoint completion, receipt retention, protocol
timing, privacy, supported public API or rollback guarantees before implementing it.
Do not expand this issue into allocation, full scheduling, SDK migration, notification
redesign or general engine changes to make an intermediate test green.

### Approved exception: durable loss while the account worker is occupied

The task owner approved the narrow loss-evidence writer on 2026-09-22 after this
source discrepancy was escalated. `lib.rs:3773` installs a cloned-store marker;
`persist_marker_before_drop` invokes it on a separate blocking task while legacy
acquisition can hold the worker. Preserve only loss-evidence persistence and its
close-terminal behavior. Demand, retry, completion, receipts and MLS remain under
the account mutation owner. This is an explicit exception to the literal sole-
worker storage-mutation sentence, not permission for another recovery dispatcher.

The current writer stops after its first successful snapshot. B2 must instead
coalesce each same-token increase into durable `max(observed_count)` before treating
that generation as fully persisted. Completion compares the captured count against
both the durable watermark and the plane fence, and joins newer loss rather than
clearing it. Migration imports its initial watermark once; startup must not count
the same migrated omission as fresh loss.

Notification lag does not widen this exception. The plane carries a typed lag exit
reason, distinct from shutdown/ordinary closure, to each affected account worker.
The worker assigns a fresh incident token, writes a zero-count notification fact
(no invented event-loss count), and imports it into the separate notification key
in one transaction. This intentionally adds bounded investigation for confirmed
consumer loss; reconnect still restores the live tail without synchronous history.
This is B2 work, not a claim that the current forwarder supplies that exit contract.

The rejected alternative was to eliminate that writer and pre-arm a worker-written
live-session guard, converting unclean close into unknown-scope debt. It would need
additional lifecycle design and recovery after process death, including the existing
close-before-graceful-cleanup shutdown order. Merely queueing the write behind a
blocking worker would weaken loss durability and was not proposed as safe.

### Approved exception: unresolved durable loss retention

On 2026-09-23 the task owner approved retaining unresolved per-generation loss
watermarks without a fixed disk-row cap. Qualified completion and the exact live
acknowledgment remain the only reclamation path; the current backend cannot
certify exhaustive history. Repeated unresolved generations can therefore grow
this table even after automatic investigation stops. Do not evict, merge away or
legacy-retire another generation to enforce a cap. This exception does not permit
unbounded active snapshots, completed metadata or automatic replay. Their
lifetimes and bounds are tracked in `../runtime-state-bounds.md`.
