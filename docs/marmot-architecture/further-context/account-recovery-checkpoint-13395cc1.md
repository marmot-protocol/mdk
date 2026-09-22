# #1946 sequencing checkpoint — incomplete, local only

Recorded 2026-09-22. Implementation is paused pending agreement on the next slice.
This is an inventory of existing work, not a revision of the agreed architecture.

## Preserved revision and provenance

- Code checkpoint: **`13395cc10fd6941d2a2f72c0398bfc501b99fc25`**.
- Branch/worktree: `codex/1946-recovery-owner`, `/Volumes/Worktrees/codex/1946-recovery-owner/mdk`.
- Parent: `1bda006b847ba7c59205249cad03fe51e3b0182c` (#1983).
- Commit subject: `WIP: incomplete #1946 recovery owner integration checkpoint`.
- All tracked and seven previously untracked files were included: 31 files, +5720/-2806.
- GPG signature verified locally: `7CC8FAD6B0074EE408E1500501FAB1F0C112C72F`.
  Worktree was clean immediately after this commit. Nothing was pushed and no owner PR was opened.
- This report and its test inventory are a subsequent documentation-only record;
  test results below refer to the code checkpoint, not an earlier development state.

| Published work | Exact head inspected | Relationship to checkpoint |
| --- | --- | --- |
| [#1982](https://github.com/marmot-protocol/mdk/pull/1982), design | `0c12ce322741c67f2e4d6647563d5a65c5da53c5` | Existing design gate and reviewed ownership/completion contracts; open draft |
| [#1983](https://github.com/marmot-protocol/mdk/pull/1983), state/migration | `1bda006b847ba7c59205249cad03fe51e3b0182c` | Checkpoint parent; open draft, explicitly gated against independent merge |
| [#1985](https://github.com/marmot-protocol/mdk/pull/1985), maintenance fencing | `73d7ccf1bbe78dd11d705539aad463724de1556f` | All six `transport-nostr-adapter` files in the checkpoint exactly match this published head; open draft |
| Additional owner work | `13395cc10fd6941d2a2f72c0398bfc501b99fc25` | Other 25 changed files: storage completion/policy primitives, migrations 0093/0094, app owner/executor/worker, account maintenance transaction, loss handling and tests; local WIP |

The long integration combined durable completion, loss acknowledgment, maintenance
session restoration, trigger replacement, evidence policy and test migration without
closing a delivery boundary. Passing subsets were repeatedly followed by edits.
That sequencing failure is why the previous progress reports overstated readiness.
The work is preserved; completing it requires substantive implementation as well as checks.

## Checks of this exact code checkpoint

All new app checks used default features, `--lib`, `--test-threads=2` and the existing
shared target directory. Feature-gated acceptance tests are **not** covered by them.

| Command filter | Result | Scope of claim |
| --- | --- | --- |
| `cargo test -p storage-sqlite account_recovery --lib` | 38 passed | Recovery storage tests, including qualified scope, loss and stagnation primitives; not the full storage or migration suite |
| `cargo test -p marmot-app --lib client::recovery::tests::` | 9 passed, 1 failed | Post-join physical session restore fails; other owner unit contracts pass |
| `cargo test -p marmot-app --lib client::sync::tests::` | 32 passed | Receipt release, cursor/inventory rotation, terminal retirement and mixed fork/capacity cases in this module |
| `cargo test -p marmot-app --lib runtime::account_worker::tests::full_history_repair` | 3 passed, 1 failed | Public worker error assertion fails; feature-gated fifth historical case was not selected |
| `cargo test -p marmot-app --lib recovery_warning_requires_qualified_local_observations` | 1 passed | Qualified synthetic coverage + actual paced local engine evaluations, sticky local-commit/reopen behavior and authenticated-peer reset |
| `cargo fmt --all -- --check` | Failed (formatting diffs) | Formatting only; no files changed by this command |

Current failures:

1. `client::recovery::tests::post_join_boundary_completes_only_its_predicate_and_keeps_grace_fixed`:
   `client/recovery.rs:1262`, `no entry found for key` after removal and attempted
   restoration of a maintenance subscription. The default configuration does not
   satisfy the test's immediate restoration assumption. Whether the defect is
   restoration behavior, timing expectation or both is unresolved; do not relax the grace guarantee.
2. `runtime::account_worker::tests::full_history_repair_consumes_prearmed_backfill_without_replaying_twice`:
   `runtime/account_worker.rs:7289`, public error text does not satisfy the
   `full_history_coverage_unproven` assertion. The following exact activation-count
   assertion is not reached. Do not report this test as proof of coalescing.

Exact logs: `/tmp/mdk-1946-checkpoint-13395cc1-{storage,owner,sync,worker-repair,qualified-warning,fmt}.log`.
The [evidence manifest](account-recovery-checkpoint-13395cc1-evidence.json) preserves command context, results and log hashes.
Full affected-crate runs, `just fast-ci`, policy/binding gates and owner review have
**not** passed for this checkpoint. It is not merge-ready.

Earlier evidence that must not be carried forward:

| Historical result | Why it does not verify this checkpoint |
| --- | --- |
| #1983 full storage 817 passed / 7 ignored; targeted post-review checks and fast-ci | Published foundation revision, before owner completion/policy changes |
| #1985 adapter 82 unit + 49 integration and fast-ci | Published adapter only; no claim about owner integration or current remote CI |
| Owner 10 passed (`mdk-1946-b3-owner-policy-tests.log`) | Before capacity buffers, acknowledgment compensation, goal bounds, waiter cleanup and ordinary-drain changes; configuration also differs from fresh default run |
| Storage 38 passed (`mdk-1946-owner-storage-current.log`) | Before stale-pressure epoch guard; superseded by checkpoint storage run |
| Sync 32 passed (`mdk-1946-owner-sync-port-2.log`) | Before final old-queue/helper removal and later fixture edits; superseded by checkpoint sync run |
| Worker repair 4 passed / 1 failed (`mdk-1946-owner-worker-repair.log`) | Earlier run with feature-gated case; current default run is 3/1 |
| Isolated startup passed; reconnect failed (`mdk-1946-owner-reconnect-fixed.log`) | Startup preceded quiet-drain fix; reconnect failure preceded new EOSE pump and has not been reverified after that edit |
| Broad 1499-test app run (`mdk-1946-owner-full-app-inventory.log`) | Aborted after roughly 12 minutes, numerous failures/timeouts, no final result; subsequent edits invalidate individual outcomes as checkpoint claims |

## Completion matrix against #1946

Paths below are relative to `crates/` unless prefixed `docs/`.
“Verified” is limited to the named passing checkpoint tests; it does not imply a
whole feature is production-qualified. Proposed acceptance tests are labeled “add”.

### 1. Implemented and verified at the checkpoint

| Concrete behavior | Files | Passing checkpoint evidence |
| --- | --- | --- |
| Durable account retry reservation, exponential cap, monotonic runtime pacing, conservative reopen, duplicate joins and one transient explicit override | `marmot-app/src/client/recovery.rs`; `storage-sqlite/src/account_recovery.rs` | `automatic_attempts_share_one_durable_exponential_schedule`, `reopened_owner_observes_reservation_and_uses_monotonic_time_thereafter`, cancellation/override and storage reservation tests |
| Frozen plans; separate history/known-event/maintenance predicates; reject EOSE-only, stale revision/token, unknown format and unversioned goal expansion; atomic checkpoint/domain failure | `storage-sqlite/src/account_recovery/{plan,demand}.rs` | `eose_is_not_coverage_and_partial_qualified_coverage_survives_new_attempt`, predicate, late-token, format and transaction-failure tests |
| Loss-evidence-only writer storage contract, exact-watermark acknowledgment and reopen guard; failed live acknowledgment restores pending debt | `storage-sqlite/src/account_recovery/{loss,plan}.rs`; `marmot-app/src/client/recovery.rs` | Loss writer/import tests; `plane_ack_reclaims_exact_evidence_only_after_qualified_completion`; `qualified_loss_completion_rolls_back_all_causes_after_plane_ack_failure` |
| Actual retained admission, scoped progress and frozen pre-I/O inventory control productive retry reset | `marmot-app/src/client/recovery.rs` | `only_new_durable_admission_resets_pacing_with_a_minimum_activation_delay`, scoped-progress and frozen-inventory tests |
| Released receipt invalidates old completion, preserves redelivery and durable retry; terminal retirement and safe cursor behavior | `marmot-app/src/client/sync.rs` | 32-test module, notably both `older_backfill_completion_*`, release/reload and cursor tests |
| Mixed contested-fork/capacity facts retain independent debt and eligible local convergence | `marmot-app/src/client/sync.rs`; `storage-sqlite/src/account_recovery/demand.rs` | `contested_fork_and_capacity_facts_keep_independent_recovery_demand`, admission-pressure test; not a composed worker-level proof |
| Qualified stagnation uses distinct paced real engine observations; warning survives local commits/reopen and clears on authenticated peer evidence | `storage-sqlite/src/account_recovery/stall.rs`; `marmot-app/src/client/{recovery,mod}.rs`, `tests.rs` | Four storage stagnation tests plus qualified-warning integration regression; qualification is injected through a test contract |

### 2. Implemented, but failing or not yet sufficiently verified

| Concrete behavior / remaining work | Files | Required acceptance / current limitation |
| --- | --- | --- |
| Every startup/receive/sync/maintenance/convergence/explicit trigger delegates to one authorization path; old epoch queues and per-seam cooldown fields removed | `marmot-app/src/client/{mod,sync,recovery,epoch_stall}.rs`, `runtime/account_worker.rs` | Run feature-gated `recovery_owner_coalesces_overflow_and_epoch_demand_across_seams`; add one interleaved all-seam counter test and worker local-progress-during-cooldown test. Existing smaller owner tests are insufficient |
| Post-join limited any-endpoint boundary uses fenced session and atomic domain update; preserve grace during replacement/restoration | `marmot-app/src/client/recovery.rs`; `marmot-account/src/runtime.rs` | Fix current default-config restoration failure and prove stale EOSE, later physical replacement and grace deadline unchanged in both normal/default and test timing configurations |
| Legacy executor runs only grants and retains unproven debt; ordinary catch-up uses its quiet drain while strict repair requires qualified completion | `marmot-app/src/client/sync.rs`, `runtime/account_worker.rs` | Fix public error failure; run unchanged full-history suite; prove positive qualified completion separately from EOSE-only incomplete, partial-prefix/cancellation and exact activation counts. Current production adapter does not produce exhaustive proof |
| Notification loss is persisted before receiver replacement; reconnect keeps bounded live tail | `marmot-app/src/relay_plane/{mod,tests}.rs`, `client/{mod,sync}.rs`, `tests.rs` | Run `notification_loss_is_durable_and_survives_receiver_replacement`; reconnect regression after EOSE-pump edit, plus add withheld-EOSE nonblocking reconnect test; prior reconnect failure is unresolved evidence |
| Migrations 0093/0094, route snapshot identity, inventory invalidation and known-event retained-copy checks | `storage-sqlite/src/migrations{.rs,/0093_recovery_route_snapshot.rs,/0094_qualified_stall_observations.rs}`, `account_recovery.rs`, `transport_reconciliation.rs`, `storage/{groups,messages,transport_routes}.rs`, `account_projection.rs` | Full populated migration/interruption suite, inventory deletion/compaction/failure tests, duplicate explicit-row compatibility, unknown format and encrypted reopen across entire stack; 38 filtered tests do not cover all these writers |
| Normal/conservative mode shares ledger and retry, keeps frozen scopes and compensation | `marmot-app/src/config.rs`, `lib.rs`, `client/{recovery,sync}.rs` | Existing owner handoff unit passes; add populated handoff at partial admission, pending loss acknowledgment, all predicates and reopen. Document public Rust configuration and old-binary refusal; no downgrade claim |
| Explicit caller rows bounded/reused; normal-return detach and abandoned-on-reopen cleanup | `storage-sqlite/src/account_recovery/demand.rs`; `marmot-app/src/client/sync.rs` | Storage row tests pass. **Runtime future-drop cleanup is absent**, see next section; current return-path detach is not cancellation completion |

### 3. Not implemented, or a necessary replacement is missing

| Concrete missing behavior | Affected files | Acceptance test to add / restore |
| --- | --- | --- |
| Bounded older-than-inventory-floor investigation per newly qualified gap, then durable deep-repair/unsupported quiescence | `marmot-app/src/client/{recovery,sync,epoch_stall}.rs`; `storage-sqlite/src/account_recovery/{demand,plan}.rs` | New gap permits bounded work; unchanged reopen/timer cannot rearm; budget exhaustion preserves debt; new independent evidence may rearm without resetting account retry |
| Minimal truthful per-endpoint acquisition outcome adaptation and capability-change handoff | `marmot-app/src/client/{recovery,sync}.rs`, existing relay-plane/adapter outcome boundaries | Distinguish unavailable/unsupported/excluded/partial/loss/budget/unknown; require designated endpoints plus admission; one retained known-event copy may satisfy only its predicate. Never synthesize exhaustive proof from EOSE; no SDK upgrade required |
| Cancellation by dropping an in-flight caller future clears transient urgency without erasing durable debt, including after admitted prefix | `marmot-app/src/client/sync.rs`, `runtime/account_worker.rs`; `storage-sqlite/src/account_recovery/demand.rs` | Cancel before activation / after admission / reopen with another demand; no orphan urgency, no lost prefix, no free retry, another account remains serviceable |
| Full replacement of old fruitless-completion escalation and timer rearm contracts; supported blocked/unknown result when coverage cannot be certified | `marmot-app/src/client/epoch_stall.rs`, `client/recovery.rs`, `tests.rs` | Retire dead production helpers and port all clock/reorg/refusal/anti-spoofing cases; qualified blocked state escalates without new replay; unknown capability remains visible, not silently suppressed |
| Changed-goal, rotating inventory floor, retired-route and scope-row growth bounds fully specified and enforced where absent | `storage-sqlite/src/account_recovery/{demand,plan,loss}.rs`; `marmot-app/src/client/recovery.rs`; `docs/marmot-architecture/runtime-state-bounds.md` | Add repeated route churn/new gaps/caller cancellation/reopen tests; bounded rows, preserved old debt, no same-revision widening or cursor beyond unretained input |
| Aggregate request/join/deferral/authorization/actual-activation diagnostics and missing deferral-regression replacement | `marmot-app/src/client/{recovery,sync}.rs`, `runtime/account_worker.rs`, relay telemetry; architecture observability docs | Same workload reports 1 activation versus baseline 2/3; joins/deferrals distinct, equal-cardinality epoch change observable, zero private identifiers |
| Policy constant ledgers, runtime-state-bounds, API/rollback and executor-handoff documentation | `docs/marmot-architecture/{convergence-constant-inventory.txt,convergence-reliability-plan.md,runtime-state-bounds.md}`, `scripts/check_convergence_constant_ledger.sh`, `cgka-conformance-simulator/src/policy_contract.rs`; API/binding docs as applicable | Both policy ledger gates, binding-docs gate if surfaced APIs change, documented same-schema conservative handoff and old-binary backup requirement. Current code adds `RecoveryExecutorMode`; adoption/support contract is unfinished |
| Complete regression replacement and positive-completion path inventory | Files in companion CSV and `marmot-app/src/client/sync/full_history_tests.rs` | Restore gaps described below; all affected-crate tests and fast-ci on final slice heads, then required review. These gates follow implementation; they do not stand in for it |

The strict full-history path currently maps a normal EOSE drain to unknown coverage, so
its ordinary production path cannot demonstrate successful exhaustive repair. That is
a substantive capability/API compatibility gap, not a test assertion to relax. Any
proposal that changes the agreed supported API guarantee must be escalated before
implementation; the storage slice does not resolve or authorize such a change.

## Test replacement audit

The [per-test inventory](account-recovery-checkpoint-13395cc1-tests.csv) maps all
10 removed tests and 48 changed test bodies to replacements/retained guarantees,
and lists 46 additions. The comparison is checkpoint versus #1983 parent, excluding
adapter tests already published in #1985. Line numbers refer to those two revisions.
Shared helper changes are discussed here because their effect crosses test bodies.

Deliberate semantic changes, required by the accepted design:

- EOSE ends a transport session; it cannot by itself clear historical debt. The
  rewritten drain tests retain their delivery counts, slow-relay/duplicate deadlines
  and persisted-prefix assertions while expecting incomplete coverage.
- Local epoch advance or one retained delivery cannot disarm independent group
  evidence. Three renamed root tests replace the old global-disarm expectations.
- Timer-driven `Arm` becomes `Reassess`; qualified coverage plus distinct engine
  observations replaces counting blanket replay completions. Sticky warning and
  authenticated peer reset remain required.
- Retry attempts receive distinct durable attempt IDs. Correlation must remain
  within each start/terminal pair; obligation identity spans attempts.

Unresolved audit findings — not authorization to weaken assertions:

1. `deferred_snapshot_distinguishes_observed_epoch_at_same_cardinality` has **no
   replacement**. Removing its old struct does not retire its diagnostic guarantee.
2. `explicit_catch_up_succeeds_after_ordinary_sync_when_backfill_defers` changes its
   follow-up from explicit catch-up to maintenance. Add a separate repeated-explicit
   test; otherwise that override/cooldown behavior is no longer covered.
3. `explicit_catch_up_runs_prearmed_backfill_before_success_response` uses
   `subscription_count >= 2`; that does not prove absence of duplicate activation.
   Require exact counts under the same workload and preserve caller-result ordering.
4. `unpersisted_unknown_group_stream_is_no_progress_and_paced` now checks
   `attempt_serial > 0` in place of one cooldown assertion. A reservation alone is
   not a future retry deadline; pin deadline/ordinal and retain no-activation checks.
5. Old positive EOSE completion tests were converted to error/debt-retained tests.
   The new storage qualified-checkpoint tests prove the predicate, but they are
   **not a replacement for public API positive-completion and cursor advancement**.
   `pending_epoch_backfill_eose_records_correlated_incomplete_attempt` similarly
   needs a separate qualified-success lifecycle case.
6. `a_replay_that_ends_terminal_escalates_nothing_and_leaves_no_evidence` replaces
   old zero/one-delivery completion branches with stale-grant rejection after group
   retirement. Restore the admitted-prefix variant; terminal retirement must not
   lose already retained delivery/projection behavior.
7. The reconnect regression gained an EOSE pump after failing. Preserve a second
   withheld-EOSE test to ensure this does not hide a new synchronous catch-up dependency.
8. Nine detector tests changed timer results to `Reassess`, but several still call
   old fruitless-completion helpers that production no longer calls. They cannot
   certify the new escalation path; preserve each clock/reorg/refusal safeguard in
   qualified-observation replacements before deleting old helpers.
9. `assert_stale_marker_worker_preserves_new_generation` now blocks acknowledgment
   while a writer is active, then manually simulates a stale-worker transition.
   Keep both public barrier and defensive stale-writer tests; the manual state
   mutation is not evidence that the public lifecycle safely reaches that state.

Unchanged critical regressions remain required, not automatically green:
`full_history_tests::{missing_eose_exhausts_overall_budget_and_retains_prefix,
cancellation_retains_prefix_and_old_eose_cannot_complete_next_attempt,
cancelled_before_start_does_not_activate_or_clear_overflow,
unfinished_overflow_repair_survives_reopen,
one_fast_endpoint_cannot_complete_full_history_repair}`. The two unchanged delayed
EOSE success tests still need truthful qualified-proof fixtures while retaining
multi-checkpoint delivery and exact generation isolation. Also rerun integration
`cursor_persistence`, `since_floor`, `partial_sync_summary`, `sync_failure_public_api`,
`next_event_backfill` and `epoch_stall_backfill_audit`. No assertions were edited during
this checkpoint/audit.

## Recommended next delivery: qualified storage completion, stacked and held

Extract the existing **qualified scope/checkpoint and loss-completion primitives**
into one focused draft based on #1983. Preserve the owner WIP branch unchanged.
This is a review boundary, not a claim of independent deployment. It isolates the
strongest existing, directly testable part of the integration before repairing runtime behavior.

Include `account_recovery/{plan,loss}.rs`, required typed request/predicate/waiter
parts of `demand.rs`, their parent/exports, route identity migration 0093 and the
inventory invalidation/retained-copy storage writers they depend on. Keep exact
completion guards, atomic maintenance callback and loss acknowledgment compensation
as one unit. Include those storage writes even though they cross several files;
splitting them from revision checks would make stale completion unsafe.

Exclude app/worker/executor code, adapter #1985 changes, stagnation module/migration
0094, capacity policy/probes, diagnostics and policy retuning. Source inspection
shows the scope/loss modules do not require the qualified-stall module; extracting
imports/exports and separating capacity methods is mechanical work for the agreed
slice, **not performed in this checkpoint**. If a semantic dependency makes this
boundary materially larger, stop and explain it before expanding.

Explicit acceptance criteria for that slice:

1. One backing ledger; populated 0092→0093 migration and interrupted migration
   preserve simultaneous gap/loss/release/maintenance/cursor state. Validate the
   single explicit-row index against reachable populated state; no unsafe cleanup
   or historical migration rewrite.
2. Frozen versioned plans, complete required endpoint policy and durable admission;
   EOSE/exclusions/unknown format cannot qualify history. Known-event and limited
   maintenance predicates stay independent. Same-revision scope widening is rejected.
3. New obligation/route/inventory/loss evidence and replaced session tokens reject
   stale results. Compatible retained proof survives unrelated changes; physical
   deletion/compaction invalidates proof atomically. Add missing failure cases.
4. Completion/domain-write failure rolls back all checkpoints; exact loss watermark
   reclamation requires qualified completion and acknowledgment. Interrupted handoff,
   new loss and reopen keep recovery pending and preserve retry cost, including zero-count loss.
5. Repeated explicit callers and detach cannot grow unbounded rows, erase other debt
   or reset retry. Runtime future-drop cleanup remains explicitly assigned to the
   runtime slice, not claimed by storage tests.
6. Full storage crate tests plus `just fast-ci` at the extracted head, focused
   failure-first tests for uncovered cases, signed commit and focused **draft** PR.
   Document test provenance and the inherited merge gate. Complete required review
   before beginning another slice.

| Delivery | Dependency and independent merge safety |
| --- | --- |
| #1982 design | Can merge independently as documentation after its own review gate; does not certify implementation |
| #1985 maintenance fencing | Independent adapter change with backward-compatible legacy paths; can merge after its own current CI/review gate. No owner integration dependency |
| #1983 + proposed completion primitives | Stacked reviewable units; **neither is safe to merge independently** under the existing gate. Schema 0092 already replaces legacy demand tables while old runtime clear callers remain |
| Subsequent owner/executor integration | Depends on state/completion primitives and adapter fencing; must retire all competing dispatch/clear authority and satisfy the missing policy, API, cancellation, migration/rollback and replacement tests before the coordinated stack activates |
| Diagnostics/documentation closeout | May be a separate review commit only if the owner acceptance slice remains gated until these required #1946 surfaces are complete; do not call #1946 finished without them |

Do not add a second ledger or relax the existing migration gate to manufacture an
independently mergeable storage PR. Same-schema conservative mode uses the same
ledger; old-binary downgrade still requires a pre-upgrade backup. The approved
loss-evidence-only writer exception remains unchanged.

The next exit criterion is the accepted storage slice's tested, signed draft PR,
not “owner integration almost finished.” #1947 acquisition/scheduling, SDK adoption
and #1955 remain outside this work. No extraction or implementation resumes until
the user agrees to the slice.
