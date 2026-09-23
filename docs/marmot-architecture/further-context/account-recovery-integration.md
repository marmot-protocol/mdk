# Recovery owner integration — implementation ledger

Completed for draft review 2026-09-23. Local verification is complete; remote CI
and coordinated stack landing remain separate gates. No merge is authorized.
The issue #1946 acceptance matrix and `account-recovery-ownership.md` remain
normative. The original checkpoint/report and replacement-test CSV are preserved.

## Provenance

- Preserved code: `13395cc10fd6941d2a2f72c0398bfc501b99fc25`;
  report/branch: `d8652d185d9fae0626ca199c944bce7ae0a4a8fb`.
- Design #1982: `0092219b974139a98bc059f3d7380668154ccbe1`.
- Ledger #1983: `13cb09a4b32f73602b046b05afb2b6d1fcae4498` (independent marker retirement regression fixed).
- Completion #1987: `4fded1e91fdbb59286cfa00b2ac3018bee97d2b5`.
- Subscription fencing #1985: `73d7ccf1bbe78dd11d705539aad463724de1556f`.
- Reconciled owner baseline: `eb89ea7f7a3c072535803533e2f0af5897e24cb1`.

The CI failure on both storage PRs was reproduced. The repaired regression follows
both tokens through retirement and encrypted reopen, then duplicate observations
and genuinely increased loss. Retiring token 11 deliberately returns false while
token 12 is outstanding. No production retirement guarantee was relaxed.

## Required completion matrix

The approved bounded-comparison amendment is implemented in two checkpoints.
The original automatic restart journeys now pass with their delivery and retained-
inventory assertions preserved. Mixed outcomes, cancellation, shared pacing and
unsupported capability have storage/runtime coverage. The complete affected-crate
run and repository gates passed on the frozen code revision recorded below. Backend limitations and dependency landing requirements
remain explicit; local verification does not claim remote CI or deployment success.

| Acceptance boundary | Implemented behavior and files | Acceptance evidence |
| --- | --- | --- |
| One history authority | `client/recovery.rs` reserves every attempt; `client/{mod,sync}.rs` and `runtime/account_worker.rs` delegate all mapped triggers | `recovery_owner_coalesces_overflow_and_epoch_demand_across_seams`; `explicit_catch_up_gap_is_replayed_on_the_owner_tick_without_later_traffic` |
| Durable pacing and local work | Owner plus storage `account_recovery.rs` / `account_recovery/demand.rs` retain exact reservations, capped retry, productive reset and wall-clock correction | `automatic_attempts_share_one_durable_exponential_schedule`; `only_new_durable_admission_resets_pacing_with_a_minimum_activation_delay`; `reopened_owner_observes_reservation_and_uses_monotonic_time_thereafter`; `due_convergence_interleaves_with_a_backlog_of_worker_commands` |
| Independent qualified completion | Frozen grants and admission receipts in `client/recovery.rs`, `client/sync.rs` and storage `account_recovery/plan.rs` reject stale revisions and require the declared predicate | `conservative_handoff_retains_partial_proof_and_completes_independently`; `history_completion_requires_every_designated_endpoint_and_durable_admission`; `scoped_progress_rejects_unrelated_windows_and_invalidated_attempts`; finite synthetic proof is test-only |
| Live loss handoff and cursor | Queue evidence-only writer in `relay_plane/mod.rs`; worker imports and acknowledges through `client/recovery.rs`; cursor fences in `client/sync.rs` | `qualified_loss_completion_rolls_back_all_causes_after_plane_ack_failure`; `conservative_loss_causes_acknowledge_together_after_separate_grants`; `reopened_overflow_uses_one_owner_replay_and_requires_qualified_acknowledgment`; `process_local_overflow_fence_freezes_cursor_while_marker_write_retries` |
| Cancellation and supported API | Caller guard and grant lease preserve durable debt; repair returns typed truthful incomplete reasons; quiet catch-up preserved | `full_history_repair_serves_snapshot_reads_and_stops_at_checkpoint`; `joined_group_is_visible_before_subscription_rebuild_and_accept_is_prompt_during_catch_up`; `cancelling_one_caller_preserves_independent_demand_and_quiescence`; full-history and cursor suites |
| Maintenance timing | Existing domain boundary remains separate from all-endpoint history; displaced sessions keep grace/quiet timing | `post_join_boundary_completes_only_its_predicate_and_keeps_grace_fixed`; `conservative_activation_keeps_displaced_unqualified_maintenance_selectable`; stale-session tests |
| Evidence and escalation | `client/epoch_stall.rs` has no replay authority; `client/recovery.rs` and storage `account_recovery/stall.rs` sample distinct qualified local observations; migration 0094 persists sample identity | `qualified_local_observations_escalate_without_replay_and_survive_reorg`; `qualified_stall_rejects_new_loss_route_and_inventory_changes`; `qualified_stall_transaction_failure_and_clock_rebase_never_forge_samples`; detector anti-spoofing suite |
| Bounded state and investigation | Constant-memory loss snapshot; grant-owned admissions; completed known-event metadata reclaimed; unknown broad-history investigation quiesces with debt retained | `completed_known_event_metadata_waits_for_grant_release_then_is_reclaimed`; `unknown_history_is_bounded_while_epoch_input_remains_retryable`; storage loss snapshot/import tests; approved unresolved-watermark disk exception in runtime-state-bounds.md |
| Populated migration and conservative mode | #1983/#1987 preserve old debt and atomic completion; one-obligation mode uses the same ledger/executor, including cross-grant loss acknowledgment | Populated/interrupted migration tests; `readiness_wait_and_mode_handoff_preserve_pending_state_and_retry_cost`; `conservative_grants_do_not_coalesce_or_buy_an_extra_retry`; conservative partial-proof/reopen/ack regressions |
| Automatic recovery below the live cutoff, within inventory window | **Implemented / complete suite passes:** migration 0095 and the shared owner slot authorize bounded comparison independently of parked coverage. Runtime joins startup/catch-up once; mixed failures remain pending and the existing tick services them | `cold_restart_reconciles_backlog_below_since_floor`; `stalled_epoch_backfill_still_arms_after_route_reconciliation`; no assertion weakening or cooldown bypass accepted |
| Combined readiness | **Local gates passed:** the final frozen code passes affected-crate suites, default-policy compatibility, simulator policy, doctests and `just fast-ci`; historical failures remain below | Exact revision and results in the final verification section; GitHub CI is reported separately |

## Source ownership and replacement inventory

- `AccountRecoveryOwner::select_authorized_attempt` and
  `AppClient::authorize_account_recovery` are the single authorization/retry path.
  Startup, receive, catch-up, full repair, overflow, epoch evidence, post-convergence
  and maintenance join durable demand there. `execute_recovery_grant` adapts the
  existing acquisition implementation to its frozen grant; it cannot chain an
  independent overflow or epoch attempt.
- `run_pending_epoch_backfill` and `run_pending_epoch_backfill_reporting_arm`
  survive as delegated adapters and lifecycle reporting, without a separate retry
  ledger. `epoch_stall.rs` retains authenticated evidence and warning projection;
  its replay backoff/completion counter and global replay-disarm authority are gone.
  Qualified local observations replace the old EOSE-counted escalation trigger.
- Live subscription installation/reconnect stays in the relay plane and
  `prepare_transport`. It does not imply history authorization or coverage.
  Backend retry and registration retry retain their existing separate responsibilities.
  `advance_post_join_maintenance_subscriptions` supplies only the maintenance domain
  boundary; its any-endpoint evidence cannot complete all-endpoint history.
- The approved off-worker writer calls only the queue-loss evidence API. Notification
  loss, demand import, reservation, completion and acknowledgment remain serialized
  with the account owner. Receipt release still uses the existing receipt journal
  and authoritative epoch-gap adapter, preserving redelivery eligibility.
- Internal calls to `clear_epoch_backfill_intents` and
  `clear_account_delivery_recovery` are absent from marmot-app. The supported
  lower-level storage compatibility methods remain ledger adapters. Terminal group
  cleanup atomically retires that group's demand and warning evidence, preserving
  independent account loss and retry state.
- Directory discovery/cache coverage, superseded-invite recovery, onboarding,
  publication and engine convergence remain their own domain owners as mapped in
  the approved design. This integration does not absorb them into history demand.
- Known-event completion and admission are implemented and exercised at the owner
  boundary, but the current SDK's aggregate reconciliation result does not expose
  identified missing event IDs. There is no production KnownEvent request producer
  to invent here. Efficient selective acquisition is #1947; the supported backend
  reports unknown/incomplete historical coverage honestly. EOSE is never upgraded
  into qualified coverage. Production escalation requires actual qualified evidence;
  the test backend's finite certificate is not a production capability claim.

The 85-row `account-recovery-integration-tests.csv` maps removed/substantially
rewritten regressions to current tests and separates deliberate completion-policy
changes from preserved delivery, cancellation, retry, cursor and stale-evidence
assertions. The original checkpoint inventory is immutable historical evidence.

## Sequencing and landing

Implementation checkpoints stay local until their stated checks pass. No new
standalone storage layer is planned. Storage changes must serve a concrete runtime
integration requirement. No SDK change, connection allocation, or #1947 scheduling
or nonblocking acquisition work belongs here.

#1985 is already merged. #1983 is open and #1987 is a draft; neither storage
change should deploy before the owner integration is ready to land with them.
Proposed coordinated order: #1982 design, #1983 ledger, #1987 completion, then owner integration,
with the storage/runtime commits treated as one release unit. Retarget the stacked
PRs as their bases merge; do not squash away required dependency ancestry silently.
Old binaries reject the upgraded schema; binary downgrade needs a pre-upgrade
backup. Conservative mode is same-schema owner behavior, not binary downgrade.

No PR is to be merged by this task. Final PR evidence must name exact dependency
and tested heads, surviving compatibility helpers, affected-crate results, failed
and superseded checks, and the remaining blocking acquisition limitations.

## Verified checkpoints

- Reconciliation baseline `eb89ea7f`: 56 storage-recovery tests pass; owner tests
  are 9 pass / 1 known maintenance-restoration failure. These results predate
  cancellation edits. Compilation also reports obsolete-helper warnings to remove
  with their replacement inventory, not suppress.
- Caller-lifetime cleanup: new dropped-future regression failed on orphaned urgency.
  Its reopen half also exposed a false backward-clock correction caused by
  second-precision startup versus millisecond retry deadlines. A synchronous caller
  guard detaches urgency on every exit, retaining incomplete debt; startup now
  samples milliseconds. The dropped-future/reopen and pre-activation cancellation
  tests pass, as do all 6 demand/waiter storage tests. The test compares every
  pending identity across reopen (including startup demand), not an assumed count.
  Full feature-gated cancellation/admitted-prefix and worker tests remain required.
- Cancellation checkpoint `4c76e363`: feature-gated admitted-prefix cancellation
  and stale-EOSE isolation also pass. Maintenance restoration now uses a controlled
  retry deadline instead of a 5 ms sleep that default builds intentionally ignore.
  It proves no activation/cost change during cooldown, fresh session afterward,
  and identical grace deadline throughout. All 10 owner tests pass with default
  policy; the restoration regression also passes with policy overrides.
- Loss-writer authority: three red regressions reproduced off-worker notification
  persistence, stopped count-growth persistence, and normal-close loss invention.
  Queue callbacks now have a queue-only type; one account-local writer persists
  count growth independently of queued control signals. Typed lag is worker-written
  with a fresh zero-count incident token; ordinary close does not create demand.
  All 46 relay-plane tests pass, including replacement, stale-writer and router
  control/count races. The notification replacement regression now exercises the
  actual worker receive boundary rather than assigning notification writes to the
  queue callback. Live-attempt cancellation and cursor handoff are the next section.
- Live-attempt lifetime: two red regressions reproduced a stranded transient plane
  flag after future drop and durable cursor advancement during an unacknowledged
  attempt. A scoped attempt guard now releases the transient flag on every exit;
  cursor fencing consults pending loss independently of dispatch visibility. Typed
  notification lag remains worker-visible during an active attempt. Both regressions,
  qualified-completion rollback after failed plane acknowledgment, and notification
  replacement pass. These focused results do not establish combined readiness.
- Same-schema execution: conservative mode now selects one obligation, using the
  same comparison/executor and account reservation as normal mode. Selection uses
  the last installed attempt to avoid starving other obligations; only a live
  explicit caller spends its existing override. Existing maintenance sessions are
  restored without inventing completion or restarting grace, and displaced pending
  boundaries remain selectable. The two loss causes can qualify in separate grants:
  at most two captured acknowledgment inputs survive in memory, while SQLite checks
  every predicate/revision again before the shared live acknowledgment. No storage
  API was added. A failed executor or acknowledgment restores pending debt; owner
  reopen also restores qualified but unacknowledged loss without forgiving retry.
  Fourteen owner tests pass with default policy, including populated mode handoff,
  independent partial-proof completion, cancellation before activation, two-grant
  loss acknowledgment, and interruption/reopen. The mode/maintenance and final
  two-grant/reopen regressions also pass with policy overrides. The initial
  conservative selection and loss-handoff regressions both failed before their fixes.
  An added maintenance fixture initially omitted its required group row; that
  fixture error was corrected by creating an actual runtime group.
- Terminal retirement: the owner now retires group-scoped demands and their
  detector/warning rows in one transaction, preserving account-wide loss/history
  and retry state. The app's two legacy clear wrappers and the last internal
  legacy-clear caller are removed; supported storage compatibility methods remain.
  An injected delete failure verifies rollback, then successful retry and idempotent
  retirement. All 5 storage stall tests and 26 app terminal tests (policy overrides)
  pass. The first verification attempt needed the StorageProvider trait import;
  that compilation failure preceded these passing runs.
- Broader diagnostic run on `60141d5b` (before conservative/terminal edits): default
  app library suite finished with 1461 pass, 18 fail, 4 ignored. This is failure
  inventory, not final acceptance evidence. It includes old EOSE-completion test
  expectations, cursor/overflow cases and worker lifecycle failures that still
  require diagnosis; they are not all classified as assertion updates.
- Cause-aware outcomes: EOSE is Unknown coverage, not proof of unsupported
  missing-epoch acquisition. Epoch and known-event debt keep capped retries;
  queue/notification/explicit/incremental history retain debt in needs-deep-repair
  after their bounded investigation ends without proof. The existing drain quantum
  is the automatic investigation budget; it creates no new scheduling loop.
  Transient unavailability remains retryable, proven unsupported/excluded capability
  is distinct, and admission refusal waits for local relief/owner-paced probing.
  Sixteen owner tests pass with policy overrides. The runtime regression first
  reproduced the erroneous permanent epoch wait, then proved that three later
  capped windows select only epoch input, reopen preserves cost/quiescence,
  duplicate loss cannot rearm, and new loss rearms without bypassing cooldown.
- Live route compensation: the existing regression reproduced a new demand
  write preventing subscription restoration after a storage-delete failure.
  Missing-cursor demand now joins once at owner construction; live-tail bounds
  perform no storage mutation. The unchanged compensation regression passes,
  as do all 16 owner tests with policy overrides. This preserves the primary
  storage error and the attempted compensating route restoration.
- Repair API classification: a reproduced worker failure hid incomplete coverage
  under `blocking_task`. A typed reason now preserves cancellation, deadline,
  silence and unproven coverage independently from outstanding loss; worker error
  channels remain unchanged. The prearmed worker regression, independent
  classification matrix, shortened-policy no-EOSE loss test and controlled overall
  deadline/prefix test pass. The first silence assertion incorrectly expected the
  overall deadline even under shortened silence policy; it now explicitly checks
  the policy-specific stop, with the actual deadline covered separately. These
  checks predate the remaining qualified runtime completion work.
- Approved retention exception (2026-09-23): unresolved per-generation durable
  loss watermarks have no fixed disk-row cap. No outstanding loss may be erased
  for a cap; qualified completion and exact live acknowledgment remain mandatory.
  Design and bounds documents record this limitation. Active snapshot/completed
  metadata reclamation and bounded investigation proofs remain acceptance work.
- Qualified runtime completion: an explicit synthetic finite-endpoint certificate
  fixture now drives the real executor, scope checkpoint, caller verdict and loss
  acknowledgment. Ordinary SDK EOSE remains Unknown; the fixture is test-only and
  makes no production-capability claim. Positive continuation tests now require
  that independent proof. Missing endpoints, incomplete admission/exhaustiveness,
  stale EOSE and newer loss refuse completion. A new regression reproduced success
  returning before cursor promotion after acknowledgment; the executor now saves
  that already-admitted candidate after the handoff and restores its old in-memory
  checkpoint if persistence fails. All 11 repair tests and 16 owner tests pass with
  policy overrides. An initial fixture compilation used a nonexistent state
  accessor; that was corrected before the cursor regression reproduced its failure.
- Bounded loss capture: the owner no longer copies all unresolved generation
  watermarks into every grant. A 40-byte SHA-256 snapshot commits to the ordered
  full token/count set, streamed with constant Rust memory. The acknowledgment
  transaction still validates the same scope/revision/no-unimported-loss rules;
  supported vector APIs share that implementation. Import uses a one-row keyset
  scan without a temporary generation vector. This storage addition serves the
  concrete approved disk-retention exception, not a future acquisition API.
  A 1,024-generation fixture verifies preservation, earliest-token growth and
  duplicate import; both acknowledgment forms exercise incomplete proof, commit
  failure and newer loss. All 58 storage recovery, 16 owner and 11 repair tests
  pass (app tests with policy overrides). The initial implementation needed an
  explicit connection guard binding before compilation; final runs include it.
- Completed metadata lifetime: a red runtime test reproduced completed known-event
  scope accumulation. The owner now reclaims those rows only after the live grant
  releases, or at owner reconstruction, preserving pending events, stale-result
  rejection and retry state. Admission snapshots are grant-owned with only a weak
  owner reference; cancellation/quiescence releases them immediately. Pending
  cross-grant loss acknowledgment retains only its own obligation revision rather
  than the whole selected demand set. All 17 owner tests pass with policy overrides,
  including the new lifetime regression and the snapshot-drop assertion. The bounds
  inventory distinguishes fixed active inventory limits from input-relative
  unresolved historical goals; no old route or unresolved event is evicted for a cap.
- Qualified local evidence reconciliation: a new red regression showed the WIP
  sampler still rejected unrelated global inventory revisions, contrary to #1987's
  scope-specific retention fences. It now validates installed scope proof; actual
  overlapping removal still rejects evidence. Tests perform real route/window
  inventory retirement rather than manually incrementing a global counter. All
  6 storage stall tests pass, including loss/route/overlap rejection, unrelated
  eviction, distinct observations, reopen, clock correction and rollback.
- Qualified observation regressions: removed the obsolete EOSE escalation counter.
  Real local convergence evaluations now test qualified finite coverage, four
  distinct paced observations, one warning, reorg/reopen continuity, and unchanged
  replay cost; ordinary EOSE produces no qualified samples. The replacement CSV
  maps every retired counter regression to its preserved guarantee. Detector
  projection tests retain epoch/expiry/clock-reset and forged-traffic boundaries.
  The final focused runs pass: 40 detector tests, 3 qualified-local tests, and the
  warning-projection test; the convergence ledger gate passes. The old EOSE
  expectations first produced four failures. These results do not cover the
  remaining capacity, worker scheduling, and overflow integration inventory.
- Capacity and reopen: the replacement regressions reproduced an integration
  defect where one refused group put every coalesced obligation into capacity
  wait. Eligibility now uses the actual refused-group set for group predicates;
  account-wide coverage remains conservative. Three capacity tests pass with
  exact activation/reservation counts, duplicate-deadline preservation and a
  later paced probe. Reopen and activation-failure tests also pass. Two initial
  timing fixtures accidentally requested zero backoff; their final versions use
  an explicit long interval and advance only the owner clock. The replacement
  CSV records the durable-owner guarantees replacing detector rearm assertions.
- Worker integration: four focused policy-override regressions pass. Startup
  coalesces incremental/epoch/loss demand; receive, maintenance and post-convergence
  preserve its reservation; one genuine explicit caller adds exactly one attempt.
  Two actual scheduled convergence passes service runnable input and queued reads
  while durable loss remains in cooldown, with unchanged retry and subscription
  counts. A gap discovered during ordinary catch-up is replayed on the existing
  maintenance tick without later live traffic; its below-floor event is admitted
  and EOSE remains incomplete. The duplicate-only quantum still yields to queued
  commands. Initial quiet-gap assertions ran before the activation barrier and
  incorrectly counted incremental grants as epoch audit rows; final assertions
  use durable admission and the actual epoch audit contract. A test-only worker
  clock command changes no storage and grants no execution authority.
- Overflow composed handoff: both replacement regressions pass with policy
  overrides. Reopen installs ordinary live interest; one owner activation recovers
  the omitted below-floor event but EOSE alone keeps the gap. A second explicit
  operation with independent synthetic endpoint proof passes the actual live/SQL
  acknowledgment and retires it. During writer retry the process-local fence
  freezes the cursor; the writer persists evidence only, the serialized owner
  imports demand, and reopen preserves the pending loss and old cursor.
- Deferral and independent completion audit: a new red regression reproduced
  missing unavailable-epoch diagnostics. The owner now retains one private
  32-byte digest, emits an unchanged decision once, and preserves changed observed
  epochs at equal cardinality. The fixture reopens a real orphaned group into
  quarantine; an initial fixture omitted the group FK, then another had not yet
  performed hydration. The final regression passes. Positive qualified-success
  lifecycle correlation and independent completion also pass. A strengthened
  independent-scope regression reproduced endless eligibility for a group with
  no executable route; it now waits for capability/policy change while preserving
  its debt. The worker failure/retry regression also passes after replacing its
  accidental zero-backoff fixture with a real cooldown and exact retry assertions.
  All 17 owner tests passed before the final no-route eligibility adjustment;
  combined verification must include that adjustment.
- Replacement-test cleanup: obsolete retry/EOSE helper implementations are
  removed. The actual owner now has the extreme-ordinal/cap checks; 39 detector
  tests preserve projection and evidence rules with explicit test-only state
  fixtures. A real admitted prefix survives both terminal outcomes while old
  completion is rejected; the zero-prefix variants remain. Repeated duplicate
  quanta, an unpersisted stream with exact cooldown/cost, explicit prearmed
  catch-up with exact activation count, and positive/negative worker repair all
  pass. The reconnect regression also passes with EOSE withheld through every
  live reopen and host wake. The four lifecycle/readiness failures seen in the
  broader cargo-test run pass unchanged in isolation; the repository uses
  process-isolated nextest for its combined CI run, which remains required.

- API catch-up compatibility: the unchanged joined-group visibility/prompt-accept
  regression failed in isolation because a coalesced maintenance prerequisite
  changed ordinary incremental catch-up into a full-history EOSE wait. Incremental
  plus maintenance grants now retain quiet-drain behavior; installation and quiet
  remain unqualified completion. The original regression and all 18 owner tests
  pass with policy overrides. The cancellation fixture also passes with another
  account performing a real catch-up while the first account waits, preserving
  same-account snapshot reads and its original cancellation bounds. The replacement
  inventory now contains 78 mappings, with every replacement symbol checked.
- Superseded broad diagnostic: `app-feature-inventory.log` reports 1491 pass,
  11 fail, 4 ignored. Source edits overlapped compilation, so it has no reliable
  exact-head attribution and is only a failure inventory. The failures were
  investigated in the focused checkpoints above. It is not combined acceptance
  evidence; the following nextest run must use a frozen signed code revision.

- Repository check cleanup: the first `fast-ci` run on `ae3fc968` rejected
  production-unused grant mode metadata and a test-only marker probe. The metadata
  was removed and the probe restricted to tests. The next run found one remaining
  test reference to the removed field; `aebad88a` corrects it to inspect owner mode.
  Neither failed run is acceptance evidence; full checks are rerunning.

- Workspace integration: exhaustive simulator classification initially rejected
  the new `FullHistoryRepairIncomplete` variant. It now retains the prior resource
  failure category (formerly carried by `BlockingTask`); the privacy-safe error
  classification regression passes with the explicit incomplete case included.
  This is an adapter correction, not an expanded simulator/campaign workstream.

- Final lint cleanup: default and diagnostics-feature clippy pass after naming
  the stored stall row type, propagating the existing repair error without a
  large-error closure, and simplifying a test boolean comparison. Runtime error
  priority and test assertions are unchanged. Full `fast-ci` and the combined
  suites will run on the following frozen signed checkpoint.

- Frozen combined run on `81c2bb5313b38735d64fcb75d720aae73904963b`:
  `fast-ci` passed, then nextest started 2866 tests across 22 binaries with four
  workers, no retries and relay-runtime serialized. The known-red run was stopped
  to fix eight real relay-runtime failures: 1493 passed, 8 assertion failures,
  4 interrupted tests, 1361 not run, 21 skipped. This is partial failure evidence,
  not combined readiness. The following simulator command was also interrupted.
- Live registration regressions: reopen could inherit cooldown without installing
  any live subscription; startup now restores floored live interest without a
  history reservation. Incremental/maintenance-only grants no longer introduce
  the inventory comparison wait into ordinary catch-up. A separate post-join
  regression left ordinary live registration waiting on its retry timer: the
  SDK's single deduplicated group copy could reach only an already-routed account
  during that interval. The worker now tries the existing live registration path
  immediately after publishing join visibility, with its original bounded retry
  on failure. All eight unchanged failing relay-runtime journeys pass. No SDK
  change, new dispatcher, deadline increase or assertion relaxation was used.
  Temporary diagnostic probes were removed. All 24 owner/API compatibility tests
  pass, including unchanged prompt-invite, reconnect, overflow and ordinary
  registration failure/retry regressions. The complete stack must be rerun.

- Review address checkpoint: Cursor/Grok reviewed draft #1992 at `81c2bb53`
  and identified maintenance widening incremental floors and transient effects
  before successful plan freeze. Both are fixed. Maintenance uses its separate
  scoped REQ; maintenance-only activation keeps the live floor. A rejected freeze
  retains observations, the caller override, durable debt and reserved retry cost;
  stale observations cannot suppress a successor or complete its predicate. Loss
  snapshots and inventory preparation precede transient commitment. A rejected
  plan reports an error instead of masquerading as no work due.
  All 20 owner tests pass with policy overrides, including both new regressions.
  Restoring only the old floor calculation makes the final new regression fail
  with an unfloored inbox; restoring the fix preserves the exact passing source.
  Claude Code 2.1.280/Opus 5.5 stalled without a review and was stopped/reaped
  after over 22 minutes (exit 143); this is a failed reviewer, not approval.
  One review/address round is being completed; no second round was launched.
- Three-crate run on `5a6811a28f2f2f79a1cf741412a64203497b3577`:
  1082 passed, 2 failed, 8 skipped. Both failures are populated-migration
  comparisons that did not account for migration 0094's appended columns.
  This run is not combined acceptance evidence. The migration corrections below
  must retain every legacy value and assert that new qualified evidence starts
  empty, including interrupted upgrade and reopen.
- Migration assurance correction: the full-row upgrade expectations retain every
  legacy value and explicitly require NULL/zero qualified-evidence fields and
  empty observation allocators. The populated test now also interrupts migration
  0094, verifies schema and all prior rows rolled back, then upgrades and reopens.
  All four recovery migration regressions pass. No production migration or
  completion guarantee was changed to make these tests pass.

- Full combined run at `3fcb823652b3bfe4f294423dc452994c16443c18`:
  2868 tests across 22 binaries, 2865 passed, 3 failed, 21 skipped, no retries.
  Features included app/engine policy overrides, engine crash hooks and adapter
  SDK. Both storage migration regressions pass in that combined run. Failures:
  `frozen_wake_collection_ingests_without_moving_the_durable_cursor` and both
  `since_floor` tests named in the matrix. Later gates were not run by that
  fail-closed script. This is an exact-head failure inventory, not readiness.
- Frozen-wake compatibility: owner authorization now defers ordinary history in
  Frozen mode without spending its permit or retry cost; live interest retains
  its loaded floor and records the existing rebuild audit. The distinct explicit
  full-history repair API still goes through the owner. All 21 owner tests and
  the unchanged three-boot cursor test pass (22 total). Durable debt survives;
  no assertion or deadline was relaxed.
- Below-floor investigation: restoring the legacy bounded comparison inside an
  authorized incremental grant is necessary but insufficient. Both cold-restart
  tests still fail because unchanged reopen cannot authorize parked history under
  the approved quiescence rule. The diagnostic source was preserved separately;
  it was not published as a fix. The contract question was escalated, with a
  concrete bounded-comparison amendment. No automatic rearm exception, competing
  authority, false coverage result or replacement assertion has been implemented.

## Bounded-comparison amendment checkpoint — 2026-09-23

The user selected automatic bounded comparison under the same owner/cooldown,
with older coverage debt retained. The adjacent amendment now specifies migration
0095, one durable coalescing comparison slot, typed reservation/freeze/admission/
settlement contracts, cancellation and conservative-mode behavior, and the exact
remaining implementation/test boundaries. No executable source or schema has
changed in this documentation checkpoint. The two `since_floor` failures remain
unresolved; the combined suite has not been rerun or claimed green.

Independent checks on exact code head
`36442cd2e62883d0290c5fc6145e7af04ec7ea08` completed successfully:

- Simulator `protocol_decision_gate`: 5 tests passed.
- Four affected crates' doctest commands passed (zero doctests present).
- Default-policy owner, receipt and prompt-invite selection: 25 tests passed.
- Complete `just fast-ci`: passed, including workspace all-target check/clippy,
  diagnostics feature builds and repository static/documentation gates.

Exact commands, exit codes and timestamps are preserved locally in
`/tmp/mdk-1946-ci-owner/independent-gates-k5dyamlj/results.json`. These checks
postdate the frozen-wake fix and do not predate any subsequent executable edits.
The earlier 2865/2868 combined result predates that fix and remains historical
failure evidence. Local review fixes and the amendment are unpushed while the two
delivery regressions remain red; #1992's published code is still `81c2bb53`.

## Amendment implementation — checkpoint 1

The approved amendment now includes the two-cutoff distinction, per-route mixed
settlement, and repeated-start guarantees. Migration 0095 adds one comparison
slot. Storage joins coverage debt atomically, shares the existing retry reservation,
freezes operational plans only inside recorded debt, preserves failed-route subsets,
and settles independently of coverage and loss acknowledgment. The owner supports
comparison-only and coalesced grants, scoped admission, atomic freeze rollback and
same-schema conservative selection. Runtime startup is not connected yet.

The first join regression failed with the intentionally absent persistence; it
passed after the implementation. The complete focused storage/owner/migration
selection then passed **93/93**, default features, no retries. It includes eight
new storage and three new owner regressions, migration-0095 interruption/rollback,
encrypted reopen, mixed failures, successor requests, spent-cost preservation,
unsupported evidence checks, and stale inventory/loss rejection. Logs:
`/tmp/mdk-1946-ci-owner/comparison-checkpoint-one-final.log`.

This is the first of the two agreed implementation checkpoints, not a completion
claim. The unchanged `since_floor` runtime journeys remain unresolved until the
second checkpoint. Full affected-crate suites and final repository checks remain
required after that integration.

## Amendment implementation — checkpoint 2

Checkpoint 1 is signed `ffd8cd5429361c186c42ff9e446db1b0ff3f6de9`. Runtime
startup and explicit catch-up now join the slot; ordinary polling, maintenance
and reconnect preparation do not. The existing tick services pending work. Mixed
route results retain the failed subset under shared pacing. An interrupted route
remains retryable; unstarted routes retain coverage debt without a new sweep.
Known absent SDK capability parks the slot, and an actual operational-capability
change can rearm it without resetting cost. Frozen wake remains excluded.

The original restart pair and unchanged frozen-cursor journey passed **3/3** in
`comparison-runtime-journeys-three.log`. The epoch companion first reproduced an
extra payload because a coalesced epoch goal widened startup acquisition. Frozen
comparison bounds now govern that partial pass; the epoch goal stays pending.
No delivery, durable-inventory or no-redownload assertion was relaxed. The test
clock proves no reservation before the shared deadline, then advances elapsed
time and waits for the existing automatic tick. Terminology now distinguishes
the live subscription cutoff from the inventory retention/compaction floor.

The final focused selection passed **37/37**, including mixed-route execution,
activation cancellation, interrupted versus unstarted routes, repeated requests
against unsupported capability, explicit full-history repair isolation, and all
owner/comparison regressions. Log: `comparison-checkpoint-two-final.log`. A new
duplicate-settlement assertion failed before the final guard was added, then
passed. Explicit full-history repair excludes bounded comparison from its grant
so an outstanding startup request cannot narrow its supported range.

The 3/3 journey run predates the final duplicate-settlement, capability-observation
and full-repair isolation guards; the 37/37 run includes them. Affected-crate
clippy passed before those guards. All will be refreshed in the frozen complete
stack run rather than treating earlier focused results as final acceptance.
The two original restart tests add two rows to the replacement map (80 total).

### Pre-publication debt-preservation correction

Checkpoint 2 is signed `3e2723cb2d08fa97bb1dcd89db82d41113c728f2`. Its frozen
full run was deliberately interrupted after 40 passes (four in-flight tests
received SIGINT; 2841 were not run), not reported as an acceptance result.
Source audit found that joining a comparison could resolve a pre-existing
unbounded incremental placeholder using the newer comparison lower bound.
`comparison_join_does_not_narrow_preexisting_unresolved_history` reproduced
`Some(10)` instead of `None`. The join now retains the unresolved prior lower
bound while its operational plan remains bounded. All **9 comparison-storage
regressions pass** after that correction; the complete stack run is restarted on
the signed successor. Logs: `comparison-placeholder-red.log`,
`comparison-placeholder-green.log`, and the interrupted `verified-stack-gmtu0_ms/`.

### Combined-run compatibility corrections

The complete affected-crate run on signed `55e0b24f0120f078cad55c5266d5843c7b77a847`
finished with **2882 passed (one leaky), four failed, 21 skipped**; no retries.
Logs: `/tmp/mdk-1946-ci-owner/verified-stack-sf5rybd5/`.
Three unchanged assertions exposed a real regression: bounding every coalesced
comparison suppressed the supported broader pass for fresh epoch/loss evidence
and explicit catch-up. Frozen activation now distinguishes those independent
reasons from previously investigated unchanged debt. Startup alone cannot widen
acquisition, including repeated cold starts with unchanged epoch debt.

The fourth failure was `reopen_and_toggle_restore_source_row_without_group_mutation`:
a startup `sync_drain` row arrived after a quiet file interval but before the queued
disable took effect. The test now waits for the existing completed-catch-up metric
before taking its pre-disable sample. The exact full-body equality, source linkage,
and re-enable assertions are unchanged. No audit implementation or timing guarantee
was weakened. This timing-only replacement is recorded in the 81-row map.

These corrections require focused recovery/restart/audit tests, then a fresh
complete run; the failed run is not final acceptance evidence.

The corrected focused selection passed **45/45**, no retries, including all four
failures, both complete original restart journeys, unchanged frozen-cursor journey,
and every owner/comparison-storage test. Log:
`/tmp/mdk-1946-ci-owner/comparison-compatibility-correction.log`.
All 81 regression-map rows resolve to existing replacement test functions.
This supersedes the four focused failures, not the required complete final stack.

## Final local verification

Signed executable checkpoint `e5fa32212c7fa4e0bc03c8c240834a09991557a7` is the frozen code used for all
five gates below. No source edits occurred during this run. Subsequent publication
documentation changes do not alter executable code; their repository gate is
recorded separately in the PR. All unpushed commits have verified signatures.

- **affected-nextest**: passed. Summary [ 910.683s] 2886 tests run: 2886 passed (1 slow), 21 skipped
- **simulator-protocol-decision**: passed. Summary [   0.018s] 5 tests run: 5 passed, 0 skipped
- **affected-doc-tests**: passed. Four affected crates; zero doctest cases present.
- **default-owner-nextest**: passed. Summary [  15.694s] 33 tests run: 33 passed, 1460 skipped
- **fast-ci**: passed. Formatting, static/documentation gates, workspace all-target
  check and clippy (normal and diagnostic feature builds), and all five release-
  assertion policy tests passed.

The affected selection includes both original complete `since_floor` journeys,
the unchanged Frozen wake journey, all owner/completion/cancellation/retirement
regressions, populated/interrupted migrations, and same-schema conservative mode.
The default-policy selection proves the production retry schedule separately from
test overrides. Simulator policy and repository convergence/binding gates pass.
The four-crate doctest command succeeds with zero doctests present; this is not
reported as additional exercised cases.

Exact commands, UTC timestamps, head and exit codes are in
`/tmp/mdk-1946-ci-owner/verified-stack-651yhfzj/results.json`, with adjacent logs.
The earlier four-failure run at `55e0b24f` remains diagnostic history; the final run
supersedes it. The untouched original WIP remains available at the provenance
revisions above. No SDK dependency/version change or #1947 acquisition/scheduling
work is included. No outstanding implementation item in the approved #1946 matrix
is relabeled as future validation; the declared backend and retention limitations
remain part of the reviewed contract.

Dependency CI was refreshed on 2026-09-23: #1983 at `13cb09a4` and #1987 at
`4fded1e9` both have green Required CI. #1987's earlier readiness-timing shard
passed after one rerun without a dependency change. This is separate from #1992's
new-head CI, which must be checked after publication. The stack remains unmerged.

## Simulator CI follow-up

CI run `35872775969` on publication head `58389f4c` exposed a validation gap:
the previous local stack ran simulator policy checks, not the app/process journey
lanes. The convergence recipe selected the retired
`explicit_catch_up_arms_and_replays_without_later_traffic` name and failed closed
with zero tests. It now selects the mapped owner-tick replacement, preserving the
recipe's exact-match/no-empty-tests guarantee.

Four simulator journeys reproduced locally (0/4 passed). Full-history repair's
honest coverage-unproven result was flattened to generic `account_catch_up` by the
worker/process boundary and aborted the scenario before its independent oracles.
The worker now retains typed reason plus the independent loss flag inside its
existing failure wrapper. A nonbreaking Rust error accessor exposes those facts;
no display-string parsing or runtime success conversion occurs. The simulator's
private RPC carries Complete versus CoverageUnproven explicitly. Only unproven
coverage **without loss** allows the action to continue, recorded in
`local.history_repairs_without_coverage`. Cancellation, deadline, EOSE failure,
loss, storage and arbitrary catch-up errors remain failures. No runtime recovery,
completion, scheduling or SDK policy changed.

The new worker-boundary regression first failed with `None` instead of the typed
reason. After the fix, all **six focused regressions passed**, including the four
unchanged CI failures and negative classification tests for every incomplete
reason with/without loss. The hidden/restored history journey additionally asserts
both repair passes remain coverage-unproven; original payload assertions remain.
Logs: `simulator-ci-red.log`, `repair-reason-red.log`, `simulator-ci-focused.log`
under `/tmp/mdk-1946-ci-owner/`. The mapping now has 85 rows. Full PR-CI simulator
coverage and repository gates remain required before this follow-up is pushed.
