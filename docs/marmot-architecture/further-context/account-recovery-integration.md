# Recovery owner integration — implementation ledger

Resumed 2026-09-23. This is work in progress, not a completion claim.
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

All behavior rows below are implemented and have focused passing evidence in the
checkpoint ledger. Combined readiness remains pending until the frozen-revision
checks and draft review are recorded; these focused results are not that claim.

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
| Combined readiness | **Pending:** freeze signed code, run affected-crate suites, required gates, and draft review | Exact revisions, commands, outcomes and any superseded failures must be recorded below before claiming readiness |

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
  `prepare_runtime_transport`. It does not imply history authorization or coverage.
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

The 78-row `account-recovery-integration-tests.csv` maps removed/substantially
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
