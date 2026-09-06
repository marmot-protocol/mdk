# Offline catch-up: work-in-progress checkpoint

**Projection and background recovery responsiveness fixed locally; the strict 1,024-message public gate now passes twice.**

Working branch: `codex/fix-offline-catchup-continued`.
Base: `565bbb2f36c5f8a7d4715c225f0067358de7aca7` from `codex/fix-offline-catchup`.
The original checkout `/Volumes/Worktrees/codex/69d9/mdk` was preserved. Its uncommitted prototype was copied here before further work. The signed checkpoint commit is `77356248bddddf13e3498a68fec2513d7b458b72`; no push has been made.

## Background recovery fix after checkpoint (2026-09-06)

This checkpoint captures the fixes after signed checkpoint `775e6459`. Background advance now shares a 64-row
allowance across all reprocessing sweeps and a cooperative 500-ms deadline. It yields only after complete
operations, reschedules remaining work, and retains the durable generation barrier before epoch settlement.
Foreground preflight semantics, key retention, raw backlog limits and app query deadlines are unchanged.

Historical peel contexts are now materialized lazily once per bounded sweep, preserving snapshot provenance and
historical retention policy. Live group storage is restored before awaiting the peeler; owned contexts are dropped
when the sweep ends. Canonical/candidate invalidation stops the sweep. This avoids repeating the same SQL snapshot
and restore work for every opaque message. No SQLCipher library or storage durability change is involved.

The production-policy public gate passes twice in 213.53 and 215.27 seconds. Both runs recover every original
payload by repair pass 11 (zero-based), agree at epoch 22, pass fresh traffic from all four members, and retain the
complete recipient timeline after restart. Terminal observations contain 1,047 timeline events per participant,
including workload, setup and follow-up events. Close reports have no errors; no native crash occurred. The six
basic public journeys pass in 108.49 seconds; the small offline canary passes in 84.43 seconds. The large test
remains an explicit slow gate; skipping it is not evidence of recovery. The input, repair/reopen allowance and
success assertions were not weakened.

A stricter engine cross-check exposed a harness false stall: eight bounded slices completed 512 distinct-context
attempts (1,086 to 1,598) without changing raw-row count or epoch. The conformance-only structural snapshot and
local drain guard now include that durable attempt aggregate. A new guard regression permits this progress while
still rejecting an identical state; all twelve neighboring guard tests pass. All four original engine regressions
(368 and 1,024 messages, natural and reverse history) pass in 166.13 seconds, retaining exact state, payload,
decryptability and no-pending-work assertions. The new background execution constant is registered on the required
ledger surfaces; the ledger gate and all five protocol-decision tests pass.

Three engine regressions cover cross-sweep work limits with restart, elapsed-time yielding with eventual completion,
and historical materialization cost for 1 versus 32 opaque rows. The full engine suite passed 530 tests before the
final conformance-only observation addition; afterward all 28 deferred-peel tests and three conformance snapshot
unit tests passed. The evidence report records exact commands and verification boundaries.

Limits: the 500-ms budget is cooperative, not cancellation of a synchronous MLS/storage operation. Two local
app runs do not establish device performance, arbitrary backlog sizes or broad real-relay coverage. Public
send/leave epoch-oracle investigation and publication/invite fault campaigns remain separate follow-ups.
There is no new general SQLCipher production fix: the earlier finding was unsafe diagnostic teardown, described
below. No push or full workspace CI run has been performed for this change.

Evidence, commands, logs, source patches, binary hashes and public observation checkpoints:
`target/background-recovery-20260906/REPORT.md`. The following sections preserve the pre-fix investigation.

## Worker timeout investigation after projection checkpoint (2026-09-06)

Signed checkpoint `775e6459` captures the projection fix, public family expansion and regressions together;
its signature is verified locally and it has not been pushed. Investigation source is unchanged from that commit;
temporary aggregate timing hooks were archived and removed after building a frozen diagnostic executable.

A sampled 1,024-message public rerun reproduces the member-query timeout at repair pass 1 (263.93 seconds).
The final recipient snapshot has 196/1,024 messages at epoch 7; peers are complete at epoch 22. No captured
background storage errors, teardown errors or native crash. Ten three-second process samples identify the busy
path as engine convergence -> deferred peeling -> historical snapshot fallback. Each message can repeatedly
save live group state, restore a past snapshot, load/derive its peel context, try decryption and restore live state.
The samples show substantial SQL snapshot/WAL commit work, not evidence of a SQLCipher crash or lock deadlock.
`retry_on_busy` is also the normal wrapper name; its presence does not prove busy retries.

The 64-row limit applies to a sweep; background advance can chain 16 sweeps with no elapsed-time budget. A
separate temporary timing probe has measured a single advance call at 11.624 seconds, followed by 149 ms of app
projection. That already exceeds the 10-second member-query deadline. The worker cannot serve commands inside
that call. Biased timer-before-command priority may compound the delay, but it is not necessary to explain a
single overlong call. The final timing run fails at repair pass 3 (248.35 seconds), with Bob at 576/1,024
messages and epoch 13. A query timeout at elapsed 237.865 seconds falls inside an 11.331-second engine call
(start 227.179, end 238.510); app projection follows in 181 ms. This directly confirms a query can expire while
engine recovery still owns the worker. No captured background storage errors, close errors or native crash.

Next controlled fix: reuse historical contexts within a bounded sweep instead of reconstructing them for each
message, preserving snapshot provenance, retention decisions and context invalidation. Also bound the complete
background work call with safe durable stopping points. Keep the durable generation barrier and existing epoch
retention; do not abort inside a rollback guard, weaken database durability, increase the query timeout, or relax
the regression oracle. Investigate broader command fairness separately if delay persists after bounded work.
Evidence, source/binary provenance and exact sample counts: `target/worker-timeout-20260906/REPORT.md`.

## Four-message app projection fix (2026-09-06)

The small failure is now localized and fixed in `crates/marmot-app/src/client/sync.rs`. The engine received,
decoded and durably processed the missing message. Live app observation assigned one triggering source ID to
an entire effects batch, including an empty ID for scheduled convergence and send-applied effects. Multiple
messages collided on `UNIQUE app_events.source_message_id_hex`, leaving the live timeline incomplete. Reopen
replayed the durable pending events through a drain path that already used each event's own stable source ID.

The shared observer now uses that per-event identity for message and Welcome events. It also avoids attributing
an unrelated triggering envelope's timestamp to a released buffered message. The restart drain shares the identity
helper. This is an app projection fix; no storage schema, SQLCipher encryption, backlog cap, or epoch policy changes
were made in this investigation. General retry after arbitrary projection failures is still a separate question.

The exact saved seed-7/case-0 public input passes all 435 actions after the fix, with zero expectation/invariant
failures. All four participants have 11 messages at epoch 2, including the four offline messages and subsequent
traffic; Bob retains the complete timeline after reopening. No background storage errors or native crashes were
observed. Before the fix, the audited repeat failed at action 98, additional repairs did not recover the message,
and reopening did. The retained-relay engine companion passes all four incoming payloads at epoch 2.

Three maintained app unit regressions cover scheduled, send-applied and inbound batches, exact source metadata,
and idempotent replay through the drain seam. The scheduled/send tests were red before the fix with the exact
UNIQUE constraint error. Nineteen focused/neighboring app tests pass; release library and debug test clippy pass
with warnings denied. App unit tests require debug plus test-policy-overrides because existing legacy test helpers
are absent in release; public runtime tests use release production policy without that feature.

The maintained small offline canary also passes (84.70 seconds); the exact saved-input audit run completes in
89.60 seconds including extra repair/reopen diagnostics. The large gate still fails (191.60 seconds), now at repair
pass 3 because public `group_members` returns `AccountWorkerResponseTimedOut`. Bob's final snapshot has 270/1,024
messages at epoch 8 versus peers at epoch 22. No background storage errors were captured and close reported no
errors; the process exited with ordinary test failure, not a native crash. The full repair budget and post-success
checks were not reached. This is an availability failure during catch-up, not proof of permanent loss.

`group_members` queues a worker command with a 10-second local response deadline. Scheduled convergence runs
synchronous engine/SQLite work inside that same worker. Long uninterrupted processing is the next hypothesis to
measure; this run does not identify which operation consumed the deadline. Do not raise the deadline or relax the
oracle just to make the test pass. General live replay after arbitrary projection failures is another follow-up.

Temporary diagnostic hooks have been removed; their source, frozen binaries and traces remain under
`target/offline-four-20260906/` with a readable `REPORT.md`. Simulator release clippy, formatting and diff-whitespace
checks also pass. The projection checkpoint captures the public-family expansion, app fix and regressions together. No push, full
fast-ci or full workspace suite has been run for this change. The following sections retain the historical pre-fix results.

## Latest checkpoint and public family expansion (2026-09-06)

The 17-file WIP checkpoint was committed and its GPG signature verified as `77356248`.
The initial uncommitted expansion changed simulator code/tests/docs only: three public seeded companion
families (send/leave, membership re-entry, small offline recovery), public state/payload predicate support, and
implicit single-group selection in the app adapter. Existing engine generators keep their versions and oracles.

Five strict re-entry cases passed across seeds 7, 42 and 17001, including one/two removal and fresh invitation cycles.
The maintained re-entry oracle canary, all nine existing app-adapter tests, new generator/capability tests, existing
shared-generator legality test, focused release clippy and formatting also passed. The inventory grows from 36
compatible cross-route inputs to 90 across four public families; preflight is not a runtime pass.

**New small reproduction:** seed 7 case 0 in `public-app-offline-recovery/v1` failed twice at action 98. Bob reached
the expected epoch after only four offline messages and one profile change, but Carol's third offline message remained
absent after 30 catch-up rounds. This is bounded incomplete public delivery, not proof of permanent loss or cause.

**Separate unresolved oracle/convergence question:** `public-app-send-leave/v1`, seed 7 case 0 exceeded 180 seconds;
a 360-second rerun failed at action 32 after 203.54 seconds. Carol had the expected three members but epoch 4 rather
than the model's epoch 2. Determine whether asynchronous app commits require a different public epoch contract
before calling this a product regression or changing its oracle. The new live canaries are explicit/ignored and
retain successful-recovery assertions; the failing families are not promoted to passing coverage.

No SQLCipher SIGSEGV was seen. The one campaign deadline used intentional SIGKILL. No production SQLCipher fix,
full fast-ci, push or full-workspace validation is claimed. The 1,024-message problem remains open.

Exact source patches/hashes, saved inputs, reports, failures and commands:
`target/public-app-families-20260906/REPORT.md`. Next: localize the four-message publication-to-projection gap,
resolve the send/leave epoch contract, then widen the remaining public catalog/relay faults. The sections below
retain the earlier checkpoint history and validation boundaries.

## What changed

| Files | Change | Evidence and limit |
| --- | --- | --- |
| `crates/cgka-engine/src/message_processor/mod.rs` | After a capacity refusal, yield background convergence between epoch advances. Schedule deferred raw messages immediately when their durable context fingerprint differs from current context. | Four strict saved-input regressions and full engine suite pass. Process-local pacing hint is not durable ownership of refused input. |
| `crates/cgka-engine/tests/deferred_peel_lifecycle.rs` | New-context scheduling regression; update initial deadline expectation; allow the notify-gated restart test enough time to reach its deterministic cancellation point. | All 25 lifecycle tests pass. |
| `crates/cgka-conformance-simulator/src/{client,subject,retained_relay}.rs` | Retained transport gets a redelivery turn before the harness repeatedly drains more convergence after capacity refusal. | Required alongside the engine change for the 1,024-message saved input. This is a harness scheduling change, not proof of production app pacing. |
| `crates/cgka-conformance-simulator/tests/offline_catchup_regression.rs`, `vectors/generated-inputs/offline-catchup-reverse-history-1024.generated-input.json`, `SCENARIOS.md` | Add original 1,024-message input and natural/reverse controls; retain payload multiplicity, exact state, fresh decryptability, and pending-work checks. | All four controls pass with Current profile and encrypted file-backed storage. Include the new JSON fixture in any checkpoint commit. |
| `crates/transport-nostr-adapter/src/sdk_client.rs` | Explicitly deliver fetched event bodies even when SDK IDs-only cache suppresses first-seen notifications. Rotate bounded repair batches so a fully refused prefix cannot starve later IDs. Add real-relay regression. | 80 unit and 42 routing tests pass. Replay cursor is bounded advisory process-local state; it never acknowledges admission or coverage. |
| `crates/marmot-app/src/client/sync.rs` | Run bounded reconciliation during current-window full-history backfill as well as older startup history. | 34 backfill and 9 overflow tests pass. Large public app run still fails. |
| `crates/cgka-conformance-simulator/src/app_runtime.rs` | Retain up to eight public background runtime error messages in observations, and continue reading the event receiver after lag. | Latest release diagnostic builds. Added after the passing fast-ci run; this final diagnostic-only change has not had another fast-ci run. |

## Verified results

Diagnostic root: `target/offline-continuation/` in this checkout. It is ignored by Git. Do not stage the entire target directory or participant databases.

- `engine-regressions-v4.log`: four tests pass, 249.55 seconds. Includes 368 and 1,024 messages, natural and reverse order. Original strict assertions remain.
- `engine-suite-v4-bounded-parallelism.log`: full engine suite, 528 tests pass with `--test-threads=4`.
- `lifecycle-v4.log`: 25 lifecycle tests pass (also included in the full engine suite).
- `adapter-v4.log`: 122 tests pass.
- `app-backfill-v4.log`: 34 tests pass.
- `app-overflow-v4.log`: 9 tests pass.
- `fast-ci-v4.log`: `just fast-ci` passes before the final app-harness error-observation change.
- `app-24-v4/result.json`: small public app control passes through all 16 commit rounds, exact payload/state checks, and recipient restart persistence.
- `app-1024-v4/result.json`: **FAIL**, 835/1,024 messages after 30 repair passes and two recovery restarts. Restart restored substantial message visibility. No native crash.
- `app-1024-v5/result.json`: **FAIL**, 320/1,024 messages after 30 repair passes and three recovery restarts. This repeat had no observed background account errors. Both failed public runs are preserved; variability remains unexplained.

The first full engine-suite attempt under default parallelism failed one test using a hard-coded 10,000-ms convergence timestamp. It passed alone in 0.48 seconds, and the full suite passed with four test threads. Preserve both logs; do not report the first attempt as passing.

## Remaining problem and next investigation

### Worktree reconciliation and cap consolidation

The September 6 reconciliation compared this worktree with `/Volumes/Worktrees/codex/69d9/mdk` and the separate
`mdk-cap-only` checkout. All three share commit `565bbb2f`, so the original committed deferred-generation barrier
and 368-message regression are already present here. The original uncommitted 1,024-message fixture is identical;
its regression differs here only by better failure output. Its app current-window backfill change is identical.

The original engine's unconditional yield-between-epochs experiment was refined here to yield after an observed
capacity refusal, with durable context-readiness scheduling added. The original SDK cache-query early-return
experiment was replaced by explicit ownership of fetched event bodies plus bounded rotating reconciliation batches:
the default SDK database retains IDs, not event bodies. Preserve the old experiment as evidence; do not reintroduce
it blindly as an additional fix. Exact original, cap-only and pre-consolidation patches and source copies are retained
under `target/app-hardening-20260906/{original,cap-only,current-before}/`.

The 2,048-row cap mitigation has now been applied to this worktree. The 16 MiB per-group and 64 MiB account byte limits
are unchanged. This combines it with the earlier WIP engine/SDK/app changes; earlier 512-cap results and separate
cap-only results are historical controls, not results for this combination. There is no separate production SQLCipher
patch to cherry-pick: the corrected orderly teardown is already embodied by the maintained app acceptance tests.

Consolidation checks: the 368/1,024 reversed engine regressions both passed (282.82 seconds), and the 2,048-row
capacity/refusal/retry boundary test passed (3.03 seconds). All six basic public acceptance tests passed again.
Eight existing `marmot-app` real-local-relay tests also passed: founding and confirmed-invite Welcome restart
recovery, persisted recipient inbox routing, own-NIP-65 profile and key-package publication, blocked founding and
existing-group Welcome publication, and the public Welcome-redelivery surface.

The first combined-cap large app execution failed just after reconnect with a generic public runtime operation
error, before its first recovery checkpoint. Its final observation had 15/1,024 messages at the recipient; the full
30-pass recovery budget was not reached. Shutdown was clean, with no native crash. This differs from the earlier
bounded missing-message results and has not been classified as a new production defect. The test now labels
reconnect/repair/catch-up/observation failures, and the app adapter records errors from public group-member and MLS
state reads instead of losing those diagnostics. These additions change test diagnostics only.

The diagnostic repeat failed in 231.52 seconds at repair pass 6: `repair_full_history` completed far enough to enter
the adapter's public member refresh, then `group_members` returned `AccountWorkerResponseTimedOut`. Bob's last
timeline had 127/1,024 messages, epoch 9 versus peers' 22, and six captured
`scheduled convergence failed: storage_backend` errors. This localizes the observed failure to account-worker read
availability during catch-up; it does not identify the underlying storage error or prove permanent message loss.
The 30-pass/restart budget was not completed. Shutdown again reported no errors; no native crash occurred. Both
combined-cap attempts remain preserved, rather than replacing one with the other's more informative result.

The new `cgka-conformance-app-inventory` tool checked 408 generated cases from twelve families at seeds 7, 42 and
17001. Only the 36 public cross-route restart cases passed action preflight unchanged. The other 372 are explicit
coverage gaps, mostly private engine observations plus virtual-time/transport controls. No assertions were deleted
to manufacture app compatibility. Runtime campaign results and the context-labelled large repeat are retained under
`target/app-hardening-20260906/`; source manifests distinguish the initial implementation and diagnostic-only repeat.

### Recommended next work, in sequence

The bounded app-runtime campaign finished with 18 strict passes across seeds 7, 42 and 17001: all twelve restart
boundaries at seed 7, four cases at seed 42, and two at seed 17001. Two further planned seed-17001 repeats were not
run after the 900-second batch budget was reached (a started case was allowed to finish). No executed case timed out
or failed. This is breadth within the public cross-route family, not coverage of the eleven unsupported sampled
families. Final focused release clippy, formatting and diff-whitespace checks passed. No full fast-ci/full crate
suite, remote CI, device test, commit or push was performed for this consolidation. Test groups ran concurrently;
their durations are diagnostic, not performance benchmarks.

1. Review this consolidated checkpoint as bounded recovery mitigations plus test coverage. Preserve the generation
   barrier already in the branch, SDK fetched-body ownership/fairness, current-window backfill, and cap mitigation;
   review the experimental engine scheduling separately. Keep large app recovery open and do not describe this as a
   completed release fix. Original worktree patches are archived; do not discard them while separating changes.
2. Expand public companion families for ordinary send/leave, membership re-entry and small offline histories.
   Reuse the logical workloads but declare public payload/roster/profile/restart assertions explicitly. Use the
   existing public cross-route family as the pattern, keep the engine-private companion intact, and then run a
   bounded seed matrix with saved inputs, strict reports and per-case process deadlines. Perfect virtual-time parity
   is not a prerequisite. The inventory prevents unsupported cases being mislabeled as product failures or passes.
3. Run targeted publication/invite fault matrices using separate sender outbox, recipient inbox and group relays:
   partial publication success, rejection, disconnect before/after acknowledgement, relay-list changes, stale
   discovery/cache, restart with a queued Welcome, and history repair on relays without reconciliation support.
   Require recipient-visible invite/message delivery and durable retry completion, not only sender API success.
   Use a concrete reported client/version/action sequence to choose the first fault combination, and retain a
   minimized reproduction before making another production change.

### Public acceptance checkpoint (September 6)

The large defect is now pinned by the maintained, explicitly runnable
`public_app_1024_message_backlog_recovers_completely` test in
`crates/cgka-conformance-simulator/tests/app_runtime_journeys.rs`. It requires full recovery rather than accepting
the previously observed missing-message count. It is marked ignored as a known unresolved slow regression; skipped
is not passed. The default six basic public journeys are ordinary tests. Exact commands and coverage limits are in
`crates/cgka-conformance-simulator/APP_PATH_COVERAGE.md`.

The six basics passed serially in release mode with debug assertions disabled and no policy-override features:
creation/bidirectional messaging; name/description updates; late join; removal; restart followed by fresh traffic;
and a 12-message offline backlog with a profile update. Each checks exact visible payload multiplicity, shared public
state/roster size, fresh messaging, and recipient restart persistence. Total test time: 107.86 seconds. Focused
release clippy for the new test binary passed with warnings denied.

The explicit maintained large regression **failed**, as a real assertion failure, in 361.79 seconds: Bob recovered
826/1,024 original messages (198 missing, no unexpected or duplicate payloads), at epoch 17 versus epoch 22 for the
three fully caught-up peers. All 30 repair passes and two recovery restarts ran. Fresh post-recovery messaging and
post-success persistence checks were not reached. Close operations reported no errors; the test process exited with
ordinary Rust test-failure status 101, not a native crash.

A newly preserved public diagnostic is repeated `scheduled convergence failed: storage_backend` while Bob's
recovery stalled. The runtime emits this from `crates/marmot-app/src/runtime/account_worker.rs`; `error.rs` maps
`StorageError::Backend(_)` to the generic `storage_backend` tag. That tag does not identify the underlying storage
failure or establish a SQLCipher defect. Reopening improved visibility from 511 to 821 and then 826 messages.
The new result and observations are in `target/app-path-20260906/large-summary.json` and its `large/` subdirectory.
Do not conflate this broader-WIP result with the earlier 320-message cap-only result.

These runs use the current broader WIP implementation, **not** the isolated cap-only checkout. They do not establish
that the unchanged baseline passes these same acceptance tests. No additional production behavior was changed for
this acceptance-test work. All previous production-source checkpoint hashes were verified unchanged.

Evidence is retained under `target/app-path-20260906/`: source revision and file hashes, source-only patch and file
copies, exact commands, build/test logs and private public-observation checkpoints. Participant databases are closed
and removed by the maintained tests. The previous private diagnostic databases remain preserved in their original
artifact directories.

The separate cap-only experiment is retained in `target/cap-only-2048/REPORT.md` and
`/Volumes/Worktrees/codex/1f8b/mdk-cap-only` on `codex/offline-catchup-cap-only`. Its only production change is the
512-to-2,048 raw-row cap. Both reversed engine cases passed; the public diagnostic still ended at 320/1,024 messages
after 30 repair passes and two reopens. It exited normally with failure status; no native SQLCipher crash occurred.

### Unresolved diagnosis

The public app path is not reliably recovering the full workload. State convergence and a successful catch-up command do not establish complete payload delivery.

Inspection of a copy of the v4 synthetic recipient database found 177 `PeelDeferred` rows, one epoch-17 `Created` row, and 16 pending application events. This establishes both remaining decoding work and decoded events awaiting app consumption; it does not establish the root cause. The temporary inspection test was removed. The copied database and aggregate report remain in the private diagnostic root.

Next: determine why convergence/application projection stops until reopen, using the retained input and public runtime observations. Check scheduler readiness, durable generation completion, and event delivery/acknowledgement. Do not weaken the payload oracle, raise queue/key-retention limits, or claim that the passing engine harness proves the app path.

## SQLCipher finding

The previous native crash matches an unsafe diagnostic teardown: one thread calls `process::exit` while SQLCipher is still writing a WAL. The pinned SQLCipher exit handler releases global allocator/provider state. A standalone probe widened this exit race and reproduced the matching `sqlite3Codec -> walWriteOneFrame -> pagerWalFrames` stack in 3/3 unsafe-exit trials; 10/10 stop-and-join trials exited cleanly.

The private app driver now returns `ExitCode` after dropping its Tokio runtime and joining worker threads. No production database-using `process::exit` site was found. **This is a diagnostic teardown correction, not a general SQLCipher production fix.** The probe source, result JSON, and crash report are under the private diagnostic root.

## Committing this checkpoint

A single WIP checkpoint is reasonable if the goal is to preserve progress. Suggested title: `WIP: continue offline catch-up recovery investigation`.

Include the eleven modified/new code, scenario, and fixture files listed above plus this handoff. Keep the implementation and matching harness tests together. The SDK materialization/fairness changes can be reviewed separately later, but they have not independently made the public app scenario pass. Do not publish a completed-fix PR from this state.

The subsequent acceptance-test work also adds `tests/app_runtime_journeys.rs`, `APP_PATH_COVERAGE.md`, and scenario
and test-map documentation in the simulator crate. It can be reviewed separately from the production experiments,
but requires the saved 1,024-message fixture already listed above. Preserve both the positive basic tests and the
explicit unresolved large gate; do not stage a partial test addition that drops the known failure.

Do not commit diagnostic databases, audit logs, generated keys, native crash files, copied build outputs, or the temporary inspection root. Source-only patches are exported under the diagnostic root as an additional backup. Sign any commit before pushing, per repository rules.

## Commands used

Set `CARGO_BUILD_JOBS=4` and `CARGO_TARGET_DIR="$PWD/target/offline-build"`.

```sh
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false cargo test --release --locked -p cgka-conformance-simulator --test offline_catchup_regression
cargo test --locked -p cgka-engine --features test-policy-overrides -- --test-threads=4
cargo test --locked -p transport-nostr-adapter --features sdk
cargo test --locked -p marmot-app --features test-policy-overrides --lib backfill
cargo test --locked -p marmot-app --features test-policy-overrides --lib overflow
just fast-ci
```

The engine compatibility suite uses debug mode because legacy fixture constructors are debug-gated. The standalone public app driver uses a release build, default production policy, real local Nostr relay, and encrypted file-backed participant roots. Its native relay order is not forced reverse. There has been no device validation.
