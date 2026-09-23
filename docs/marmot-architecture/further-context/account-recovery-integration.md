# Recovery owner integration — implementation ledger

Resumed 2026-09-23. This is work in progress, not a completion claim.
The issue #1946 acceptance matrix and `account-recovery-ownership.md` remain
normative. The original checkpoint/report and replacement-test CSV are preserved.

## Provenance

- Preserved code: `13395cc10fd6941d2a2f72c0398bfc501b99fc25`;
  report/branch: `d8652d185d9fae0626ca199c944bce7ae0a4a8fb`.
- Design #1982: `0092219b974139a98bc059f3d7380668154ccbe1`.
- Ledger #1983: `13cb09a4` (independent marker retirement regression fixed).
- Completion #1987: `4fded1e91fdbb59286cfa00b2ac3018bee97d2b5`.
- Subscription fencing #1985: `73d7ccf1bbe78dd11d705539aad463724de1556f`.
- Reconciled owner baseline: `eb89ea7f7a3c072535803533e2f0af5897e24cb1`.

The CI failure on both storage PRs was reproduced. The repaired regression follows
both tokens through retirement and encrypted reopen, then duplicate observations
and genuinely increased loss. Retiring token 11 deliberately returns false while
token 12 is outstanding. No production retirement guarantee was relaxed.

## Required completion matrix

| Acceptance boundary | Current remaining implementation / proof | Exit evidence |
| --- | --- | --- |
| All history triggers share one owner | Verify startup, receive, maintenance, convergence and explicit paths together; remove remaining internal legacy retirement calls | One interleaved worker fixture with exact activation counts; source replacement inventory |
| Durable pacing and local work | Verify duplicate joins, cap, productive admission reset, clock/reopen and eligible local convergence under cooldown | Controlled-clock owner tests and composed worker counters |
| Qualified independent completion | Adapt truthful endpoint outcomes; complete runtime admission-to-checkpoint path; preserve unknown/incomplete outcomes | All-endpoint versus known-copy/maintenance matrix; stale route/loss/scope rejection; qualified synthetic backend fixture distinguished from production capability |
| Live loss handoff | Reconcile queue-only off-worker writer, continuing count growth, worker notification-lag recording and external acknowledgment barrier | Writer/ack races, failed persistence compensation, zero-count incident, reopened pending loss |
| Cancellation and API behavior | Detach dropped futures; preserve admitted prefix, durable independent demand, urgency cleanup and other-account service | Before activation/after admission/drop/reopen tests; public worker/API and cursor suites |
| Maintenance timing | Fix baseline restoration failure without resetting grace or quiet deadlines | Default and override-policy restore tests plus stale EOSE rejection |
| Evidence policy and escalation | Replace dead replay-completion detector tests/helpers; preserve authenticated evidence, distinct local observations, blocked/unknown status | Reorg/refusal/clock/anti-spoofing and mixed evidence matrix through actual owner |
| Bounded state/investigation | Bound retained evidence and completed known-event rows with live grant lifetime protection; retain unresolved older debt after budget exhaustion | Repeated generation/route/caller/reopen fixtures; no timer-only rearm |
| Same-schema conservative mode | One obligation per grant with the same executor/ledger/pacing/receipts/completion | Populated normal→conservative→normal handoff, partial admission, pending acknowledgment and reopen |
| Combined readiness | Tests and docs on the complete dependency stack | Affected-crate suites (including policy overrides), fast-ci, policy decision/binding gates, test-replacement audit and draft PR review |

## Sequencing and landing

Implementation checkpoints stay local until their stated checks pass. No new
standalone storage layer is planned. Storage changes must serve a concrete runtime
integration requirement. No SDK change, connection allocation, or #1947 scheduling
or nonblocking acquisition work belongs here.

#1985 can land independently. #1983 and #1987 remain drafts and must not deploy
before the owner integration is ready to land with them. Proposed coordinated order:
#1982 design, #1985 fencing, #1983 ledger, #1987 completion, then owner integration,
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
