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
