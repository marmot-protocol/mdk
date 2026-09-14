# Public app-path acceptance coverage

## Large offline catch-up regression

`public_app_1024_message_backlog_recovers_completely` in
[`tests/app_runtime_journeys.rs`](tests/app_runtime_journeys.rs) is the original maintained public regression.
`public_app_1024_message_backlog_with_extra_epochs_recovers_completely` adds two public profile updates while
the recipient is offline, before the same workload. This variant reproduced retry-budget release followed by
blocked app redelivery in #1721; it requires the same complete recovery contract. Each run records its extra
updates in `prelude.json`, alongside the unchanged expanded `backlog-input.json`.
It requires all 1,024 original payloads exactly once, shared public group state, fresh messages from every member,
and complete recipient history after restart. Reaching the repair budget is a failure, never success.

The engine and app tests share `tests/support/offline_catchup.rs`, a compact reconstruction of the checkpoint
inputs with hashes over every action and expected outcome. Before removing the expanded JSON, parsed equality
was verified against both original fixtures. The originals remain in checkpoint `9282a643`; the large public
journey writes the expanded `backlog-input.json` into each run's artifacts. A changed generator fails the hash
check before execution. The recorded source hash now covers the compact serialized input, rather than the old
pretty-printed file bytes.

This is a public workload companion to the pinned 1,024-message engine input. It preserves all original sends and
16 profile-update rounds, with a founding recipient offline throughout. The real local Nostr relay chooses query
order; this does **not** reproduce the engine fixture's forced reverse delivery. Initial group creation uses public
app acknowledgement semantics. Private MLS assertions and simulated relay steps are not presented as app coverage.

The reproduction repeats explicit full-history repairs with two seconds between passes, allowing up to three recipient
reopens after six unchanged transitions. A 900-second watchdog bounds the whole journey; there is no separate pass-count
cutoff because production time-bounded slices guarantee no minimum message throughput per call. Success additionally checks
every participant's exact payload multiset, then fresh bidirectional messaging and recipient restart persistence.
These latter checks strengthen the earlier private diagnostic driver and run only after full recovery.

The test remains ignored in ordinary crate runs because it is slow. The dedicated **Public app 1024-message
recovery** job in `.github/workflows/ci.yml` builds once, then selects each journey with `--exact` in its own timed
step, in release mode without test-policy overrides. The second runs even if the first fails. The job
uses the same conformance path classifier, and participates in **Required CI**. It uploads source provenance,
expanded synthetic input and public observations, excluding participant databases and keys. It asserts successful
recovery, not a particular failure count. A run that skips this job is not recovery evidence.

Set `MDK_BACKLOG_TRACE=1` to include aggregate engine preparation, retry-slice and transport-release diagnostics
on stderr. The required recovery job enables this to distinguish slow preparation with zero attempts from
retry progress or resource release. Preparation and per-slice traces use debug level, enabled by this test flag,
so idle sweeps do not add production INFO traffic. These traces contain counts, durations and fixed outcome labels; participant
databases and keys remain excluded from uploaded evidence.

Recovery artifacts have fixed filenames: `recovery-progress.json` retains compact counts and the last completed pass,
and `recovery-checkpoint.json` retains the latest tenth-pass or successful full observation. `terminal.json` captures
the final observation when available. Files are replaced rather than accumulated across passes. Watchdog failures
include the active phase, current/last-completed pass, last observed counts and completed restart count.

On September 6, the worker-responsiveness fix passed this unchanged recovery contract twice. Background engine
advance now shares a 64-row allowance and a cooperative 500-ms budget across sweeps; historical peel contexts
are materialized once per sweep and released afterward. All 1,024 original payloads recovered, all four participants
agreed at epoch 22, fresh messaging passed, and the recipient retained the complete timeline after restart.
Both runs closed cleanly. The small offline canary and all six basic public journeys also passed. Evidence and
executable provenance: `target/background-recovery-20260906/`. These are local production-policy runs over a
loopback relay and encrypted databases, not device or broad real-relay campaign validation. The budget is
cooperative between complete operations; one synchronous operation can exceed it.

The cap-only experiment on base `565bbb2f36c5f8a7d4715c225f0067358de7aca7`, with the raw-row cap changed from
512 to 2,048, passed the 368/1,024 reversed engine regressions but recovered only 320/1,024 messages in the public
app run. This was bounded incomplete recovery, not proof of permanent loss. The broader WIP checkout also had
incomplete public runs. Investigation history and checkpoint provenance are retained in
[PR #1711](https://github.com/marmot-protocol/mdk/pull/1711). The earlier native SQLCipher crash occurred during
unsafe diagnostic process exit while workers were writing. Maintained tests stop and join runtimes before asserting;
no general production SQLCipher fix is claimed.

## First basic public journeys

These tests use `AppRuntimeHarness`, which invokes `MarmotAppRuntime` over a real loopback Nostr relay and separate
encrypted participant databases. No engine-private operations or direct database repairs are used. Each test requires
exact visible payload multiplicity, shared public group state and roster size, post-operation messaging, and
recipient restart persistence. A late joiner is not required to recover pre-admission history; a removed member must
not see post-removal messages.

| Test suffix | Public contract |
| --- | --- |
| `01_bidirectional_messaging` | Create/join, send from both members, retain messages after reopen |
| `02_profile_update_and_messaging` | Update name and description, agree on profile, continue messaging |
| `03_late_join_and_messaging` | Invite a third member after initial traffic; exchange messages after admission |
| `04_removal_and_remaining_member_messaging` | Remove the third member; remaining members exchange messages |
| `05_restart_and_continue_messaging` | Reopen the recipient before fresh traffic, then reopen again |
| `06_small_offline_backlog` | Recover 12 offline messages and a profile update, then exchange fresh traffic |

These are explicit public acceptance companions, not evidence that every existing generated scenario has been
replayed through the app. They begin the coverage expansion. Additional generated coverage is described below. Remaining work includes self-update,
multiple groups, duplicate/reordered retained history, partitions, competing commits, and the broader generated
catalog. Capability-preflight failures must stay visible as coverage gaps; do not discard incompatible assertions
and call the original scenario covered.

## Interaction journeys

`tests/app_runtime_interaction_journeys.rs` uses the same harness and evidence layout and covers interactions the
serialized generated families cannot express. `AppRuntimeHarness::race_mutations` issues several public commands from
different participants at the same instant, so each device commits against its own current epoch; a rejected command
may already have reached the relay, so only accepted publications are correlated strictly in that case.
`AppRuntimeHarness::run_due_maintenance` drives the maintenance sweep instead of the worker's fifteen-second timer.

| Test suffix | Public contract |
| --- | --- |
| `07_two_groups_stay_isolated` | Work and pair groups on one device; the second invite of Bob needs a fresh KeyPackage; a non-member has no projection; a removal and a reopen leave the other group's exact history untouched |
| `08_concurrent_admin_profile_edits_are_never_lost` | Two admins save name and description at the same instant; members settle on one state in which both edits are present, because the losing commit's edit is re-issued when the winner left its field untouched (#1734; measured on the settled projection, not on the commands' return values); fresh traffic and reopen persistence hold; dropped accepted edits are recorded |
| `09_concurrent_invite_and_rename_converge` | An invite races a rename; founders settle with at least one edit present; an invitee the founders admitted sends and receives; an excluded invitee's device state is recorded as `no_projection` or `stranded` |
| `09_strict_concurrent_invite_and_rename_are_never_lost` (opt-in) | Choose the larger-identity inviter so the invitation loses; require automatic fresh invitation, explicit recipient rejoin, offer and acceptance persistence across reopen, canonical roster/name, and fresh bidirectional messaging |
| `10_member_removed_while_offline_learns_removal` | A closed device is removed; on reconnect it learns the removal from relay history, never decrypts post-removal traffic, keeps its exact pre-removal history across reopen, and its sends are refused as `group_removed` |
| `11_manual_self_update_advances_every_member` (ignored with production timing) | A manual SelfUpdate advances every member; ordinary test-policy builds zero maintenance windows, while production timing requires an explicit run |
| `12_leave_with_several_remaining_members_converges` | David leaves a four-member group; within three minutes the survivors apply it, settle, exchange decryptable traffic in every direction, and persist across reopen; the leaver keeps exactly its pre-departure history and nothing it sends afterwards reaches them |
| `12_strict_leave_is_applied_by_survivors_promptly` | Ordinary 30-second regression: the worker arms the pending SelfRemove deadline and survivors promptly apply a voluntary departure |

On 2026-09-06 the four default race, group, and removal journeys passed locally in debug mode in about 80 seconds
total, the default leave journey passed in about two minutes, and the strict variants failed only on the documented
contracts below. The default concurrent journeys accept either race outcome. They fail when members do not settle, when neither edit
is present in the settled state, or when fresh traffic or reopen persistence breaks. They do not prove that a same-epoch
fork occurred on a given run; real socket timing is not seed-controlled. The three gaps below are tracked in
[#1734](https://github.com/marmot-protocol/mdk/issues/1734), [#1735](https://github.com/marmot-protocol/mdk/issues/1735),
and [#1736](https://github.com/marmot-protocol/mdk/issues/1736). The profile-edit never-lost contract is now the default
journey 08. The strict 30-second departure regression also runs ordinarily. Strict journey 09 is an opt-in
real-socket diagnostic: it requires an actual recipient rejoin, and a run that misses the intended fork is
inconclusive evidence. Required coverage of invitation recovery is the deterministic engine regression.

Run the default journeys the way the conformance CI job does, or serially with retained evidence:

```sh
cargo nextest run -p cgka-conformance-simulator --locked --profile ci --test app_runtime_interaction_journeys
```

```sh
MDK_APP_JOURNEY_ARTIFACTS="$PWD/target/app-interaction-evidence" \
cargo test --release --locked -p cgka-conformance-simulator --test app_runtime_interaction_journeys -- \
  --test-threads=1 --nocapture
```

Add `--include-ignored` to also run the strict stranded-invitee regression and, against production maintenance timing, the manual
self-update journey; `just simulator-fast-maintenance` runs that journey with zeroed maintenance windows instead. Under nextest the
`app-runtime-journeys` test group in `.config/nextest.toml` runs at most two public journeys at a time, because each
one starts a local relay and several SQLCipher runtimes and then waits on real settlement windows.

### Fixed: a losing admin edit is re-issued or reported, never silently dropped (#1734)

The first run of the strict profile-edit journey (2026-09-06) showed both `update_group_profile` calls returning
success, every member settling at the next epoch with Bob's description, and Alice's rename absent everywhere, with
no error event on any device. Until #1734 that matched the account layer: when convergence parked an own commit,
only a `SelfUpdate` evolution re-armed its maintenance obligation; `Invite`, `RemoveMembers`, `UpdateGroupData`, and
`UpdateAppComponents` evolutions were marked superseded and their intent was neither re-issued nor reported. The
engine now retains the intent behind every own group evolution together with the authoring baseline
(`cgka_own_commit_intents`, kept until the group has advanced past the rewind horizon), and when a pass withdraws
that commit it decides per kind: a profile or component edit is re-queued when the winning branch left the edited
field untouched and reported as a conflict when it changed it; a removal is re-queued for targets that are still
members; an invite retains durable recovery material while the app obtains fresh KeyPackages and reissues it (#1735). Re-issue is bounded to
two attempts. Terminal and reissued decisions reach the host as `MarmotAppEvent::GroupChangeSuperseded { kind, outcome, reason }`
(UniFFI and C ABI mirrors), and `run_due_maintenance` re-derives a missed announcement from the stored disposition.
Journey 08 now requires both edits in the settled state; `crates/marmot-app/tests/relay_runtime.rs` races two admins
on a real relay for the re-issued and the conflict outcome, and `crates/cgka-engine/tests/distributed_convergence.rs`
pins the field rule, the bounded re-issue, and the horizon garbage collection.

### Fixed scheduling gap: wake the runtime for a peer's voluntary leave (#1736)

The engine schedules a peer's SelfRemove auto-commit 10 to 50 ms after the proposal. Previously, its runtime deadline
query only exposed convergence passes. A processed proposal could therefore read as idle and lose its timer wakeup.
On 2026-09-06 instrumented runs showed survivors unchanged for 50 to 80 seconds until unrelated post-join rotations
carried the removal. The 2026-09-07 original-master canary spent 97 seconds at its departure checkpoint, and the
strict public test reproduced survivors failing to apply the departure within 30 seconds. The eventual campaign
contract still passed, demonstrating why the stricter regression is necessary.

`scheduled_self_remove_auto_commit_delay_ms` exposes the earliest scheduled SelfRemove deadline through the engine,
session and account runtime. The app uses this deadline only after active convergence passes, unresolved inputs,
and durable outbound fanout retries have had priority. A due leave cannot shorten a collecting pass or spin while
publication is in backoff. Non-stable publication states retain their existing handling. The separate deadline API
and preservation of voluntary `Left` status are adapted from #1743; rejoining resets that attribution so a later
eviction still reports `Removed`. The
engine regression `selfremove_runtime_deadline_survives_encrypted_reopen_and_clears_after_publish` failed before
the correction and passes through encrypted-file close/reopen, exact deadline boundaries and publication cleanup.
With the fixed production-policy binary, the strict public journey applied departure in four seconds and passed;
the original saved canary input also passed. The strict 30-second journey now runs in the ordinary suite. No manual
`retry_group_convergence` is involved. Evidence is under `target/app-launch-20260907/`.

The invite-versus-rename race decides differently from run to run (#1735). When the invite won, the rename was dropped and
the invitee joined normally. When the rename won (strict run, same day), `invite_members` had still returned
success, the founders settled at the next epoch with three members and the new name, and the invitee's device had
accepted the Welcome from the parked branch: it reported itself a full member at the same epoch number with four
members and the old name, with no pending confirmation and no error event. That device cannot decrypt the real
group's traffic and its own sends are undecryptable to the members. This is the stale-Welcome incident archetype
reaching the public app with no repair; the engine family `membership-reentry/v1` covers the shape only after an
explicit remove and fresh re-invite. The default journey records the invitee's view in `after-race.json` whenever
the founders' settled roster excludes it.

## Running and preserving evidence

The later consolidation applies the 2,048-row mitigation to the broader WIP checkout. Evidence for this combination
is under `target/app-hardening-20260906/`; the earlier `target/app-path-20260906/` results below used the 512-row cap.
The original and cap-only worktrees were preserved; PR #1711 records their consolidation.

### Inventory existing generated families before expanding execution

`cgka-conformance-app-inventory` checks the actual app adapter's action capabilities against a bounded selection
from the twelve original families and six public journey families. It defaults to seeds 7, 42 and 17001; explicit seed arguments replace them.
It saves unchanged generated inputs only for action-compatible cases and records every rejected case with its missing
capabilities. This is preflight coverage, not a test pass: each selected case must still pass its strict runtime oracle.

```sh
cargo run --release --locked -p cgka-conformance-simulator --bin cgka-conformance-app-inventory -- \
  target/app-inventory-run-1 7 42 17001 --vectors crates/cgka-conformance-simulator/vectors
```

The optional `--vectors DIR` recursively inventories fixture and saved-generated-input JSON under `fixed_vectors`,
recording input kinds, relative filenames, source hashes, compiler errors, required-capability gaps and whether each
fixture has an exact expected trace. Catalog manifests, byte fixtures and schemas are listed separately as
`non_scenario_documents`; they are not engine scenario failures.
Those rows are port-planning evidence only: the original fixture and its oracle are unchanged and unexecuted.
In particular, an engine receive-event trace can differ from the app's persisted local-and-remote timeline even
when every action passes capability preflight. An app command that already published also cannot satisfy an
engine-only request to roll that publication back; capability matching alone does not establish semantic compatibility.

Replay a saved compatible input with `cgka-conformance-simulator-report --generated-input INPUT --adapter app-runtime
--storage file --strict-oracle --out FRESH_DIRECTORY`. Preserve the input, execution adapter and report together.
Start with one canary per compatible family, then expand seeds and case indices for passing families. Distinguish
unsupported actions, incomplete oracle coverage, environment/setup failures and semantic failures. Do not rewrite
the inputs to remove private engine assertions; those cases remain explicit gaps until a deliberate public companion
exists. Cross-route restart cases already have such a companion family.

The first inventory contains 408 cases at seeds 7, 42 and 17001. Thirty-six pass action preflight, all from
`cross-route-restart-permutations/v1`; 372 require unsupported controls or observations. All other sampled families
require exact engine observations, often alongside virtual time, private transport faults, or internal progress
checks. This is a coverage gap, not 372 failed product executions. The inventory is bounded by the case counts in the
tool; it is not an exhaustive enumeration of every arm in every family.

### Maintained acceptance tests

Historical result, before the recovery fix: the first local release execution on the broader WIP checkout passed all six basic tests in 107.86 seconds. The
explicit large test failed in 361.79 seconds: 826/1,024 messages, 198 missing, recipient epoch 17 versus peers' 22,
after 30 repair passes and two recovery restarts. There were no unexpected/duplicate messages and no native crash.
Repeated public `scheduled convergence failed: storage_backend` errors are recorded for later investigation; their
underlying cause is not established. Post-success fresh messaging and persistence checks were not reached.
This is evidence for the source snapshot in `target/app-path-20260906/source.json`, not a guarantee for other
revisions or all relay schedules. The prior cap-only run and this broader WIP run are different implementations.

From the repository root, run the basic tests serially:

```sh
MDK_APP_JOURNEY_ARTIFACTS="$PWD/target/app-path-evidence" \
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false \
cargo test --release --locked -p cgka-conformance-simulator --test app_runtime_journeys -- \
  --test-threads=1 --nocapture
```

Run the large regression explicitly:

```sh
MDK_APP_JOURNEY_ARTIFACTS="$PWD/target/app-path-evidence" \
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false \
cargo test --release --locked -p cgka-conformance-simulator --test app_runtime_journeys \
  public_app_1024_message_backlog -- --ignored --test-threads=1 --nocapture
```

Release mode without policy-override features is the production-policy verification command. Workspace debug or
feature-unified CI runs are supplementary evidence. The six basic tests are ordinary tests, included by the existing
simulator smoke filter. The `Simulator Nightly` workflow runs both ignored 1,024-message recovery variants
on master daily at 03:17 UTC, with production policy and retained JSON evidence. They do not block each PR;
the smaller recovery journeys and strict regressions remain in PR CI. To run just the large recovery lane
on demand, dispatch `simulator-nightly.yml` with `recovery_only=true` (and select the desired branch).
These statements describe test selection; inspect the job at the revision under review for its observed result.

Each test writes a fresh owner-only subdirectory containing input metadata, public checkpoint observations and a
terminal result. The large input is pinned by the source fixture SHA-256. Preserve the source revision plus dirty
patch/new-file hashes and exact command alongside results when testing WIP. Never commit runtime databases or
private observations. Failures retain their artifact directory even when the environment variable is unset.
Participant databases are closed and removed normally; this maintained test does not leak runtimes or retain secret
database snapshots. All runtime shutdown work happens before the final test assertion; there is no `process::exit`.

The large public assertion passes at the acceptance checkpoint recorded below. Historical incomplete runs above
explain the regression's provenance; they are not the current acceptance status. Smaller cases establish only their
own contracts. Every subsequent revision must pass the dedicated large recovery job.


## Seeded public companion families

The public send/leave, membership re-entry, admin handoff and small offline recovery families are documented in
[SCENARIOS.md](SCENARIOS.md#public-app-journey-families). Each input owns its public expectations; no engine
assertions are stripped during replay. `Exactly` and bounded `Eventually` predicates now read public app epoch,
member count and visible payload counts. Generator version 4 also checks exact expected public roster/admin/profile
state jointly across online members, agreement on epoch and a logical-mutation epoch lower bound. It permits additional
automatic-maintenance epochs. Exact engine state and private pending work still fail capability preflight;
virtual-time `Within`/`Never` assertions remain unsupported. `Eventually` bounds tick rounds, not wall time; the
campaign child deadline separately bounds a stuck runtime operation.

Run the ordinary generator/capability checks, then the explicit real-socket canaries:

```sh
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false cargo test --release --locked -p cgka-conformance-simulator \
  --test public_app_families -- --test-threads=1
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false cargo test --release --locked -p cgka-conformance-simulator \
  --test public_app_families -- --ignored --test-threads=1
```

For broader execution, build the campaign binary, run one file-backed case per family as a canary, and then widen
passing families to six cases at seeds 7, 42 and 17001. Use a fresh output directory for each invocation:

```sh
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false cargo run --release --locked -p cgka-conformance-simulator \
  --bin cgka-conformance-campaign -- --family public-app-offline-recovery/v1 --seed 42 --cases 6 \
  --storage file --case-timeout-secs 360 --out target/public-offline-seed42-attempt1
```

The input preserves the logical workload, assertions, family version and seed. It does not preserve cryptographic
randomness or socket scheduling. The separate 1,024-message regression remains its own required gate.


### First generated execution results (2026-09-06, before recovery fixes)

Five isolated membership re-entry cases passed at seeds 7, 42 and 17001 (case 0 at seed 7; cases 0/1 at the other
seeds). The maintained re-entry oracle mutation canary and all nine existing app-adapter tests passed. The updated
inventory has 462 sampled cases: 90 action-compatible across four public families and 372 capability gaps.

The four-message offline case (seed 7, case 0) failed twice at payload assertion 98: Bob reached the expected epoch
but lacked Carol's third offline message after 30 catch-up rounds. The send/leave canary hit a 180-second deadline;
a longer rerun failed on Carol's epoch 4 versus modeled epoch 2 with the correct three-member roster. The latter
needs an oracle-versus-runtime investigation before calling it a product regression. Neither failing family is
promoted to passing coverage; the explicit canaries assert success and remain red when those outcomes occur.

Source provenance, exact inputs, commands, reports and failure capsules are under
`target/public-app-families-20260906/`. Its `REPORT.md` separates initial harness failures, repeated delivery failures,
oracle uncertainty and test passes. No full CI or production SQLCipher fix is claimed.

### Four-message projection regression follow-up (2026-09-06, before worker-budget fix)

The saved offline seed-7/case-0 input now passes all 435 actions with zero expectation/invariant failures after
an app projection fix. Every participant has all 11 messages at epoch 2; Bob retains them after reopen. The engine
had already decoded the previously missing message. Live effects observation reused one source ID for a batch,
causing a UNIQUE source-message constraint failure. Each message now projects with its own durable event source.
The unit regressions cover scheduled convergence, send-applied effects, inbound effects, and restart replay.
The original failure and post-fix public observations are preserved in `target/offline-four-20260906/REPORT.md`.
The separate send/leave epoch mismatch remains uninvestigated; this does not promote that family to passing coverage.

Historical result at checkpoint `775e6459`, before the bounded background recovery fix: the small offline
canary passed (84.70 seconds), but the 1,024-message regression was red:
a group-members query hits `AccountWorkerResponseTimedOut` during repair pass 3; the final recipient snapshot is
270/1,024 messages at epoch 8 versus peers at epoch 22. No background storage errors were captured, and teardown
reported no errors. The 191.60-second run exited as an ordinary test failure; it did not exhaust the full recovery
budget or reach fresh-message/persistence checks.

**Historical large-backlog acceptance at PR #1711:** passing at `fe395e8c`. The bounded background recovery fix
resolved this worker timeout. The post-cleanup run passed all seven public journeys (330.50 seconds), including
all 1,024 original messages, fresh traffic and recipient persistence after restart. The release-policy commands are maintained above; PR #1711 records local artifact provenance. Full GitHub CI
subsequently passed at `be004e3d`, before the dedicated large public recovery job was introduced; that CI result
must not be represented as execution of the newly added job.

### Subsequent recovery investigation (2026-09-07)

The dedicated Linux job exposed intermittent failures after that checkpoint. Keep the original 1,024-message
journey and its extra-epoch companion as required regressions, including exact message sets, fresh traffic and
reopen persistence. A successful earlier run does not establish that every recovery path is correct.

The investigation separated several causes:

- Released raw inputs must retire their transport receipts and durably re-arm replay. The SQLCipher release
  journal bridges that engine/app boundary across failures and reopen; its acknowledgement also retains a
  retry obligation if loading the newly armed work fails. Historical pre-journal losses require separate repair
  ([#1724](https://github.com/marmot-protocol/mdk/issues/1724)).
- Queued outbound work incorrectly selected the four-row foreground preflight from background convergence.
  Background recovery must retain its 64-row allowance and generation barrier even when an outbound intent is
  waiting. A deterministic queued-output regression distinguishes this from foreground send latency limits.
- Slow preparation can consume the cooperative slice budget before an attempt. A bounded minimum-progress
  regression covers that case. However, the instrumented Linux plateau had fast preparation and repeated
  four-row slices; it is not evidence that slow preparation caused that plateau.
- A chat send can publish older queued work in the same engine pass. The harness must correlate its own
  message through the public timeline's transport identity, rather than count every relay publication in the
  interval. Unrelated publications remain on the relay and are excluded only from that action's fault selectors.

Repeated effect observation refreshes local `received_at`; projection replay tests compare stable identities,
insertion order and all other message fields across that timestamp change. The large-recovery journeys have not
reproduced a native SQLCipher crash. A separate concurrent storage-close test exited with SIGSEGV after a failed
assertion in Linux CI; without a native trace, its origin is unproven. Keep that evidence separate from ordinary
recovery assertion failures and worker response timeouts.


### Recovery checkpoint and next public coverage slice (2026-09-06)

The later worker-budget fix and deferred-input barrier resolved the large public regression at checkpoint
`fe395e8c` (PR #1711). Its validation ran all seven app journeys, including the 1,024-message case with complete
delivery to all four participants, fresh messages and reopen persistence. The compact fixture preserves the original
workload digest. Evidence is under `target/fixture-cleanup-20260906/`; earlier failures above are historical results.

The next slice adds `public-app-admin-handoff/v1` and advances the public journey generator to version 3.
Application actions and payloads retain their original meaning; checkpoints now assert public semantic state instead
of predicting an exact epoch number. Existing saved version-1 inputs retain their original assertions on replay.
Version 3 includes the parent's send-checkpoint optimization (full history is still checked at restart, reconnect
and completion). Its distinct version avoids reusing the parent's version-2 generator identity.
Production code and engine-private oracles are unchanged by this stacked slice.
It covers one/two grant-edit-revoke cycles, reopen before delegated editing or after revocation, and continued
messaging by the revoked administrator. Its explicit strict canary is:

```sh
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false cargo test --release --locked -p cgka-conformance-simulator \
  --test public_app_families public_admin_handoff_strict_canary -- --ignored --exact
```

The default contract tests include this family in replay, seed variation, prefix and capability checks. The socket
canary also rejects a mutated terminal admin set, in addition to missing/duplicate payloads and wrong profile or
membership count. Broader executed results and the preserved send/leave investigation are recorded under
`target/public-app-slice2-20260906/`.

The expanded version-1 runs exposed exact-epoch assertion failures in longer offline histories and repeated admin
cycles as well as send/leave. The semantic checkpoints check the intended public state jointly before later traffic. The original
send/leave case now waits until all three survivors agree at epoch 4, then verifies the profile change and complete
delivery at epoch 5. It also checks the departed member receives no later messages. Saved version-1 failures remain
available with their original contracts.

Before integrating the parent PR review fixes, the version-2 isolated full-app matrix at `392969bc`
passed **15/15** (these saved inputs retain their original contracts):

| Family | Seed | Case indices | Result |
| --- | --- | --- | --- |
| Admin handoff | 17001 | 0–5 | 6/6 |
| Offline recovery | 42 | 0–5 | 6/6 |
| Send/leave | 7 | 0–1 | 2/2 |
| Membership re-entry | 7 | 0 | 1/1 |

Each run used production policy, public app calls, per-participant SQLCipher databases, real local relay sockets,
fresh saved inputs and a 360-second isolated-worker deadline. All completed without timeouts, native crashes,
artifact-integrity errors or missing oracle evidence. The report directory contains frozen binary/source hashes,
commands and per-case public observations. `just fast-ci`, three generator/compiler contract tests, the seven-mutation
public-state unit test, six compiler tests, 33 subject tests and the revised admin socket canary passed as well.
The subject unit tests use their supported debug/test-policy configuration; full-app runs use production policy.

After integrating parent checkpoint `097e9101`, generator version 3 passes all three public contracts,
the send/restart checkpoint regression, the full-app admin-handoff canary (91.28 seconds), and `just fast-ci`.
Logs are under `target/pr1711-review-20260906/`; the earlier 15-case matrix remains version-2 evidence.

This coverage remains bounded to serialized journeys. Real relay rejection, partial publication fanout and invite
delivery/retry faults remain separate next targets; preflight inventory does not establish those outcomes.

## Public commit-history companions

The generator-version-1 `public-app-admin-churn/v1` and `public-app-late-join/v1` catalogs add serialized
administration with traffic and fresh admission after up to 36 profile commits. Their workload, restart boundaries
and exact public history/state contracts are documented in [SCENARIOS.md](SCENARIOS.md#public-admin-churn-and-late-joining-after-commit-history).
The original four public families remain generator version 4 with unchanged saved-input semantics.

The first two explicit canaries are:

```sh
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false cargo test --release --locked -p cgka-conformance-simulator \
  --test public_app_families public_admin_churn_strict_canary -- --ignored --exact
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false cargo test --release --locked -p cgka-conformance-simulator \
  --test public_app_families public_late_join_strict_canary -- --ignored --exact
```

For the full six-case catalogs, use the isolated campaign runner with `--storage file --case-timeout-secs 900`
and a fresh evidence directory. These companions preserve public expectations rather than removing incompatible
private assertions from an engine input. A bounded inventory or a compiled generator is not a passing campaign.

### Launch campaign, 2026-09-07

Against local master `d42f516909cd41680192eb2e813af6965c9a4348`, all four original public families passed a seed-0
canary and six cases at each of seeds 7, 42 and 17001: 76/76 runs. The two new companions each passed a seed-7
canary and six seed-42 cases: 14/14 runs, including both 36-commit late-admission/reopen variants. These used
frozen production-policy release binaries, per-participant SQLCipher files, local relay sockets and at most two
isolated workers concurrently. The original families kept their 360-second deadline; the new pressure companions
used 900 seconds. The longest completed case took 405.116 seconds. No campaign timed out, crashed, reported
artifact-integrity errors or lacked required oracle evidence.

Evidence and source/binary provenance are under `target/app-launch-20260907/`; the 76 baseline runs and 14 new-family
runs used separate frozen binaries. The recursive inventory records 516 generated samples (144 action-compatible,
372 capability gaps) and 32 fixed/saved scenarios (12 action-compatible). All 108 previously compatible generated
input envelopes are unchanged. Inventory compatibility is not execution coverage. These bounded four-participant,
serialized campaigns do not resolve the concurrent accepted-command/Welcome risks described above.
Both new-family strict socket canaries also passed their oracle-mutation checks for lost/duplicate payloads and
incorrect membership, profile, admin or epoch observations.

Before integrating the own-intent recovery fix, the departure-fix production-policy binary passed both 1,024-message recovery journeys (including extra epochs), all nine
app adapter tests, all six ordinary interaction tests and all four public generator contracts. The ordinary
interaction run includes the promoted strict leave regression; its three ignored tests are the two known strict
concurrent-operation regressions and the slow manual self-update journey. The engine suite passed 555 tests with
its supported test-policy feature, and `just fast-ci` passed. These are local results, not device or remote-CI evidence.

Explicit original-master race checks remained red: the strict profile race lost an accepted rename, and all three
invite-versus-rename repetitions failed. Two left the invitee on a stranded branch; the third admitted the invitee
but dropped an accepted rename. Inputs and public observations are retained under `target/app-launch-20260907/known-races/`.
The departure scheduling correction alone did not repair those gaps. The combined reliability branch now also
includes own-intent recovery for #1734, with strict journey 08 promoted to the ordinary suite. The stranded-invitee
case (#1735) is now covered by automatic fresh-material recovery plus explicit recipient rejoin; its strict real-socket regression is opt-in because socket scheduling cannot guarantee the same-epoch race.
The deterministic engine regression is required; an opt-in run that misses the race is inconclusive evidence. Intent retention failures roll back staging;
re-issue transfers the retained intent into the outbound queue atomically, with fault-injection regressions for
both queue insertion and source deletion. The account dispatcher constructs only the selected command future
to keep nested MLS work within the configured runtime stack budget.

## Recovery implementation boundaries

The durable deferred-generation barrier covers uncontested catch-up as well as competing branches: all admitted
raw rows must try the current context before recovered commits can prune it. Each background recovery slice shares
64 rows and a cooperative 500-ms deadline; queued-intent foreground preflights retain their separate budgets.
Explicit-time engine calls share the recovery row bound without consulting elapsed real
time. Partial work survives cancellation and restart. Historical peel contexts are materialized once per sweep,
and live storage is restored before awaiting the peeler; secret retention policy is unchanged.

Each released application event projects using its own authenticated content identity. Effect batches do not carry
a reliable content-to-envelope timestamp mapping, so their optional skew diagnostic is skipped rather than adding
fallible per-message storage reads. This does not change message timestamps, ordering or persisted projections.

SDK repair owns fetched event bytes even when the SDK remembers only an id. Its overlap with a first-sighting
notification is expected; exact-id SDK and app projection regressions check the overlap and idempotence separately.
The raw row cap is 2,048 with unchanged byte ceilings and 32-context retry bound; the cap alone was insufficient.

The public send/leave exact-epoch expectation is not passing coverage in parent PR #1711. Its semantic public-state
correction belongs to stacked [PR #1713](https://github.com/marmot-protocol/mdk/pull/1713), which must supply its own
validation. Publication failures, partial relay fanout and invite retry scenarios remain subsequent work.

Readiness now uses the storage backend's state-filtered query, excluding unrelated processed history. Follow-up
[#1715](https://github.com/marmot-protocol/mdk/issues/1715) covers payload-free readiness queries, preparation cost
and repeated zero-attempt wake pressure. [#1716](https://github.com/marmot-protocol/mdk/issues/1716) covers fairness
when the bounded SDK reconciliation cursor map evicts active routes.

### CI recovery driver correction after #1711 merged

The earlier #1713 CI run `34054398652` reached 256/1,024 messages and epoch 8 after 30 repair
passes, with progress still occurring in its final passes. It failed the pass-count guard at 613 seconds,
not the 900-second watchdog. The driver now keeps attempting within that unchanged watchdog.
Exact payload/state equality, fresh traffic, restart persistence, and clean runtime closure are still required.
This corrects premature test termination; it does not establish a preparation-time bound or claim to fix
all large-backlog recovery failures (see #1715).


### Revocation enforcement coverage

Public journey generator version 4 adds a negative authorization probe after every delegated-admin revocation,
including the revoke-then-reopen variant. The delegate attempts to promote itself through the public app; only
`NotGroupAdmin` maps to the expected `not_group_admin` result. Busy workers, timeouts and storage errors cannot
satisfy it. The harness pauses unrelated maintenance while checking that the attempt changes neither public
protocol state nor relay publication count, then resumes maintenance and checks ordinary messaging still works.
The strict admin-handoff canaries execute cases 0–3, including both one- and two-cycle handoffs in both restart
variants; the saved version-3 inputs retain their earlier contracts.


## September 8 invitation recovery

The September 7 stranded-invitee observations above describe the original defect. The strict journey now forces
its inviter to lose the identity tiebreak and requires recipient-confirmed replacement, including a persisted offer
before restart and accepted state after another restart. An engine regression independently fixes the exact sibling
commit schedule and checks consumed-package rejection, stale consent after self-update, and bidirectional decryption.
See [invitation recovery](../../docs/marmot-architecture/invitation-recovery.md) for the runtime/binding integration contract.
