# Public app-path acceptance coverage

## Large offline catch-up regression

`public_app_1024_message_backlog_recovers_completely` in
[`tests/app_runtime_journeys.rs`](tests/app_runtime_journeys.rs) is the maintained public regression.
It requires all 1,024 original payloads exactly once, shared public group state, fresh messages from every member,
and complete recipient history after restart. Reaching the repair budget is a failure, never success.

This is a public workload companion to the saved 1,024-message engine input. It preserves all original sends and
16 profile-update rounds, with a founding recipient offline throughout. The real local Nostr relay chooses query
order; this does **not** reproduce the engine fixture's forced reverse delivery. Initial group creation uses public
app acknowledgement semantics. Private MLS assertions and simulated relay steps are not presented as app coverage.

The reproduction allows 30 explicit full-history repairs, two seconds between passes, and up to three recipient
reopens after six unchanged transitions. A 900-second watchdog bounds the whole journey. Success additionally checks
every participant's exact payload multiset, then fresh bidirectional messaging and recipient restart persistence.
These latter checks strengthen the earlier private diagnostic driver and run only after full recovery.

The test remains explicitly ignored because it is slow and needs an appropriate CI lane. It asserts **successful
recovery**, not a particular failure count, and is not a `should_panic` test. An ordinary green suite with this test
skipped is not recovery evidence; run the explicit gate.

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
incomplete public runs. See [`OFFLINE_CATCHUP_HANDOFF.md`](../../OFFLINE_CATCHUP_HANDOFF.md) for preserved changes,
previous results, and the diagnostic SQLCipher shutdown correction. No general production SQLCipher fix is claimed.

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

## Running and preserving evidence

The later consolidation applies the 2,048-row mitigation to the broader WIP checkout. Evidence for this combination
is under `target/app-hardening-20260906/`; the earlier `target/app-path-20260906/` results below used the 512-row cap.
The original and cap-only worktrees were preserved and their changes reconciled in the root handoff.

### Inventory existing generated families before expanding execution

`cgka-conformance-app-inventory` checks the actual app adapter's action capabilities against a bounded selection
from the twelve original families and three new public journey families. It defaults to seeds 7, 42 and 17001; explicit seed arguments replace them.
It saves unchanged generated inputs only for action-compatible cases and records every rejected case with its missing
capabilities. This is preflight coverage, not a test pass: each selected case must still pass its strict runtime oracle.

```sh
cargo run --release --locked -p cgka-conformance-simulator --bin cgka-conformance-app-inventory -- \
  target/app-inventory-run-1 7 42 17001
```

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

The first local release execution on the broader WIP checkout passed all six basic tests in 107.86 seconds. The
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

Run the unresolved large regression explicitly:

```sh
MDK_APP_JOURNEY_ARTIFACTS="$PWD/target/app-path-evidence" \
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false \
cargo test --release --locked -p cgka-conformance-simulator --test app_runtime_journeys \
  public_app_1024_message_backlog_recovers_completely -- --ignored --exact --test-threads=1 --nocapture
```

Release mode without policy-override features is the production-policy verification command. Workspace debug or
feature-unified CI runs are supplementary evidence. The six basic tests are ordinary tests, included by the existing
simulator smoke filter; the ignored large test requires the explicit command above. These statements describe test
selection, not observed remote CI results.

Each test writes a fresh owner-only subdirectory containing input metadata, public checkpoint observations and a
terminal result. The large input is pinned by the source fixture SHA-256. Preserve the source revision plus dirty
patch/new-file hashes and exact command alongside results when testing WIP. Never commit runtime databases or
private observations. Failures retain their artifact directory even when the environment variable is unset.
Participant databases are closed and removed normally; this maintained test does not leak runtimes or retain secret
database snapshots. All runtime shutdown work happens before the final test assertion; there is no `process::exit`.

Local run results for this work are recorded in the root handoff and the ignored evidence directory. The defect stays
open until the large public assertion passes; smaller passing cases only establish their own listed contracts.


## Seeded public companion families

The public send/leave, membership re-entry and small offline recovery families are documented in
[SCENARIOS.md](SCENARIOS.md#public-app-journey-families). Each input owns its public expectations; no engine
assertions are stripped during replay. `Exactly` and bounded `Eventually` predicates now read public app epoch,
member count and visible payload counts. Exact engine state and private pending work still fail capability preflight;
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
randomness or socket scheduling. These small generated cases do not close the known 1,024-message failure.


### First generated execution results (2026-09-06)

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

### Four-message projection regression follow-up (2026-09-06)

The saved offline seed-7/case-0 input now passes all 435 actions with zero expectation/invariant failures after
an app projection fix. Every participant has all 11 messages at epoch 2; Bob retains them after reopen. The engine
had already decoded the previously missing message. Live effects observation reused one source ID for a batch,
causing a UNIQUE source-message constraint failure. Each message now projects with its own durable event source.
The unit regressions cover scheduled convergence, send-applied effects, inbound effects, and restart replay.
The original failure and post-fix public observations are preserved in `target/offline-four-20260906/REPORT.md`.
The separate send/leave epoch mismatch remains uninvestigated; this does not promote that family to passing coverage.

The maintained small offline canary passes too (84.70 seconds). The post-fix 1,024-message regression remains red:
a group-members query hits `AccountWorkerResponseTimedOut` during repair pass 3; the final recipient snapshot is
270/1,024 messages at epoch 8 versus peers at epoch 22. No background storage errors were captured, and teardown
reported no errors. The 191.60-second run exited as an ordinary test failure; it did not exhaust the full recovery
budget or reach fresh-message/persistence checks. Keep the large gate open and investigate account-worker response
availability during sustained recovery separately from the now-fixed source-ID collision.
