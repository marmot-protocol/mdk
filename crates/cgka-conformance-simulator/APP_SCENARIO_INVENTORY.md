# Public app scenario inventory

This is a coverage inventory, not a claim that every workload has passed on this revision.
Use the run artifacts to distinguish selection, preflight, execution and semantic success.

## Execution shared by the catalog

`AppRuntimeHarness::new`, its pinned-settlement and maintenance variants, fixed public
journeys, generated app families, report `--adapter app-runtime`, and the app-stack
campaign use one child process per account-device participant plus a separate relay child.
Each participant owns its public `MarmotAppRuntime`, four Tokio workers, and its own private
SQLCipher database root. The relay is the existing `nostr-relay-builder` loopback WebSocket
relay with retained history and a real socket fault proxy. It is a real local relay service;
this does not test a public relay operator's admission limits or deployment configuration.

The coordinator retains the existing action scheduling, public assertions, exact publication
correlation, concurrent-call barrier, recovery consent, and fault-evidence checks. Processes
share the host CPU and memory; four workers per process do not reserve four CPU cores.
Orderly offline/reopen steps close the app and restart the child against the same identity
and databases. Abrupt action-boundary kills remain separately covered by the canonical
process adapter and its process-kill canary. Neither route injects a kill inside a transaction.

`AppRuntimeHarness::new_in_process_stress` is an explicit shared-runtime component/stress
control. It is not the default acceptance route. Engine scenarios remain engine scenarios.
The older `ProcessOrchestrator` also uses the shared relay child for locally owned relays;
its separate versioned node protocol retains its existing capability checks. External
container/VM relays remain owned by those runners. Both adapters execute the canonical cross-route
public-state wait before the branch witness; the process report retains bounded assertion evidence.
No assertion is removed to fit an adapter. Both cross-route recovery regressions run in `just simulator-smoke`.

`cross-route-restart-permutations/v1` and `public-app-recovery-schedules/v1` now use generator version 2,
which includes that wait. Saved version-1 inputs keep their original action schedule when replayed;
regenerate these families for a new catalog campaign instead of relabeling old inputs.

The private stdio protocol is versioned and bounded (32 MiB/frame, 120 seconds/request).
The parent verifies the helper's timing-policy feature mode. Normal close waits for child
exit; failed exit has a five-second bound and is killed/reaped. Owner drop kills/reaps children.
App harness children inherit the campaign process group. On Unix an independent parent-liveness
watch also exits children if a case watchdog kills their coordinator directly, bypassing Rust Drop.
Scenario report metadata records `execution_layout`; fixed journeys save
`execution-layout.json`. Participant roots also contain a private `process.json` receipt.
These are execution diagnostics, not protocol oracles.

Catch-up remains serial by default. The opt-in `MDK_APP_CATCH_UP_PARALLELISM=8`
switch runs distinct participants in bounded batches within one catch-up step; accepted values
are 1–8 and `execution_layout.catch_up_parallelism` records the setting. Every started call in
a batch is awaited before an ordinary app failure is returned. Scenario steps and assertions
stay ordered, but participant interleaving changes. The seed-7 catalog evidence below uses 8;
this does not change the default or establish exhaustive failure/cancellation coverage.

## Fixed journeys: 18 entrypoints

| Area | Entrypoints | What is exercised |
| --- | ---: | --- |
| Basic app lifecycle, numbered 01–06 | 6 | Bidirectional messages, profile edits, late join, removal, restart, small offline backlog |
| Interaction journeys, numbered 07–14 and two strict variants | 10 | Two-group isolation/recovery, concurrent profile edits, invite/rename race, offline removal, maintenance, survivor leave, rejoin with history |
| Large backlog variants | 2 | All 1,024 payloads recovered, with and without extra epoch changes |

The strict invite/rename diagnostic is explicitly ignored by ordinary test runs.
The manual self-update journey needs the explicitly selected `test-policy-overrides` build.
The two 1,024-message journeys are also explicit slow gates. An ordinary `cargo test` pass
therefore does not establish all 18. The strict survivor-leave regression is an ordinary test.

## Generated families

| Family (all `/v1`) | Default campaign cases per seed | Main variation |
| --- | ---: | --- |
| public-app-large-group | 6 | 10, 20, 50 participants; bulk or staged joins, backlog, offline members, admin/profile/membership changes and restart |
| public-app-stateful-recovery | 6 | Seeded operation schedules including concurrent edits, actual relay interruption, membership and recovery |
| public-app-recovery-schedules | 6 | Seeded ordering of offline, reconnect/restart and recovery interactions |
| public-app-send-leave | 6 | Message and departure ordering |
| public-app-membership-reentry | 6 | Departure and re-entry histories |
| public-app-offline-recovery | 6 | Offline history, recovery and subsequent communication |
| public-app-admin-handoff | 6 | Grant/revoke and repeated handoff with restart boundaries |
| public-app-admin-churn | 6 | Administrative mutations and convergence |
| public-app-late-join | 6 | Join timing relative to prior group activity |
| public-app-backlog-recovery | 6 | Backlog and repair/restart combinations |
| cross-route-restart-permutations | 12 | Four-participant route-history comparison at twelve restart boundaries |

That is **10 public-app families plus one cross-route family**, selecting **72 cases per seed**
in the full campaign. The counts are the campaign's configured selection, not a promise that
larger case indices produce new structures. A family is a generator/workload category; a case
index chooses its arm or schedule; the seed controls deterministic choices within that generator.
The newer stateful generators vary operation order as well as actors and values. Diversity
checks remove labels and payload text before comparing schedules.

Adapter and harness tests are additional infrastructure checks: encrypted roots/public
projections, publication acknowledgement refusals, retained-event correlation and visibility,
quiet offline recovery, process separation/reaping, malformed RPC framing, retry/error
classification, generator determinism, stimulus evidence and intentionally wrong oracles.
Private fixture/history diagnostics are diagnostic entrypoints, not extra acceptance families.

## Running consistently

Cargo integration tests build the sibling node helper. For direct report/inventory binaries,
build the helper in the same profile and feature mode first:

```sh
cargo build --release --locked -p cgka-conformance-simulator \
  --bin cgka-conformance-node --bin cgka-conformance-simulator-report \
  --bin cgka-conformance-app-inventory
RUST_MIN_STACK=4194304 target/release/cgka-conformance-app-inventory target/app-inventory-new 7 42 17001
python3 scripts/app_stack_campaign.py target/app-campaign-new --mode canary --allow-dirty
```

For copied binaries set `MDK_APP_PROCESS_NODE` to the matching helper. The unified campaign
builds and freezes that helper, records its hash, and supplies its absolute path to every task.
Never let a later feature/compatibility build silently replace a running campaign's executable.
Use fresh evidence roots and the saved generated input for reproduction.

## CI placement

PR CI runs `just simulator-smoke` (ordinary simulator tests and four selected process regressions)
and the Python campaign-contract tests. It does **not** execute the full 72-case app catalog.
The nightly workflow runs the broader simulator lane and two separate production-policy
1,024-message app recovery journeys. The weekly hardening lane runs broader engine/container
campaigns. Its separate app-catalog job runs the generated canary selection followed by all 72
seed-7 catalog cases with eight-way participant catch-up, one family at a time, and uploaded evidence.
It uses `--generated-only` to exclude fixed journeys and the separately classified invite/rename
diagnostic. It runs weekly or by manual workflow dispatch, never on PR events.

Focused saved-input regressions and harness tests remain the PR gate for timing fixes. Weekly
workflow execution is a separate result from the verified local catalog run.

## Recorded validation and remaining gates

The 13 September 2026 local campaign completed all six large-group variants at seeds 42, 7 and
17001: 17 new executions plus the independently verified earlier seed-42/case-0 pass. All 18
full reports passed, including later history repair, removal/reinvite and restart: 5,364 steps
and 3,000 assertion samples. Frozen production-policy helpers used separate participant and
relay processes. The new executions took about 3 hours 6 minutes serially. Staged 50-member
runs took 26.8–29.3 minutes against the unchanged 30-minute case deadline.

The ignored local evidence root `target/app-large-group-variants-20260913-1` retains exact
inputs, reports, binary/source provenance, completion verification and timings. The preceding
runner validation is recorded in `target/app-process-runner-implementation-20260913`: ordinary
fixed journeys, adapter/lifecycle tests, a stateful case and catalog preflight. Those checks
used staged builds; the final source manifest and workspace gate do not imply every earlier
test binary was built from that final snapshot. Neither evidence set is remote CI proof.

The 14 September seed-7 catalog completed all 72 selections with strict public oracles: 32,332
actions, 23,720 assertion samples and 2,022 final expectations. This is combined evidence across
builds: 43 passes precede the historical-sender correction and 29 use that correction. The final
26 previously unrun selections took 29 minutes 33 seconds with participant catch-up concurrency
8; staged 50-member case 5 passed in 330.3 seconds. Exact inputs, per-result build provenance and
independent completion verification remain in `target/app-full-eight-seed7-20260914-4`.
These results do not establish 72 passes on one final build or replace the earlier failure records.

A later frozen-head run at `788bac21` attempted all 72 seed-7 selections: 70 passed and backlog
cases 2 and 5 exhausted 120 polling rounds before background recovery completed. Saved-input
probes recovered during an extra wait; a serial-catch-up control passed case 2. These failed
verdicts remain preserved in `target/app-full-eight-seed7-pr-20260914-1`. Real-app eventual assertions
now pace rounds and record their wall-clock watchdog; focused replay establishes that fix separately.

Full-catalog acceptance on a final build remains a separate assurance result, not an automatic
requirement to rerun every case for each PR edit. Other gates include the two explicit
1,024-message slow tests and the separately classified strict race diagnostic. Measure structural
diversity when widening seeds. Keep completed-case ledgers so
broadening does not repeat prior passes; a deliberate regression campaign uses a fresh ledger. A fresh-stack campaign establishes repeated execution coverage; continuous longevity
requires repeated activity and recovery in the same long-lived participant processes and databases.

## Opt-in recovery expansion

See [the first-increment generator and campaign guide](APP_RECOVERY_EXPANSION.md).
`public-app-invite-profile-recovery/v1`, `public-app-longevity/v1` and
`public-app-retained-traffic/v1` add six opt-in selections per seed: invite/profile generator version 2,
activity/pressure version 1. The 48-cycle `public-app-longevity-extended/v1` is separately selected.
The existing default 72-case campaign is unchanged; use `--catalog expansion`.
`app_recovery_expansion.rs` checks replay, prefix stability, structural diversity,
required interactions and rejection of missing/refused recovery evidence.
