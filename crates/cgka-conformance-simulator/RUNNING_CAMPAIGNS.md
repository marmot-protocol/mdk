# Running Convergence Scenarios And Campaigns

This is the operator manual for the Marmot convergence reliability lab. Start here when you want to run an existing
vector, generate deterministic scenarios, reproduce a saved case, or move one scenario through more
production-shaped adapters.

The short rule is: use the cheapest subject that can answer the question, keep strict oracle checking enabled, save
the exact generated input, and promote only representative cases or failures to processes, containers, or VMs.

For campaign scaling and family development, continue with [`SCALING_CAMPAIGNS.md`](SCALING_CAMPAIGNS.md). For the
scenario language itself, see [`SCENARIO_IR.md`](SCENARIO_IR.md). The complete scenario registry is in
[`SCENARIOS.md`](SCENARIOS.md).

## What each execution layer proves

| Layer | Entrypoint | What it adds | What it does not prove |
| --- | --- | --- | --- |
| Fixed vectors | `cgka-conformance-simulator-report --vectors ...` | Stable, reviewable semantic regressions | Broad generated coverage |
| In-process report | `cgka-conformance-simulator-report --family ...` | Fast strict scenario execution and saved reports | OS process isolation or real sockets |
| Isolated case worker | `cgka-conformance-campaign` | One child per case, timeout/reaping, OS CPU/RSS/write measurements | One OS process per participant |
| App-runtime adapter | report replay with `--adapter app-runtime` | Production-shaped app/session/projection behavior in one process | Participant process or host isolation |
| Process adapter | `cgka-conformance-process` | One account-device per child process, private SQLCipher roots, restart | Separate kernels or real network namespaces |
| Container runner | `cgka-distributed-campaign` / ignored container tests | One participant per container, real sockets, isolated OCI network, network faults | A distinct kernel, block device, or VM host |
| VM driver | distributed manifest with VM backend | External host lifecycle, kernel/filesystem/block-device isolation | More semantic coverage by itself |

Public app/process/container projections cannot establish exact MLS-private state, durable internal input dispositions,
or active decryptability when those surfaces are not exposed by the adapter. Pair wider public runs with an
engine-capable exact control when the claim requires those facts.

## Before the first run

Run commands from the repository root. The workspace pins its Rust toolchain; use `--locked` for CI-like runs. Cargo
launches supply the simulator's required stack size. When invoking a built binary directly, set
`RUST_MIN_STACK=4194304`.

Use a new output directory for every run. The isolated campaign runner intentionally refuses to overwrite earlier
evidence. Keep generated inputs and failure artifacts private: sensitive replay capsules can contain recipient
database/OpenMLS state and key material and must never be committed.

Generated inputs and reports do not currently embed the tested Git commit. For evidence that must outlive the local
session, require a clean worktree and preserve the exact `git rev-parse HEAD` value plus the command matrix beside the
artifacts. [`SCALING_CAMPAIGNS.md`](SCALING_CAMPAIGNS.md) provides a private-by-default shard recipe that does this.

For a quick installation and compile check:

```sh
just simulator-smoke
```

## The five-minute local workflow

### 1. Run a small strict generated batch

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report --locked -- \
  --family chat-journey/v1 \
  --seed 42 \
  --cases 3 \
  --storage file \
  --out target/convergence-manual/chat-journey-seed-42
```

Strict oracle checking is the default. A zero exit means every scenario completed and its declared expectations were
observed. It does not mean the engine is universally correct. `--allow-weak-oracle` is for deliberately exploratory
legacy diagnostics only; never use it as green assurance evidence.

### 2. Inspect the evidence

The report directory contains, per case:

- `*-generated-input.json`: the exact versioned input envelope to replay;
- `*.json`: the scenario report, step log, oracle evidence, input dispositions, and campaign measurements;
- `*-fixture.v1.json`: a candidate fixed vector, not automatically approved truth;
- `*-failure-capsule.v1.json`: a shareable synthetic failure capsule when a failure occurs; and
- optionally `*-sensitive-replay-capsule.v1.json`: engine byte-replay material, only when explicitly requested.

Read `expectation_failures`, `oracle`, `step_log`, `pending_resolution_observations`,
`app_invalidation_observations`, and `campaign_measurements` before deciding what failed. A timeout, resource refusal,
unsupported adapter capability, infrastructure error, and semantic mismatch are different outcomes.

### 3. Replay exactly the saved logical input

Use a fresh output directory:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report --locked -- \
  --generated-input target/convergence-manual/chat-journey-seed-42/chat-journey-v1-seed-42-case-0-generated-input.json \
  --storage file \
  --out target/convergence-manual/chat-journey-seed-42-case-0-replay
```

The stable logical identity of a generated case is
`(family_name, generator_version, seed, case_index)`, plus an independently versioned workload profile when one is
defined. `family_name` and `generator_version` are separate: for example, `convergence-chaos/v1` currently uses
generator version `6`. The saved input is stronger than remembering that tuple because it pins the resolved scenario,
subject, expectations, provenance, and digest. Logical replay does not recreate randomized MLS bytes. A
checkpoint-bearing sensitive capsule is required for byte replay:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report --locked -- \
  --replay-capsule PATH_TO_SENSITIVE_CAPSULE
```

### 4. Isolate every case in its own worker process

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-campaign --locked -- \
  --family convergence-chaos/v1 \
  --seed 42 \
  --cases 12 \
  --case-timeout-secs 300 \
  --storage file \
  --out target/convergence-manual/chaos-seed-42-isolated
```

The parent saves each input before spawning its worker, kills and reaps deadline failures, verifies artifact
provenance, and writes `process-campaign.v1.json`. This is the preferred local discovery boundary: a panic or hang in
one case cannot erase the remaining cases, and the summary contains real child-process resource measurements.
The worker also saves the original report, fixture candidate, and failure capsule before optional semantic reduction.
The campaign summary records each case's minimization status and classifies a process deadline as scenario execution,
minimization, or later post-processing when enough durable evidence exists to tell them apart. After reaping a worker,
the parent removes any same-worker atomic-replacement temporaries; cleanup failures are retained as artifact-integrity
errors rather than leaving undeclared evidence behind.

Semantic reduction defaults to 30 seconds overall, 256 reproduction trials, and five seconds per trial. Override these
with `--minimization-wall-time-secs`, `--minimization-max-trials`, and
`--minimization-trial-timeout-secs`. A `budget_exhausted` status is a bounded post-processing result, not a scenario
timeout, and the original failure artifacts remain authoritative.

## Choosing a generated family

| Family | Use it for |
| --- | --- |
| `send-leave/v1` | Small membership/application lifecycle coverage |
| `convergence-e2e-delivery/v1` | Peeler-to-engine delivery under duplicate, delay, and reorder noise |
| `convergence-chaos/v1` | Broad adversarial forks, partitions, storms, restarts, and delayed messages |
| `admin-churn/v1` | Sequential/competing administration, joins, restarts, and churn |
| `adversarial-reliability/v1` | Named real-world and resource-pressure workload catalog |
| `bounded-convergence-pressure/v1` | Finite self-update/profile/admin pressure under a bounded quiescence contract |
| `large-group-pressure/v1` | Explicit 10–200 member, admin-population, committer-width, traffic, growth, and churn profiles |
| `offline-catchup-pressure/v1` | Founding member returns only after a retained 24–1,024-message backlog plus commit pressure |
| `membership-reentry/v1` | Single/repeated removal and fresh-Welcome re-entry with restart, self-update, self-leave, and stale-Welcome interactions |
| `cross-route-restart-permutations/v1` | Twelve public app-runtime restart boundaries in the four-party route scenario |
| `cross-route-exact-restart-permutations/v1` | Exact/private engine companion to the public restart catalog |
| `chat-journey/v1` | Legality-aware product journeys: membership, profile, app traffic, offline/catch-up, and restart |

`--cases` is a count, not a complexity dial. Case index selects a deterministic arm or generated history. More cases
increase coverage; they do not promise that later cases are larger. `--seed` changes the deterministic choices within
each indexed case. A family defines the available operations, weights/motifs, subject, and expectations.

For `large-group-pressure/v1`, six consecutive cases form one size block, ordered by execution cost: 10, 16, 20, 32,
50, 64, 100, 128, then 200 members. Cases `0..17` cover the 10/16/20-member blocks, `18..35` cover 32/50/64, and
`36..53` cover 100/128/200. Use `--cases 6` for the 10-member six-arm smoke run, `--cases 24` through the 32-member
anchor, `--cases 36` through the 64-member anchor, and `--cases 54` only as a deliberately budgeted complete catalog.
Run `cargo test -p cgka-conformance-simulator --test large_group_family --locked` for the ordinary 10-member
application and retained-join canaries. Prefer the isolated file-backed campaign runner for broader execution;
generator tests already compile all 54 shapes without running the expensive large/xlarge blocks.

For `offline-catchup-pressure/v1`, six consecutive cases form one volume block: 24, 96, 384, then 1,024 application
messages, interleaved with 4, 8, 12, then 16 commit rounds. Each block covers natural full history, reverse history,
reverse history with three copies, natural two-copy incremental followed by full repair, reverse two-copy restart after
sync but before processing, and reverse three-copy history containing competing commit waves. Cases `0..5` are the
smoke block, `0..11` run through 96 messages, `0..17` through 384, and `0..23` complete the 1,024-message catalog. Every
case uses the retained-relay subject and keeps Bob offline until the final catch-up phase. Use the isolated file-backed
runner for volume campaigns:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-campaign --locked -- \
  --family offline-catchup-pressure/v1 --seed 42 --cases 18 \
  --case-timeout-secs 300 --storage file \
  --out target/convergence-manual/offline-catchup-seed-42
```

For `membership-reentry/v1`, ten consecutive cases cover the complete catalog: one clean cycle, two
cycles, three cycles with victim restarts, self-updates between cycles, a self-update/removal race, self-leave then
re-entry, self-leave racing administrative removal, and a stale original Welcome followed by the trusted removal
commit and a fresh re-invitation. The final two arms widen the group to eight members: case `8` lets all seven
incumbents stage competing commits for the same self-leave before any commit delivery, while case `9` lets only two
to four seeded early committers do so before
the winner reaches the remaining incumbents. All cases are ordinary strict regressions. Case `7` pins the
trusted-removal continuity rule: a delayed older Welcome may install a stale active local view, but a newer
re-invitation remains retryable until the victim processes the removal from its trusted branch. The same Welcome then
restores convergence. Cases `8` and `9` require the all-committer and production-shaped partial-impact fork to
converge before re-entry.

## Running vectors and adapter comparisons

Run all portable vectors:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report --locked -- \
  --vectors crates/cgka-conformance-simulator/vectors \
  --storage file \
  --out target/convergence-manual/vector-reports
```

A saved generated input can be rerun on a compatible subject:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report --locked -- \
  --generated-input PATH_TO_GENERATED_INPUT \
  --adapter retained-relay \
  --storage file \
  --out target/convergence-manual/retained-relay-replay
```

Valid overrides are `engine`, `retained-relay`, and `app-runtime`. The full schedule is capability-preflighted before
step zero. Rejection means the selected adapter cannot honestly execute that scenario; do not delete operations or
assertions merely to force it through. Choose a capability-overlap scenario or add a deliberate, digest-recorded
lowering in the adapter.

## Running the separate-process adapter

First build both binaries:

```sh
cargo build -p cgka-conformance-simulator \
  --bin cgka-conformance-process \
  --bin cgka-conformance-node \
  --locked
```

Then run one saved canonical/generated input:

```sh
RUST_MIN_STACK=4194304 target/debug/cgka-conformance-process \
  PATH_TO_GENERATED_INPUT \
  target/debug/cgka-conformance-node \
  target/convergence-manual/process-report.json
```

The process adapter launches one node per account-device, gives each a separate private database/artifact root, and
writes a public process report plus participant-owned failure material. The scenario must fit the process adapter's
declared capabilities.

The bounded four-party restart catalog also has an explicit manual test:

```sh
cargo test -p cgka-conformance-simulator --test process_orchestrator --locked -- \
  --ignored four_party_cross_route_process_restart_permutations_match_unified_route
```

## Running the restart catalogs

The two stable recipes cover all twelve v1 boundaries at seed zero:

```sh
just cross-route-restart-campaign 0 12 target/convergence-manual/cross-route-public-seed-0
just cross-route-exact-restart-campaign 0 12 target/convergence-manual/cross-route-exact-seed-0
```

Use the exact/private campaign as the correctness control and the public app-runtime campaign as the
production-shaped projection check. A wider `--cases` value repeats the bounded v1 catalog under its documented seed
rotation; it does not create new restart boundaries.

## Running containers

Containers are the right next step for real sockets, OCI network isolation, participant image separation, and network
fault injection. They are expensive enough that broad seed discovery should stay in isolated local workers.

Build the current source image and run the real-container tests:

```sh
docker build -f Dockerfile.convergence-campaign -t marmot-conformance:local .
CGKA_CONVERGENCE_IMAGE=marmot-conformance:local \
  cargo test -p convergence-campaign-runner --test container_runtime --locked -- --ignored
```

Retain the exact four-party checkpoint artifacts:

```sh
CGKA_CONVERGENCE_IMAGE=marmot-conformance:local \
CGKA_DISTRIBUTED_ARTIFACTS_DIR="$PWD/target/convergence-manual/distributed-container-evidence" \
  cargo test -p convergence-campaign-runner --test container_runtime --locked \
    four_party_cross_route_recovery_containers_match_unified_route -- --ignored --exact
```

The runner creates an isolated relay/network and one non-root participant container per member. Each participant owns
separate encrypted storage. All containers still share the host kernel.

For a checked-in or privately prepared distributed manifest, always validate and inspect before mutation:

```sh
cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign --locked -- \
  validate PATH_TO_MANIFEST
cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign --locked -- \
  plan PATH_TO_MANIFEST
cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign --locked -- \
  doctor PATH_TO_MANIFEST
cargo run -p convergence-campaign-runner --bin cgka-distributed-campaign --locked -- \
  run PATH_TO_MANIFEST
```

Review the normalized plan for image assignments, exact scenario digest, output root, fault capability, cleanup, and
timeouts. Never point campaign manifests at public relays or put credentials, real payloads, identifiers, or key
material in them.

## When a VM is justified

The distributed runner has a versioned external VM-driver contract, but MDK intentionally does not own one universal
provisioner. Use a VM only for a hypothesis that a container cannot represent: distinct kernels, filesystem or
block-device behavior, host reboot, stronger host isolation, or mixed host images. A VM run should consume the same
canonical input and oracle as its cheaper control and add only the layer-specific fault.

Do not move thousands of ordinary semantic cases into VMs. First discover and minimize locally, reproduce on the
app/process boundary, then promote the smallest representative scenario to containers or VMs.

## Core recipes versus budgeted workflows

These are useful local core-test recipes:

```sh
just simulator-smoke
just convergence-nightly-lane
just convergence-weekly-lane
just focused-convergence-regressions
just convergence-release-hardening-lane PATH_TO_MIXED_BUILD_MANIFEST
```

The bare Just recipes do **not** collect or enforce the checked-in wall-clock, CPU, RSS, disk, artifact, retry, and
flake budgets. `convergence-weekly-lane` and recipes it invokes also remove fixed output roots before rerunning, so use
them as local test entrypoints rather than retained campaign evidence.

The GitHub workflows wrap the core commands with `observe-step`, `collect-observation`, `check-budget`, and artifact
upload. Dispatch those workflows on the exact branch or tag to obtain a budget-evaluated, retained run:

```sh
gh workflow run simulator-nightly.yml --ref BRANCH_OR_TAG
gh workflow run convergence-hardening.yml --ref BRANCH_OR_TAG -f lane=weekly_manual
gh workflow run convergence-hardening.yml --ref BRANCH_OR_TAG \
  -f lane=release_hardening \
  -f baseline_revision=EXACT_40_CHARACTER_ANCESTOR_COMMIT
```

Use `gh run list --workflow WORKFLOW_FILE` to find the run, `gh run watch RUN_ID` to wait for it, and
`gh run download RUN_ID` to retain its artifacts. A green workflow is evidence for the exact `GITHUB_SHA` it checked
out and the declared lane contents. Release hardening additionally requires a reviewed baseline revision and is not
complete assurance until its digest-pinned evidence bundle and scoped claim have been downloaded and reviewed.

## Failure handling checklist

1. Preserve the exact generated input, report, campaign summary, and capsule. Do not rerun into the same directory.
2. Reproduce from `--generated-input`; use byte replay only when a sensitive capsule exists and can be handled safely.
3. Classify the outcome: product defect, protocol ambiguity, environment failure, or expected resource refusal.
4. Minimize semantically while keeping the same failure class and action/failure identity. A changed terminal digest
   can still be a useful diagnostic reduction, but it is not exact-fingerprint equivalence.
5. Move down the adapter ladder. If a container failure reproduces in the process or engine subject, debug the smaller
   boundary. If it only reproduces in the wider layer, retain the relevant receipts and environment facts.
6. After a fix, rerun the minimized case, its original case, the family canary, and the relevant wider adapter.
7. Promote a stable synthetic regression into `vectors/` only after human review. Never promote incident/private
   material.

## Interpreting confidence correctly

A large green matrix raises confidence over the exact operation distribution, constants, resource envelope, adapters,
and source revision it exercised. It does not prove universal correctness, optimal constants, full offline history, or
administrator progress under infinite valid self-updates. Campaign results may motivate a policy change, but must not
automatically tune production constants.
