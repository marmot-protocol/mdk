# Scaling Convergence Campaigns

This guide describes how to grow from a local canary to thousands of deterministic scenarios without losing
reproducibility, oracle strength, privacy, or useful failure attribution. Read
[`RUNNING_CAMPAIGNS.md`](RUNNING_CAMPAIGNS.md) first for the execution layers and commands.

## Scale the cheap boundary first

Use this promotion ladder:

1. in-process strict report for authoring and a very small canary;
2. file-backed isolated case workers for broad discovery;
3. app-runtime or separate-process replay for production orchestration/projection questions;
4. containers for real sockets, namespaces, image differences, and network faults; and
5. VMs only for kernel, host, filesystem, or block-device hypotheses.

Thousands of engine cases and dozens of process/container cases usually provide more useful coverage per hour than
thousands of VM cases. Wider execution should confirm layer-specific behavior and representative minimized failures,
not duplicate the entire cheap corpus.

## Reproducible case identity

The stable logical identity is:

```text
(family_name, generator_version, seed, case_index[, profile_version])
```

`--cases N` generates indices `0..N-1`. It is not a complexity setting. Increasing it must preserve the existing
prefix. The current CLI has no case-start offset, so parallelize a large discovery run by assigning distinct seeds to
shards. Do not run the same seed with several different case counts unless intentional prefix duplication is
acceptable.

Always retain `*-generated-input.json`. It pins more than the tuple: the selected subject, expectations, exact
canonical IR, provenance, and digests. `family_name` and `generator_version` are independent fields; a family-name
version does not replace the generator version. Include a separately versioned workload profile when applicable. Any
output-changing generator or profile change requires its corresponding version bump.

## A staged campaign

### Stage 1: canary

Run one to three cases from every relevant family with file-backed storage. Stop on infrastructure, oracle coverage,
or artifact-integrity errors before spending the larger budget.

### Stage 2: breadth matrix

Require a clean source revision, build once, and put that exact revision plus the command matrix beside the evidence.
The generated-input and report schemas do not currently carry a Git commit, so this companion metadata is required to
identify the implementation under test:

```bash
set -euo pipefail
test -z "$(git status --porcelain)" || {
  echo "refusing to build campaign evidence from a dirty worktree" >&2
  exit 1
}
source_revision="$(git rev-parse HEAD)"
family_name="convergence-chaos/v1"
generator_version="6"
case_count="25"
case_timeout_secs="300"
parallelism="4"
run_id="seeds-1000-1007-cases-$case_count-attempt-1"

cargo build -p cgka-conformance-simulator --bin cgka-conformance-campaign --locked

umask 077
campaign_parent="target/convergence-scale/$source_revision/convergence-chaos-v1-g$generator_version"
campaign_root="$campaign_parent/$run_id"
mkdir -p "$campaign_parent"
mkdir "$campaign_root" || {
  echo "refusing to overwrite campaign evidence root: $campaign_root" >&2
  exit 1
}
printf '%s\n' \
  "source_revision=$source_revision" \
  "family_name=$family_name" \
  "generator_version=$generator_version" \
  "run_id=$run_id" \
  "seeds=1000..1007" \
  "cases_per_seed=$case_count" \
  "case_timeout_secs=$case_timeout_secs" \
  "storage=file" \
  "parallelism=$parallelism" \
  >"$campaign_root/campaign-matrix.txt"
rustc --version --verbose >>"$campaign_root/campaign-matrix.txt"

export campaign_root family_name case_count case_timeout_secs
seq 1000 1007 | xargs -P "$parallelism" -I SEED sh -c '
  seed="$1"
  RUST_MIN_STACK=4194304 target/debug/cgka-conformance-campaign \
    --family "$family_name" \
    --seed "$seed" \
    --cases "$case_count" \
    --case-timeout-secs "$case_timeout_secs" \
    --storage file \
    --out "$campaign_root/seed-$seed"
' sh SEED

expected_inputs="$((8 * case_count))"
actual_inputs="$(find "$campaign_root" -name '*-generated-input.json' -type f | wc -l | tr -d ' ')"
test "$actual_inputs" -eq "$expected_inputs"
find "$campaign_root" -name '*-generated-input.json' -type f -print0 |
  while IFS= read -r -d '' input; do
    jq -e \
      --arg family_name "$family_name" \
      --arg generator_version "$generator_version" \
      '.case.family_name == $family_name and .case.generator_version == $generator_version' \
      "$input" >/dev/null
  done
```

This example is a clean-build, source-bound 200-case campaign across eight seed shards. Update the recorded generator
version whenever the selected family changes; the final check fails when it does not match the generated inputs.
Increase the seed range, cases per seed, or both only after measuring peak RSS, disk use, and case time. Start
parallelism conservatively. A useful limit is the smaller of available CPU capacity and the number of worst-case
workers that fit in the memory/disk budget. The campaign summary records the measurements needed to tune that
operational limit.

Use a separate immutable directory per `(source revision, family name, generator version, seed)`. The runner's
per-case overwrite refusal protects shard artifacts, while the recipe's exclusive run-leaf creation protects the
top-level provenance manifest. For a second execution of the same matrix, choose a fresh `run_id`; never reuse or
empty an earlier evidence root.

### Stage 3: sustained depth

Once breadth is clean, run a smaller number of seeds with larger case counts or the named sustained workloads. Keep
the same per-case deadline so a slow tail becomes visible rather than silently stretching the job. Compare:

- completed, failed, signaled, and timed-out cases;
- artifact integrity and missing reports/capsules;
- wall time, user/system CPU, peak RSS, database bytes, and filesystem write lower bounds;
- input dispositions, unresolved work, queue depth, replay probes, and reorg distributions; and
- operation/interaction coverage when the selected family reports it.

Do not treat a zero-failure aggregate as sufficient if the intended operation or interaction never occurred.

### Stage 4: promote representative cases outward

Choose cases because they cover a layer-specific hypothesis, a slow/resource boundary, an unusual decision route, or
a real failure. Replay the saved input against the next compatible adapter. Preserve selected and executed IR digests
when a wider adapter performs deterministic lowering.

Run a small container matrix over representative cases and image combinations. Reserve VMs for named gaps that need a
separate kernel/host/block device. Record the exact source revisions and image digests; a previous green soak does not
automatically cover later production changes.

## What to run first

For broad defect discovery, prioritize:

1. `chat-journey/v1` for legal product histories;
2. `convergence-chaos/v1` for adversarial schedule and traffic breadth;
3. `bounded-convergence-pressure/v1` for the self-update/admin/profile pressure boundary;
4. `large-group-pressure/v1` for explicit 10–200 member, administrator-population, committer-width, and traffic
   profiles;
5. `admin-churn/v1` for membership and administrator transitions; and
6. the two twelve-case cross-route restart catalogs as fixed high-value regressions.

Cover all registered families with a small seed matrix before making one family enormous. Then allocate additional
cases using measured coverage gaps, failures, slow tails, and recent production changes.

## Adding useful chaos instead of undirected randomness

Every new workload must begin with a question and an oracle. “More random traffic” without a falsifiable expected
outcome is load generation, not convergence verification.

Prefer extending the legality-aware `chat-journey` product model when the behavior is a real user operation. Keep
transport/process/storage/resource faults in the separately typed fault layer. A specialized family is justified when
it enforces a named motif, has a distinct subject or budget, or needs a focused oracle.

High-value motifs that should drive future profiles include:

- an offline founding member returning to a large application/commit backlog while group state changes (implemented
  as the retained-relay `offline-catchup-pressure/v1` family; membership-changing extensions remain future work);
- sustained application traffic interspersed with proposals, commits, administrator handoff, removals, and re-adds;
- bounded self-update pressure racing administrator/profile commits, with explicit input closure;
- restart after publication acceptance, ingest, freeze, selection, application, confirmation, rollback, or retained
  history repair;
- delayed application input from a losing branch followed by replacement, invalidation, or retry eligibility;
- unequal multi-relay histories, reconnect, duplicates, EOSE, incremental cursor advance, and full-history repair;
- transient resource refusal around candidate materialization, replay, database contention, disk limits, and recovery;
  and
- mixed-version participants applying the same canonical scenario across a rolling upgrade.

For each motif, specify:

1. legality preconditions and symbolic state transitions;
2. required actions/interactions that must appear in the generated corpus;
3. terminal and intermediate expectations, including no-pending or named non-progress outcomes;
4. compatible adapters and capabilities;
5. case timeout and resource envelope;
6. deterministic prefix/replay behavior; and
7. which assurance claim or known risk the motif owns.

## Family implementation checklist

1. Add or extend product actions in `src/stateful_generator.rs`; use `src/family.rs` for family registration and thin
   workload selection. Reuse shared builders instead of creating another executor.
2. Emit canonical Scenario IR and semantic expectations together. Never let an adapter invent the scenario's truth.
3. Use the complete capability preflight. Do not partially execute an unsupported scenario.
4. Add deterministic same-seed, different-seed, and prefix-invariance tests.
5. Add reachability tests for every registered action and interaction tests for every required motif.
6. Prove the strict oracle observes each expected behavior; add a sentinel/mutation that fails when the important
   operation or assertion is removed.
7. Update [`SCENARIOS.md`](SCENARIOS.md), [`PROPERTY_TESTS.md`](PROPERTY_TESTS.md), and the family table in
   [`RUNNING_CAMPAIGNS.md`](RUNNING_CAMPAIGNS.md).
8. Run a small memory/file-backed batch, then the isolated worker. Promote stable synthetic failures into fixed vectors
   only after review.
9. Bump `generator_version` if any existing `(family_name, generator_version, seed, case_index)` changes meaning or
   output. Bump an independently versioned profile when its choices or meaning change.

## Aggregation and retention

Each isolated shard writes `process-campaign.v1.json`; treat the shard summaries and their referenced inputs/reports as
one evidence set. An aggregate summary must derive totals and slowest/resource extrema from every included shard, not
only a subset. Keep the exact source revision and command matrix beside the artifacts.

Campaign artifacts can grow quickly. Retain:

- all failed/timed-out/signaled cases and their exact inputs;
- all artifact-integrity failures;
- per-shard summaries and the aggregate manifest;
- representative slow/resource-bound successful cases; and
- the inputs and digests behind any published assurance claim.

Routine successful case reports may use a documented retention window. Never discard the only reproducer for a
failure. Never copy sensitive byte-replay checkpoints into a shareable aggregate or committed fixture.

## Stop and investigate when

Pause scale-out if any shard shows:

- a strict oracle gap or missing observed behavior;
- an unexplained timeout, signal, panic, or missing artifact;
- different outcomes for the same saved input and compatible subject;
- a resource trend approaching the lane budget;
- a failure that disappears only when `--allow-weak-oracle` is used; or
- an intended action/interaction with zero coverage.

More cases do not repair an invalid oracle or nondeterministic reproducer. Fix the laboratory first, rerun the canary,
then resume the larger matrix.

## Confidence and constants

Use one-variable-at-a-time policy sweeps and fixed scenario inputs to characterize a constant boundary. Campaign
curves are evidence for review, not an auto-tuning mechanism. Compare failure rate, outcome class, latency, resource
use, and coverage across the boundary while keeping the authenticated input and eligibility assumptions fixed.

The practical success criterion is not “no failures in a very large number.” It is that high-risk interactions are
reachable, strict oracles would detect their relevant defects, failures replay and minimize, operating envelopes are
measured, and the same representative semantics survive increasingly production-shaped subjects.
