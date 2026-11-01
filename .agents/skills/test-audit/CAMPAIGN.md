# Test campaign

A campaign audits the whole test surface of one crate or subsystem, such as
`storage-sqlite`, the `cgka-engine` integration tests, or `marmot-app`'s relay
runtime. The gate, junk patterns, retention bar and evidence rules in
[SKILL.md](SKILL.md) apply to every step. This file adds the order of work.
Meet each step's completion criterion before starting the next.

## 1. Baseline

Pin an `origin/master` SHA and record for the scope:

- test and production lines, counted separately, with unit tests
  (`#[cfg(test)]` modules and `src/**/tests*`) split from integration tests
  (`tests/`);
- the number of tests and of test binaries
  (`cargo nextest list -p <crate> --message-format json`);
- each test's result and wall time from one run with the exact features of
  the crate's CI job. Take them from `.github/workflows/ci.yml` and the
  `test-features` list at the top of the `Justfile`; a crate's `AGENTS.md`
  may name only some. A crate whose CI job passes no features runs without
  `--features`. Where a feature changes harness defaults, as
  `test-policy-overrides` does in the simulator, apply it only to the tests
  CI selects with it. Record any feature-gated suite CI does not run (the
  engine's `test-conformance-snapshot` tests) in a separate run, so its owner
  appears in the baseline too;
- what the shared setup costs: time one store open, fixture or process start
  alone, and count how many each test pays for. nextest runs every test in
  its own process, so anything a test binary builds once per process is built
  again by every test;
- line coverage of the production owner, saved for later diffs.

```sh
SCRATCH=<your scratch directory>; mkdir -p "$SCRATCH"
FEATURES=(--features <ci-features>)   # FEATURES=() when the CI job passes none
cargo nextest run -p <crate> --locked --no-fail-fast "${FEATURES[@]}" \
  > "$SCRATCH/<crate>-baseline.log" 2>&1; echo "exit=$?"   # PASS [ 1.234s] lines carry wall time
```

For coverage, build instrumented into a target directory of its own and run
plain nextest. `cargo llvm-cov nextest` rebuilt the workspace for every
package in this repository.

```sh
export CARGO_TARGET_DIR="$PWD/target/coverage"
export RUSTFLAGS='-C instrument-coverage --cfg=coverage --cfg=trybuild_no_target'
export LLVM_PROFILE_FILE="$SCRATCH/profraw/%p-%14m.profraw"
mkdir -p "$SCRATCH/profraw"     # the profile runtime does not create it
cargo nextest run -p <crate> --locked --no-fail-fast "${FEATURES[@]}"
TOOLS="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
find "$SCRATCH/profraw" -name '*.profraw' > "$SCRATCH/profraw.list"
test -s "$SCRATCH/profraw.list" || echo "no profiles written"
"$TOOLS/llvm-profdata" merge -sparse -f "$SCRATCH/profraw.list" -o "$SCRATCH/<crate>.profdata"
set -- $(cargo nextest list -p <crate> --locked "${FEATURES[@]}" --message-format json |
  jq -r '.["rust-suites"][]["binary-path"]')
first=$1; shift
objects=(); for binary in "$@"; do objects+=(-object "$binary"); done
"$TOOLS/llvm-cov" export -format=lcov -instr-profile "$SCRATCH/<crate>.profdata" "$first" \
  "${objects[@]}" -ignore-filename-regex='/\.cargo/registry/|/rustc/|/target/' \
  > "$SCRATCH/<crate>-baseline.lcov"
```

Check each step's exit status rather than piping it: a pipeline hides a
failed merge. Raw profiles grow fast (about 100 GB for the workspace), so
delete them once merged.

Run one crate at a time: other agents build on the same machine. Keep
baseline failures in their own list. Each is a product bug until shown
otherwise (step 9).

When shared setup is a large share of the time, fix the harness before the
ledger, in its own change (step 6). In `storage-sqlite`, the migration replay
and SQLCipher settings of each test store were about 70% of the crate's and
the engine's test time (#2807 fixed both). Fixing them first means the ledger
judges each test by what it asserts, not by setup cost no single test can
remove.

Done when every test in scope has a recorded result and the coverage report
is saved.

## 2. Lanes

A lane is the unit of work in a campaign: one production owner (a module or
subsystem of the crate) together with the test files that prove its
contracts. One subagent writes its ledger and one PR changes it. A CI lane, a
job in the CI matrix, is unrelated.

Draw lanes along production owners, not file names: for `storage-sqlite`,
the base layer, migrations, protocol storage, the chat list, the timeline and
so on; for the engine, the subsystems in `crates/cgka-engine/AGENTS.md`. A
test file joins the lane of the owner most of its tests exercise, and unit
and integration tests of one owner share a lane. Size a lane so its PR is a
diff a reviewer reads whole; in `storage-sqlite` that was 70 to 220 tests.
Lanes share no test or production files, so their ledgers and PRs can run in
parallel. The routing files several lanes update (nextest config, workflows,
`AGENTS.md` file maps) are the only overlap: rebase a lane when another lane
that touched the same routing merges first.

Read the owner's tests in other crates (simulator scenarios, app journeys,
CLI end-to-end) with the lane so layer replays are visible. They stay out of
its file list and its PR.

Done when every test file in scope belongs to exactly one lane.

## 3. Ledger

Give each lane to its own read-only subagent. It reads every test in full,
including tables, proptest strategies and fixtures, and also the production
owner, its callers, its history and its CI routing. Every test function gets
one mark. A table or property is one entry unless its rows need different
marks.

- `R` retain: name the contract and the regression it catches. A test that
  only moves to a better binary or module stays `R`, with the move noted.
- `F` fix: keep the contract, repair the test (a vacuous negative, a
  sleep-to-settle, a misleading name).
- `C` consolidate: name the keeper that absorbs the assertion first: a
  sibling table row, a property, or a test at the owning layer.
- `D` delete: name the proof that remains, or why there is no contract.

Judge each test by its assertions, not its name. For every `C` and `D`, quote
the keeper's assertion lines that check the same behavior, edge cases
included; step 7 mutates production code against each one. A keeper must
carry the same risk, not only the same values:

- an in-memory keeper does not absorb a test that drops and reopens the store
  or reads through a second connection: persistence is its own contract;
- a keeper that checks selected columns does not absorb one that compares
  whole rows for each kind of row.

When unsure, mark `R` and say what would decide it. A wrong `C` or `D` costs
more than a missed one.

The same subagent can do step 5's triage for its lane: it has already read
the owner.

Done when every test in the lane has a mark and an evidence line.

## 4. Layer plan

The ledger is input, not the edit list. A second read-only pass, starting
from the ledger, looks for redundant layers: whole files or binaries that
replay a contract another suite owns. Name the keeper for each contract.
Prefer the cheapest layer that runs real production code over a fake network
(the in-memory relay, `TransportBus`) to a mocked collaborator, and keep one
higher-layer journey per user-visible flow for the risks that layer adds.

Coverage finds candidates. Run the suspect suite and its keeper alone with
the step 1 coverage build and compare the production owner's covered lines.
A suite whose covered lines are a subset of the keeper's, and whose
assertions the keeper already makes, is a `C` or `D` candidate. Equal
coverage is necessary, not sufficient: the mutation check in step 7 is the
proof.

Plan the cost work too: binaries to merge, sleeps to replace with awaited
state or paused time, tests to move to a cheaper layer, and the seams each
change unlocks. Correct any ledger errors this pass finds.

Done when each lane plan names its retired tests and files, the keeper for
each contract, the assertions to carry into keepers, the binaries to merge
and the seams to delete.

## 5. Gaps

Trimming is half of a campaign; the other half is the owner's contracts that
no test proves. From the step 1 report, list the production lines that no
test reaches, grouped by function, and read each group with its callers. Mark
each group:

- `T` test: a reachable contract with no proof, such as a persisted format,
  an error or rollback path with a visible effect, or an edge case of a public
  method. Add a test at the owning layer and show it fail under a matching
  mutation.
- `X` dead: no production caller. For code only this repository can reach
  (private items, and `pub` items no binding or host exports), grep the whole
  workspace. Exported surface (a UniFFI or C ABI export, an API that host apps
  or integrations link, a CLI command) has callers outside the repository: it
  is dead only when its owner confirms that no supported consumer uses it, so
  until then mark it `T` or `U` with the reason. File an issue or delete it in
  its own change, not in a lane.
- `U` untested on purpose: defensive code that cannot run, such as an
  impossible match arm or an invariant `expect`, or reachable code with no
  contract worth a test, such as a `Debug` impl that prints fields as they
  are. A `Debug` impl that redacts content, keys or ids is a privacy contract:
  `T`.

Coverage cannot see a line that runs while nothing asserts its result: a
persisted integer no test pins, or a trigger whose only probe fails first on
a `CHECK`. The ledger reads find these; list them with the `T` groups.

Rank the `T` groups by what a regression would cost. Add the top ones with the
lane and list the rest on the tracking issue. Each added test passes the
authoring gate in [SKILL.md](SKILL.md).

Done when every uncovered group in the owner has a mark and every added test
has a caught mutation.

## 6. Cutover

Change shared harnesses and support modules first, on their own, so lanes do
not collide. Then edit each lane on its own branch and worktree.

Check each ledger row against the code before applying it. When the row is
wrong, or you cannot tell, keep the test and record why. Moving a test to a
cheaper store keeps every reopen and second-connection read it had (the
storage rule in SKILL.md's Cost section): two `storage-sqlite` lanes dropped
reopens they judged incidental, and both reviewers flagged it.

With each
lane, add its step 5 tests, delete the seams it unlocks, update the routing
listed in SKILL.md's validation section, and update the test file maps in the
crate's `AGENTS.md` files. Put
durable test-ownership rules that came from real mistakes in this campaign
into the nearest `AGENTS.md`.

Done when the lane's keepers and siblings pass.

## 7. Preservation review

Before a lane leaves your machine, have an independent read-only reviewer
compare the deleted tests with the keepers. It looks for contracts that lost
their only proof, and for new assertions that cannot fail, such as a
rejection row production never reaches.

Check each finding's premise before acting on it. Run the test a reviewer
says cannot pass and build the target it says does not compile, both with
the features the crate's CI job uses (`cargo check -p <crate> --all-targets`
builds test targets; a plain `cargo check` does not). Apply the mutation it
says no test catches. In one `storage-sqlite` round, three reviewer blockers
fell to a single test run or `cargo check --tests`. Reject a finding only
with that evidence, and give it to the reviewer in the next round.

For each consolidated or restored contract, mutate the production owner once
by hand (flip a comparison, drop a guard, skip a write), confirm the keeper
fails, then restore the source until `git diff` shows no change to it. Rerun
the lane's coverage and compare it with the baseline; explain every
production line that lost coverage.

Done when every reported gap is restored or rejected with source evidence,
and every consolidated contract has a caught mutation.

## 8. Land

One lane per PR, through `.agents/skills/land-change`. A lane is a diff a
reviewer can read whole; a crate-wide diff is not. Land the shared-harness
PR first. Lanes that touch disjoint files can be reviewed and queued
together; the queue squashes, so rebase a lane onto master when one it
overlaps merges first.

Done when every lane PR is merged.

## 9. Product defects

A baseline failure that survives into a keeper is a bug. Fix it at its owner
in its own PR and its own session, not inside a lane. Prove the fix through
the real flow with a control: revert the fix and show the keeper fail on the
same harness. Record unrelated product problems you find as issues instead of
fixing them in the campaign.

Done when each repaired defect has a failing control and a passing fix.

## 10. Report

Post the [SKILL.md](SKILL.md) report on the tracking issue, plus:

- baseline and final test and production lines, tests, binaries and total
  wall time, with the slowest tests before and after;
- production-owner coverage before and after, with every lost line
  explained;
- lanes, retired layers and their keepers;
- preservation gaps found and the mutations that proved them closed;
- coverage gaps: the tests added and the mutations that proved them, the dead
  and unreachable code recorded, and the gaps left on the tracking issue;
- product defects with their control and fix.
