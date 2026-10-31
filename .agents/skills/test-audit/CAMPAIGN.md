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
- each test's result and wall time from one run with the features CI uses
  for the crate (the crate `AGENTS.md` names them; many need
  `test-policy-overrides`);
- what the shared setup costs: time one store open, fixture or process start
  alone, and count how many each test pays for. nextest runs every test in
  its own process, so anything a test binary builds once per process is built
  again by every test;
- line coverage of the production owner, saved for later diffs.

```sh
cargo nextest run -p <crate> --locked --no-fail-fast --features <ci-features> \
  2>&1 | tee "$SCRATCH/<crate>-baseline.log"          # PASS [ 1.234s] lines carry wall time
```

For coverage, build instrumented into a target directory of its own and run
plain nextest. `cargo llvm-cov nextest` rebuilt the workspace for every
package in this repository.

```sh
export CARGO_TARGET_DIR="$PWD/target/coverage"
export RUSTFLAGS='-C instrument-coverage --cfg=coverage --cfg=trybuild_no_target'
export LLVM_PROFILE_FILE="$SCRATCH/profraw/%p-%14m.profraw"
cargo nextest run -p <crate> --locked --no-fail-fast --features <ci-features>
TOOLS="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
find "$SCRATCH/profraw" -name '*.profraw' > "$SCRATCH/profraw.list"
"$TOOLS/llvm-profdata" merge -sparse -f "$SCRATCH/profraw.list" -o "$SCRATCH/<crate>.profdata"
set -- $(cargo nextest list -p <crate> --locked --features <ci-features> --message-format json |
  jq -r '.["rust-suites"][]["binary-path"]')
first=$1; shift
"$TOOLS/llvm-cov" export -format=lcov -instr-profile "$SCRATCH/<crate>.profdata" "$first" \
  $(printf -- '-object %s ' "$@") -ignore-filename-regex='/\.cargo/registry/|/rustc/|/target/' \
  > "$SCRATCH/<crate>-baseline.lcov"
```

Check each step's exit status rather than piping it: a pipeline hides a
failed merge. Raw profiles grow fast (about 100 GB for the workspace), so
delete them once merged.

Run one crate at a time: other agents build on the same machine. Keep
baseline failures in their own list. Each is a product bug until shown
otherwise (step 8).

When shared setup is a large share of the time, fix the harness before the
ledger, in its own change (step 5). In `storage-sqlite`, the migration replay
and SQLCipher settings of each test store were about 70% of the crate's and
the engine's test time. Fixing them first means the ledger judges each test by
what it asserts, not by setup cost no single test can remove.

Done when every test in scope has a recorded result and the coverage report
is saved.

## 2. Lanes

Split the scope into lanes along production owners, not file names: for
`storage-sqlite`, the base layer, migrations, OpenMLS storage, protocol
storage and snapshots; for the engine, the subsystems in
`crates/cgka-engine/AGENTS.md`. Unit and integration tests of one owner share
a lane. Include the owner's tests that live elsewhere (simulator scenarios,
app journeys, CLI end-to-end) so layer replays are visible, even if those
tests are not edited in this campaign.

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

Judge each test by its assertions, not its name.

Done when every test in the lane has a mark and an evidence line.

## 4. Layer plan

The ledger is input, not the edit list. A second read-only pass, starting
from the ledger, looks for redundant layers: whole files or binaries that
replay a contract another suite owns. Name the keeper for each contract.
Prefer the cheapest layer that runs real production code over a fake network
(the in-memory relay, `TransportBus`) to a mocked collaborator, and keep one
higher-layer journey per user-visible flow for the risks that layer adds.

Coverage finds candidates. Run the suspect suite and its keeper alone with
the step 1 coverage build and compare the production owner's covered lines. A suite
whose covered lines are a subset of the keeper's, and whose assertions the
keeper already makes, is a `C` or `D` candidate. Equal coverage is necessary,
not sufficient: the mutation check in step 6 is the proof.

Plan the cost work too: binaries to merge, sleeps to replace with awaited
state or paused time, tests to move to a cheaper layer, and the seams each
change unlocks. Correct any ledger errors this pass finds.

Done when each lane plan names its retired tests and files, the keeper for
each contract, the assertions to carry into keepers, the binaries to merge
and the seams to delete.

## 5. Cutover

Edit one lane at a time. Change shared harnesses and support modules first,
on their own, so lanes do not collide. With each lane, delete the seams it
unlocks, update the routing listed in SKILL.md's validation section, and
update the crate's `tests/AGENTS.md` file map. Put durable test-ownership
rules that came from real mistakes in this campaign into the nearest
`AGENTS.md`.

Done when the lane's keepers and siblings pass.

## 6. Preservation review

Before a lane leaves your machine, have an independent read-only reviewer
compare the deleted tests with the keepers. It looks for contracts that lost
their only proof, and for new assertions that cannot fail, such as a
rejection row production never reaches.

For each consolidated or restored contract, mutate the production owner once
by hand (flip a comparison, drop a guard, skip a write), confirm the keeper
fails, then restore the source until `git diff` shows no change to it. Rerun
the lane's coverage and compare it with the baseline; explain every
production line that lost coverage.

Done when every reported gap is restored or rejected with source evidence,
and every consolidated contract has a caught mutation.

## 7. Land

One lane per PR, through `.agents/skills/land-change`. A lane is a diff a
reviewer can read whole; a crate-wide diff is not. The queue squashes, so
land the shared-harness PR first and rebase each lane onto master after the
previous one merges.

Done when every lane PR is merged.

## 8. Product defects

A baseline failure that survives into a keeper is a bug. Fix it at its owner
in its own PR and its own session, not inside a lane. Prove the fix through
the real flow with a control: revert the fix and show the keeper fail on the
same harness. Record unrelated product problems you find as issues instead of
fixing them in the campaign.

Done when each repaired defect has a failing control and a passing fix.

## 9. Report

Post the [SKILL.md](SKILL.md) report on the tracking issue, plus:

- baseline and final test and production lines, tests, binaries and total
  wall time, with the slowest tests before and after;
- production-owner coverage before and after, with every lost line
  explained;
- lanes, retired layers and their keepers;
- preservation gaps found and the mutations that proved them closed;
- product defects with their control and fix.
