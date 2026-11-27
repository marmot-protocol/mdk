---
name: land-change
description: >-
  Take an mdk change from an issue or a request to a ready PR, and merge it
  when the user asked you to land it: confirm the issue is real and not a
  symptom of a deeper cause, build it test-first, verify locally with
  everything team CI no longer runs, get two independent cross-model reviews
  of the local diff, and open the PR only once that is done. Report mode
  (the default) stops at a green PR; land mode squash-merges it. Use when
  asked to fix an issue ("fix #123", an issue URL), build and ship a change,
  land, open a PR for, or merge a change.
---

# Land a change

Your machine is the only place this change is built and tested before it
reaches `master`. Team PR CI (`Required CI`) is a ~1-minute static gate:
commit signatures, formatting, static contracts, `cargo-audit`, and commit
trailers (advisory, except that a Rust crate change must record `just
dependents-nextest`), with zero Rust compile. There is no merge queue, and `master`
requires only `Required CI`, any CODEOWNERS approvals, and a branch that is up
to date with `master`. A ready PR that goes green can be merged a minute later
with nothing else between it and `master`. Post-merge `Canary` (bare-metal
Linux on `mdk-ci-1` plus hourly cross-platform `.github/workflows/canary.yml`)
builds and tests `master` afterwards, and the Bisect Agent reverts what breaks
it. That is a safety net, not your test run.

So verification (step 2) and review (step 3) are finished, on the exact commit
you push, **before** the PR is ready. Opening a ready PR means "this can
merge". Nothing reaches `master` by direct push, `gh pr merge --admin`, or an
unsigned commit.

Check `gh auth status` first; if it fails, ask the user to run `gh auth
login`.

## Report or land

Decide the mode before you build, because it decides where you stop:

- **Report** (the default): bring the PR to ready and green, then stop and
  report (step 6). The user merges, or tells you to.
- **Land**: merge it yourself (step 7) without asking. Only when the user said
  so: "land it", "merge it", "take it through to merge", or a list of issues
  with "land these on your own".

A request to fix or build something is not by itself permission to merge. If
you cannot tell which mode the user wants, ask once, now, in one line, and
carry on building while you wait. Do not save the question for the end.

Some stops apply in either mode: review that does not converge (step 3), a
failure you cannot classify or a second flake (step 5), or a CODEOWNERS
approval you cannot give yourself (step 7).

## 0. Start from an issue

Skip this step when the user gave a request rather than an issue.

1. **Read it.** `gh issue view <url-or-number> --comments`. Read the body,
   labels, comments, and linked issues and PRs. Restate the problem, expected
   vs actual behavior, and the reporter's constraints. If it is closed,
   already has a fix PR, or is too vague to act on, stop and say so.
   Otherwise assign yourself (`gh issue edit <n> --add-assignee @me`) without
   removing anyone.
2. **Confirm it still exists.** Reproduce it in the current code from the
   issue, not from memory: read the code, run the relevant tests or a minimal
   reproduction. If it is already fixed, no longer reproduces, or has a
   different effect now, stop and report what you found.
3. **Ask whether it is a symptom.** Before writing a fix: is the reported bug
   the real problem, or a symptom of a deeper cause that a broader fix would
   serve better? If it is a symptom, do not fix the symptom. Describe the root
   cause (what is wrong, where, and why this issue follows from it), scan the
   open issues for other symptoms (`gh issue list --state open --limit
   1000`), and bring both to the user. Continue only if they decide to.

The issue text becomes part of the review context in step 3.

## 1. Build

Before writing code, read review-local's
[karpathy-guidelines.md](../review-local/karpathy-guidelines.md) and
[simplicity-guidelines.md](../review-local/simplicity-guidelines.md). They are
the standard you build to, and the reviewers in step 3 judge the change
against the same two files.

Work on a new branch off `origin/master`, never on master itself. Sign every
commit as you make it (master rejects unsigned ones), so nothing is rewritten
after review.

- **Design it twice.** Unless the change is trivial (a one-line fix, a
  rename), sketch two genuinely different approaches before coding: where
  the change lives, what it adds or removes, what it assumes. Pick the one
  that is simpler for the reader and the callers, not the quicker to write.
  Write both down, with one line on why you chose one: it goes in the review
  context in step 3.
- **Bug fixes are test-first.** Write a test that captures the bug, run it,
  and confirm it fails for the reason the bug describes. Then make the
  smallest change that passes it. A test that never failed proves nothing.
  If you cannot write a correct failing test, stop and tell the user.
- **Every test you add or change passes the `test-audit` gate**: name the
  contract and the regression, at the cheapest layer that runs real code.
- **Keep it surgical and small.** Touch only what the change needs: reuse
  what exists, no speculative features or abstractions, no drive-by
  refactors, and a deleted line is as good as an added one.

Commit when it works.

## 2. Verify locally

This step stands in for the CI that team PRs no longer run. Run it on the
commit you will push: rebase onto `origin/master` first (`git fetch origin
master && git rebase origin/master`), and run it again after any later
rebase.

Always run what the root `AGENTS.md` Verification section and the nearest
crate `AGENTS.md` ask for:

```sh
cargo fmt --all
cargo clippy -p <crate> --all-targets --locked -- -D warnings                  # each crate you changed, default features
cargo clippy -p <crate> --all-targets --all-features --locked -- -D warnings   # each crate you changed, all features
just dependents-nextest                                                        # changed crates and every crate depending on one
```

`just dependents-nextest` is the Canary's workspace test run cut down to what
your change can break: the full suites of every crate changed since the
merge-base with `origin/master` (committed or not) and of every crate that
depends on one, `marmot-app`'s `relay_runtime` included, with the Canary's
test features. A change to a lower crate breaks the crates above it, and a
targeted run of your own crate never sees that. A runtime-crate change almost
always reaches `marmot-app`, about 8 minutes on a warm build: run it once, on
the commit you push, and use targeted `cargo nextest run -p <crate> -E
'test(<area>)'` while you iterate. Run one at a time per machine; concurrent
full suites saturate the CPU and timing-sensitive tests fail. When `wn-cli` is
affected it then runs `wn-cli`'s CLI end-to-end suite on its own, as CI does.
It leaves the simulator to the smoke below and the table rows. Record it in
`Local-Checks:`; `Required CI` rejects a team PR that changes a crate without it.

Clippy runs twice because CI does: code used only by feature-gated tests is
dead in the default build (#3826 broke `master` that way).

Stress every test you add or change, alone and without retries: `just
flake-stress <crate> 'test(=<name>)' 5`, adding `--features
test-policy-overrides` when its module needs it. A test that fails once in
five is a flake you are about to merge.

Then run the end-to-end smoke, unless the change touches only docs or CI
metadata:

```sh
# App runtime, account, engine, SQLite, Nostr adapter and relay plane against
# a separate local relay process, at production settlement (no test features).
cargo nextest run -p cgka-conformance-simulator --locked \
  --test app_runtime_journeys --test process_orchestrator \
  -E 'test(=public_app_03_late_join_and_messaging) | test(=engine_app_runtime_and_process_adapters_reach_equivalent_public_state)'

# The wn/wnd CLI and daemon over the same stack, against a mock relay.
cargo nextest run -p wn-cli --locked --test cli --features test-policy-overrides \
  -E 'test(=local_group_message_workflow_runs_through_the_dm_contract) | test(=daemon_start_status_execute_and_stop_are_user_facing_commands)'
```

Keep them as two commands: one invocation would unify features and turn
`test-policy-overrides` on for the simulator. Both run offline. The four tests
take under a minute; the two builds take a few minutes on a warm cache, and the
first simulator build is the heaviest compile in the workspace.

Then run each row below that your change matches. These are the Canary jobs a
team PR skips; a row you skip is a failure you push to `master`.

| Your change touches | Run |
| --- | --- |
| A `pub` item other crates use (type, field, variant, trait, signature, feature) | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` (`just dependents-nextest` already ran its dependents' tests) |
| `cgka-traits`, `cgka-engine`, `transport-nostr-peeler`, or anything they depend on | `just wasm-check` |
| A crate in `marmot-uniffi`'s tree (through `marmot-app` that is nearly every runtime crate; check with `cargo tree -p marmot-uniffi -i <crate>`) | `just android-check`, and `just binding-docs-gate` when the binding surface changed |
| Convergence, delivery, branch selection, or multi-client behavior | `just simulator-smoke` |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/`, `Justfile`, `vendor/`, or `.github/workflows/` | `just fast-ci` (includes `cargo-audit-policy-gate`); `cargo --locked audit` for dependency changes |
| Engine selection, convergence, freeze/settle, recovery, or protocol policy | `just convergence-verification-ci` (reference-model, mutation-adequacy, decision-gate, route-assurance and Stateright mirror tests against production code, then TLC) |
| `formal/liveness/` (`.tla`, `.cfg`, counterexamples), or the Stateright mirror (`cgka-conformance-simulator`'s `lifecycle_model.rs`) | `just tla-liveness tla-liveness-counterexample` |
| `formal/tamarin/` or `formal/pairing/` (`.spthy`, `policy_cases.json`), or `cgka-policy-casegen` | `just tamarin` |
| Behavior a formal model makes claims about (lifecycle fairness, freeze/settle, restart rehydration, device linking, pairing, selector policy), even with no model file changed | Check the model still matches the code with `.agents/skills/formal-verification`; if you change the model, run its row above. Say in the review context which model you checked |
| Code compiled only for Apple targets (`target_os = "ios"` or `"macos"`, `target_vendor = "apple"`; `marmot-account`'s keychain, for one), or `marmot-uniffi`'s Swift bindings | On a Mac: step 2's clippy for each changed crate, plus the commands of the `iOS keychain and Swift cancellation` and `MarmotKit native host lifecycle` jobs (`ios-account-clippy`, `marmotkit-native-host`): `cargo clippy -p marmot-account -p marmot-session --target aarch64-apple-ios --locked -- -D warnings`, `bash crates/marmot-uniffi/subscription-cancellation-smoke.sh`, `bash crates/marmot-uniffi/native-host-smoke.sh`. Without a Mac, those jobs stand in (`ci:apple`, below) only for the targets they build: the `marmot-account` and `marmot-session` libraries for iOS, and for macOS `marmot-uniffi`'s library, `uniffi-bindgen` binary and `native-host-relay` example with the `cli` feature, plus the libraries they depend on. Apple-only code in any other target, tests included (`marmot-uniffi`'s `runtime_threads` test, `wn-cli`'s daemon), needs a Mac |
| Code compiled only for Windows (`cfg(windows)`, `target_os = "windows"`; `fs-private`'s lease, for one) | On Windows: the `cargo nextest run` commands of the `Windows filesystem contracts` job (`windows-filesystem` in `.github/workflows/ci.yml`). Without Windows, that job stands in (`ci:full`, below) only for the targets it builds: the libraries and tests of `fs-private`, `marmot-account` and `marmot-forensics`, the `marmot-session` and `marmot-app` libraries with their unit tests, and the libraries they depend on. Windows-only code in any other target (`wn-cli`, or `marmot-session`'s integration tests) needs a Windows machine |
| A gate the nearest `AGENTS.md` names for the files you touched | that gate |

**A row you cannot run here.** Linux compiles neither Apple- nor Windows-only
code, and an unlabelled team PR compiles nothing at all, so a row you skip
locally is checked nowhere before merge. When a row needs an OS or tool your
machine lacks (a Mac, Windows, the Android NDK, `clang` for WASM), the
matching hosted job stands in for it, but only where that job builds the
Cargo target (library, test, example) and features you changed: label the PR `ci:apple` for the Apple row and `ci:full` for
any other, keep it a draft, and mark it ready only once that job passed on the
current head (steps 4 and 5). When no hosted job builds the code, stop and ask
the user for a machine that can run the row. Name each stand-in row and its
job in the PR's Verification section and in the report. Saying you skipped a
row does not cover it.

An initial cohort-release PR follows the release exception in the root
`AGENTS.md` Verification section instead of this step: run only
`just release-pr-preflight <version>`.

A test that fails locally is yours until shown otherwise. Before calling it
unrelated, `git fetch origin master` and run it on the merge-base in a
temporary worktree (`git worktree add --detach <tmp> "$(git merge-base HEAD
origin/master)"`), never by checking it out in your own; remove the worktree
afterwards. If it fails there too, note that in the PR. If it passes there,
your change broke it. Tests with real sockets or timing can stretch on a
loaded machine: rerun a failure alone before judging it.

Keep a list of every command you ran; it becomes the `Local-Checks:` trailer.

## 3. Review locally

Get two independent reviews of the whole local diff from the model families
that are not yours, using `.agents/skills/review-local` (default seats:
`codex`, `claude`, and `antigravity` with Gemini 4 Neon, with `cursor` as an
alternative and `opencode` as fallback). Its context file holds the issue or
the user's request, and the two designs from step 1 with why you chose one. You
are the author: you do not review your own change, and you do not decide alone
that it is good enough.

- Reviewers are read-only. They report findings; you make every change.
- Check a finding's premise before acting on it. When you reject one, say why
  in the next round's notes so the reviewer can answer it.
- Fix what is real, redo step 2 for what the fix touched, commit, and review
  again.
- You are done when both reviewers say `VERDICT: merge` on the same head
  commit. Record that commit as the **reviewed head**.
- Put the proposed `Release-Impact: none | patch | minor` trailer on the tip
  commit (or in the review context) **before** the final `review-local` round so
  both seats audit it alongside any `changelog.d/<slug>.md` fragments.

**When the verdicts still hold.** A later HEAD keeps the verdicts in exactly
two cases; anything else needs a new round, with no exception for small
fixes:

1. **Same files.** `git rev-parse HEAD^{tree}` equals `git rev-parse
   <reviewed-head>^{tree}`: a reworded message, added trailers, an added
   signature.
2. **Clean rebase.** A rebase onto newer `master` that applied without
   conflicts and with no edits, where every one of your commits is unchanged.
   Before rebasing, note the old base and head (`old_base=$(git merge-base
   HEAD origin/master) old_head=$(git rev-parse HEAD)`). After it, run:

   ```sh
   git range-diff "$old_base..$old_head" origin/master..HEAD
   ```

   Every line must show `=`. A `!`, `<`, or `>` (a changed patch, including
   changed context lines, or a dropped or added commit) needs a new round.
   A clean rebase still needs step 2 again on the rebased head, sized to what
   `master` brought in (below): that rerun is what catches your change
   breaking against the new `master` code.

**Re-verifying after a clean rebase.** Look at what the new `master` commits
touched: `git diff --stat "$old_base" origin/master`.

- **No overlap**: they touch none of the crates you changed, none of their
  dependencies, and none of their dependents (`cargo tree -p <your-crate> -i
  <their-crate>` finds a dependency; `cargo tree -i <your-crate> --workspace`
  lists dependents). Rerun only `cargo fmt --all`, `cargo clippy` for
  your crates, and the targeted `cargo nextest` for your change.
- **Overlap**, or `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`,
  `.cargo/`, or `vendor/` changed: rerun all of step 2, including the
  end-to-end smoke and every table row your change matches.

Keep the rerun short so another merge is less likely to land while it runs;
`Local-Checks:` names what you reran.

When a case holds, the new HEAD becomes the reviewed head. To need a rebase
less often, rebase onto `origin/master` before the final round.

**Trailers.** Once both seats say `VERDICT: merge`, amend the signed tip
commit message (`git commit --amend -S`, preserving `HEAD^{tree}`) to record
`Local-Checks:` and `Local-Review:` while keeping the reviewed
`Release-Impact:` unchanged, then verify with `just pr-trailers-check`. The
CI trailer check is advisory apart from the `just dependents-nextest` record;
for you all of it is required.

```text
Local-Checks: <commands run locally>
Local-Review: <seat-a> + <seat-b> merge @ <reviewed-short-sha>
Release-Impact: none | patch | minor
```

`Local-Review:` names the commit the seats read; keep it after a clean rebase.
Changing `Release-Impact:` during or after the amend invalidates the prior
review and requires a fresh `review-local` round. Ensure `Release-Impact:`
agrees with any `changelog.d/<slug>.md` fragments (`### Breaking changes`
requires `minor`; user-facing entries forbid `none`).

Count the rounds; the report says how many it took.

### When review does not converge

As soon as a round's verdicts are in, before fixing anything, apply
review-local's "When review does not converge": when to stop, what stopping
means, what to report, and how far the user's answer lets you go.

## 4. Open the PR

Push only when all of these hold on HEAD:

- HEAD is the reviewed head (step 3).
- Step 2 ran on HEAD, or on a commit with the same tree.
- Every step 2 row your change matches ran locally. A row a hosted job
  stands in for (step 2) keeps the PR a draft until that job passes on HEAD.
- HEAD is on top of current `origin/master` (`git fetch origin master`; `git
  merge-base --is-ancestor origin/master HEAD`). If master moved, rebase and
  apply step 3's clean-rebase rule before pushing.
- `just pr-trailers-check` passes.

Then push the branch and open a ready (not draft) PR with a description from
`.agents/skills/gh-create-pr`, including its Verification section with the
end-to-end smoke and every step 2 row you ran or left to a hosted job. Put
`Fixes #<n>` below Problem and Fix when there is an issue.

If you need to open the PR before that (to share a branch, to wait on a
human, or to let a stand-in job run), open it as a draft and mark it ready
(`gh pr ready <pr>`) only once the list above holds. Give a stand-in job's
label at creation (`gh pr create --draft --label ci:apple`); a label added
later applies only to the next push or to "Re-run all jobs".

The same list holds for every head a ready PR gets, including a fix or a
rebase from step 5. When its readiness rests on a stand-in job, mark it draft
again (`gh pr ready <pr> --undo`) before pushing the new head, and ready once
the job passed on it.

## 5. Make it ready

The PR is ready when its head is the reviewed head (step 3), its required
checks pass, every stand-in job from step 2 passed on that head, it is up to
date with `master`, and it has no conflicts. Read its state:

```sh
gh pr view <pr> --json headRefOid,isDraft,mergeable,mergeStateStatus,reviewDecision
gh pr checks <pr>
```

`headRefOid` must be the reviewed head. A green `Required CI` does not say
which jobs ran: on an unlabelled team PR it passes with no Rust compiled. Find
each stand-in job by its display name (its `name:` in `ci.yml`, as step 2
gives it) in `gh pr checks <pr>` and confirm it shows `pass`;
a job that is missing or `skipping` means the label was not applied to this
head.

A draft is never ready, whatever `mergeStateStatus` says: GitHub reports
some drafts as `DRAFT` and others as their underlying state, `CLEAN`
included. While `isDraft` is `true`, work through the table below, then run
`gh pr ready <pr>` once everything above holds, and read the state again. Go
to step 6 or 7 only with `isDraft: false`. Then act on `mergeStateStatus`:

| State | Meaning | What to do |
| --- | --- | --- |
| `CLEAN`, `HAS_HOOKS` | Checks pass, nothing blocks | Ready: step 6 or 7 |
| `UNSTABLE` | A non-required check failed | Classify it with the table below; ready once it is not yours |
| `BEHIND` | Master moved; `master` requires an up-to-date branch | Rebase on `origin/master`. Clean rebase (step 3): rerun step 2 as sized there, push. Otherwise redo steps 2 and 3, push. Check again. After the third `BEHIND` in a row, stop and report instead of rebasing again |
| `DIRTY` | Conflicts | Rebase and resolve, redo steps 2 and 3 (resolving a conflict is never a clean rebase), push, check again |
| `BLOCKED` | Required checks pending or failing, or a required human review | Wait for checks (below). If only a human approval is missing (`reviewDecision: REVIEW_REQUIRED`), it is ready: step 6, in either mode |
| `UNKNOWN` | GitHub is still computing | Check again shortly |
| `DRAFT` | A draft whose underlying state GitHub hides | Wait for checks (below), then handle it as a draft (above) |

To wait for checks, use your host's PR watching if it has it, instead of a
polling loop. The only required check, `Required CI`, does not exist until the
other CI jobs finish, so `gh pr checks <pr> --required` reports "no required
checks reported" straight away, even with `--watch`. Wait for the head's
`ci.yml` run instead (`gh run list --workflow ci.yml --event pull_request
--commit <sha>`, then `gh run watch <id>`) and read `gh pr checks <pr>
--required` after it. "No required checks reported" once that run has finished
means it ended without creating the check (for example the workflow failed to
start): treat it as a failed gate.

When a check fails, read `gh run view <id> --log-failed`. The failed job is
the cause; jobs shown as cancelled were stopped by it.

Classify a failure by the job that failed, not by who opened the PR: a team
PR labelled `ci:apple` or `ci:full` builds and tests Rust like an external
one.

**A static job** (`PR signatures`, `Classify CI changes`, `Rust format`,
`Rust audit`: all an unlabelled team PR runs) compiles no Rust, so a failure
is a signature, formatting, static-contract, trailer, or `cargo-audit`
problem. Run the failing command locally (`cargo fmt --all --check`, the
`just` gate the job names, `cargo --locked audit`), fix it, redo step 2 for
what the fix touched and step 3 (a fix is a new tree), and push. An audit
advisory that also fails on `origin/master` is master being broken (table
below).

**Any other job** builds or tests Rust. Reproduce a failing test by name
(`cargo nextest run -p <crate> -E 'test(=<name>)'`) after `git fetch origin
master`, so every comparison uses current master. A macOS or Windows job you
cannot run here is judged from its log and the same job's latest result on
`master` in `Canary`; its hosted rerun confirms the fix. Then decide which
case it is:

| Case | How you know | What to do |
| --- | --- | --- |
| Your bug | Fails on your branch, passes on `origin/master` | Fix it, redo steps 2 and 3, push |
| Conflict with a change that landed ahead of you | Passes on your branch alone, fails once rebased onto `origin/master` | Rebase, fix the interaction, redo steps 2–3, push |
| Flake | Intermittent, also fails on `origin/master`, or in code your change cannot reach | Leave the test alone. Open or update an issue for it (search the test name first), then rerun the job once |
| Master is frozen (`tree-state=red`) | `Required CI` reports Meltdown Mode (`tree-state=red`) | Only `tree-fix` or `revert` PRs should merge until Canary turns green. If your PR fixes or reverts the broken commit, apply the `tree-fix` or `revert` label and re-run all jobs (not just `Required CI`, because `changes` recomputes labels and `tree-state`); otherwise wait for recovery, then re-run all jobs |
| Master is broken | The same failure in master's own CI or Canary | Find the open PR fixing it and rebase once it lands. Do not fix it again in your PR |

A flake already on the `just flake-report` leaderboard, or with an open
`Flaky:` issue, is already tracked: do only what the flake row asks (update
the open issue, or open one if there is none) and leave the fix to the
leaderboard's order.

Bring in the user, with the run link and what you found, after a second flake
or for any failure you cannot classify. Never skip, weaken, ignore or
retry-loop a test to get a change through.

Human review comments that arrive on the PR are handled with the
`gh-address-comments` skill.

## 6. Report mode: stop and report

Stop here and tell the user, in a few lines:

```text
<PR URL> is ready for you to review and merge.
- Review: <seat> and <seat> both said merge at <short sha>, after <n> round(s).
- CI: required checks green. Branch up to date with master, no conflicts.
- <Only if it needs their attention: a finding you rejected and why, a flake
  you filed, a step 2 row a hosted job stood in for, a stated limitation, or
  a human approval still required.>
```

Nothing else: no finding lists, no round-by-round history, no diff tour.

If the user later tells you to merge it, go to step 7.

## 7. Land mode: merge

Merge only in land mode, and only the head that was verified and reviewed.

1. Wait until `Required CI` is green on the head and every stand-in job from
   step 2 passed on it (step 5). If a CODEOWNERS approval is
   required and missing, stop and report as in step 6, naming the approval;
   you cannot give it yourself.
2. Unless the PR carries the `tree-fix` or `revert` label, confirm `master`
   is not in Meltdown Mode right before merging (`Required CI` is a check-time
   gate and GitHub does not retroactively invalidate an older green check or
   block a concurrent freeze at merge time):

   ```sh
   git fetch --no-tags --depth=1 origin refs/heads/tree-state && git show FETCH_HEAD:state.json
   ```

   Proceed only when `"state"` is `"green"`.
3. Re-read `gh pr view <pr> --json headRefOid,isDraft,mergeStateStatus`.
   `headRefOid` must be the reviewed head, `isDraft` must be `false`, and
   `mergeStateStatus` must be
   `CLEAN` or `HAS_HOOKS`. `BEHIND` means another PR landed first: handle it
   with the step 5 table, then start this list again.
4. Squash-merge right away, pinned to that head; any wait between green and
   the merge is time for another PR to land first:

   ```sh
   gh pr merge <pr> --squash --match-head-commit <sha>
   ```

   If the merge is refused because the branch is no longer up to date, treat
   it as `BEHIND`.

Do not use `--auto`: auto-merge stays on when someone with write access
pushes, and `--match-head-commit` is checked only when it is turned on, so a
later, unreviewed commit could merge. Do not use `--admin`, and do not push
to `master`.

After the merge, confirm the squash commit on master (`gh pr view <pr> --json
mergeCommit`), delete the branch and your worktree, and report the merged
commit in one line. Post-merge Canary and the Bisect Agent take it from
there: you do not wait for Canary. With a list of issues, move to the next
one.
