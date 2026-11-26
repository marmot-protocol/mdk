---
name: land-change
description: >-
  Take an mdk change from an issue or a request to a PR that is ready to
  merge: confirm the issue is real and not a symptom of a deeper cause, build
  it test-first, verify locally with the end-to-end smoke, get two independent
  cross-model reviews of the local diff, open the PR, and bring it to green CI
  with no conflicts. Then stop and report. Enqueues only when the user asks,
  and then owns the merge-queue result until the change merges. Use when asked
  to fix an issue ("fix #123", an issue URL), build and ship a change, land,
  open a PR for, enqueue, or merge a change.
---

# Land a change

The merge queue is the only full gate. Verification and review happen on your
machine, the PR carries the change to CI, and the queue runs the full CI
matrix on the exact commit that becomes master. Nothing reaches master any
other way: no direct pushes, no admin merges, no ruleset bypass.

You own the change until it is a ready PR: CI green, both reviewers say
merge, no conflicts. Then stop and report (step 6). Enqueue only when the user
asks (step 7), and then own the queue result until the change merges.

Check `gh auth status` first; if it fails, ask the user to run `gh auth
login`.

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

Run what the root `AGENTS.md` Verification section and the nearest crate
`AGENTS.md` ask for:

```sh
cargo fmt --all
cargo clippy -p <crate> --all-targets --all-features --locked -- -D warnings   # each crate you changed
cargo nextest run -p <crate> -E 'test(<area>)'                                 # tests covering the change
```

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

## 3. Review locally

Get two independent reviews of the whole local diff from the model families
that are not yours, using `.agents/skills/review-local`. Its context file
holds the issue or the user's request, and the two designs from step 1 with
why you chose one. You are the author: you do not review your own change, and
you do not decide alone that it is good enough.

- Reviewers are read-only. They report findings; you make every change.
- Check a finding's premise before acting on it. When you reject one, say why
  in the next round's notes so the reviewer can answer it.
- Fix what is real, redo step 2 for what the fix touched, commit, and review
  again.
- You are done when both reviewers say `VERDICT: merge` on the same head
  commit. Record that commit as the **reviewed head**.
- A later change of HEAD keeps the verdicts only when the files are exactly
  the same: `git rev-parse HEAD^{tree}` equals `git rev-parse
  <reviewed-head>^{tree}`. That covers a reworded message or an added
  signature. The new HEAD then becomes the reviewed head. Anything else,
  including any rebase, needs a new round; there is no exception for small
  fixes. To make that rarer, rebase onto `origin/master` before the final
  round.
- Once both seats say `VERDICT: merge`, amend the signed tip commit message
  (`git commit --amend -S`, preserving `HEAD^{tree}`) to record the three
  required trailers and check them with `just pr-trailers-check`:

  ```text
  Local-Checks: <commands run locally>
  Local-Review: <seat-a> + <seat-b> merge @ <reviewed-short-sha>
  Release-Impact: none | patch | minor
  ```

  Ensure `Release-Impact:` agrees with any `changelog.d/<slug>.md` fragments
  (`### Breaking changes` requires `minor`; user-facing entries forbid `none`)
  and that no earlier commit on the branch declares a conflicting
  `Release-Impact:`.

Count the rounds; the report in step 6 says how many it took.

### When review does not converge

As soon as a round's verdicts are in, before fixing anything, apply
review-local's "When review does not converge": when to stop, what stopping
means, what to report, and how far the user's answer lets you go.

## 4. Open the PR

Push the branch and open a ready (not draft) PR with a description from
`.agents/skills/gh-create-pr`, including its Verification section; list the
end-to-end smoke there too. Put `Fixes #<n>` below Problem and Fix when there
is an issue.

## 5. Make it ready

The PR is ready when its head is the reviewed head (step 3), its required
checks pass, and it can merge without conflicts. Read its state:

```sh
gh pr view <pr> --json headRefOid,mergeable,mergeStateStatus,reviewDecision
```

`headRefOid` must be the reviewed head. Then act on
`mergeStateStatus`:

| State | Meaning | What to do |
| --- | --- | --- |
| `CLEAN`, `HAS_HOOKS` | Checks pass, nothing blocks | Ready: step 6 |
| `UNSTABLE` | A non-required check failed | Classify it with the table below; ready once it is not yours |
| `BEHIND` | Master moved and the branch must be up to date | Rebase on `origin/master`, redo step 2, redo step 3 (a rebase needs a new round), push, check again |
| `DIRTY` | Conflicts | Rebase and resolve, redo steps 2 and 3, push, check again |
| `BLOCKED` | Required checks pending or failing, or a required human review | Wait for checks (below). If only a human approval is missing (`reviewDecision: REVIEW_REQUIRED`), it is ready: step 6 |
| `UNKNOWN` | GitHub is still computing | Check again shortly |

PR CI is the pre-check of a few minutes; the full matrix runs in the merge
queue (step 7). To wait for it, use your host's PR watching if it has it,
instead of a polling loop. The only required check, `Required CI`, does not
exist until the other CI jobs finish, so `gh pr checks <pr> --required`
reports "no required checks reported" straight away, even with `--watch`.
Wait for the head's `ci.yml` run instead (`gh run list --workflow ci.yml
--event pull_request --commit <sha>`, then `gh run watch <id>`) and read
`gh pr checks <pr> --required` after it. "No required checks reported" once
that run has finished means it ended without creating the check (for example
the workflow failed to start): treat it as a failed pre-check.

When a check fails, read `gh run view <id> --log-failed`. The failed job is
the cause; jobs shown as cancelled were stopped by it. Reproduce the failing
test by name (`cargo nextest run -p <crate> -E 'test(=<name>)'`) after `git
fetch origin master`, so every comparison uses current master, then decide
which case it is:

| Case | How you know | What to do |
| --- | --- | --- |
| Your bug | Fails on your branch, passes on `origin/master` | Fix it, redo steps 2 and 3, push |
| Conflict with a change that landed ahead of you | Passes on your branch alone, fails once rebased onto `origin/master` | Rebase, fix the interaction, redo steps 2–3, push |
| Flake | Intermittent, also fails on `origin/master`, or in code your change cannot reach | Leave the test alone. Open or update an issue for it (search the test name first), then rerun the job once |
| Master is broken | The same failure in master's own CI | Find the open PR fixing it and rebase once it lands. Do not fix it again in your PR |

A flake already on the `just flake-report` leaderboard, or with an open
`Flaky:` issue, is already tracked: do only what the flake row asks (update
the open issue, or open one if there is none) and leave the fix to the
leaderboard's order.

Bring in the user, with the run link and what you found, after a second flake
or for any failure you cannot classify. Never skip, weaken, ignore or
retry-loop a test to get a change through.

Human review comments that arrive on the PR are handled with the
`gh-address-comments` skill.

## 6. Stop and report

Stop here and tell the user, in a few lines:

```text
<PR URL> is ready for you to review and merge.
- Review: <seat> and <seat> both said merge at <short sha>, after <n> round(s).
- CI: required checks green. Branch up to date with master, no conflicts.
- <Only if it needs their attention: a finding you rejected and why, a flake
  you filed, a stated limitation, or a human approval still required.>
```

Nothing else: no finding lists, no round-by-round history, no diff tour.

## 7. Merge (only when asked)

Merge only when the user asks, and only the head that was verified and
reviewed: confirm `headRefOid` is still the reviewed head.

Master has a merge queue, so enqueue that head. `expectedHeadOid` makes the
enqueue fail if the PR head has moved:

```sh
gh api graphql \
  -f query='mutation($id: ID!, $oid: GitObjectID!) { enqueuePullRequest(input: {pullRequestId: $id, expectedHeadOid: $oid}) { mergeQueueEntry { position } } }' \
  -f id="$(gh pr view <pr> --json id -q .id)" \
  -f oid=<sha>
```

An enqueue refused with `Required status check "Required CI" is expected`
means CI has not finished on the head yet. Wait and enqueue again. Do not use
`gh pr merge`; repository auto-merge is off, so it fails.

Then own the queue run until the PR merges. A queue run takes about 30–35
minutes; one that fails stops at its first failed job, and the queue ejects
the PR within minutes. Use your host's PR watching if it has it; otherwise
check every few minutes:

```sh
gh api graphql -F owner='{owner}' -F repo='{repo}' -F n=<pr> -f query='
query($owner: String!, $repo: String!, $n: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $n) {
      state isInMergeQueue
      timelineItems(last: 1, itemTypes: [ADDED_TO_MERGE_QUEUE_EVENT, REMOVED_FROM_MERGE_QUEUE_EVENT]) {
        nodes {
          __typename
          ... on AddedToMergeQueueEvent { createdAt }
          ... on RemovedFromMergeQueueEvent { createdAt reason }
        }
      }
    }
  }
}'
```

Judge only the latest queue event:

- `state: MERGED`: done.
- Latest is `AddedToMergeQueueEvent`: queued, keep waiting. A rebuild because
  a PR ahead of yours failed is not your failure.
- Latest is `RemovedFromMergeQueueEvent` after your enqueue, with the PR
  still `OPEN`: the queue ejected it, and `reason` says why. Find its run
  (its branch is `gh-readonly-queue/master/pr-<pr>-<sha>`):

  ```sh
  gh run list --workflow ci.yml --event merge_group --limit 50 \
    --json databaseId,headBranch,conclusion,createdAt \
    --jq '.[] | select(.headBranch | startswith("gh-readonly-queue/master/pr-<pr>-"))'
  ```

  Classify the failure with the step 5 table, fix it, bring the PR back to
  ready, and enqueue again.
- No queue event since your enqueue: not recorded yet, check again.

After the merge, confirm the squash commit on master (`gh pr view <pr> --json
mergeCommit`), delete the branch and your worktree, and report the merged
commit in one line.
