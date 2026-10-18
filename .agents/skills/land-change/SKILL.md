---
name: land-change
description: >-
  Take a finished mdk change from a local branch to master: targeted local
  verification, the local end-to-end smoke, two independent cross-model reviews
  of the local diff, a short PR, the merge queue, and owning the queue result
  until the change merges. Use when a change is ready to ship, or when asked to
  land, ship, open a PR for, enqueue, or merge a change.
---

# Land a change

The merge queue is the only full gate. Verification and review happen on your
machine, the PR carries the change into the queue, and the queue runs the full
CI matrix on the exact commit that becomes master. Nothing reaches master any
other way: no direct pushes, no admin merges, no ruleset bypass.

You own the change until it is on master. Opening the PR is the midpoint.

## 1. Verify locally

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
first simulator build is the heaviest compile in the workspace. The tests use
real sockets and settlement windows, so a heavily loaded machine can stretch
them. If one fails, rerun it alone before treating the failure as yours.

An initial cohort-release PR follows the release exception in the root
`AGENTS.md` Verification section instead of this step: run only
`just release-pr-preflight <version>`.

A test that fails locally is yours until shown otherwise. Before calling it
unrelated, run `git fetch origin master` and then run the test on the
merge-base (`git merge-base HEAD origin/master`). If it fails there too, note
it in the PR. If it passes there, your change broke it.

## 2. Review locally

Get two independent reviews of the whole local diff from model families other
than yours, using `.agents/skills/review-local`. You are the author: you do not
review your own change, and you do not decide alone that it is good enough.

- Reviewers are read-only. They report findings; you make every change.
- Check a finding's premise before acting on it. When you reject one, say why
  in the next round's prompt so the reviewer can answer it.
- Fix what is real, redo step 1 for what the fix touched, and review again.
- You are done when both reviewers recommend merging the same head commit. A
  follow-up commit that only answers a reviewer's note does not need another
  round; a substantive change does.

### When review does not converge

Three rounds without two merge recommendations usually means the design, or
the request itself, is flawed, not that the next patch will finish the job.
Stop patching at the first of:

- three rounds without two merge recommendations;
- a round whose findings share a root cause with the previous round's;
- a fix that would weaken an invariant documented in an `AGENTS.md`.

Signs of a flawed design or request:

- Flip-flopping: fixing condition A breaks B, and fixing B brings A back.
- A growing tail: each round finds new edge cases in the same machinery, and
  the list keeps getting longer.
- Fixes that need special cases, flags or toggles to keep the design standing.
- Reviewers who disagree about what the change should do, not just how.
- A fix that works only by assuming something the system does not guarantee
  (timing, ordering, sizes, a trusted peer).

Then step back before reporting. Reread the original request and its issue,
and the whole branch, not only the last round. Then ask:

- Does the change still solve the problem that was asked?
- Was that problem stated correctly?
- Which assumption is producing the findings?
- Is there a structurally different approach?
- Did an existing pattern get reused under assumptions that no longer hold?

Report to the person who asked for the change, so they decide with concrete
context:

- the request as you understood it, and anything in it that now looks wrong;
- what you built and why;
- the findings across all rounds, grouped by root cause rather than by round;
- the flaw you think is behind them, with your evidence;
- two or three ways forward (for example a different design, a narrower scope,
  accepting a stated limitation, or reworking the request), each with its
  cost, plus your recommendation.

Do not open the PR or start another round until they decide.

## 3. Open the PR

Sign every commit; master rejects unsigned ones. Push the branch and open the
PR with a description a person can scan in thirty seconds:

```markdown
## Problem

<At most four sentences: what was wrong, and who feels it. If nobody outside
the codebase does, say so.>

## Fix

<At most four sentences: the idea of the change. No file, function or flag
lists.>

## Verification

- Local: <each command run, one line each, including the end-to-end smoke>
- Review: <seat> and <seat> recommend merge at <short sha>
```

`Fixes #<n>` and implementation notes go below these sections. Keep review
transcripts, finding lists and round-by-round history out of the PR.

## 4. Enqueue

Wait for the PR's required pre-check, then enqueue the head you verified and
had reviewed:

```sh
gh pr checks <pr> --required --watch --fail-fast &&
  gh api graphql \
    -f query='mutation($id: ID!, $oid: GitObjectID!) { enqueuePullRequest(input: {pullRequestId: $id, expectedHeadOid: $oid}) { mergeQueueEntry { position } } }' \
    -f id="$(gh pr view <pr> --json id -q .id)" \
    -f oid="$(git rev-parse HEAD)"
```

The `&&` keeps a failed pre-check from enqueueing. `expectedHeadOid` makes the
enqueue fail if the PR head is not the commit you verified. Do not use
`gh pr merge`; repository auto-merge is off, so it fails.

If the pre-check fails, open this head's pull-request run
(`gh run list --workflow ci.yml --commit "$(git rev-parse HEAD)"`, then
`gh run view <id> --log-failed`) and classify the failure with the table in
step 5.

## 5. Own the queue result

A queue run takes about 30–35 minutes. If your host watches PRs for you, use
that. Otherwise check every few minutes until the PR merges:

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

The node is the PR's latest queue event. Removal events stay in the timeline, so
judge only the latest one:

- `state: MERGED`: done, go to step 6.
- Latest is `AddedToMergeQueueEvent`: queued, keep waiting. A rebuild because
  a PR ahead of yours failed is not your failure.
- Latest is `RemovedFromMergeQueueEvent` after your enqueue, with the PR still
  `OPEN`: the queue ejected it, and `reason` says why (for example
  `failed_checks`). Fixing that is now your job.
- No queue event since your enqueue: it has not been recorded yet, so check
  again.

On an ejection, find your PR's queue run. Its branch is named
`gh-readonly-queue/master/pr-<pr>-<sha>`, and other PRs' runs share the list:

```sh
gh run list --workflow ci.yml --event merge_group --limit 50 \
  --json databaseId,headBranch,conclusion,createdAt \
  --jq '.[] | select(.headBranch | startswith("gh-readonly-queue/master/pr-<pr>-"))'
```

Read the newest one with `gh run view <id> --log-failed`, and reproduce the
failing test by name (`cargo nextest run -p <crate> -E 'test(=<name>)'`). Run
`git fetch origin master` first: changes may have landed while your PR was in
the queue, and every comparison below must use current master. Then decide
which case it is:

| Case | How you know | What to do |
| --- | --- | --- |
| Your bug | Fails on your branch, passes on `origin/master` | Fix it, redo step 1 (and step 2 if the fix is substantive), push, enqueue again |
| Conflict with a change that landed ahead of you | Passes on your branch alone, fails once rebased onto `origin/master` | Rebase, fix the interaction, redo steps 1–2, push, enqueue again |
| Flake | Intermittent, also fails on `origin/master`, or in code your change cannot reach | Leave the test alone. Open or update an issue for it (search the test name first), then enqueue again once |
| Master is broken | The same failure in master's own CI | Find the open PR fixing it and rebase once it lands. Do not fix it again in your PR |

Bring in the person who asked for the change, with the run link and what you
found, after a second flake ejection or for any case you cannot classify. Never
skip, weaken, ignore or retry-loop a test to get a change through the queue.

## 6. After merge

Confirm the squash commit on master (`gh pr view <pr> --json mergeCommit`),
delete the branch and your worktree, and report the merged commit.
