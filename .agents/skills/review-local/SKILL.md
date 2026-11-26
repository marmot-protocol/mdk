---
name: review-local
description: >-
  Get two independent, read-only reviews of the current branch's committed
  local diff from the two default agent seats that are not you (Codex GPT-6.1
  Sol, Claude Opus 5.5, Antigravity Gemini 4 Neon), before any PR exists, with
  Cursor Grok medium-fast as an alternative and free Numes models in OpenCode
  as the fallback when seats are out of usage. Then answer their findings.
  Nothing is posted to GitHub. Use from land-change step 3, or when asked for a
  self-review, a local review, or to have the other agents review a change,
  branch or worktree.
---

# Review a local change

You are the author. Do not review your own change. Launch the two seats that
are not you, collect their verdicts, and answer their findings. Reviewers
never edit, commit, push or post; the only thing a review produces is its
final message.

Nothing goes to GitHub. The round covers one commit on your machine.

## Seats

| Seat | Model |
| --- | --- |
| `codex` | `gpt-6.1-sol`, medium reasoning |
| `claude` | `claude-opus-5-5` (not the `opus` alias), `--effort medium` |
| `antigravity` | `gemini-4-neon`, `--effort medium` (via `agy`) |
| `cursor` | alternative / first fallback: the newest `grok-*-medium-fast` in `agent --list-models`, resolved at launch (Cursor names the reasoning level in the model id) |
| `opencode` | last-resort fallback, through `numes run opencode`: the first of Kimi K3.1 Pro `#medium`, GLM 5.3 Flash `#high`, DeepSeek V4.1 Flash `#high`, Nemotron 3 Ultra `#high` (all `:free`) that finishes with a verdict |

Your seat is your **host product**, not the model in this session:

- Codex → launch `claude` and `antigravity`
- Claude → launch `antigravity` and `codex`
- Antigravity → launch `claude` and `codex`
- Cursor → launch `claude` and `codex`
- OpenCode, or any other builder → launch the two default seats outside your
  session's model family: on a GPT model `claude` and `antigravity`, on a Claude
  model `antigravity` and `codex`, on a Gemini model `claude` and `codex`,
  otherwise `claude` and `codex`

If you cannot tell which host you are in, ask. Do not guess. If a seat's CLI
is missing or not logged in, stop and tell the user. Do not improvise a
launch: the restrictions live only in `scripts/launch-review.sh`. A teammate
without one of these CLIs adds a seat there, from another model family and
with equivalent restrictions.

**Alternatives and fallback.** `cursor` is a viable alternative to any default
seat when the user asks for it, and is the first fallback when a default seat
cannot run because its product is out of usage (its log shows a usage or rate
limit, or the user tells you it is out). Fall back in order, skipping your own
host, your session's model family, and any seat already in the round: unused
default seat (for example `antigravity` when Cursor is the host) → `cursor` →
`opencode`. If none remains, stop. Tell the user which seat you replaced and
why. If the other seat already finished on the same `HEAD_SHA`, its verdict
stands: prepare a round with the replacement alone, with the same `--round`,
`--notes` and `--user-approved` as the round it replaces (`prepare-round.sh
cursor --round <n> --context ...`, or `opencode`). The `opencode` seat tries
its models in order and moves to the next only when one exits nonzero or ends
without a verdict; the review's first line names the model that answered, and
`opencode.log` records each attempt.

## What this protects against

Each seat works in its own throwaway checkout of one commit, reads only its
own read-only copy of the inputs, and is never shown the other
seat's output. Every launch strips write tools and MCP servers (see the
comments in `scripts/launch-review.sh`). The end-of-round check catches
accidental writes. It is a tripwire, not a sandbox: a reviewer that
deliberately changes file modes or writes outside its checkout would need an
OS sandbox or a container to stop it.

## Scripts

All four live in `scripts/` next to this file. Call each as **one bare
command** with its absolute path and literal arguments: no `$VARS`, pipes,
redirects or command substitution. That keeps them inside simple permission
allow rules, so a launch does not stall on a prompt.

| Script | Does |
| --- | --- |
| `prepare-round.sh <seat-a> [<seat-b>] --round n [--user-approved] [--context file] [--notes file] [--base ref]` | Fetches, finds the merge-base with the default branch, makes each seat's checkout and read-only input (diff, context, guidelines, prompt), and prints `REVIEW_DIR`, `OUT_DIR`, `BASE`, `HEAD_SHA`, `ROUND`. Refuses a round past 3 without `--user-approved` |
| `launch-review.sh <seat> <review-dir> <out-dir>` | Runs one seat with its restriction flags. Review → `<out-dir>/<seat>.md`, stamped with the seat and model; log → `<out-dir>/<seat>.log` |
| `check-seat.sh <seat> <review-dir> <out-dir> <exit-code>` | Decides one seat: exit 0, a final `VERDICT:` line, and a checkout with no writes |
| `cleanup-round.sh <review-dir>` | Removes the round's checkouts and inputs |

## Prepare a round

**Commit first.** `prepare-round.sh` refuses to run with uncommitted or
untracked files, so every verdict covers exactly what you will ship.

**Write the context.** Reviewers judge whether the change should exist, not
only whether the code is right, so they need to know what it is for. Write a
short file in your scratch space: the issue (`gh issue view <n> --comments`)
or the user's request, plus any constraints they gave, and the designs you
considered with why you chose one. Then, from the repository:

```sh
bash /abs/repo/.agents/skills/review-local/scripts/prepare-round.sh claude codex --round 1 --context /abs/context.md
```

**Number the round.** `--round` is required. Round 1 is a change's first
review, and each round after you answer findings adds one. A seat rerun after
a failure, or a fallback replacing a seat, keeps the round's number. Once both
seats have said merge on some head, the count is over: a later round (after a
rebase that had to resolve a conflict, say) starts again at 1. A clean rebase
needs no new round; see land-change step 3. The script refuses a round past 3 unless you
pass `--user-approved` (see [When review does not
converge](#when-review-does-not-converge)).

The prompt tells each reviewer to read the repo's `AGENTS.md`/`CLAUDE.md`
files, then:

1. **Question the need**: is the change needed now, does it treat a symptom
   rather than the root cause, is there a smaller change (including none)?
2. **Review the code** for real defects, and verify the stated release impact
   (`Release-Impact: none | patch | minor` and any `changelog.d/` fragments):
   a breaking public API, binding, storage-migration, or wire change must be
   classified `minor` with a `### Breaking changes` fragment. A behavior change
   a model under `formal/` makes claims about must update the model or say why
   it still matches.
3. **Judge simplicity** against [karpathy-guidelines.md](karpathy-guidelines.md)
   and [simplicity-guidelines.md](simplicity-guidelines.md): fewer lines, net
   deletions, no needless abstraction, duplication, dead code or drive-by
   changes.

Each finding has a severity (blocker, should-fix or minor), `file:line`, a
failure scenario or cost, and a fix. The review ends in `VERDICT: merge` when
no blocker or should-fix remains, and `VERDICT: changes-needed` otherwise.
Minor findings never block a merge. A rare edge case is minor when its effect
is recoverable, and a should-fix when it can lose data, open a security hole
or leave state that cannot recover.

For a later round, write the previous findings and your answer to each
(fixed in `<sha>`, or rejected and why) to a file in your scratch space, and
pass it as `--notes`. The base defaults to `origin/HEAD`.

## Launch

Start both seats in parallel, each as its own background task that your host
tracks, so you are notified when each exits and you get its exit code:

```sh
bash /abs/repo/.agents/skills/review-local/scripts/launch-review.sh claude /abs/review-dir /abs/out-dir
bash /abs/repo/.agents/skills/review-local/scripts/launch-review.sh codex  /abs/review-dir /abs/out-dir
```

Tell the user which two seats you started, `HEAD_SHA`, and `OUT_DIR`. You can
keep working in your own worktree while they run; the round is pinned to
`HEAD_SHA`.

A quiet log while a seat runs is normal: these CLIs buffer until they exit.
If a log already shows a fatal error (bad model id, auth, usage limit), kill
that seat and count it as failed. Kill and fail any seat still running 30
minutes after launch. Thirty minutes is a ceiling, not a wait.

## Collect

Decide each seat as soon as it exits; do not hold one decision for the other:

```sh
bash /abs/repo/.agents/skills/review-local/scripts/check-seat.sh claude /abs/review-dir /abs/out-dir <exit-code>
```

Anything but `OK` is a failure, whatever the review says. Tell the user right
away: the seat, the reason, the log excerpt and any paths it wrote. Then
check that seat's launch flags.

If a seat fails, rerun it once in a freshly prepared round with the same
`--round`, `--notes` and `--user-approved` (one that is out of usage goes to
its fallback instead). If it fails again, stop and tell the user; one review
is not enough.

When both seats are decided, run `cleanup-round.sh` on `REVIEW_DIR`. Keep
`OUT_DIR` until you have answered the findings.

## Answer the findings

Read `<out-dir>/<seat>.md` for both seats. Do not ask the user which findings
to take.

**Check whether to stop first.** Before you fix anything, check this round
against [When review does not converge](#when-review-does-not-converge). If
it says stop, do not patch or commit: check premises only as far as the
report needs, write the report and end your turn.

- Check each finding's premise before acting on it: run the test it says
  fails, build what it says does not compile, read the code it cites.
- Fix what is real, surgically. Rerun the tests the fix touches, and commit.
- When you reject a finding, write down why, with the evidence. That goes in
  the next round's `--notes`.
- Skip noise: informational notes and nits not worth a code change.
- When both seats say merge, leave their minor findings out of this change.
  Any code change would need a new round. Put the ones worth keeping in the
  PR description or a follow-up issue.

**Standalone** (the user asked for a review): do one round and one answer
pass, then stop and report each seat's verdict, what you fixed, and what you
rejected and why. Do not start another round unless asked.

**From land-change**: repeat rounds until both seats say `VERDICT: merge` on
the same head commit, but stop as soon as the next section says to.

## When review does not converge

Three rounds without two merge verdicts usually means the design, or the
request itself, is flawed, not that the next patch will finish the job. A
round that ends with two merge verdicts is done, and nothing here applies.
Otherwise stop patching at the first of:

- round 3 ends without two merge verdicts;
- the round's blocker or should-fix findings share a root cause with the
  previous round's (minor findings do not count);
- a fix would weaken an invariant documented in an `AGENTS.md` or
  `CLAUDE.md`.

Signs of a flawed design or request:

- Flip-flopping: fixing condition A breaks B, and fixing B brings A back.
- A growing tail: each round finds new edge cases in the same machinery, and
  the list keeps getting longer.
- Fixes that need special cases, flags or toggles to keep the design standing.
- Reviewers who disagree about what the change should do, not just how.
- A fix that works only by assuming something the system does not guarantee
  (timing, ordering, sizes, a trusted peer).

**Stopping means ending your turn with a report.** If a seat is still
running, wait for its verdict first, but do not start fixing anything. Then
step back. Reread the original request and its issue, and the whole branch,
not only the last round, and ask:

- Does the change still solve the problem that was asked?
- Was that problem stated correctly?
- Which assumption is producing the findings?
- Is there a structurally different approach?
- Did an existing pattern get reused under assumptions that no longer hold?

Write the report as your reply to the person who asked for the change, so
they decide with concrete context:

- the request as you understood it, and anything in it that now looks wrong;
- what you built and why;
- the findings across all rounds, grouped by root cause rather than by round;
- the flaw you think is behind them, with your evidence;
- two or three ways forward (for example a different design, a narrower scope,
  accepting a stated limitation, or reworking the request), each with its
  cost, plus your recommendation.

Then end your turn. Do not boil the report down to a multiple-choice question
about which patch to apply. Picking a patch is not the decision the user has
to make here. Do not open a PR or start another round until they answer.

**After they decide**, their answer covers one more round, unless they say
otherwise. Run it as the next number with `--user-approved`. If it ends
without two merge verdicts, stop and report again, with the new findings
added to the grouping.
