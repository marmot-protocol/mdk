---
name: review-local
description: >-
  Get two independent, read-only reviews of the current branch's local diff
  from model families other than the author's, before any PR exists. Use from
  land-change step 2, or when asked to have the other agents review a local
  change, branch or worktree.
---

# Review a local change

You are the author. Launch the two seats that are not you, collect their
verdicts, and answer their findings. Reviewers never edit, commit, push or
post; the only thing a review produces is its final message.

## Seats

| Seat | Model |
| --- | --- |
| Codex | `gpt-6.1-sol` |
| Claude | `claude-opus-5-5` (not the `opus` alias) |
| Cursor | the newest `grok-*-high-fast` in `agent --list-models` |

Your seat is your host product. If you cannot tell which it is, ask. If a
teammate's setup lacks one of these CLIs, any reviewer from another model
family can take that seat.

## What this protects against

The setup below keeps a reviewer that follows its instructions from changing
anything by accident, and keeps the two reviews independent: each seat reads
only its own copy of the inputs and its own checkout, and no seat is shown the
other's output. It does not contain a reviewer that deliberately works around
it, for example by changing file permissions or writing outside its checkout;
that would need an OS sandbox or a container. The end-of-round check is a
tripwire for accidental writes, not proof that nothing was written.

## Prepare a round

From the repository root, with `<seat-a>` and `<seat-b>` the two seats you
launch (`codex`, `claude` or `cursor`):

```sh
git fetch origin master
REVIEW_DIR="$(mktemp -d "${TMPDIR:-/tmp}/review-local.XXXXXX")"
OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/review-out.XXXXXX")"
BASE="$(git merge-base HEAD origin/master)"
HEAD_SHA="$(git rev-parse HEAD)"
for seat in <seat-a> <seat-b>; do
  git worktree add --detach "$REVIEW_DIR/$seat" "$HEAD_SHA"
  mkdir "$REVIEW_DIR/$seat-input"
  git diff "$BASE" HEAD > "$REVIEW_DIR/$seat-input/change.diff"
done
```

Each seat works in its own throwaway checkout of `HEAD_SHA`, never in your
worktree. The round covers exactly that commit, and you can keep working while
it runs. Commit before you review; uncommitted changes are not in the round.
Each seat's output goes to `$OUT_DIR`, which no reviewer is given.

Write `$REVIEW_DIR/<seat>-input/prompt.md` for each seat from this template,
then make the inputs read-only with `chmod -R a-w "$REVIEW_DIR/<seat>-input"`:

```text
Review a change to the mdk repository before it is merged. Your working
directory is a checkout of the head commit. The change is the diff in
<REVIEW_DIR>/<seat>-input/change.diff (base <BASE>, head <HEAD_SHA>).
Read AGENTS.md and the nearest AGENTS.md for every file the diff touches, then
read the surrounding code you need. Do not edit files, commit, push or post
anything.

Report real defects only: wrong behavior, broken AGENTS.md invariants, missing
or wrong tests for changed behavior, torn multi-step state changes,
privacy-unsafe logging, security problems. Skip style nits.

For each finding give severity (blocker, should-fix, minor), file:line, a
concrete failure scenario, and a suggested fix.

<Later rounds only: the previous round's findings and the author's response
to each — fixed in <sha>, or rejected and why. Say whether each is resolved.>

End with exactly one line: VERDICT: merge or VERDICT: changes-needed
```

## Launch

Start your two seats in parallel, each as its own background job, and keep
each PID. Each seat writes its review to `$OUT_DIR/<seat>.md`:

```sh
# Codex: the read-only sandbox blocks writes; --ignore-user-config drops the
# MCP servers in ~/.codex/config.toml, which run outside the sandbox.
codex exec --ignore-user-config -s read-only -m gpt-6.1-sol -C "$REVIEW_DIR/codex" \
  -o "$OUT_DIR/codex.md" - < "$REVIEW_DIR/codex-input/prompt.md" > "$OUT_DIR/codex.log" 2>&1

# Claude: --restricted ignores personal settings, --tools leaves only read
# tools, and --strict-mcp-config drops every MCP server and claude.ai connector.
(cd "$REVIEW_DIR/claude" && claude -p --restricted --tools Read Grep Glob --strict-mcp-config \
  --add-dir "$REVIEW_DIR/claude-input" --model claude-opus-5-5 \
  < "$REVIEW_DIR/claude-input/prompt.md") > "$OUT_DIR/claude.md" 2> "$OUT_DIR/claude.log"

# Cursor: ask mode inside the sandbox; ask mode also refuses MCP tools that
# write. Take the model id from `agent --list-models`.
agent -p --mode ask --sandbox enabled --trust --workspace "$REVIEW_DIR/cursor" \
  --add-dir "$REVIEW_DIR/cursor-input" --model <grok-*-high-fast> --output-format text \
  "$(cat "$REVIEW_DIR/cursor-input/prompt.md")" > "$OUT_DIR/cursor.md" 2> "$OUT_DIR/cursor.log"
```

Keep every restriction flag. Checked on 2026-10-17 and 2026-10-18:

- Without `--restricted --tools`, the Claude reviewer could write into the
  checkout. Without `--strict-mcp-config`, it still had the user's MCP servers
  and claude.ai connectors (Drive, Docs, Sheets, Gmail), which edit or share
  outside the checkout.
- Without `--sandbox enabled`, the Cursor reviewer could write into the
  checkout. In ask mode it refused a writing MCP tool call.
- Without `--ignore-user-config`, the Codex reviewer had a JavaScript REPL
  MCP server that is not covered by its read-only sandbox.

## Collect

A seat succeeded when all three hold:

- its process exited 0;
- `$OUT_DIR/<seat>.md` ends with a `VERDICT:` line;
- `git -C "$REVIEW_DIR/<seat>" status --porcelain --ignored=matching` prints
  nothing. A fresh checkout has no ignored files, so this also catches writes
  to ignored paths such as `target/` or `reviews/`.

Anything else is a failure, whatever the verdict says. Report the seat, the exit
code, a log excerpt, and any paths it wrote, then check that seat's launch
flags. A quiet log while the process runs is normal. Kill and count as failed
any seat still running after 30 minutes.

If one seat fails, rerun it once in a fresh checkout. If it fails again, stop
and tell the person who asked for the change; one review is not enough to land.

When a seat is decided, remove its checkout with
`git worktree remove --force "$REVIEW_DIR/<seat>"`. When the round is over,
remove the rest with `chmod -R u+w "$REVIEW_DIR" && rm -rf "$REVIEW_DIR"`.
Then answer the findings as `land-change` step 2 describes, and start the next
round from "Prepare a round" with new directories.
