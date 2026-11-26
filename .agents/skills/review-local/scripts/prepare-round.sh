#!/usr/bin/env bash
# Prepare one review round: a throwaway detached checkout of HEAD for each
# seat, a read-only input directory holding the diff, the context, the
# guidelines and the prompt, and an output directory no reviewer is given.
#
# usage: prepare-round.sh <seat-a> [<seat-b>] --round n [--user-approved]
#                         [--context file] [--notes file] [--base ref]
#   seat       codex | claude | cursor | opencode; one seat only to replace a
#              seat that could not run (see SKILL.md)
#   --round    this round's number (SKILL.md says how to count). Rounds after
#              the first need --notes. Rounds past the limit need
#              --user-approved: the user read the stop report and chose to go on
#   --context  what the change is for: the issue text or the user's request
#   --notes    later rounds only: previous findings and the author's answers
#   --base     defaults to the remote's default branch (origin/HEAD)
#
# Run from inside the repository. Prints shell assignments for REVIEW_DIR,
# OUT_DIR, BASE, HEAD_SHA and ROUND.
set -euo pipefail

# Rounds without two merge verdicts before the author must stop and report.
round_limit=3

usage() {
  echo "usage: prepare-round.sh <seat-a> [<seat-b>] --round n [--user-approved] [--context file] [--notes file] [--base ref]" >&2
  exit 2
}

seats=()
while [[ $# -gt 0 && $1 != --* ]]; do
  seats+=("$1")
  shift
done
[[ ${#seats[@]} -eq 1 || ${#seats[@]} -eq 2 ]] || usage
context_file=""
notes_file=""
base_ref=""
round=""
user_approved=0
while [[ $# -gt 0 ]]; do
  if [[ $1 == --user-approved ]]; then
    user_approved=1
    shift
    continue
  fi
  [[ $# -ge 2 ]] || usage
  case "$1" in
    --round) round=$2 ;;
    --context) context_file=$2 ;;
    --notes) notes_file=$2 ;;
    --base) base_ref=$2 ;;
    *) usage ;;
  esac
  shift 2
done

if [[ ! $round =~ ^[1-9][0-9]*$ ]]; then
  echo "--round <n> is required: 1 for a change's first round (see SKILL.md)" >&2
  exit 2
fi
if [[ $round -gt 1 && -z $notes_file ]]; then
  echo "round $round needs --notes: the previous findings and your answer to each" >&2
  exit 2
fi
if [[ $round -gt $round_limit && $user_approved -eq 0 ]]; then
  echo "round $round is past the limit of $round_limit. Stop: write the report in" >&2
  echo "SKILL.md's 'When review does not converge', end your turn and wait for the" >&2
  echo "user. Pass --user-approved only once they have chosen to go on." >&2
  exit 3
fi

for seat in "${seats[@]}"; do
  case "$seat" in
    codex | claude | cursor | opencode) ;;
    *) echo "unknown seat: $seat (want codex, claude, cursor or opencode)" >&2; exit 2 ;;
  esac
done
if [[ ${#seats[@]} -eq 2 && "${seats[0]}" == "${seats[1]}" ]]; then
  echo "the two seats must differ" >&2
  exit 2
fi
for file in "$context_file" "$notes_file"; do
  if [[ -n "$file" && ! -f "$file" ]]; then
    echo "file not found: $file" >&2
    exit 2
  fi
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guidelines=("$script_dir/../karpathy-guidelines.md" "$script_dir/../simplicity-guidelines.md")
repo_root="$(git rev-parse --show-toplevel)"
# Name the repository from its remote: worktree directories have arbitrary names.
repo_url="$(git remote get-url origin 2>/dev/null || echo "$repo_root")"
repo_name="$(basename "${repo_url%/}" .git)"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "uncommitted or untracked files; commit (or remove) them first:" >&2
  git status --short >&2
  exit 1
fi
if [[ -z "$context_file" ]]; then
  echo "warning: no --context; reviewers cannot judge whether the change is needed" >&2
fi

git fetch --quiet origin
if [[ -z "$base_ref" ]]; then
  base_ref="$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)"
  if [[ -z "$base_ref" ]]; then
    for candidate in origin/main origin/master; do
      if git rev-parse --verify --quiet "$candidate" >/dev/null; then
        base_ref=$candidate
        break
      fi
    done
  fi
fi
if [[ -z "$base_ref" ]]; then
  echo "cannot find the base branch; pass --base" >&2
  exit 1
fi

base="$(git merge-base HEAD "$base_ref")"
head_sha="$(git rev-parse HEAD)"
if [[ "$base" == "$head_sha" ]]; then
  echo "HEAD has no commits beyond $base_ref; nothing to review" >&2
  exit 1
fi

tmp_root="${TMPDIR:-/tmp}"
tmp_root="${tmp_root%/}"
# Resolve symlinks (macOS: /var -> /private/var) so every path in the prompt
# matches what the reviewers resolve, including OpenCode's allow rule.
review_dir="$(cd "$(mktemp -d "$tmp_root/review-local.XXXXXX")" && pwd -P)"
out_dir="$(cd "$(mktemp -d "$tmp_root/review-out.XXXXXX")" && pwd -P)"
# A failure past this point would leave worktrees registered in the repository
# under a path nobody was told; remove the partial round.
trap 'bash "$script_dir/cleanup-round.sh" "$review_dir" >&2; rmdir "$out_dir"' ERR

for seat in "${seats[@]}"; do
  git worktree add --quiet --detach "$review_dir/$seat" "$head_sha"
  input="$review_dir/$seat-input"
  mkdir "$input"
  git diff "$base" "$head_sha" > "$input/change.diff"
  cp "${guidelines[@]}" "$input/"
  if [[ -n "$context_file" ]]; then
    cp "$context_file" "$input/context.md"
  fi

  {
    cat <<EOF
Review a change to the $repo_name repository before it is merged. Your
working directory is a checkout of the head commit. The change is the diff in
$input/change.diff (base $base, head $head_sha).
EOF
    if [[ -n "$context_file" ]]; then
      echo "What the change is for (the issue or request) is in $input/context.md."
    fi
    cat <<EOF

Read the repository's agent instructions (AGENTS.md or CLAUDE.md at the root,
and the nearest one for every file the diff touches), then read the
surrounding code you need. Do not edit files, commit, push or post anything.

1. Question the need first. Should this change land at all? Is it needed now,
   or speculative? Does it treat a symptom where a root-cause fix would be
   better? Is there a simpler or smaller change, including doing nothing? If
   the context lists the designs the author considered, say whether the
   chosen one is the simpler. If the premise is weak, that can be the main
   finding.

2. Then review the code. Report real defects: wrong behavior, broken
   documented invariants, missing or wrong tests for changed behavior, torn
   multi-step state changes, unsafe logging of private data, security
   problems. Also check release-impact classification when stated in the
   commit or context: flag as should-fix if a breaking public API, binding,
   storage-migration, or protocol change is labeled none/patch instead of
   minor, or lacks a matching changelog.d/ fragment when user-facing.

3. Judge simplicity as a defect class, not a style nit. Use
   $input/karpathy-guidelines.md and $input/simplicity-guidelines.md.
   Fewer lines is better and net deletions are a win.
   Flag unnecessary abstractions, duplication of existing code, dead code,
   speculative flexibility, and drive-by changes outside the change's scope.

Skip pure style preferences. Every finding must be actionable and worth the
author's time. For each give severity, file:line, a concrete failure scenario
or cost, and a suggested fix. Severities:

- blocker: the change should not land as built. It is wrong, unsafe, breaks
  a documented invariant, or should not exist.
- should-fix: a real defect that normal use or a normal caller will hit, or
  a rare one whose damage is severe or cannot be undone: data loss or
  corruption, a security or privacy hole, state that cannot recover.
- minor: everything else worth saying, such as a small cleanup, a weak test
  name, or a rare edge case whose effect is recoverable (a retry, a reload or
  a restart fixes it).

The verdict follows from severity. Say VERDICT: merge when no blocker or
should-fix remains, even if you list minor findings; minor findings never
block a merge. Say VERDICT: changes-needed only for a blocker or a
should-fix.
EOF
    if [[ -n "$notes_file" ]]; then
      printf '\nThis is a later round. The previous findings and the author'"'"'s answers\n'
      printf 'follow. Say whether each is resolved, and answer each rejection.\n\n'
      cat "$notes_file"
    fi
    printf '\nEnd with exactly one line: VERDICT: merge or VERDICT: changes-needed\n'
  } > "$input/prompt.md"

  chmod -R a-w "$input"
done

printf 'REVIEW_DIR=%q\nOUT_DIR=%q\nBASE=%q\nHEAD_SHA=%q\nROUND=%s\n' \
  "$review_dir" "$out_dir" "$base" "$head_sha" "$round"
