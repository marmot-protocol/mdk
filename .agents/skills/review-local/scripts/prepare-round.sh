#!/usr/bin/env bash
# Prepare one review round: a throwaway detached checkout of HEAD for each
# seat, a read-only input directory holding the diff, the context, the
# guidelines and the prompt, and an output directory no reviewer is given.
#
# usage: prepare-round.sh <seat-a> [<seat-b>] [--context file] [--notes file] [--base ref]
#   seat       codex | claude | cursor | opencode; one seat only to replace a
#              seat that could not run (see SKILL.md)
#   --context  what the change is for: the issue text or the user's request
#   --notes    later rounds only: previous findings and the author's answers
#   --base     defaults to the remote's default branch (origin/HEAD)
#
# Run from inside the repository. Prints shell assignments for REVIEW_DIR,
# OUT_DIR, BASE and HEAD_SHA.
set -euo pipefail

usage() {
  echo "usage: prepare-round.sh <seat-a> [<seat-b>] [--context file] [--notes file] [--base ref]" >&2
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
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || usage
  case "$1" in
    --context) context_file=$2 ;;
    --notes) notes_file=$2 ;;
    --base) base_ref=$2 ;;
    *) usage ;;
  esac
  shift 2
done

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
cd "$repo_root"
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
review_dir="$(mktemp -d "$tmp_root/review-local.XXXXXX")"
out_dir="$(mktemp -d "$tmp_root/review-out.XXXXXX")"

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
   problems.

3. Judge simplicity as a defect class, not a style nit. Use
   $input/karpathy-guidelines.md and $input/simplicity-guidelines.md.
   Fewer lines is better and net deletions are a win.
   Flag unnecessary abstractions, duplication of existing code, dead code,
   speculative flexibility, and drive-by changes outside the change's scope.

Skip pure style preferences. Every finding must be actionable and worth the
author's time. For each give severity (blocker, should-fix, minor),
file:line, a concrete failure scenario or cost, and a suggested fix.
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

printf 'REVIEW_DIR=%q\nOUT_DIR=%q\nBASE=%q\nHEAD_SHA=%q\n' \
  "$review_dir" "$out_dir" "$base" "$head_sha"
