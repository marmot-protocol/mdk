#!/usr/bin/env bash
# Remove a round's checkouts and inputs. Runs from any directory: the
# repository is found through the checkouts. Leaves OUT_DIR alone so the
# reviews can still be read.
#
# usage: cleanup-round.sh <review-dir>
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: cleanup-round.sh <review-dir>" >&2
  exit 2
fi

review_dir=${1%/}
# Only a round directory itself: a mktemp name whose physical parent is a temp
# root. That refuses a seat checkout and any path that leaves the temp root.
refuse() { echo "refusing to remove $review_dir: not a review-local round" >&2; exit 2; }
case "$(basename "$review_dir")" in review-local.??????) ;; *) refuse ;; esac
parent="$(cd "$(dirname "$review_dir")" 2>/dev/null && pwd -P)" || refuse
case "$parent" in
  "$(cd "${TMPDIR:-/tmp}" && pwd -P)" | "$(cd /tmp && pwd -P)") ;;
  *) refuse ;;
esac
review_dir="$parent/$(basename "$review_dir")"

git_dir=""
for seat in codex claude antigravity cursor opencode; do
  if [[ -d "$review_dir/$seat" ]]; then
    git_dir="$(git -C "$review_dir/$seat" rev-parse --path-format=absolute --git-common-dir)"
    git --git-dir="$git_dir" worktree remove --force "$review_dir/$seat"
  fi
done
if [[ -n "$git_dir" ]]; then
  git --git-dir="$git_dir" worktree prune
fi

chmod -R u+w "$review_dir"
rm -rf "$review_dir"
echo "removed $review_dir"
