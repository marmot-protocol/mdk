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

review_dir=$1
tmp_root="${TMPDIR:-/tmp}"
tmp_root="${tmp_root%/}"
case "$review_dir" in
  "$tmp_root"/review-local.* | /tmp/review-local.* | /private/tmp/review-local.* | \
    /var/folders/*/review-local.* | /private/var/folders/*/review-local.*) ;;
  *) echo "refusing to remove $review_dir: not a review-local round" >&2; exit 2 ;;
esac

git_dir=""
for seat in codex claude cursor opencode; do
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
