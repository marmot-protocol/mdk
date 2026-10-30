#!/usr/bin/env bash
# Every selected test must appear in exactly one shard, including ignored tests.
# Usage: check_ci_partitions.sh <scheme>:<shards> <nextest list args...>,
# with the same nextest partition scheme the shards run (`count` or `slice`).
set -euo pipefail

if [[ ! "${1:-}" =~ ^(count|slice):[1-9][0-9]*$ ]]; then
    echo "usage: $0 <count|slice>:<shards> <nextest list args...>" >&2
    exit 2
fi
scheme="${1%%:*}"
partitions="${1#*:}"
shift
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

list_tests() {
    cargo nextest list --message-format json "$@" |
        jq -r '."rust-suites" | to_entries[] | .key as $suite | .value.testcases | to_entries[] | select(.value["filter-match"].status == "matches") | "\($suite)::\(.key)"'
}

list_tests "$@" | sort > "$work_dir/expected"
test -s "$work_dir/expected"
for ((partition = 1; partition <= partitions; partition++)); do
    list_tests "$@" --partition "$scheme:$partition/$partitions" >> "$work_dir/actual"
done
sort "$work_dir/actual" -o "$work_dir/actual"
diff -u "$work_dir/expected" "$work_dir/actual"
