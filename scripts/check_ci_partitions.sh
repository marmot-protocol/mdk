#!/usr/bin/env bash
# Every selected test must appear in exactly one shard, including ignored tests.
set -euo pipefail

partitions="$1"
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
    list_tests "$@" --partition "count:$partition/$partitions" >> "$work_dir/actual"
done
sort "$work_dir/actual" -o "$work_dir/actual"
diff -u "$work_dir/expected" "$work_dir/actual"
