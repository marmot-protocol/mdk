#!/usr/bin/env bash
# Check the output and checkout of one finished seat. Pass the exit code the
# launch returned. Prints the verdict and exits 0 only when the seat
# succeeded; on failure prints why and exits 1.
#
# usage: check-seat.sh <seat> <review-dir> <out-dir> <launch-exit-code>
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: check-seat.sh <seat> <review-dir> <out-dir> <launch-exit-code>" >&2
  exit 2
fi

seat=$1
review_dir=$2
out_dir=$3
exit_code=$4
review="$out_dir/$seat.md"
failed=0

if [[ "$exit_code" != 0 ]]; then
  echo "FAIL $seat: exited $exit_code"
  failed=1
fi

verdict=""
if [[ -f "$review" ]]; then
  verdict="$(grep -v '^[[:space:]]*$' "$review" | tail -1 | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' || true)"
fi
case "$verdict" in
  "VERDICT: merge" | "VERDICT: changes-needed") ;;
  *)
    echo "FAIL $seat: $review does not end with a VERDICT line"
    failed=1
    ;;
esac

# A fresh checkout has no ignored files, so --ignored also catches writes to
# ignored paths such as build output.
if ! written="$(git -C "$review_dir/$seat" status --porcelain --ignored=matching 2>&1)"; then
  echo "FAIL $seat: cannot inspect its checkout: $written"
  failed=1
elif [[ -n "$written" ]]; then
  echo "FAIL $seat: wrote into its checkout:"
  echo "$written"
  failed=1
fi

if [[ $failed -ne 0 ]]; then
  if [[ -f "$out_dir/$seat.log" ]]; then
    echo "--- last lines of $out_dir/$seat.log"
    tail -20 "$out_dir/$seat.log"
  fi
  exit 1
fi

echo "OK $seat: $verdict"
