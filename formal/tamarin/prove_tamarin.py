#!/usr/bin/env python3
"""Run Tamarin batch proofs with a narrow crash-only retry for GHC RTS <<loop>>."""

import argparse
import re
import subprocess
import sys

# Tamarin 1.12.0 is built with GHC 9.6.7 (-threaded -feager-blackholing), which
# intermittently aborts right after theory closure with NonTermination before
# proving any lemma (mdk#3033, tamarin-prover#973, GHC#26324). Remove this
# single-retry workaround once CI upgrades to a GHC 9.12.5+ release binary.
MAX_ATTEMPTS = 2
SUMMARY_MARKER = "summary of summaries:"
SUMMARY_LINE_RE = re.compile(r"^summary of summaries:", re.M)
LOOP_CRASH_RE = re.compile(r"^tamarin-prover: <<loop>>$", re.M)


def is_ghc_loop_crash(status: int | None, output: str) -> bool:
    """Return True only when tamarin-prover exited non-zero on GHC <<loop>> before any summary."""
    return (
        status is not None
        and status > 0
        and bool(LOOP_CRASH_RE.search(output))
        and SUMMARY_MARKER not in output
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tamarin", default="tamarin-prover")
    parser.add_argument("--model", required=True)
    parser.add_argument("--derivcheck-timeout", default="60")
    args = parser.parse_args()

    command = [
        args.tamarin,
        args.model,
        "--prove",
        "--quit-on-warning",
        f"--derivcheck-timeout={args.derivcheck_timeout}",
    ]

    status = 0
    output = ""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        status = completed.returncode
        output = completed.stdout
        if attempt < MAX_ATTEMPTS and is_ghc_loop_crash(status, output):
            print(
                "warning: tamarin-prover aborted with GHC RTS <<loop>> before summary; "
                f"retrying once (attempt {attempt}/{MAX_ATTEMPTS}, mdk#3033, tamarin-prover#973, GHC#26324)",
                file=sys.stderr,
                flush=True,
            )
            continue
        break

    if status != 0:
        sys.stdout.write(output)
        return status if status > 0 else 128 - status

    match = SUMMARY_LINE_RE.search(output)
    if match is None:
        print("error: Tamarin completed but no summary block was found")
        sys.stdout.write(output)
        return 1

    sys.stdout.write(output[match.start() :])
    return 0


if __name__ == "__main__":
    sys.exit(main())
