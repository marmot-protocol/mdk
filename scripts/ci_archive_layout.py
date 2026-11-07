#!/usr/bin/env python3
"""Manual paired comparison of slice:14 and two binary-local slice:7 groups."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import ci_runner


_BUILD_ARGS = [
    "--workspace", "--exclude", "cgka-conformance-simulator", "--features",
    "wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks",
    "--locked", "--profile", "ci",
]


def _partition(layout, number):
    if layout not in ("slice", "binary-local") or not 1 <= number <= 14:
        raise ValueError("expected slice or binary-local partition 1..14")
    if layout == "slice":
        return 0, f"slice:{number}/14"
    return (number - 1) // 7 + 1, f"slice:{(number - 1) % 7 + 1}/7"


def _inventory(document):
    return Counter(
        (binary, name)
        for binary, suite in document["rust-suites"].items()
        for name, case in suite["testcases"].items()
        if case["filter-match"]["status"] == "matches"
    )


def _groups(inventory):
    weights = Counter()
    for (binary, _name), count in inventory.items():
        weights[binary] += count
    groups, loads = [[], []], [0, 0]
    for binary in sorted(weights, key=lambda binary: (-weights[binary], binary)):
        index = min(range(2), key=lambda index: (loads[index], index))
        groups[index].append(binary)
        loads[index] += weights[binary]
    if not all(groups):
        raise ValueError("binary-local comparison requires two nonempty groups")
    return groups, weights


def _binary_filter(binary):
    # Equality (not the DSL's default glob); encode punctuation and whitespace
    # as Unicode escapes so IDs cannot inject a delimiter or filter expression.
    escaped = "".join(c if c.isalnum() or c in "_:-." else f"\\u{{{ord(c):x}}}" for c in binary)
    return f"binary_id(={escaped})"


def _coverage(expected, actual):
    if not expected or expected != actual:
        missing, extra = expected - actual, actual - expected
        raise ValueError(f"partition coverage mismatch: missing={list(missing.items())[:5]}, "
                         f"extra={list(extra.items())[:5]}")


def _list(arguments):
    result = subprocess.run(["cargo", "nextest", "list", "--message-format", "json", *arguments],
                            check=True, stdout=subprocess.PIPE, text=True)
    return _inventory(json.loads(result.stdout))


def _metadata(root):
    return ["--cargo-metadata", str(root / "target/nextest/cargo-metadata.json"),
            "--binaries-metadata", str(root / "target/nextest/binaries-metadata.json"),
            "--workspace-remap", str(Path.cwd()), "--target-dir-remap", str(root / "target")]


def _build(output):
    base = os.environ["WORKSPACE_FILTER"]
    started = time.monotonic()
    # The existing baseline gate performs the single native compilation. Later
    # archive commands reuse Cargo's fresh artifacts with identical build flags.
    subprocess.run(["bash", "scripts/check_ci_partitions.sh", "slice:14", *_BUILD_ARGS,
                    "--timings", "-E", base], check=True)
    expected = _list([*_BUILD_ARGS, "-E", base])
    groups, weights = _groups(expected)
    verification = {"baseline_seconds": time.monotonic() - started}
    actual = Counter()
    rows = []
    for group, binaries in enumerate([sorted(weights), *groups]):
        folder = output / ("slice" if group == 0 else f"binary-local-{group}")
        folder.mkdir(parents=True, exist_ok=True)
        expression = base if group == 0 else (
            f"({base}) and (" + " or ".join(_binary_filter(binary) for binary in binaries) + ")")
        plan = {"layout": "slice" if group == 0 else "binary-local", "group": group,
                "filter": expression, "binaries": {binary: weights[binary] for binary in binaries}}
        (folder / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
        archive = folder / "tests.tar.zst"
        started = time.monotonic()
        subprocess.run(["cargo", "nextest", "archive", *_BUILD_ARGS, "-E", expression,
                        "--archive-file", str(archive)], check=True)
        creation = time.monotonic() - started
        started = time.monotonic()
        ci_runner.manifest(archive)
        row = {"artifact": folder.name, "creation_seconds": creation,
               "manifest_seconds": time.monotonic() - started,
               **json.loads(ci_runner.manifest_path(archive).read_text())}
        if group:
            started = time.monotonic()
            # List the actual native archive, not a model of slice assignment.
            # Extract one group at a time to bound the builder's disk overhead.
            with tempfile.TemporaryDirectory(prefix="archive-layout-") as temporary:
                root = Path(temporary)
                subprocess.run(["cargo", "nextest", "list", "--archive-file", str(archive),
                                "--extract-to", str(root), "--workspace-remap", str(Path.cwd()),
                                "--list-type", "binaries-only"], check=True, stdout=subprocess.DEVNULL)
                for number in range((group - 1) * 7 + 1, group * 7 + 1):
                    _, partition = _partition("binary-local", number)
                    actual.update(_list([*_metadata(root), "--profile", "ci", "-E", expression,
                                         "--partition", partition]))
            row["partition_verification_seconds"] = time.monotonic() - started
        rows.append(row)
        print(json.dumps(row), flush=True)
    _coverage(expected, actual)
    report = {"selected_tests": expected.total(), "archives": rows, **verification}
    (ci_runner.reports() / "archive-layout.json").write_text(json.dumps(report, indent=2) + "\n")
    print("All fourteen binary-local partitions cover the selected inventory exactly once.", flush=True)


def _run(layout, number, child_umask):
    group, partition = _partition(layout, number)
    plan = json.loads(Path("plan.json").read_text())
    if (plan["layout"], plan["group"]) != (layout, group):
        raise ValueError("downloaded archive plan does not match requested partition")
    (ci_runner.reports() / "plan.json").write_text(json.dumps(plan) + "\n")
    return ci_runner.run(f"{layout}-{number}", ["cargo", "nextest", "run", *_metadata(Path.cwd()),
                         "--partition", partition, "--no-tests=pass", "--profile", "ci",
                         "-E", plan["filter"]], child_umask)


def _main():
    child_umask = os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("build").add_argument("output", type=Path)
    consumer = commands.add_parser("run")
    consumer.add_argument("layout", choices=("slice", "binary-local"))
    consumer.add_argument("partition", type=int)
    args = parser.parse_args()
    try:
        if args.action == "build":
            # Preserve normal Cargo/build-script filesystem behavior.
            os.umask(child_umask)
            _build(args.output)
            return 0
        return _run(args.layout, args.partition, child_umask)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Archive comparison infrastructure error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_main())
