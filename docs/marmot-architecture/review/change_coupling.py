#!/usr/bin/env python3
"""Count how often the architecture review's systems (A-H) change together.

Usage: python3 -I change_coupling.py <repo> <since> [<until-ref>]

Counts non-merge commits reachable from <until-ref> (default HEAD) since <since>, using only non-test files under
crates/. Each path maps to one review system; see README.md#plan.
"""

import collections
import re
import subprocess
import sys

TEST_PATH = re.compile(
    r"(^|/)(tests?|test_support|benches)(/|\.rs$)|_tests?\.rs$|scenario_tests"
)


def system(path):
    parts = path.split("/")
    if len(parts) < 3 or parts[0] != "crates":
        return None
    crate, rest = parts[1], "/".join(parts[2:])
    if crate in ("cgka-engine", "traits"):
        return "A engine"
    if crate in ("cgka-session", "marmot-account"):
        return "D session/account"
    if crate.startswith("transport-nostr"):
        return "E transport"
    if crate == "marmot-forensics":
        return "H sidecars"
    if crate in (
        "marmot-uniffi",
        "marmot-c",
        "cli",
        "agent-connector",
        "agent-control",
        "agent-stream-compose",
    ) or crate.startswith("transport-quic"):
        return "G surfaces"
    if crate == "storage-sqlite":
        return "F content" if re.search(r"attachment|avatar", rest) else "C storage"
    if crate == "marmot-app":
        if re.match(
            r"src/(media|runtime/account_worker/attachments|runtime/attachment|runtime/avatar)",
            rest,
        ):
            return "F content"
        if re.match(r"src/(relay_plane|collector_host_safety|network_proxy)", rest):
            return "E transport"
        if re.match(
            r"src/(audit|app_telemetry|product_analytics|relay_telemetry_export|startup_diagnostics)",
            rest,
        ):
            return "H sidecars"
        return "B app runtime"
    return None


def main():
    repo, since = sys.argv[1], sys.argv[2]
    until = sys.argv[3] if len(sys.argv) > 3 else "HEAD"
    log = subprocess.run(
        ["git", "-C", repo, "log", until, f"--since={since}", "--no-merges",
         "--name-only", "--pretty=format:@@%H"],
        capture_output=True, text=True, check=True,
    ).stdout
    commits = []
    for line in log.splitlines():
        if line.startswith("@@"):
            commits.append(set())
        elif line.strip() and commits and not TEST_PATH.search(line):
            touched = system(line.strip())
            if touched:
                commits[-1].add(touched)
    touching = [c for c in commits if c]
    per_system = collections.Counter(s for c in touching for s in c)
    pairs = collections.Counter(
        (a, b) for c in touching for a in c for b in c if a < b
    )
    width = collections.Counter(len(c) for c in touching)

    print(f"commits={len(commits)} touching_reviewed_source={len(touching)}")
    print("systems touched per commit:", dict(sorted(width.items())))
    for name in sorted(per_system):
        print(f"  {name:20s} {per_system[name]}")
    print("most frequent pairs:")
    for (a, b), count in pairs.most_common(12):
        smaller = min(per_system[a], per_system[b])
        print(f"  {a} + {b}: {count} ({100 * count // smaller}% of smaller)")


if __name__ == "__main__":
    main()
