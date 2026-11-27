#!/usr/bin/env python3
"""Run the nextest suites of the crates a change touches and of every crate that depends on them.

Team PRs compile nothing in CI, so this is the local stand-in for the Canary's
workspace tests, scoped to what the change can break. It uses the Canary's
feature set and runs `marmot-app`'s `relay_runtime` suite too. When `wn-cli` is
affected it then runs `wn-cli`'s subprocess-heavy `cli` binary on its own, as
CI's `CLI e2e` job does. It leaves out `cgka-conformance-simulator` (the
land-change smoke and `just simulator-smoke` cover it).

Usage: python3 scripts/dependents_nextest.py --features <pkg/feat,...> [--base origin/master] [--print]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from classify_ci_changes import EXECUTABLE_MARKDOWN, EXECUTABLE_MARKDOWN_PREFIXES

ROOT = Path(__file__).resolve().parent.parent

# Inputs every crate builds from: a change here selects the whole workspace.
SHARED_INPUTS = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/", "vendor/", ".config/nextest.toml")
EXCLUDED_PACKAGES = frozenset({"cgka-conformance-simulator"})
TEST_FILTER = "not (package(wn-cli) & binary(cli))"


def workspace_graph(metadata: dict) -> tuple[dict[str, Path], dict[str, set[str]]]:
    """Return each workspace package's directory and its workspace dependencies (all dependency kinds)."""
    members = set(metadata["workspace_members"])
    root = Path(metadata["workspace_root"])
    names = {pkg["id"]: pkg["name"] for pkg in metadata["packages"] if pkg["id"] in members}
    dirs = {
        pkg["name"]: Path(pkg["manifest_path"]).parent.relative_to(root)
        for pkg in metadata["packages"]
        if pkg["id"] in members
    }
    deps: dict[str, set[str]] = {name: set() for name in names.values()}
    for node in metadata["resolve"]["nodes"]:
        if node["id"] in names:
            deps[names[node["id"]]] = {names[d["pkg"]] for d in node["deps"] if d["pkg"] in names}
    return dirs, deps


def changed_packages(files: list[str], dirs: dict[str, Path]) -> set[str]:
    """Map changed paths to the workspace packages that own them; a shared build input selects all."""
    changed: set[str] = set()
    for file in files:
        if file in SHARED_INPUTS or any(file.startswith(p) for p in SHARED_INPUTS if p.endswith("/")):
            return set(dirs)
        if file.endswith(".md") and file not in EXECUTABLE_MARKDOWN and not file.startswith(EXECUTABLE_MARKDOWN_PREFIXES):
            continue
        path = Path(file)
        owners = [name for name, d in dirs.items() if d != Path(".") and d in (path, *path.parents)]
        if owners:
            changed.add(max(owners, key=lambda name: len(dirs[name].parts)))
    return changed


def closure(start: set[str], edges: dict[str, set[str]]) -> set[str]:
    seen = set(start)
    stack = list(start)
    while stack:
        for nxt in edges.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def nextest_commands(files: list[str], metadata: dict, features: list[str]) -> list[list[str]]:
    """Return the nextest commands for a change, empty when it touches no testable crate."""
    dirs, deps = workspace_graph(metadata)
    rdeps: dict[str, set[str]] = {name: set() for name in deps}
    for name, its_deps in deps.items():
        for dep in its_deps:
            rdeps[dep].add(name)
    selected = sorted(closure(changed_packages(files, dirs), rdeps) - EXCLUDED_PACKAGES)
    if not selected:
        return []

    def run(packages: list[str]) -> list[str]:
        # Cargo accepts `pkg/feature` only for a selected package or a direct dependency of one.
        in_scope = set(packages).union(*(deps[name] for name in packages))
        kept = [f for f in features if f.split("/", 1)[0] in in_scope]
        command = ["cargo", "nextest", "run", "--locked", "--profile", "ci", "--no-fail-fast"]
        for name in packages:
            command += ["-p", name]
        return command + (["--features", ",".join(kept)] if kept else [])

    commands = [run(selected) + ["-E", TEST_FILTER]]
    if "wn-cli" in selected:
        commands.append(run(["wn-cli"]) + ["--test", "cli"])
    return commands


def git_changed_files(base: str) -> list[str]:
    """Files changed since the merge-base with `base`, committed or not, plus untracked files."""

    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout

    merge_base = git("merge-base", base, "HEAD").strip()
    # No rename detection: a moved file changes both its old crate and its new one.
    tracked = git("diff", "--no-renames", "--name-only", "-z", merge_base).split("\0")
    untracked = git("ls-files", "--others", "--exclude-standard", "-z").split("\0")
    return sorted((set(tracked) | set(untracked)) - {""})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="origin/master")
    parser.add_argument("--features", default="", help="Comma-separated `pkg/feature` list (the Canary's test features)")
    parser.add_argument("--print", action="store_true", help="Print the command instead of running it")
    args = parser.parse_args(argv)

    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    features = [f for f in args.features.split(",") if f]
    commands = nextest_commands(git_changed_files(args.base), metadata, features)
    if not commands:
        print(f"dependents-nextest: no testable crate changed since {args.base}")
        return 0
    failed = False
    for command in commands:
        print("dependents-nextest: " + " ".join(command), flush=True)
        if not args.print:
            failed |= subprocess.run(command, cwd=ROOT).returncode != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
