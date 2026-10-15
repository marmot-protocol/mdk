#!/usr/bin/env python3
"""Select PR tests from workspace dependencies; unknown inputs run full CI."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

from classify_ci_changes import ROOT_BUILD_PATHS, _is_documentation, classify


ROOT = Path(__file__).resolve().parents[1]
DEDICATED = (
    "not (package(marmot-app) & binary(relay_runtime)) and "
    "not (package(wn-cli) & binary(cli))"
)
# This test fixture is shared through include_str!, outside Cargo's graph.
EXTRA_TEST_DEPENDENCIES = {"transport-nostr-adapter": {"marmot-forensics"}}


def workspace_graph(root: Path) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Include dev/build/target dependencies: false positives are preferable here."""
    workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
    manifests = {}
    directories = {}
    for pattern in workspace["members"]:
        for directory in sorted(root.glob(pattern)):
            manifest = tomllib.loads((directory / "Cargo.toml").read_text())
            name = manifest["package"]["name"]
            if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
                raise ValueError(f"unsupported package name: {name!r}")
            directories[directory.relative_to(root).as_posix()] = name
            manifests[name] = manifest
    reverse = {name: set() for name in manifests}
    for name, manifest in manifests.items():
        sections = [manifest, *manifest.get("target", {}).values()]
        for section in sections:
            for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
                for alias, declaration in section.get(kind, {}).items():
                    if not isinstance(declaration, dict):
                        continue
                    if declaration.get("workspace"):
                        declaration = workspace.get("dependencies", {}).get(alias, {})
                    if not isinstance(declaration, dict):
                        continue
                    dependency = declaration.get("package", alias)
                    if dependency in reverse:
                        reverse[dependency].add(name)
    for consumer, dependencies in EXTRA_TEST_DEPENDENCIES.items():
        for dependency in dependencies:
            if consumer in reverse and dependency in reverse:
                reverse[dependency].add(consumer)
    return directories, reverse


def select(paths: list[str], *, root: Path = ROOT, full: bool = False) -> dict:
    directories, reverse = workspace_graph(root)
    paths = sorted(set(paths))
    affected = set()
    directly_changed = set()
    reason = "changed crates and transitive dependents"
    full_workspace = full or not paths
    for path in paths:
        if _is_documentation(path):
            continue
        if path in ROOT_BUILD_PATHS or path.startswith("vendor/"):
            full_workspace = True
            reason = "shared build input"
            continue
        owner = next(
            (name for directory, name in directories.items() if path.startswith(directory + "/")),
            None,
        )
        if owner:
            affected.add(owner)
            directly_changed.add(owner)
        elif classify([path])["run_full"]:
            full_workspace = True
            reason = "unclassified or shared assurance input"
    if full_workspace:
        affected = set(reverse)
        if full:
            reason = "master, merge group, manual run or ci:full opt-in"
    pending = list(affected)
    while pending:
        for dependent in reverse[pending.pop()]:
            if dependent not in affected:
                affected.add(dependent)
                pending.append(dependent)

    # Do not defer a regression being added or edited in a test source. New
    # ordinary tests are included by default; these paths also restore the
    # scale cases and dedicated end-to-end suites excluded by ci-pr.
    test_change = any(
        "/tests/" in path or Path(path).stem in {"tests", "test"}
        or Path(path).stem.endswith("_tests")
        or Path(path).stem.startswith(("test_", "tests_"))
        for path in paths if path.endswith(".rs")
    )
    profile = "ci-full" if full_workspace or test_change else "ci-pr"
    packages = sorted(affected - {"cgka-conformance-simulator"})
    package_filter = " | ".join(f"package(={name})" for name in packages) or "none()"
    return {
        "test_profile": profile,
        "cli_profile": "ci-full" if profile == "ci-full" or "wn-cli" in directly_changed else "ci-pr",
        "relay_profile": "ci-full" if profile == "ci-full" or "marmot-app" in directly_changed else "ci-pr",
        "test_packages": packages,
        "workspace_filter": f"({package_filter}) & ({DEDICATED})",
        "run_tests": bool(packages),
        "full_workspace": full_workspace,
        "run_cli": "wn-cli" in affected,
        "run_relay": "marmot-app" in affected,
        "run_simulator": "cgka-conformance-simulator" in affected,
        "selection_reason": reason,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    paths = [item.decode("utf-8") for item in sys.stdin.buffer.read().split(b"\0") if item]
    result = select(paths, full=args.all)
    lines = []
    for key, value in result.items():
        if isinstance(value, bool):
            value = str(value).lower()
        elif isinstance(value, list):
            value = json.dumps(value)
        lines.append(f"{key}={value}\n")
    output = "".join(lines)
    if args.github_output:
        with args.github_output.open("a") as handle:
            handle.write(output)
    else:
        print(output, end="")
    if args.summary:
        with args.summary.open("a") as handle:
            handle.write(
                "### Native test selection\n\n"
                f"Profile: `{result['test_profile']}`. {result['selection_reason']}.\n\n"
                f"CLI profile: `{result['cli_profile']}`; runtime profile: `{result['relay_profile']}`.\n\n"
                "Workspace test packages: "
                + (", ".join(f"`{name}`" for name in result["test_packages"]) or "none")
                + ".\n"
            )


if __name__ == "__main__":
    main()
