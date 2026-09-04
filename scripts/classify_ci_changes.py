#!/usr/bin/env python3
"""Classify changed paths for conservative CI job selection."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT_BUILD_PATHS = {
    ".cargo/config.toml",
    ".config/nextest.toml",
    ".github/workflows/ci.yml",
    "Cargo.lock",
    "Cargo.toml",
    "Justfile",
    "rust-toolchain.toml",
}

# These Markdown files are executable assurance inputs, not documentation-only
# changes: simulator tests parse them and enforce their contents.
EXECUTABLE_MARKDOWN = {
    "crates/cgka-conformance-simulator/CONVERGENCE_ROUTE_MATRIX.md",
    "crates/cgka-conformance-simulator/MUTATION_MATRIX.md",
    "crates/cgka-conformance-simulator/PROTOCOL_DECISIONS.md",
}

C_WORKSPACE_CRATES = {
    "cgka-engine",
    "cgka-session",
    "fs-private",
    "marmot-account",
    "marmot-app",
    "marmot-c",
    "marmot-forensics",
    "marmot-markdown",
    "marmot-uniffi",
    "storage-sqlite",
    "traits",
    "transport-nostr-adapter",
    "transport-nostr-peeler",
    "transport-quic-broker",
    "transport-quic-stream",
}

CONFORMANCE_WORKSPACE_CRATES = {
    "cgka-conformance-simulator",
    "cgka-engine",
    "cgka-session",
    "convergence-campaign-runner",
    "fs-private",
    "marmot-account",
    "marmot-app",
    "marmot-forensics",
    "marmot-markdown",
    "storage-sqlite",
    "traits",
    "transport-nostr-adapter",
    "transport-nostr-peeler",
    "transport-quic-broker",
    "transport-quic-stream",
}

IOS_WORKSPACE_CRATES = {
    "cgka-engine",
    "cgka-session",
    "fs-private",
    "marmot-account",
    "marmot-forensics",
    "storage-sqlite",
    "traits",
}

INDEPENDENT_WORKSPACE_CRATES = {
    "agent-connector",
    "agent-control",
    "agent-stream-compose",
    "cli",
    "incident-replay",
}

CLASSIFIED_WORKSPACE_CRATES = (
    C_WORKSPACE_CRATES
    | CONFORMANCE_WORKSPACE_CRATES
    | IOS_WORKSPACE_CRATES
    | INDEPENDENT_WORKSPACE_CRATES
)

SPECIALIST_EXACT_PATHS = {
    ".github/workflows/bindings.yaml",
    ".github/workflows/c-smoke-nightly.yml",
    ".github/workflows/convergence-hardening.yml",
    ".github/workflows/simulator-nightly.yml",
    "Dockerfile.convergence-campaign",
    "crates/cgka-conformance-simulator/src/policy_cases.rs",
    "crates/cgka-conformance-simulator/tests/generated_policy_cases.rs",
    "crates/cgka-conformance-simulator/tests/policy_case_tamarin_drift.rs",
    "docs/marmot-architecture/convergence-constant-inventory.txt",
    "scripts/check_c_binding_parity.py",
    "scripts/check_campaign_toolchain.sh",
    "scripts/tests/test_campaign_toolchain.sh",
}


def _is_documentation(path: str) -> bool:
    return (
        (path.endswith(".md") and path not in EXECUTABLE_MARKDOWN)
        or path.startswith(".github/ISSUE_TEMPLATE/")
        or path.startswith(".github/PULL_REQUEST_TEMPLATE/")
    )


def _crate_name(path: str) -> str | None:
    parts = path.split("/", 2)
    if len(parts) >= 2 and parts[0] == "crates":
        return parts[1]
    return None


def _touches_crates(path: str, crates: set[str]) -> bool:
    return _crate_name(path) in crates


def _is_recognized_specialist_path(path: str) -> bool:
    return (
        _crate_name(path) in CLASSIFIED_WORKSPACE_CRATES
        or path in ROOT_BUILD_PATHS
        or path in SPECIALIST_EXACT_PATHS
        or path.startswith("formal/tamarin/")
        or path.startswith("formal/tla/")
    )


def classify(paths: list[str], *, force_all: bool = False) -> dict[str, bool]:
    normalized = sorted({path.strip("/") for path in paths if path.strip("/")})
    if force_all or not normalized:
        return {
            "run_full": True,
            "run_c": True,
            "run_conformance": True,
            "run_ios": True,
            "run_formal": True,
        }

    run_full = not all(_is_documentation(path) for path in normalized)
    if not run_full:
        return {
            "run_full": False,
            "run_c": False,
            "run_conformance": False,
            "run_ios": False,
            "run_formal": False,
        }

    workflow_changed = ".github/workflows/ci.yml" in normalized
    root_build_changed = any(path in ROOT_BUILD_PATHS for path in normalized)
    unclassified_path = any(
        not _is_documentation(path) and not _is_recognized_specialist_path(path)
        for path in normalized
    )

    run_c = unclassified_path or workflow_changed or root_build_changed or any(
        _touches_crates(path, C_WORKSPACE_CRATES)
        or path == ".github/workflows/c-smoke-nightly.yml"
        or path == "scripts/check_c_binding_parity.py"
        for path in normalized
    )
    run_conformance = unclassified_path or workflow_changed or root_build_changed or any(
        _touches_crates(path, CONFORMANCE_WORKSPACE_CRATES)
        or path
        in {
            ".github/workflows/convergence-hardening.yml",
            ".github/workflows/simulator-nightly.yml",
            "Dockerfile.convergence-campaign",
            "scripts/check_campaign_toolchain.sh",
            "scripts/tests/test_campaign_toolchain.sh",
            "docs/marmot-architecture/convergence-constant-inventory.txt",
        }
        or path.startswith("formal/tla/")
        for path in normalized
    )
    run_ios = unclassified_path or workflow_changed or root_build_changed or any(
        _touches_crates(path, IOS_WORKSPACE_CRATES)
        or path == ".github/workflows/bindings.yaml"
        for path in normalized
    )
    run_formal = unclassified_path or workflow_changed or any(
        path.startswith("formal/tamarin/")
        or path
        in {
            "Justfile",
            "crates/cgka-conformance-simulator/src/policy_cases.rs",
            "crates/cgka-conformance-simulator/tests/generated_policy_cases.rs",
            "crates/cgka-conformance-simulator/tests/policy_case_tamarin_drift.rs",
        }
        for path in normalized
    )

    return {
        "run_full": run_full,
        "run_c": run_c,
        "run_conformance": run_conformance,
        "run_ios": run_ios,
        "run_formal": run_formal,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", dest="force_all")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    raw = sys.stdin.buffer.read()
    paths = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    result = classify(paths, force_all=args.force_all)
    output = "".join(f"{key}={str(value).lower()}\n" for key, value in result.items())
    if args.github_output is None:
        sys.stdout.write(output)
    else:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
