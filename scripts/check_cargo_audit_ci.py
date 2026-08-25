#!/usr/bin/env python3
"""Fail closed when the CI cargo-audit gate no longer enforces repository policy."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


class PolicyError(ValueError):
    """The workflow no longer satisfies the cargo-audit policy."""


APPROVED_ADVISORY_IGNORES = ["RUSTSEC-2024-0384"]
APPROVED_AUDIT_CONFIG = {"advisories": {"ignore": APPROVED_ADVISORY_IGNORES}}


def _mapping_key(line: str, indent: int) -> str | None:
    pattern = rf"^ {{{indent}}}(?P<key>[A-Za-z0-9_-]+|'[^']+'|\"[^\"]+\")\s*:\s*(?:#.*)?$"
    match = re.match(pattern, line)
    if match is None:
        return None
    return match.group("key").strip("'\"")


def _job_block(workflow: str, job_name: str) -> str:
    lines = workflow.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if _mapping_key(line, 2) == job_name),
        None,
    )
    if start is None:
        raise PolicyError(f"missing required {job_name} job")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if _mapping_key(lines[index], 2) is not None:
            end = index
            break
    return "\n".join(lines[start:end])


def validate(workflow_path: Path, audit_config_path: Path) -> None:
    if not audit_config_path.is_file():
        raise PolicyError(f"missing repository audit.toml: {audit_config_path}")

    try:
        audit_config = tomllib.loads(audit_config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise PolicyError(f"invalid repository audit.toml: {error}") from error
    if audit_config != APPROVED_AUDIT_CONFIG:
        raise PolicyError(
            "audit.toml must exactly match the approved policy: "
            f"{APPROVED_AUDIT_CONFIG}"
        )

    workflow = workflow_path.read_text(encoding="utf-8")
    job = _job_block(workflow, "rust-audit")

    if re.search(r"(?m)^\s+(?:if|'if'|\"if\")\s*:", job):
        raise PolicyError("rust-audit job and steps must not have an if condition")

    if "uses: actions/checkout@" not in job:
        raise PolicyError("rust-audit job must check out the repository")
    if "rustup toolchain install" not in job or "cargo --version" not in job:
        raise PolicyError("rust-audit job must install and activate the repository Rust toolchain")
    if "tool: cargo-audit@0.22.1" not in job:
        raise PolicyError("rust-audit job must install cargo-audit@0.22.1")
    if re.search(r"(?m)^\s*continue-on-error:\s*true\s*$", job):
        raise PolicyError("rust-audit job must not use continue-on-error")
    if re.search(r"(?m)^\s*working-directory:", job):
        raise PolicyError("rust-audit must run at the repository root so .cargo/audit.toml is loaded")

    commands = re.findall(r"(?m)^\s*run:\s*(.*?)\s*$", job)
    audit_commands = [command for command in commands if re.search(r"\bcargo\b.*\baudit\b", command)]
    if audit_commands != ["cargo --locked audit"]:
        raise PolicyError(
            "rust-audit command must be exactly 'cargo --locked audit' so Cargo.lock is immutable, "
            "repository-root .cargo/audit.toml is loaded, and an unignored advisory exits nonzero"
        )


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    try:
        validate(
            repo_root / ".github" / "workflows" / "ci.yml",
            repo_root / ".cargo" / "audit.toml",
        )
    except (OSError, PolicyError) as error:
        print(f"cargo-audit CI policy check failed: {error}", file=sys.stderr)
        return 1
    print("cargo-audit CI policy check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
