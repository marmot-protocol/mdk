#!/usr/bin/env python3
"""Fail closed when install examples bypass published SHA-256 checks."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

INSTALLERS = (
    "install-hermes-marmot.sh",
    "install-openclaw-marmot.sh",
    "install-codex-marmot.sh",
    "install-opencode-marmot.sh",
    "install-pi-marmot.sh",
)
SCAN_SUFFIXES = {".md", ".sh", ".yaml", ".yml"}
SCAN_EXCLUDES = {
    Path("scripts/check_install_example_sha256.py"),
    Path("scripts/test_install_example_sha256_gate.py"),
}
# Existing debt outside this task's release/install-help scope. The gate scans
# every tracked guidance surface and allows no increase above these counts.
LEGACY_PIPELINE_BASELINE = {
    "crates/cli/CHANGELOG.md": 1,
    "scripts/hermes_marmot_dev_setup.sh": 1,
}
DOCUMENTED_INSTALL_CALLS = {
    # The repository-level quickstart owns release commands. The crate-level
    # connector guide intentionally links there rather than duplicating them.
    "integrations/hermes/marmot/README.md": {"install-hermes-marmot.sh": 4},
    "integrations/openclaw/marmot/README.md": {"install-openclaw-marmot.sh": 3},
    "integrations/opencode/marmot/README.md": {"install-opencode-marmot.sh": 2},
    "integrations/pi/marmot/README.md": {"install-pi-marmot.sh": 2},
}


def find_download_to_shell_pipelines(text: str) -> list[str]:
    """Return curl/wget commands whose bytes are piped directly to a shell."""
    logical_lines = text.replace("\\\n", " ").splitlines()
    pattern = re.compile(r"\b(?:curl|wget)\b[^\n]*\|\s*(?:ba)?sh\b")
    return [line.strip() for line in logical_lines if pattern.search(line)]


def verify_then_execute_errors(text: str, installer: str) -> list[str]:
    """Check the minimum download -> companion -> verify -> execute contract."""
    errors: list[str] = []
    script_pos = text.find(installer)
    checksum_candidates = (
        text.find(f"{installer}.sha256", max(script_pos, 0)),
        text.find("$installer_script.sha256", max(script_pos, 0)),
        text.find("${installer_script}.sha256", max(script_pos, 0)),
    )
    checksum_pos = min((pos for pos in checksum_candidates if pos >= 0), default=-1)
    verify_match = re.search(r"(?:shasum\s+-a\s+256|sha256sum)(?:\s+-c)?", text)
    execute_match = re.search(
        rf"^[ \t]*(?:bash|sh)\b[^\n]*{re.escape(installer)}|"
        r"^[ \t]*(?:bash|sh)\b[^\n]*installer_script",
        text,
        flags=re.MULTILINE,
    )

    if script_pos < 0:
        errors.append("missing installer download")
    if checksum_pos < 0:
        errors.append("missing companion .sha256 download")
    if verify_match is None:
        errors.append("missing SHA-256 verification")
    if execute_match is None:
        errors.append("missing execution of the verified local installer")
    if (
        script_pos >= 0
        and checksum_pos >= 0
        and verify_match is not None
        and execute_match is not None
        and not (script_pos < checksum_pos < verify_match.start() < execute_match.start())
    ):
        errors.append("installer example does not verify before execution")
    return errors


def documented_surface_errors(
    text: str, installers: dict[str, int]
) -> list[str]:
    """Require each documented path to use the verified installer helper."""
    errors: list[str] = []
    if "install_verified() (" not in text:
        errors.append("missing verify-then-execute helper")
    if not re.search(r"install_verified\(\) \(\s*\n\s*set -eu\b", text):
        errors.append("verify-then-execute helper must fail closed with set -eu")
    if "shasum -a 256 -c" not in text:
        errors.append("missing shasum SHA-256 verification branch")
    if "sha256sum -c" not in text:
        errors.append("missing sha256sum verification branch")
    for installer, minimum in installers.items():
        call = f'install_verified "$base_url/{installer}"'
        checksum = f'"$base_url/{installer}.sha256"'
        if text.count(call) < minimum:
            errors.append(f"expected at least {minimum} verified calls for {installer}")
        if text.count(checksum) < minimum:
            errors.append(
                f"expected at least {minimum} companion checksums for {installer}"
            )
    return errors


def scan_paths(root: Path, paths: Iterable[Path]) -> list[str]:
    errors: list[str] = []
    for relative in paths:
        if relative in SCAN_EXCLUDES:
            continue
        path = root / relative
        if not path.is_file() or path.suffix not in SCAN_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8")
        for line in find_download_to_shell_pipelines(text):
            errors.append(f"{relative}: download-to-shell pipeline: {line}")
    return errors


def tracked_paths(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [Path(raw.decode("utf-8")) for raw in result.stdout.split(b"\0") if raw]


def render_installer_help(root: Path, installer: str) -> str:
    result = subprocess.run(
        ["bash", str(root / "scripts" / installer), "--help"],
        cwd=root,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{installer} --help failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def repository_errors(root: Path) -> list[str]:
    pipeline_hits = scan_paths(root, tracked_paths(root))
    hits_by_path: dict[str, list[str]] = {}
    for hit in pipeline_hits:
        path = hit.split(":", 1)[0]
        hits_by_path.setdefault(path, []).append(hit)

    errors: list[str] = []
    for path, hits in sorted(hits_by_path.items()):
        allowed = LEGACY_PIPELINE_BASELINE.get(path, 0)
        if len(hits) > allowed:
            errors.extend(hits[allowed:])

    for relative, installers in DOCUMENTED_INSTALL_CALLS.items():
        text = (root / relative).read_text(encoding="utf-8")
        for error in documented_surface_errors(text, installers):
            errors.append(f"{relative}: {error}")

    for installer in INSTALLERS:
        try:
            help_text = render_installer_help(root, installer)
        except RuntimeError as exc:
            errors.append(str(exc))
            continue
        for error in verify_then_execute_errors(help_text, installer):
            errors.append(f"{installer} --help: {error}")
        if "shasum -a 256" not in help_text:
            errors.append(f"{installer} --help: missing shasum fallback")
        if "sha256sum" not in help_text:
            errors.append(f"{installer} --help: missing sha256sum fallback")

    release_text = (root / "release.md").read_text(encoding="utf-8")
    workflow_text = (root / ".github/workflows/wn-agent-binaries.yml").read_text(
        encoding="utf-8"
    )
    for installer in INSTALLERS:
        verified_call = re.compile(
            rf"install_verified[^\n]*{re.escape(installer)}[^\n]*"
            rf"{re.escape(installer)}\.sha256"
        )
        if verified_call.search(release_text) is None:
            errors.append(f"release.md: missing verified install call for {installer}")
        if len(verified_call.findall(workflow_text)) < 2:
            errors.append(
                ".github/workflows/wn-agent-binaries.yml: expected latest and "
                f"version-pinned verified calls for {installer}"
            )

    for label, text, minimum in (
        ("release.md", release_text, 1),
        (".github/workflows/wn-agent-binaries.yml", workflow_text, 2),
    ):
        if text.count("shasum -a 256 -c") < minimum:
            errors.append(f"{label}: missing shasum SHA-256 verification branch")
        if text.count("sha256sum -c") < minimum:
            errors.append(f"{label}: missing sha256sum verification branch")
        if text.count("install_verified() (") < minimum:
            errors.append(f"{label}: missing verify-then-execute helper")

    return errors


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    errors = repository_errors(root)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("install example SHA-256 gate: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
