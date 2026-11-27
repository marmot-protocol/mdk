#!/usr/bin/env python3
"""Validate commit trailers and changelog consistency for pull requests.

Every change targeting master records three trailers in the final Git trailer
block of its tip commit:

    Local-Checks: cargo fmt, clippy -p <crate>, nextest <area>, smoke
    Local-Review: claude + codex merge @ <short-sha>
    Release-Impact: none | patch | minor

Landed-commit contract (for Stage 3 release tooling reading `master`):
  - Under GitHub's `COMMIT_MESSAGES` squash setting, a single-commit PR keeps
    its tip trailer block at the end of the squash message, and a multi-commit
    PR puts the tip commit last (optionally followed by GitHub's `---------`
    separator and hoisted `Co-authored-by:` footer).
  - `extract_landed_trailers(message)` parses the final Git trailer block via
    `git interpret-trailers --parse --unfold` and strips a trailing GitHub
    `---------` trailer footer when needed, recovering the tip commit's
    attestation without reading earlier commits in the squash body.

PR cross-checks (against the branch's merge-base with `base`):
  - A change to a Rust workspace crate (or a shared build input) requires
    `Local-Checks:` to record `just dependents-nextest` (land-change step 2),
    except a release metadata PR (`just release-pr-preflight`) and an automated
    Bisect Agent revert. `--enforce-dependents` makes this one check block in
    `--advisory` mode; Required CI passes it on team PRs.
  - Any added or modified `changelog.d/<slug>.md` with a `### Breaking changes`
    section requires `Release-Impact: minor`.
  - Any added or modified `changelog.d/<slug>.md` with other sections forbids
    `Release-Impact: none`.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import changelog  # noqa: E402
from dependents_nextest import changed_packages  # noqa: E402

VALID_IMPACTS = ("none", "patch", "minor")
MDK_TRAILER_KEYS = frozenset({"local-checks", "local-review", "release-impact"})
PLACEHOLDER_VALUES = frozenset({"", "-", "...", "?", "n/a", "na", "none", "tbd", "todo"})
CROSS_MODEL_REVIEW = re.compile(
    r"^(?P<seat_a>[a-z][a-z0-9_-]*)\s*\+\s*(?P<seat_b>[a-z][a-z0-9_-]*)"
    r"\s+merge\s+@\s*(?P<sha>[0-9a-f]{7,40})(?:\s+.*)?$"
)
HUMAN_REVIEW = re.compile(r"^human(?:\s+\S.*)?$")
EXEMPT_REVIEW = re.compile(r"^exempt\s*\((?P<reason>[^()]+)\)$")
FRAGMENT_PATH = re.compile(r"(?:^|/)changelog\.d/[^/]+\.md$")
DEPENDENTS_EVIDENCE = ("dependents-nextest", "release-pr-preflight")
BISECT_REVERT_REVIEW = re.compile(r"^exempt\s*\(automated bisect revert of [0-9a-f]{7,40}\)$")
GITHUB_SQUASH_SEPARATOR = "---------"
GITHUB_SQUASH_FOOTER_LINE = re.compile(
    r"^(?:Co-authored-by|Signed-off-by|On-behalf-of):[ \t]+(?:\S[^\r\n]*[ \t]+)?<[^<>\s]+>$",
    re.IGNORECASE,
)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout


def parse_trailers(message: str) -> tuple[dict[str, str], list[str]]:
    """Parse Git trailers from a commit message using `git interpret-trailers`.

    Uses `--no-divider` so standalone `---` lines in commit bodies are never
    treated as format-patch dividers, unfolds multi-line values via Git's
    parser, permits repeated standard trailers (such as multiple
    `Co-authored-by:` lines), and rejects duplicate MDK trailers
    (`Local-Checks`, `Local-Review`, `Release-Impact`).
    """
    out = subprocess.run(
        [
            "git",
            "-c",
            "trailer.separators=:",
            "interpret-trailers",
            "--parse",
            "--unfold",
            "--no-divider",
        ],
        input=message,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    ).stdout

    trailers: dict[str, str] = {}
    errors: list[str] = []
    for line in out.splitlines():
        raw_key, sep, raw_value = line.partition(":")
        if not sep:
            continue
        key = raw_key.strip().lower()
        value = raw_value.strip()
        if key in MDK_TRAILER_KEYS:
            if key in trailers:
                errors.append(f"duplicate trailer '{raw_key.strip()}'")
            else:
                trailers[key] = value
        else:
            trailers.setdefault(key, value)
    return trailers, errors


def strip_github_squash_footer(message: str) -> str | None:
    """Return `message` before GitHub's trailing `---------` trailer footer, if present."""
    lines = message.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()

    sep_idx = None
    for idx in range(len(lines) - 1, -1, -1):
        if lines[idx] == GITHUB_SQUASH_SEPARATOR:
            sep_idx = idx
            break
    if sep_idx is None:
        return None

    footer_slice = lines[sep_idx + 1 :]
    while footer_slice and not footer_slice[0].strip():
        footer_slice.pop(0)
    if not footer_slice or any(not GITHUB_SQUASH_FOOTER_LINE.match(line) for line in footer_slice):
        return None
    return "\n".join(lines[:sep_idx]).rstrip() + "\n"


def extract_landed_trailers(message: str) -> tuple[dict[str, str], list[str]]:
    """Extract MDK trailers from a landed commit message on `master`.

    Handles single-commit squash messages, multi-commit `COMMIT_MESSAGES`
    squashes where the tip commit sits at the end, and multi-commit squashes
    where GitHub appends a `---------` co-author footer after the tip commit.
    """
    trailers, errors = parse_trailers(message)
    if any(key in trailers for key in MDK_TRAILER_KEYS):
        return trailers, errors
    prefix = strip_github_squash_footer(message)
    if prefix is not None:
        return parse_trailers(prefix)
    return trailers, errors


def validate_local_checks(value: str | None) -> list[str]:
    if value is None:
        return ["missing required trailer 'Local-Checks:' on tip commit"]
    if value.strip().lower() in PLACEHOLDER_VALUES:
        return [f"invalid 'Local-Checks:' value {value!r}; list the commands run locally"]
    return []


def validate_local_review(value: str | None) -> list[str]:
    if value is None:
        return ["missing required trailer 'Local-Review:' on tip commit"]
    stripped = value.strip()
    if stripped.lower() in PLACEHOLDER_VALUES:
        return [
            f"invalid 'Local-Review:' value {value!r}; expected "
            "'<seat-a> + <seat-b> merge @ <sha>', 'human', or 'exempt (<reason>)'"
        ]
    if HUMAN_REVIEW.match(stripped):
        return []
    if match := EXEMPT_REVIEW.match(stripped):
        if match.group("reason").strip().lower() in PLACEHOLDER_VALUES:
            return [f"invalid 'Local-Review:' exemption reason in {value!r}"]
        return []
    if match := CROSS_MODEL_REVIEW.match(stripped):
        seat_a, seat_b = match.group("seat_a"), match.group("seat_b")
        if seat_a in PLACEHOLDER_VALUES or seat_b in PLACEHOLDER_VALUES:
            return [f"placeholder seat name in 'Local-Review: {stripped}'"]
        if seat_a == seat_b:
            return [f"'Local-Review:' requires two distinct seats, got '{seat_a} + {seat_b}'"]
        return []
    return [
        f"invalid 'Local-Review:' format {value!r}; expected "
        "'<seat-a> + <seat-b> merge @ <sha>', 'human', or 'exempt (<reason>)'"
    ]


def validate_release_impact(value: str | None) -> tuple[str | None, list[str]]:
    if value is None:
        return None, [
            "missing required trailer 'Release-Impact:' on tip commit "
            f"(expected one of: {', '.join(VALID_IMPACTS)})"
        ]
    stripped = value.strip()
    if stripped not in VALID_IMPACTS:
        return None, [
            f"invalid 'Release-Impact:' value {value!r} "
            f"(expected one of: {', '.join(VALID_IMPACTS)})"
        ]
    return stripped, []


def validate_range(root: Path, base: str, head: str) -> tuple[str | None, list[str]]:
    """Validate tip-commit trailers and changelog consistency for `base..head`."""
    revs = git(root, "rev-list", "--reverse", f"{base}..{head}").splitlines()
    if not revs:
        return None, [f"no commits found in range {base}..{head}"]

    tip_sha = revs[-1]
    tip_msg = git(root, "show", "-s", "--format=%B", tip_sha)
    trailers, errors = parse_trailers(tip_msg)

    errors.extend(validate_local_checks(trailers.get("local-checks")))
    errors.extend(validate_local_review(trailers.get("local-review")))
    impact, impact_errors = validate_release_impact(trailers.get("release-impact"))
    errors.extend(impact_errors)

    # Cross-check changelog.d/ fragments added or modified since the branch point
    # (merge-base), using -z so non-ASCII paths are never Git-quoted or skipped.
    changed_files = [
        rel_path
        for rel_path in git(
            root, "diff", "--no-renames", "--name-only", "-z", "--diff-filter=AM", f"{base}...{head}"
        ).split("\0")
        if rel_path
    ]
    for rel_path in changed_files:
        if not FRAGMENT_PATH.search(rel_path):
            continue
        content = git(root, "show", f"{head}:{rel_path}")
        sections, parse_errors = changelog.parse_fragment(content)
        if parse_errors:
            errors.append(
                f"{rel_path}: invalid changelog fragment ({'; '.join(parse_errors)})"
            )
            continue
        if impact is None:
            continue
        if "Breaking changes" in sections and impact != "minor":
            errors.append(
                f"{rel_path} includes '### Breaking changes', so 'Release-Impact:' "
                f"must be 'minor' (got '{impact}')"
            )
        elif sections and impact == "none":
            errors.append(
                f"{rel_path} records a user-facing changelog entry, so 'Release-Impact:' "
                "cannot be 'none' (use 'patch' or 'minor')"
            )

    return impact, errors


def validate_dependents_tests(root: Path, base: str, head: str) -> list[str]:
    """Require `just dependents-nextest` in `Local-Checks:` when `base...head` changes a workspace crate."""
    try:
        manifest = git(root, "show", f"{head}:Cargo.toml")
    except subprocess.CalledProcessError:
        return []
    members = tomllib.loads(manifest).get("workspace", {}).get("members", [])
    crates = {member: Path(member) for member in members if isinstance(member, str)}
    files = [f for f in git(root, "diff", "--no-renames", "--name-only", "-z", f"{base}...{head}").split("\0") if f]
    if not changed_packages(files, crates):
        return []
    tip = git(root, "rev-list", "-1", head).strip()
    tip_trailers, _ = parse_trailers(git(root, "show", "-s", "--format=%B", tip))
    checks = tip_trailers.get("local-checks") or ""
    if any(evidence in checks for evidence in DEPENDENTS_EVIDENCE):
        return []
    if BISECT_REVERT_REVIEW.match((tip_trailers.get("local-review") or "").strip()):
        return []
    return [
        "this change touches a Rust workspace crate, so 'Local-Checks:' must record "
        "`just dependents-nextest` (land-change step 2)"
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--base", default="origin/master", help="base commit or ref")
    parser.add_argument("--head", default="HEAD", help="head commit or ref")
    parser.add_argument(
        "--advisory",
        action="store_true",
        help="emit GitHub Actions warnings instead of failing (Phase 0-2 rollout mode)",
    )
    parser.add_argument(
        "--enforce-dependents",
        action="store_true",
        help="with --advisory, still fail when a crate change does not record `just dependents-nextest`",
    )
    args = parser.parse_args(argv)

    try:
        impact, errors = validate_range(args.root, args.base, args.head)
        dependents_errors = validate_dependents_tests(args.root, args.base, args.head)
    except subprocess.CalledProcessError as exc:
        msg = f"pr-trailers: failed to inspect {args.base}..{args.head}: {exc}"
        if args.advisory:
            print(f"::warning title=PR trailers::{msg}")
            return 0
        print(msg, file=sys.stderr)
        return 1

    if args.advisory:
        enforced = dependents_errors if args.enforce_dependents else []
        warnings = errors + ([] if args.enforce_dependents else dependents_errors)
        for err in warnings:
            print(f"::warning title=PR trailers::{err}")
        for err in enforced:
            print(f"::error title=PR trailers::{err}")
            print(f"pr-trailers: {err}", file=sys.stderr)
        if enforced:
            return 1
        if warnings:
            print(
                f"pr-trailers: {len(warnings)} advisory warning(s) "
                "(enforcement starts in Phase 3; see AGENTS.md)"
            )
            return 0
    errors += dependents_errors
    if errors:
        for err in errors:
            print(f"pr-trailers: {err}", file=sys.stderr)
        return 1

    print(f"pr-trailers: OK (Release-Impact: {impact})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
