#!/usr/bin/env python3
"""Validate commit trailers and changelog/label consistency for pull requests.

Every change targeting master records three trailers on its tip commit (which
GitHub preserves in the squash commit under `COMMIT_MESSAGES`):

    Local-Checks: cargo fmt, clippy -p <crate>, nextest <area>, smoke
    Local-Review: claude + codex merge @ <short-sha>
    Release-Impact: none | patch | minor

Cross-checks:
  - Any added or modified `changelog.d/<slug>.md` with a `### Breaking changes`
    section requires `Release-Impact: minor`.
  - Any added or modified `changelog.d/<slug>.md` with other sections forbids
    `Release-Impact: none`.
  - Earlier commits in `base..head` must not carry a conflicting
    `Release-Impact:` trailer (squash merge concatenates commit messages).
  - Optional PR labels (`impact:none`, `impact:patch`, `impact:minor`) must be
    unique and agree with `Release-Impact:`.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import changelog  # noqa: E402

VALID_IMPACTS = ("none", "patch", "minor")
VALID_SEATS = frozenset({"claude", "codex", "cursor", "opencode"})
PLACEHOLDER_VALUES = frozenset({"", "-", "...", "?", "n/a", "na", "tbd", "todo"})
TRAILER_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)$")
CROSS_MODEL_REVIEW = re.compile(
    r"^(?P<seat_a>[a-z]+)\s*\+\s*(?P<seat_b>[a-z]+)\s+merge\s+@\s*(?P<sha>[0-9a-f]{7,40})(?:\s+.*)?$"
)
HUMAN_REVIEW = re.compile(r"^human(?:\s+\S.*)?$")
EXEMPT_REVIEW = re.compile(r"^exempt\s*\((?P<reason>[^()]+)\)$")
FRAGMENT_PATH = re.compile(r"(?:^|/)changelog\.d/[^/]+\.md$")


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout


def parse_trailers(message: str) -> tuple[dict[str, str], list[str]]:
    """Parse Git trailers from the final non-empty paragraph of a commit message.

    Returns (lowercased_key -> value, duplicate_or_format_errors).
    """
    lines = message.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return {}, []

    block: list[str] = []
    for line in reversed(lines):
        if not line.strip():
            break
        block.append(line)
    block.reverse()

    # A trailer block consists solely of `Key: value` lines (comment lines ignored).
    parsed: list[tuple[str, str]] = []
    for line in block:
        if line.startswith("#"):
            continue
        match = TRAILER_LINE.match(line)
        if not match:
            return {}, []
        parsed.append((match.group(1), match.group(2).strip()))

    trailers: dict[str, str] = {}
    errors: list[str] = []
    for raw_key, value in parsed:
        key = raw_key.lower()
        if key in trailers:
            errors.append(f"duplicate trailer '{raw_key}'")
        else:
            trailers[key] = value
    return trailers, errors


def validate_local_checks(value: str | None) -> list[str]:
    if value is None:
        return ["missing required trailer 'Local-Checks:' on tip commit"]
    normalized = value.strip().lower()
    if normalized in PLACEHOLDER_VALUES:
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
        if seat_a not in VALID_SEATS or seat_b not in VALID_SEATS:
            return [
                f"unknown review-local seat in 'Local-Review: {stripped}'; "
                f"expected two of {', '.join(sorted(VALID_SEATS))}"
            ]
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


def validate_range(
    root: Path,
    base: str,
    head: str,
    labels: list[str] | None = None,
) -> tuple[str | None, list[str]]:
    """Validate commit trailers and changelog/label consistency for `base..head`."""
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

    # Check earlier commits for conflicting Release-Impact trailers that GitHub's
    # COMMIT_MESSAGES squash would concatenate onto master.
    if impact is not None:
        for sha in revs[:-1]:
            msg = git(root, "show", "-s", "--format=%B", sha)
            earlier_trailers, earlier_errors = parse_trailers(msg)
            for err in earlier_errors:
                if "release-impact" in err.lower():
                    errors.append(f"earlier commit {sha[:9]}: {err}")
            earlier_impact = earlier_trailers.get("release-impact")
            if earlier_impact is not None and earlier_impact.strip() != impact:
                errors.append(
                    f"earlier commit {sha[:9]} declares 'Release-Impact: {earlier_impact.strip()}' "
                    f"which conflicts with tip commit 'Release-Impact: {impact}'; "
                    "squash-merge would emit conflicting trailers on master"
                )

    # Cross-check added/modified changelog.d/ fragments against Release-Impact.
    changed_files = git(
        root, "diff", "--no-renames", "--name-only", "--diff-filter=AM", base, head
    ).splitlines()
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

    # Cross-check optional PR impact:* labels.
    if labels:
        impact_labels = sorted(
            {
                label.split(":", 1)[1]
                for label in labels
                if label.startswith("impact:") and label.split(":", 1)[1] in VALID_IMPACTS
            }
        )
        if len(impact_labels) > 1:
            joined = ", ".join(f"impact:{lvl}" for lvl in impact_labels)
            errors.append(f"multiple impact labels set on PR ({joined}); keep at most one")
        elif len(impact_labels) == 1 and impact is not None and impact_labels[0] != impact:
            errors.append(
                f"PR label 'impact:{impact_labels[0]}' disagrees with tip commit "
                f"'Release-Impact: {impact}'"
            )

    return impact, errors


def parse_labels_json(raw: str | None) -> list[str]:
    if not raw or not raw.strip():
        return []
    decoded = json.loads(raw)
    if not isinstance(decoded, list):
        raise ValueError("--labels-json must decode to a JSON array")
    labels: list[str] = []
    for item in decoded:
        if isinstance(item, str):
            labels.append(item)
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            labels.append(item["name"])
        else:
            raise ValueError(f"unsupported label entry in --labels-json: {item!r}")
    return labels


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--base", default="origin/master", help="base commit or ref")
    parser.add_argument("--head", default="HEAD", help="head commit or ref")
    parser.add_argument(
        "--labels-json",
        default="",
        help="optional JSON array of PR label names or GitHub label objects",
    )
    parser.add_argument(
        "--advisory",
        action="store_true",
        help="emit GitHub Actions warnings instead of failing (Phase 0-2 rollout mode)",
    )
    args = parser.parse_args(argv)

    try:
        labels = parse_labels_json(args.labels_json)
        impact, errors = validate_range(args.root, args.base, args.head, labels=labels)
    except (subprocess.CalledProcessError, ValueError, json.JSONDecodeError) as exc:
        msg = f"pr-trailers: failed to inspect {args.base}..{args.head}: {exc}"
        if args.advisory:
            print(f"::warning title=PR trailers::{msg}")
            return 0
        print(msg, file=sys.stderr)
        return 1

    if errors:
        if args.advisory:
            for err in errors:
                print(f"::warning title=PR trailers::{err}")
            print(
                f"pr-trailers: {len(errors)} advisory warning(s) "
                "(enforcement starts in Phase 3; see AGENTS.md)"
            )
            return 0
        for err in errors:
            print(f"pr-trailers: {err}", file=sys.stderr)
        return 1

    print(f"pr-trailers: OK (Release-Impact: {impact})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
