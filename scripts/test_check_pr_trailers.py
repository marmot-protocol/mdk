#!/usr/bin/env python3
"""Unit tests for scripts/check_pr_trailers.py."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_pr_trailers as trailers  # noqa: E402


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


class PrTrailerTests(unittest.TestCase):
    def make_repo(self) -> tuple[tempfile.TemporaryDirectory[str], Path, str]:
        tmp = tempfile.TemporaryDirectory()
        repo = Path(tmp.name)
        git(repo, "init", "-b", "master")
        git(repo, "config", "user.name", "Test Author")
        git(repo, "config", "user.email", "test@example.com")
        git(repo, "config", "commit.gpgsign", "false")
        (repo / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
        git(repo, "add", "CHANGELOG.md")
        git(repo, "commit", "-m", "Initial commit")
        base = git(repo, "rev-parse", "HEAD")
        return tmp, repo, base

    def commit_file(self, repo: Path, rel_path: str, content: str, message: str) -> str:
        path = repo / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        git(repo, "add", rel_path)
        git(repo, "commit", "-m", message)
        return git(repo, "rev-parse", "HEAD")

    def test_valid_cross_model_human_and_exempt_trailers(self) -> None:
        cases = [
            (
                "Add feature\n\n"
                "Local-Checks: cargo fmt, clippy -p marmot-app, nextest\n"
                "Local-Review: claude + codex merge @ 37a9067\n"
                "Release-Impact: patch\n",
                "patch",
            ),
            (
                "Doc tweak\n\n"
                "Local-Checks: docs-only\n"
                "Local-Review: human (@reviewer)\n"
                "Release-Impact: none\n",
                "none",
            ),
            (
                'Revert "bad commit"\n\n'
                "This reverts commit abcdef1.\n\n"
                "Local-Checks: bisect verified on mdk-ci-1\n"
                "Local-Review: exempt (revert)\n"
                "Release-Impact: patch\n",
                "patch",
            ),
            (
                "Case-insensitive keys and extra standard trailers\n\n"
                "Signed-off-by: Test Author <test@example.com>\n"
                "local-checks: cargo clippy\n"
                "local-review: opencode + cursor merge @ 0123456789abcdef\n"
                "release-impact: minor\n",
                "minor",
            ),
        ]
        for message, expected_impact in cases:
            with self.subTest(expected_impact=expected_impact):
                tmp, repo, base = self.make_repo()
                try:
                    head = self.commit_file(repo, "note.txt", expected_impact, message)
                    impact, errors = trailers.validate_range(repo, base, head)
                    self.assertEqual(errors, [])
                    self.assertEqual(impact, expected_impact)
                finally:
                    tmp.cleanup()

    def test_rejects_missing_placeholder_duplicate_and_same_seat_trailers(self) -> None:
        bad_messages = [
            ("No trailers at all", ["Local-Checks", "Local-Review", "Release-Impact"]),
            (
                "Placeholder values\n\n"
                "Local-Checks: todo\n"
                "Local-Review: tbd\n"
                "Release-Impact: major\n",
                ["invalid 'Local-Checks:'", "invalid 'Local-Review:'", "invalid 'Release-Impact:'"],
            ),
            (
                "Same seat twice\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: claude + claude merge @ 37a9067\n"
                "Release-Impact: none\n",
                ["two distinct seats"],
            ),
            (
                "Unknown seat\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: unknown + codex merge @ 37a9067\n"
                "Release-Impact: none\n",
                ["unknown review-local seat"],
            ),
            (
                "Duplicate trailer\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: patch\n"
                "Release-Impact: minor\n",
                ["duplicate trailer"],
            ),
        ]
        for message, expected_substrings in bad_messages:
            with self.subTest(first_line=message.splitlines()[0]):
                tmp, repo, base = self.make_repo()
                try:
                    head = self.commit_file(repo, "note.txt", "x", message)
                    _, errors = trailers.validate_range(repo, base, head)
                    joined = "\n".join(errors)
                    for sub in expected_substrings:
                        self.assertIn(sub, joined)
                finally:
                    tmp.cleanup()

    def test_changelog_fragment_cross_checks(self) -> None:
        tmp, repo, base = self.make_repo()
        try:
            breaking = "### Breaking changes\n\n- Renamed public API.\n"
            head = self.commit_file(
                repo,
                "changelog.d/rename-api.md",
                breaking,
                "Rename API\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: patch\n",
            )
            _, errors = trailers.validate_range(repo, base, head)
            self.assertTrue(
                any("Breaking changes" in e and "minor" in e for e in errors),
                errors,
            )

            head = self.commit_file(
                repo,
                "changelog.d/rename-api.md",
                breaking + "- Updated callers.\n",
                "Fix impact to minor\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: minor\n",
            )
            # Earlier commit still had Release-Impact: patch -> conflict detected.
            _, errors = trailers.validate_range(repo, base, head)
            self.assertTrue(any("conflicts with tip commit" in e for e in errors), errors)
        finally:
            tmp.cleanup()

        # Breaking fragment paired with Release-Impact: minor passes cleanly.
        tmp, repo, base = self.make_repo()
        try:
            head = self.commit_file(
                repo,
                "changelog.d/rename-api.md",
                "### Breaking changes\n\n- Renamed public API.\n",
                "Rename API\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: minor\n",
            )
            impact, errors = trailers.validate_range(repo, base, head)
            self.assertEqual(errors, [])
            self.assertEqual(impact, "minor")
        finally:
            tmp.cleanup()

        # Non-breaking changelog fragment paired with Release-Impact: none must fail.
        tmp, repo, base = self.make_repo()
        try:
            head = self.commit_file(
                repo,
                "changelog.d/fix-bug.md",
                "### Fixed\n\n- Fixed a crash.\n",
                "Fix crash\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: none\n",
            )
            _, errors = trailers.validate_range(repo, base, head)
            self.assertTrue(any("cannot be 'none'" in e for e in errors), errors)
        finally:
            tmp.cleanup()

        # Non-breaking changelog fragment with Release-Impact: patch passes.
        tmp, repo, base = self.make_repo()
        try:
            head = self.commit_file(
                repo,
                "changelog.d/fix-bug.md",
                "### Fixed\n\n- Fixed a crash.\n",
                "Fix crash\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: patch\n",
            )
            impact, errors = trailers.validate_range(repo, base, head)
            self.assertEqual(errors, [])
            self.assertEqual(impact, "patch")
        finally:
            tmp.cleanup()

    def test_multi_commit_pr_allows_unmarked_earlier_commits_and_rejects_conflicts(self) -> None:
        tmp, repo, base = self.make_repo()
        try:
            self.commit_file(repo, "a.txt", "1", "WIP commit without trailers")
            head = self.commit_file(
                repo,
                "b.txt",
                "2",
                "Final reviewed commit\n\n"
                "Local-Checks: cargo test\n"
                "Local-Review: claude + codex merge @ 1234567\n"
                "Release-Impact: patch\n",
            )
            impact, errors = trailers.validate_range(repo, base, head)
            self.assertEqual(errors, [])
            self.assertEqual(impact, "patch")
        finally:
            tmp.cleanup()

    def test_label_cross_checks(self) -> None:
        tmp, repo, base = self.make_repo()
        try:
            head = self.commit_file(
                repo,
                "a.txt",
                "1",
                "Internal change\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: none\n",
            )
            _, errors = trailers.validate_range(repo, base, head, labels=["impact:none", "ci:full"])
            self.assertEqual(errors, [])

            _, errors = trailers.validate_range(repo, base, head, labels=["impact:patch"])
            self.assertTrue(any("disagrees" in e for e in errors), errors)

            _, errors = trailers.validate_range(
                repo, base, head, labels=["impact:none", "impact:minor"]
            )
            self.assertTrue(any("multiple impact labels" in e for e in errors), errors)
        finally:
            tmp.cleanup()

    def test_cli_strict_vs_advisory_mode(self) -> None:
        tmp, repo, base = self.make_repo()
        try:
            head = self.commit_file(repo, "a.txt", "1", "Missing trailers")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = trailers.main(["--root", str(repo), "--base", base, "--head", head])
            self.assertEqual(code, 1)
            self.assertIn("missing required trailer", stderr.getvalue())

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = trailers.main(
                    [
                        "--root",
                        str(repo),
                        "--base",
                        base,
                        "--head",
                        head,
                        "--advisory",
                        "--labels-json",
                        json.dumps([{"name": "impact:none"}]),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertIn("::warning title=PR trailers::", stdout.getvalue())
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
