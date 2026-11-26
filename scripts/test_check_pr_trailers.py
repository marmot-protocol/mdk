#!/usr/bin/env python3
"""Unit tests for scripts/check_pr_trailers.py."""

from __future__ import annotations

import io
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

    def test_valid_cross_model_human_exempt_folded_and_coauthored_trailers(self) -> None:
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
                "Folded trailer value, custom seat, and multiple Co-authored-by lines\n\n"
                "Local-Checks: cargo fmt --all --check,\n"
                "  cargo clippy -p marmot-app --all-targets,\n"
                "  cargo nextest run -p marmot-app\n"
                "Local-Review: gemini-pro + codex merge @ 0123456789abcdef\n"
                "Release-Impact: minor\n"
                "Co-authored-by: Alice <alice@example.com>\n"
                "Co-authored-by: Bob <bob@example.com>\n",
                "minor",
            ),
            (
                "Markdown horizontal rule before valid trailer block\n\n"
                "Section 1\n\n"
                "---\n\n"
                "Section 2\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: none\n",
                "none",
            ),
        ]
        for message, expected_impact in cases:
            with self.subTest(first_line=message.splitlines()[0]):
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
                "Placeholder seat name\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: tbd + codex merge @ 37a9067\n"
                "Release-Impact: none\n",
                ["placeholder seat name"],
            ),
            (
                "Duplicate MDK trailer\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: patch\n"
                "Release-Impact: minor\n",
                ["duplicate trailer"],
            ),
            (
                "Trailer-shaped example before --- divider followed by trailing prose\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: none\n\n"
                "---\n\n"
                "Trailing prose after a Markdown rule.\n",
                ["Local-Checks", "Local-Review", "Release-Impact"],
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

    def test_changelog_fragment_cross_checks_and_advancing_base(self) -> None:
        # Breaking fragment with patch fails; breaking fragment with minor passes.
        tmp, repo, base = self.make_repo()
        try:
            head = self.commit_file(
                repo,
                "changelog.d/rename-api.md",
                "### Breaking changes\n\n- Renamed public API.\n",
                "Rename API\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: human\n"
                "Release-Impact: patch\n",
            )
            _, errors = trailers.validate_range(repo, base, head)
            self.assertTrue(any("Breaking changes" in e and "minor" in e for e in errors), errors)
        finally:
            tmp.cleanup()

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

        # Non-breaking fragment forbids none and accepts patch.
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

        # Advancing master (e.g. a release PR folding and deleting a breaking fragment)
        # must not cause an open docs-only branch to inherit that fragment's impact.
        tmp, repo, _ = self.make_repo()
        try:
            self.commit_file(
                repo,
                "changelog.d/already-on-master.md",
                "### Breaking changes\n\n- Prior breaking change.\n",
                "Prior breaking PR on master",
            )
            git(repo, "checkout", "-b", "docs-pr")
            pr_head = self.commit_file(
                repo,
                "README.md",
                "# Updated docs\n",
                "Update README\n\n"
                "Local-Checks: docs-only\n"
                "Local-Review: human\n"
                "Release-Impact: none\n",
            )
            git(repo, "checkout", "master")
            git(repo, "rm", "changelog.d/already-on-master.md")
            git(repo, "commit", "-m", "Release 0.21.0 (fold changelog fragments)")
            advanced_master = git(repo, "rev-parse", "master")

            impact, errors = trailers.validate_range(repo, advanced_master, pr_head)
            self.assertEqual(errors, [])
            self.assertEqual(impact, "none")
        finally:
            tmp.cleanup()

    def test_extract_landed_trailers_handles_github_squash_formats(self) -> None:
        single_commit_squash = (
            "Enforce device roster key binding (#3767)\n\n"
            "Summary body.\n\n"
            "Local-Checks: cargo fmt, nextest\n"
            "Local-Review: claude + codex merge @ 37a9067\n"
            "Release-Impact: patch\n"
            "Co-authored-by: Claude Opus 5.5 <noreply@anthropic.com>\n"
        )
        parsed, errors = trailers.extract_landed_trailers(single_commit_squash)
        self.assertEqual(errors, [])
        self.assertEqual(parsed["release-impact"], "patch")
        self.assertEqual(parsed["local-review"], "claude + codex merge @ 37a9067")

        # Multi-commit COMMIT_MESSAGES squash with trailers only on tip, no footer.
        multi_no_footer = (
            "Add feature (#3800)\n\n"
            "* WIP commit\n\n"
            "Earlier body.\n\n"
            "* Final reviewed commit\n\n"
            "Local-Checks: cargo fmt,\n"
            "  cargo nextest run -p marmot-app\n"
            "Local-Review: claude + codex merge @ 1234567\n"
            "Release-Impact: minor\n"
        )
        parsed, errors = trailers.extract_landed_trailers(multi_no_footer)
        self.assertEqual(errors, [])
        self.assertEqual(parsed["release-impact"], "minor")
        self.assertEqual(parsed["local-checks"], "cargo fmt, cargo nextest run -p marmot-app")

        # Multi-commit COMMIT_MESSAGES squash with GitHub's hoisted `---------`
        # Co-authored-by footer (modeled on landed master commit bfa559b46).
        multi_with_footer = (
            "Answer an unreadable control request (#3668)\n\n"
            "* Earlier commit with old note\n\n"
            "Release-Impact: minor\n\n"
            "* Tip commit\n\n"
            "Final summary.\n\n"
            "Local-Checks: cargo test -p agent-control\n"
            "Local-Review: claude + codex merge @ abcdef1\n"
            "Release-Impact: patch\n\n"
            "---------\n\n"
            "Co-authored-by: Claude Opus 5.5 <noreply@anthropic.com>\n"
            "Co-authored-by: Second Author <second@example.com>\n"
        )
        parsed, errors = trailers.extract_landed_trailers(multi_with_footer)
        self.assertEqual(errors, [])
        self.assertEqual(parsed["release-impact"], "patch")
        self.assertEqual(parsed["local-checks"], "cargo test -p agent-control")
        self.assertEqual(parsed["local-review"], "claude + codex merge @ abcdef1")

        # Multi-commit squash where trailers were only on an earlier commit
        # (modeled on landed master commit 19d0a3092) does not fabricate a tip attestation.
        earlier_only = (
            "Stop automatic packaging (#3768)\n\n"
            "* First commit\n\n"
            "Release-Impact: none\n\n"
            "* Second commit without trailers\n"
        )
        parsed, errors = trailers.extract_landed_trailers(earlier_only)
        self.assertEqual(errors, [])
        self.assertNotIn("release-impact", parsed)

        # A `---------` divider followed by normal or colon-bearing prose is ignored.
        for suffix in (
            "This is prose after a horizontal rule, not a trailer footer.\n",
            "Example: cargo fmt\n",
        ):
            with self.subTest(suffix=suffix.strip()):
                prose_after_divider = (
                    "Explain layout (#3801)\n\n"
                    "Local-Checks: cargo fmt\n"
                    "Local-Review: human\n"
                    "Release-Impact: minor\n\n"
                    "---------\n\n"
                    + suffix
                )
                parsed, errors = trailers.extract_landed_trailers(prose_after_divider)
                self.assertEqual(errors, [])
                self.assertNotIn("release-impact", parsed)

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
                    ["--root", str(repo), "--base", base, "--head", head, "--advisory"]
                )
            self.assertEqual(code, 0)
            self.assertIn("::warning title=PR trailers::", stdout.getvalue())
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
