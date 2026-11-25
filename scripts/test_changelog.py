#!/usr/bin/env python3
"""Regression tests for changelog fragments: the gate and the release fold."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from changelog import check, release

HEADER = "# Changelog\n\n"
OLDER = "## 0.1.0 - 2026-01-01\n\n### Added\n\n- The first release.\n"


class ChangelogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write("crates/a/CHANGELOG.md", HEADER + OLDER)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, rel: str, text: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def errors(self, none_pending: bool = False) -> str:
        return "\n".join(check(self.root, none_pending))

    def test_accepts_a_well_formed_fragment(self) -> None:
        self.write("crates/a/changelog.d/fix-x.md", "### Fixed\n\n- X no longer fails.\n")
        self.assertEqual(self.errors(), "")

    def test_rejects_an_unreleased_section_in_a_changelog(self) -> None:
        # The section every PR used to edit, and so conflict on.
        self.write("crates/a/CHANGELOG.md", HEADER + "## [Unreleased]\n\n- New.\n\n" + OLDER)
        self.assertIn("crates/a/CHANGELOG.md:3: no Unreleased section", self.errors())

    def test_rejects_malformed_fragments(self) -> None:
        self.write("crates/a/changelog.d/unknown.md", "### Improvements\n\n- Y.\n")
        self.write("crates/a/changelog.d/preamble.md", "Some text.\n\n### Added\n\n- Z.\n")
        self.write("crates/a/changelog.d/empty.md", "### Added\n\n")
        self.write("crates/a/changelog.d/version.md", "## 0.2.0\n\n### Added\n\n- W.\n")
        errors = self.errors()
        self.assertIn("unknown.md: line 1: unknown section 'Improvements'", errors)
        self.assertIn("preamble.md: line 1: text before the first", errors)
        self.assertIn("empty.md: section 'Added' has no entries", errors)
        self.assertIn("version.md: line 1: only `### <Section>` headings", errors)

    def test_rejects_misplaced_or_misnamed_fragments(self) -> None:
        self.write("crates/b/changelog.d/orphan.md", "### Added\n\n- Q.\n")
        self.write("crates/a/changelog.d/Fix_X.md", "### Added\n\n- Q.\n")
        self.write("crates/a/changelog.d/nested/deep.md", "### Added\n\n- Q.\n")
        errors = self.errors()
        self.assertIn("crates/b/changelog.d/orphan.md: no CHANGELOG.md beside", errors)
        self.assertIn("crates/a/changelog.d/Fix_X.md: name a fragment", errors)
        self.assertIn("nested/deep.md: fragments go directly in changelog.d/", errors)

    def test_none_pending_fails_while_a_fragment_is_left(self) -> None:
        self.write("crates/a/changelog.d/fix-x.md", "### Fixed\n\n- X.\n")
        self.assertIn("fix-x.md: still pending", self.errors(none_pending=True))

    def test_release_folds_fragments_in_section_order_and_deletes_them(self) -> None:
        first = self.write("crates/a/changelog.d/a-fix.md", "### Fixed\n\n- X no longer fails.\n")
        second = self.write(
            "crates/a/changelog.d/b-api.md",
            "### Added\n\n- `b` reads B.\n  It wraps.\n\n### Fixed\n\n- Y no longer fails.\n",
        )
        self.assertEqual(release(self.root, "0.2.0", "2026-02-02"), [])
        self.assertEqual(
            (self.root / "crates/a/CHANGELOG.md").read_text(),
            HEADER
            + "## 0.2.0 - 2026-02-02\n\n### Added\n\n- `b` reads B.\n  It wraps.\n\n"
            + "### Fixed\n\n- X no longer fails.\n- Y no longer fails.\n\n"
            + OLDER,
        )
        self.assertFalse(first.exists() or second.exists())
        self.assertEqual(self.errors(none_pending=True), "")

    def test_release_keeps_a_bracketed_heading_style(self) -> None:
        self.write("crates/a/CHANGELOG.md", HEADER + "## [0.1.0] - 2026-01-01\n\n- Old.\n")
        self.write("crates/a/changelog.d/x.md", "### Added\n\n- X.\n")
        self.assertEqual(release(self.root, "0.2.0", "2026-02-02"), [])
        self.assertIn("## [0.2.0] - 2026-02-02\n\n### Added\n\n- X.\n\n## [0.1.0]",
                      (self.root / "crates/a/CHANGELOG.md").read_text())

    def test_release_refuses_a_version_already_released_or_a_bad_fragment(self) -> None:
        fragment = self.write("crates/a/changelog.d/x.md", "### Added\n\n- X.\n")
        self.assertIn("already has a 0.1.0 heading", "\n".join(release(self.root, "0.1.0", "2026-02-02")))
        self.write("crates/a/changelog.d/bad.md", "### Misc\n\n- Y.\n")
        self.assertIn("unknown section", "\n".join(release(self.root, "0.2.0", "2026-02-02")))
        self.assertTrue(fragment.exists())
        self.assertEqual((self.root / "crates/a/CHANGELOG.md").read_text(), HEADER + OLDER)


if __name__ == "__main__":
    unittest.main()
