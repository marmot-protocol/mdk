#!/usr/bin/env python3
"""Unit and synthetic-repo tests for Phase 4 SemVer RC classification, publishing, and promotion."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_binding_docs  # noqa: E402
import classify_release_impact as classifier  # noqa: E402
import promote_release  # noqa: E402
import rc_release  # noqa: E402


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def _init_synthetic_repo(repo: Path) -> str:
    """Create a minimal synthetic MDK repo tagged at v0.19.0 and advanced to 0.20.0-dev."""
    _git(repo, "init", "-b", "master")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "commit.gpgsign", "false")

    (repo / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/marmot-uniffi"]\n\n[workspace.package]\nversion = "0.19.0"\n',
        encoding="utf-8",
    )
    (repo / "Cargo.lock").write_text(
        'version = 4\n\n[[package]]\nname = "marmot-uniffi"\nversion = "0.19.0"\n\n'
        '[[package]]\nname = "serde"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    (repo / "crates/marmot-uniffi/src").mkdir(parents=True)
    (repo / "crates/marmot-uniffi/Cargo.toml").write_text(
        '[package]\nname = "marmot-uniffi"\nversion.workspace = true\n', encoding="utf-8"
    )
    (repo / "crates/marmot-uniffi/src/lib.rs").write_text(
        """#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountSummaryFfi {
    /// Account identifier.
    pub account_id: String,
}

#[uniffi::export]
impl Marmot {
    pub fn list_accounts(&self) -> Vec<AccountSummaryFfi> {
        Vec::new()
    }
}
""",
        encoding="utf-8",
    )
    (repo / "crates/marmot-c/include").mkdir(parents=True)
    (repo / "crates/marmot-c/include/marmot.h").write_text(
        """typedef struct MarmotAccountSummary {
  const char *account_id;
} MarmotAccountSummary;

MarmotStatus marmot_list_accounts(void *client, MarmotAccountSummary **out);
""",
        encoding="utf-8",
    )
    (repo / "crates/storage-sqlite/src/base/migrations").mkdir(parents=True)
    (repo / "crates/storage-sqlite/src/base/migrations/0218_initial.rs").write_text(
        "pub const VERSION: u32 = 218;\n", encoding="utf-8"
    )
    (repo / "crates/cgka-conformance-simulator/vectors").mkdir(parents=True)
    (repo / "crates/cgka-conformance-simulator/vectors/sample.v1.json").write_text(
        '{\n  "conformance_version": "0.19.0",\n  "name": "sample"\n}\n', encoding="utf-8"
    )
    (repo / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [0.19.0] - 2026-11-22\n\n### Fixed\n\n- Initial release.\n\n"
        "[Unreleased]: https://github.com/marmot-protocol/mdk/compare/v0.19.0...HEAD\n"
        "[0.19.0]: https://github.com/marmot-protocol/mdk/compare/v0.18.0...v0.19.0\n",
        encoding="utf-8",
    )
    (repo / "docs/release").mkdir(parents=True)
    (repo / "docs/integration").mkdir(parents=True)
    (repo / "docs/release/0.19.0.md").write_text(
        "# MDK 0.19.0\n\nSee [guide](../integration/0.19.0.md).\n", encoding="utf-8"
    )
    (repo / "docs/integration/0.19.0.md").write_text(
        "# Integration 0.19.0\n\nSee [notes](../release/0.19.0.md).\n", encoding="utf-8"
    )
    (repo / "docs/integration/README.md").write_text(
        "| Upgrade | Detailed guide | Release notes |\n| --- | --- | --- |\n"
        "| 0.18.0 → 0.19.0 | [0.19.0 integration](0.19.0.md) | [0.19.0 notes](../release/0.19.0.md) |\n",
        encoding="utf-8",
    )
    (repo / "README.md").write_text(
        "# MDK\n\n"
        "The latest is [0.18.0 → 0.19.0](docs/integration/0.19.0.md); read guides.\n\n"
        "## Overview\n\n"
        "Line 1.\n"
        "Line 2.\n"
        "Line 3.\n"
        "Line 4.\n\n"
        "## Crates\n\n"
        "- cgka-engine\n",
        encoding="utf-8",
    )
    (repo / "release.md").write_text(
        'base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.19.0"\n',
        encoding="utf-8",
    )
    (repo / "integrations").mkdir(parents=True)
    (repo / "integrations/README.md").write_text(
        'base_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.19.0"\n',
        encoding="utf-8",
    )
    (repo / "scripts").mkdir(parents=True)
    (repo / "scripts/install-hermes-marmot.sh").write_text(
        "#!/usr/bin/env bash\n# help:\n  base_url=https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.19.0\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "Release 0.19.0")
    _git(repo, "tag", "-a", "v0.19.0", "-m", "mdk v0.19.0")

    # Move workspace to 0.20.0-dev like master between releases.
    promote_release.stamp_workspace_version(repo, "0.20.0-dev")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "Start 0.20.0-dev\n\nLocal-Checks: fmt\nLocal-Review: human\nRelease-Impact: none\n")
    return _git(repo, "rev-parse", "HEAD")


class ReleaseImpactClassifierTests(unittest.TestCase):
    def test_additive_uniffi_and_c_exports_classify_as_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_synthetic_repo(repo)
            (repo / "crates/marmot-uniffi/src/lib.rs").write_text(
                """#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountSummaryFfi {
    /// Updated doc comment only must not trigger a breaking change.
    pub account_id: String,
}

#[uniffi::export]
impl Marmot {
    pub fn list_accounts(&self) -> Vec<AccountSummaryFfi> {
        Vec::new()
    }

    pub fn ping(&self) -> bool {
        true
    }
}
""",
                encoding="utf-8",
            )
            (repo / "crates/marmot-c/include/marmot.h").write_text(
                """typedef struct MarmotAccountSummary {
  const char *account_id;
} MarmotAccountSummary;

MarmotStatus marmot_list_accounts(void *client, MarmotAccountSummary **out);
MarmotStatus marmot_ping(void *client, uint8_t *out);
""",
                encoding="utf-8",
            )
            (repo / "changelog.d").mkdir()
            (repo / "changelog.d/add-ping.md").write_text("### Added\n\n- Added `ping` health check.\n", encoding="utf-8")
            _git(repo, "add", ".")
            _git(
                repo,
                "commit",
                "-m",
                "Add ping helper\n\nLocal-Checks: cargo test\nLocal-Review: claude + codex merge @ 1234567\nRelease-Impact: patch\n",
            )

            report, delta = classifier.classify_range(repo, target_ref="HEAD")
            self.assertEqual(report["impact"], "patch")
            self.assertEqual(report["target_base_version"], "0.19.1")
            self.assertEqual(delta["uniffi"]["breaking"], [])
            self.assertEqual(delta["c_abi"]["breaking"], [])
            self.assertEqual([fn["name"] for fn in delta["uniffi"]["functions"]["added"]], ["Marmot::ping"])
            self.assertEqual([fn["name"] for fn in delta["c_abi"]["functions"]["added"]], ["marmot_ping"])

    def test_breaking_uniffi_record_change_triggers_minor(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_synthetic_repo(repo)
            (repo / "crates/marmot-uniffi/src/lib.rs").write_text(
                """#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountSummaryFfi {
    pub account_id: String,
    pub display_name: String,
}

#[uniffi::export]
impl Marmot {
    pub fn list_accounts(&self) -> Vec<AccountSummaryFfi> {
        Vec::new()
    }
}
""",
                encoding="utf-8",
            )
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "Add required field\n\nRelease-Impact: patch\n")

            report, delta = classifier.classify_range(repo, target_ref="HEAD")
            self.assertEqual(report["impact"], "minor")
            self.assertEqual(report["target_base_version"], "0.20.0")
            self.assertIn("changed UniFFI type `AccountSummaryFfi`", delta["uniffi"]["breaking"])

    def test_new_sqlite_migration_triggers_minor(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_synthetic_repo(repo)
            (repo / "crates/storage-sqlite/src/base/migrations/0219_new_index.rs").write_text(
                "pub const VERSION: u32 = 219;\n", encoding="utf-8"
            )
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "Add migration 219\n\nRelease-Impact: patch\n")

            report, delta = classifier.classify_range(repo, target_ref="HEAD")
            self.assertEqual(report["impact"], "minor")
            self.assertEqual(report["target_base_version"], "0.20.0")
            self.assertEqual(
                delta["storage_migrations"],
                ["crates/storage-sqlite/src/base/migrations/0219_new_index.rs"],
            )

    def test_breaking_changelog_or_minor_trailer_with_github_squash_footer_triggers_minor(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_synthetic_repo(repo)
            (repo / "README.md").write_text("Updated doc\n", encoding="utf-8")
            _git(repo, "add", ".")
            _git(
                repo,
                "commit",
                "-m",
                "Behavioral breaking change (#4000)\n\n"
                "Local-Checks: cargo test\n"
                "Local-Review: claude + codex merge @ abcdef1\n"
                "Release-Impact: minor\n\n"
                "---------\n\n"
                "Co-authored-by: Bot <bot@example.com>\n",
            )

            report, _ = classifier.classify_range(repo, target_ref="HEAD")
            self.assertEqual(report["impact"], "minor")
            self.assertEqual(report["target_base_version"], "0.20.0")

            # Human override can downgrade minor -> patch explicitly.
            overridden, _ = classifier.classify_range(repo, target_ref="HEAD", override_impact="patch")
            self.assertEqual(overridden["computed_impact"], "minor")
            self.assertEqual(overridden["impact"], "patch")
            self.assertEqual(overridden["target_base_version"], "0.19.1")


class RcReleaseRulesTests(unittest.TestCase):
    def test_rc_workspace_dev_compatibility_allows_minor_and_preceding_patch(self):
        self.assertTrue(rc_release.rc_matches_workspace_dev("0.20.0-rc.1", "0.20.0-dev"))
        self.assertTrue(rc_release.rc_matches_workspace_dev("0.19.1-rc.1", "0.20.0-dev"))
        self.assertTrue(rc_release.rc_matches_workspace_dev("0.19.2-rc.4", "0.20.0-dev"))
        for bad_rc, ws in [
            ("0.21.0-rc.1", "0.20.0-dev"),
            ("0.19.0-rc.1", "0.20.0-dev"),
            ("0.18.1-rc.1", "0.20.0-dev"),
            ("0.20.1-rc.1", "0.20.0-dev"),
            ("0.20.0-rc.0", "0.20.0-dev"),
            ("0.20.0-rc.1", "0.20.0"),
        ]:
            with self.subTest(rc=bad_rc, ws=ws):
                self.assertFalse(rc_release.rc_matches_workspace_dev(bad_rc, ws))

    def test_choose_rc_version_is_monotonic_across_all_tracks_and_persisted_counters(self):
        self.assertEqual(rc_release.choose_rc_version("0.20.0", []), "0.20.0-rc.1")
        taken = ["marmotc-v0.20.0-rc.1", "wn-agent-v0.20.0-rc.3", "marmotkit-v0.19.1-rc.9"]
        self.assertEqual(rc_release.choose_rc_version("0.20.0", taken), "0.20.0-rc.4")
        self.assertEqual(rc_release.choose_rc_version("0.19.1", taken), "0.19.1-rc.10")
        # Even after retention deletes every tag for 0.20.0, persisted counter and
        # historical rc/releases records prevent reusing deleted immutable tag names.
        self.assertEqual(rc_release.choose_rc_version("0.20.0", [], min_counter=4), "0.20.0-rc.5")
        self.assertEqual(
            rc_release.choose_rc_version("0.20.0", [], min_counter=2, historical_versions=["0.20.0-rc.6"]),
            "0.20.0-rc.7",
        )

    def test_select_canary_source_requires_first_parent_canary_and_never_rewinds(self):
        master = ["c4", "c3", "c2", "c1"]
        self.assertEqual(rc_release.select_canary_source(master, "c3", "c1"), "c3")
        # Never moves backwards past previous_sha even if canary ref is older.
        self.assertEqual(rc_release.select_canary_source(master, "c2", "c3"), "c3")
        with self.assertRaises(rc_release.ReleaseError):
            rc_release.select_canary_source(master, None, None)
        with self.assertRaises(rc_release.ReleaseError):
            rc_release.select_canary_source(master, "diverged", None)

    def test_retention_expires_old_rcs_and_legacy_nightlies_only(self):
        today = dt.date(2026, 11, 26)
        releases = {
            "marmotkit-v0.20.0-rc.1": {"prerelease": True, "draft": False, "published_at": "2026-10-20T00:00:00Z"},
            "marmotkit-v0.20.0-rc.2": {"prerelease": True, "draft": False, "published_at": "2026-11-20T00:00:00Z"},
            "marmotkit-v0.20.0-rc.3": {"prerelease": True, "draft": False, "published_at": "2026-10-10T00:00:00Z"},
            "marmotkit-v0.19.0": {"prerelease": False, "draft": False, "published_at": "2026-09-01T00:00:00Z"},
        }
        tags = list(releases.keys()) + [
            "marmotc-v0.19.0-nightly.20261015",
            "marmotc-v0.20.0-nightly.20261125",
            "marmotkit-snapshot-" + "a" * 40,
            "v0.19.0",
        ]
        expired = rc_release.expired_prerelease_tags(
            tags, releases, today, protected=["marmotkit-v0.20.0-rc.3"], days=30
        )
        self.assertEqual(expired, ["marmotc-v0.19.0-nightly.20261015", "marmotkit-v0.20.0-rc.1"])


class PromoteReleaseTests(unittest.TestCase):
    def test_next_dev_version_advances_only_when_minor_ships(self):
        self.assertEqual(promote_release.next_dev_version_after("0.20.0", "0.20.0-dev"), "0.21.0-dev")
        self.assertEqual(promote_release.next_dev_version_after("0.19.1", "0.20.0-dev"), "0.20.0-dev")

    def test_stamp_and_metadata_diff_guard_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_synthetic_repo(repo)
            (repo / "changelog.d").mkdir()
            (repo / "changelog.d/fix-thing.md").write_text("### Fixed\n\n- Fixed retry race.\n", encoding="utf-8")
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "Fix retry race\n\nRelease-Impact: patch\n")
            base_sha = _git(repo, "rev-parse", "HEAD")

            # Patch promotion stamps 0.19.1 cleanly and passes binding-docs reciprocal link check.
            args = argparse.Namespace(root=str(repo), version="0.19.1", baseline_ref="v0.19.0", date="2026-11-26")
            with unittest.mock.patch.object(promote_release.changelog, "shipped_tags", return_value=([], [])):
                self.assertEqual(promote_release.command_stamp(args), 0)

            self.assertEqual(promote_release.verify_metadata_only_diff(repo, base_sha), [])
            self.assertEqual(check_binding_docs.release_problems(repo, "0.19.1"), [])
            self.assertFalse((repo / "changelog.d/fix-thing.md").exists())
            self.assertIn("## [0.19.1] - 2026-11-26", (repo / "CHANGELOG.md").read_text(encoding="utf-8"))
            self.assertIn("0.19.1", (repo / "crates/cgka-conformance-simulator/vectors/sample.v1.json").read_text())
            self.assertIn("wn-agent-v0.19.1", (repo / "scripts/install-hermes-marmot.sh").read_text())

            # Mutating any Rust source file must fail closed.
            (repo / "crates/marmot-uniffi/src/lib.rs").write_text("// tampered\n", encoding="utf-8")
            errors = promote_release.verify_metadata_only_diff(repo, base_sha)
            self.assertTrue(any("disallowed non-metadata file modified" in e for e in errors))

            # Reverting Rust file and touching non-base_url line in installer script must also fail closed.
            _git(repo, "checkout", "--", "crates/marmot-uniffi/src/lib.rs")
            with (repo / "scripts/install-hermes-marmot.sh").open("a", encoding="utf-8") as handle:
                handle.write("echo pwned\n")
            inst_errors = promote_release.verify_metadata_only_diff(repo, base_sha)
            self.assertTrue(any("only the pinned release base_url help comment may change" in e for e in inst_errors))

    def test_verify_rc_evidence_rejects_draft_or_mismatched_track(self):
        sha = "a" * 40
        rc_ver = "0.20.0-rc.1"

        class FakeGH:
            def __init__(self, broken_track=None):
                self.broken_track = broken_track

            def read_meta_json(self, path):
                return {"version": rc_ver, "source_sha": sha, "baseline_tag": "v0.19.0"}

            def read_latest_rc(self):
                return None

            def release_for_tag(self, tag):
                prefix = tag.removesuffix(f"-v{rc_ver}")
                title = dict(rc_release.TRACKS)[prefix]
                return {
                    "tag_name": tag,
                    "name": f"v{rc_ver} - {title}",
                    "draft": prefix == self.broken_track,
                    "prerelease": True,
                    "immutable": prefix != self.broken_track,
                }

            def tag_commit(self, tag):
                return "b" * 40 if self.broken_track == "wrong_sha" and tag.startswith("marmotc-") else sha

        self.assertEqual(promote_release.verify_rc_evidence(FakeGH(), rc_ver)["source_sha"], sha)
        with self.assertRaises(promote_release.PromoteError):
            promote_release.verify_rc_evidence(FakeGH("marmotkit"), rc_ver)
        with self.assertRaises(promote_release.PromoteError):
            promote_release.verify_rc_evidence(FakeGH("wrong_sha"), rc_ver)

    def test_promotion_then_squash_sync_preserves_concurrent_master_edits_and_advances_next_rc_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_synthetic_repo(repo)
            # Add a breaking change on master (RC source commit).
            (repo / "crates/storage-sqlite/src/base/migrations/0219_rc_mig.rs").write_text(
                "pub const VERSION: u32 = 219;\n", encoding="utf-8"
            )
            (repo / "changelog.d").mkdir()
            (repo / "changelog.d/rc-feature.md").write_text("### Breaking changes\n\n- Migration 219.\n", encoding="utf-8")
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "Add migration 219\n\nRelease-Impact: minor\n")
            rc_source_sha = _git(repo, "rev-parse", "HEAD")

            # Cut promoted release commit on release/v0.20.0 and tag v0.20.0 off-master.
            _git(repo, "checkout", "-b", "release/v0.20.0", rc_source_sha)
            stamp_args = argparse.Namespace(root=str(repo), version="0.20.0", baseline_ref="v0.19.0", date="2026-11-26")
            with unittest.mock.patch.object(promote_release.changelog, "shipped_tags", return_value=([], [])):
                self.assertEqual(promote_release.command_stamp(stamp_args), 0)
            _git(repo, "add", "-A")
            _git(repo, "commit", "-m", "Release MDK 0.20.0")
            release_sha = _git(repo, "rev-parse", "HEAD")
            _git(repo, "tag", "-a", "v0.20.0", "-m", "mdk v0.20.0", release_sha)

            # Meanwhile master advances with a Rust fix, a concurrent README edit, and a new fragment!
            _git(repo, "checkout", "master")
            (repo / "crates/marmot-uniffi/src/lib.rs").write_text(
                (repo / "crates/marmot-uniffi/src/lib.rs").read_text(encoding="utf-8") + "\n// concurrent rust fix\n",
                encoding="utf-8",
            )
            (repo / "README.md").write_text(
                (repo / "README.md").read_text(encoding="utf-8") + "\nExtra section added after RC.\n",
                encoding="utf-8",
            )
            (repo / "changelog.d/post-rc-fix.md").write_text("### Fixed\n\n- Post-RC bugfix.\n", encoding="utf-8")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-m", "Post-RC fix on master\n\nRelease-Impact: patch\n")
            newer_master_sha = _git(repo, "rev-parse", "HEAD")

            # Simulate stale checkout on rc_source_sha before running apply_release_metadata_sync:
            # it MUST checkout newer_master_sha, preserve the Rust fix + README section + post-rc fragment,
            # and pass the metadata-only diff guard.
            _git(repo, "checkout", "--detach", rc_source_sha)
            promote_release.apply_release_metadata_sync(
                repo,
                master_sha=newer_master_sha,
                rc_source_sha=rc_source_sha,
                release_sha=release_sha,
                next_dev="0.21.0-dev",
            )
            self.assertEqual(_git(repo, "rev-parse", "HEAD"), newer_master_sha)
            self.assertIn("// concurrent rust fix", (repo / "crates/marmot-uniffi/src/lib.rs").read_text())
            self.assertIn("Extra section added after RC.", (repo / "README.md").read_text())
            self.assertIn("0.19.0 → 0.20.0", (repo / "README.md").read_text())
            self.assertFalse((repo / "changelog.d/rc-feature.md").exists())
            self.assertTrue((repo / "changelog.d/post-rc-fix.md").exists())
            self.assertEqual(promote_release.verify_metadata_only_diff(repo, newer_master_sha), [])

            # Squash-merge sync PR onto master (so v0.20.0 release commit is NOT a direct ancestor of master).
            _git(repo, "checkout", "-B", "master", newer_master_sha)
            _git(repo, "add", "-A")
            _git(repo, "commit", "-m", "Sync v0.20.0 release docs and advance to 0.21.0-dev\n\nRelease-Impact: none\n")
            post_sync_sha = _git(repo, "rev-parse", "HEAD")

            # Next RC planner must pick v0.20.0 (NOT v0.19.0!) and classify post-RC fix as patch -> 0.20.1!
            report, _ = classifier.classify_range(repo, target_ref=post_sync_sha)
            self.assertEqual(report["baseline_tag"], "v0.20.0")
            self.assertEqual(report["impact"], "patch")
            self.assertEqual(report["target_base_version"], "0.20.1")
            self.assertTrue(rc_release.rc_matches_workspace_dev("0.20.1-rc.1", "0.21.0-dev"))

    def test_apply_release_metadata_sync_fails_closed_if_folded_fragment_was_edited_on_master(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_synthetic_repo(repo)
            (repo / "changelog.d").mkdir()
            (repo / "changelog.d/feat.md").write_text("### Fixed\n\n- Original.\n", encoding="utf-8")
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "Add frag\n\nRelease-Impact: patch\n")
            rc_source_sha = _git(repo, "rev-parse", "HEAD")

            _git(repo, "checkout", "-b", "release/v0.19.1", rc_source_sha)
            stamp_args = argparse.Namespace(root=str(repo), version="0.19.1", baseline_ref="v0.19.0", date="2026-11-26")
            with unittest.mock.patch.object(promote_release.changelog, "shipped_tags", return_value=([], [])):
                self.assertEqual(promote_release.command_stamp(stamp_args), 0)
            _git(repo, "add", "-A")
            _git(repo, "commit", "-m", "Release 0.19.1")
            release_sha = _git(repo, "rev-parse", "HEAD")

            _git(repo, "checkout", "master")
            (repo / "changelog.d/feat.md").write_text("### Fixed\n\n- Revised on master after RC.\n", encoding="utf-8")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-m", "Edit fragment\n\nRelease-Impact: patch\n")
            master_sha = _git(repo, "rev-parse", "HEAD")

            with self.assertRaisesRegex(promote_release.PromoteError, "sync conflict: changelog.d/feat.md"):
                promote_release.apply_release_metadata_sync(
                    repo,
                    master_sha=master_sha,
                    rc_source_sha=rc_source_sha,
                    release_sha=release_sha,
                    next_dev="0.20.0-dev",
                )

            # Conflicting edit on the exact same README line as the release pin must also fail closed.
            _git(repo, "checkout", "master")
            _git(repo, "checkout", rc_source_sha, "--", "changelog.d/feat.md")
            (repo / "README.md").write_text(
                (repo / "README.md")
                .read_text(encoding="utf-8")
                .replace("read guides.", "read updated guides on master."),
                encoding="utf-8",
            )
            _git(repo, "add", "-A")
            _git(repo, "commit", "-m", "Conflicting README line edit\n\nRelease-Impact: none\n")
            conflicting_master_sha = _git(repo, "rev-parse", "HEAD")
            with self.assertRaisesRegex(promote_release.PromoteError, "sync conflict applying metadata delta to README.md"):
                promote_release.apply_release_metadata_sync(
                    repo,
                    master_sha=conflicting_master_sha,
                    rc_source_sha=rc_source_sha,
                    release_sha=release_sha,
                    next_dev="0.20.0-dev",
                )

    def test_check_release_version_single_source_of_truth(self):
        self.assertEqual(rc_release.check_release_version("0.20.0-rc.1", "0.20.0-dev"), "rc")
        self.assertEqual(rc_release.check_release_version("0.19.1-rc.3", "0.20.0-dev"), "rc")
        self.assertEqual(rc_release.check_release_version("0.20.0", "0.20.0"), "stable")
        for bad_rel, bad_ws in [
            ("0.21.0-rc.1", "0.20.0-dev"),
            ("0.20.0-rc.0", "0.20.0-dev"),
            ("0.20.0-rc.1", "0.20.0"),
            ("0.20.0", "0.20.0-dev"),
            ("0.20.0-nightly.20261126", "0.20.0-dev"),
        ]:
            with self.subTest(release=bad_rel, workspace=bad_ws):
                with self.assertRaises(rc_release.ReleaseError):
                    rc_release.check_release_version(bad_rel, bad_ws)

    def test_publish_stable_and_open_sync_pr_split_signing_and_release_tokens(self):
        calls: list[tuple[str, str, str]] = []

        class RecordingGH:
            def __init__(self, repo_name, token, api_url="https://api.github.com"):
                self.repository = repo_name
                self.token = token
                self.api_url = api_url

            def repo(self, suffix):
                return f"repos/{self.repository}/{suffix}"

            def request(self, method, path, body=None, **_):
                calls.append((self.token, method, path))
                if path.endswith("/pulls"):
                    return {"number": 42, "html_url": "https://example/pulls/42"}, ""
                return {"sha": "deadbeef" * 5, "html_url": "https://example/rel"}, ""

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_synthetic_repo(repo)
            (repo / "changelog.d").mkdir()
            (repo / "changelog.d/fix.md").write_text("### Fixed\n\n- A fix.\n", encoding="utf-8")
            _git(repo, "add", ".")
            _git(repo, "commit", "-m", "Add fix\n\nRelease-Impact: patch\n")
            rc_source_sha = _git(repo, "rev-parse", "HEAD")

            _git(repo, "checkout", "-b", "release/v0.19.1", rc_source_sha)
            stamp_args = argparse.Namespace(root=str(repo), version="0.19.1", baseline_ref="v0.19.0", date="2026-11-26")
            with unittest.mock.patch.object(promote_release.changelog, "shipped_tags", return_value=([], [])):
                self.assertEqual(promote_release.command_stamp(stamp_args), 0)
            _git(repo, "add", "-A")
            _git(repo, "commit", "-m", "Release 0.19.1")
            release_sha = _git(repo, "rev-parse", "HEAD")
            _git(repo, "checkout", "master")

            env_patch = {
                "GH_TOKEN": "gh-actions-token",
                "PR_GH_TOKEN": "release-pat-token",
                "GITHUB_REPOSITORY": "o/r",
            }
            args = argparse.Namespace(
                root=str(repo),
                master_ref="master",
                version="0.19.1",
                rc_version="0.19.1-rc.1",
                rc_source_sha=rc_source_sha,
                release_sha=release_sha,
                next_dev_version="0.20.0-dev",
            )
            with (
                unittest.mock.patch.dict(os.environ, env_patch, clear=False),
                unittest.mock.patch.object(rc_release, "GitHub", RecordingGH),
                unittest.mock.patch.object(
                    promote_release, "create_signed_commit_from_worktree", return_value="1" * 40
                ) as mock_commit,
            ):
                self.assertEqual(promote_release.command_open_sync_pr(args), 0)
                self.assertEqual(mock_commit.call_args.args[0].token, "gh-actions-token")
            self.assertIn(("release-pat-token", "POST", "repos/o/r/pulls"), calls)

    def test_c_enum_underlying_type_and_callback_signature_changes_are_detected(self):
        old_header = """
typedef enum MarmotStatus
#ifdef __cplusplus
  : int32_t
#endif
{
  MARMOT_OK = 0,
} MarmotStatus;
typedef void (*MarmotEventCallback)(const char *item, void *user_data);
"""
        new_header = """
typedef enum MarmotStatus
#ifdef __cplusplus
  : int64_t
#endif
{
  MARMOT_OK = 0,
} MarmotStatus;
typedef void (*MarmotEventCallback)(const char *item, int flags, void *user_data);
"""
        old_types = classifier.extract_c_types_in(old_header)
        new_types = classifier.extract_c_types_in(new_header)
        self.assertIn("MarmotStatus", old_types)
        self.assertIn("typedef MarmotEventCallback", old_types)
        self.assertNotEqual(old_types["MarmotStatus"], new_types["MarmotStatus"])
        self.assertNotEqual(old_types["typedef MarmotEventCallback"], new_types["typedef MarmotEventCallback"])

    def test_shared_sqlite_and_directory_cache_migration_registries_trigger_minor(self):
        for rel_path in (
            "crates/storage-sqlite/src/shared/migrations.rs",
            "crates/nostr-directory/src/cache/migrations.rs",
        ):
            with self.subTest(path=rel_path), tempfile.TemporaryDirectory() as tmp:
                repo = Path(tmp)
                _init_synthetic_repo(repo)
                target = repo / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("pub const MIGRATIONS: &[u32] = &[1];\n", encoding="utf-8")
                _git(repo, "add", ".")
                _git(repo, "commit", "-m", f"Add migration in {rel_path}\n\nRelease-Impact: patch\n")
                report, delta = classifier.classify_range(repo, target_ref="HEAD")
                self.assertEqual(report["impact"], "minor")
                self.assertIn(rel_path, delta["storage_migrations"])

    def test_command_publish_rejects_missing_companion_files_before_publishing(self):
        args = argparse.Namespace(
            version="0.20.0-rc.1",
            source_sha="a" * 40,
            impact_report="/nonexistent/impact_report.json",
            signature_delta="/nonexistent/signature_delta.json",
            integration_notes="/nonexistent/integration-notes.md",
        )
        with unittest.mock.patch.dict(os.environ, {"GH_TOKEN": "tok", "GITHUB_REPOSITORY": "o/r"}):
            with self.assertRaisesRegex(rc_release.ReleaseError, "--impact-report file is missing"):
                rc_release.command_publish(args)


if __name__ == "__main__":
    unittest.main()
