#!/usr/bin/env python3
"""Regression tests for the install-example SHA-256 gate."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import check_install_example_sha256 as gate


class InstallExampleSha256GateTests(unittest.TestCase):
    def test_rejects_download_to_shell_pipeline(self) -> None:
        text = "curl -fsSL https://example.test/install.sh | bash\n"
        self.assertTrue(gate.find_download_to_shell_pipelines(text))

    def test_rejects_local_execution_without_checksum_verification(self) -> None:
        text = """\
curl -fsSLo /tmp/install.sh https://example.test/install.sh
bash /tmp/install.sh
"""
        errors = gate.verify_then_execute_errors(text, "install.sh")
        self.assertIn("missing companion .sha256 download", errors)
        self.assertIn("missing SHA-256 verification", errors)

    def test_accepts_verify_then_execute_sequence(self) -> None:
        text = """\
curl -fsSLo /tmp/install.sh https://example.test/install.sh
curl -fsSLo /tmp/install.sh.sha256 https://example.test/install.sh.sha256
(cd /tmp && shasum -a 256 -c install.sh.sha256)
bash /tmp/install.sh
"""
        self.assertEqual(gate.verify_then_execute_errors(text, "install.sh"), [])

    def test_rejects_documented_helper_without_fail_closed_shell(self) -> None:
        text = """\
install_verified() (
  installer_url="$1"
  shasum -a 256 -c installer.sha256
  sha256sum -c installer.sha256
  bash "$installer_url"
)
install_verified "$base_url/install.sh" "$base_url/install.sh.sha256"
"""
        errors = gate.documented_surface_errors(text, {"install.sh": 1})
        self.assertIn("verify-then-execute helper must fail closed with set -eu", errors)

    def test_rejects_documented_call_without_companion_checksum(self) -> None:
        text = """\
install_verified() (
  shasum -a 256 -c installer.sha256
  sha256sum -c installer.sha256
)
install_verified "$base_url/install.sh"
"""
        errors = gate.documented_surface_errors(text, {"install.sh": 1})
        self.assertIn("expected at least 1 companion checksums for install.sh", errors)

    def test_codex_readme_is_a_documented_install_surface(self) -> None:
        installers = gate.DOCUMENTED_INSTALL_CALLS["integrations/codex/marmot/README.md"]
        self.assertEqual(installers, {"install-codex-marmot.sh": 1})
        readme = (Path(__file__).resolve().parents[1] / "integrations/codex/marmot/README.md").read_text(
            encoding="utf-8"
        )
        self.assertEqual(gate.documented_surface_errors(readme, installers), [])
        mutated = readme.replace(
            '"$base_url/install-codex-marmot.sh.sha256"',
            '"$base_url/install-codex-marmot.sh.sig"',
            1,
        )
        self.assertIn(
            "expected at least 1 companion checksums for install-codex-marmot.sh",
            gate.documented_surface_errors(mutated, installers),
        )

    def test_release_guide_rejects_download_to_shell_mutation(self) -> None:
        release = (Path(__file__).resolve().parents[1] / "release.md").read_text(encoding="utf-8")
        installers = {installer: 1 for installer in gate.INSTALLERS}
        self.assertEqual(gate.documented_surface_errors(release, installers), [])
        verified = (
            'install_verified "$base_url/install-hermes-marmot.sh" '
            '"$base_url/install-hermes-marmot.sh.sha256"'
        )
        mutated = release.replace(
            verified,
            "curl -fsSL https://example.test/install-hermes-marmot.sh | bash",
            1,
        )
        self.assertTrue(gate.find_download_to_shell_pipelines(mutated))
        self.assertIn(
            "expected at least 1 verified calls for install-hermes-marmot.sh",
            gate.documented_surface_errors(mutated, installers),
        )

    def test_same_shell_notice_regression_is_rejected(self) -> None:
        readme = (Path(__file__).resolve().parents[1] / "integrations/hermes/marmot/README.md").read_text(
            encoding="utf-8"
        )
        self.assertEqual(gate.same_shell_notice_errors(readme), [])
        mutated = readme.replace(
            "Run this example in the same shell where `install_verified` above was defined.",
            "Prerequisite omitted.",
            1,
        )
        self.assertTrue(gate.same_shell_notice_errors(mutated))

    def test_quickstart_same_shell_notice_regression_is_rejected(self) -> None:
        quickstart = (Path(__file__).resolve().parents[1] / "integrations/README.md").read_text(
            encoding="utf-8"
        )
        self.assertEqual(gate.same_shell_notice_errors(quickstart), [])
        mutated = quickstart.replace(
            "Run this example in the same shell where `install_verified` above was defined.",
            "Prerequisite omitted.",
            1,
        )
        self.assertTrue(gate.same_shell_notice_errors(mutated))

    def test_generated_note_claim_mutations_are_rejected(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[1] / ".github/workflows/wn-agent-binaries.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(gate.workflow_release_note_claim_errors(workflow), [])
        mutations = (
            workflow.replace("mutable \\`wn-agent-latest\\`", "rolling \\`wn-agent-latest\\`", 1),
            workflow.replace("mutable \\`$latest_tag\\`", "rolling \\`$latest_tag\\`", 1),
            workflow.replace(
                'base_url="https://github.com/$GITHUB_REPOSITORY/releases/download/wn-agent-latest"',
                'base_url="https://github.com/$GITHUB_REPOSITORY/releases/latest"',
                1,
            ),
        )
        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                self.assertTrue(gate.workflow_release_note_claim_errors(mutated))

    def test_repository_scan_rejects_new_unverified_example(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "release.md").write_text(
                "curl -fsSL https://example.test/install-hermes-marmot.sh | bash\n",
                encoding="utf-8",
            )
            errors = gate.scan_paths(root, [Path("release.md")])
        self.assertTrue(any("download-to-shell" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
