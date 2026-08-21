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
