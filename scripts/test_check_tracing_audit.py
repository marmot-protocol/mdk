#!/usr/bin/env python3
"""Regression tests for the standalone tracing audit gate."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
AUDIT = "crates/cgka-conformance-simulator/tests/tracing_audit.rs"
GATE = "scripts/check_tracing_audit.sh"


class TracingAuditGateTests(unittest.TestCase):
    def run_gate(self, manifest: str, library: str, build_script: str | None = None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in (AUDIT, GATE):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(SOURCE / name, target)
            (root / "Cargo.toml").write_text(manifest)
            probe = root / "crates/probe/src/lib.rs"
            probe.parent.mkdir(parents=True)
            probe.write_text(library)
            if build_script is not None:
                (probe.parent.parent / "Cargo.toml").write_text('[package]\nname = "probe"\nversion = "0.0.0"\n')
                (probe.parent.parent / "build.rs").write_text(build_script)
            return subprocess.run([str(root / GATE)], capture_output=True, text=True, timeout=300)

    def test_fails_on_a_tracing_call_without_a_method_field_and_passes_once_it_has_one(self):
        manifest = '[workspace]\nmembers = ["crates/probe"]\n\n[workspace.package]\nedition = "2024"\n'
        call = 'pub fn probe() {{\n    tracing::info!(target: "probe", {fields}"probed");\n}}\n'
        missing = self.run_gate(manifest, call.format(fields=""))
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("tracing call is missing a method field", missing.stdout)
        present = self.run_gate(manifest, call.format(fields='method = "probe", '))
        self.assertEqual(present.returncode, 0, present.stdout + present.stderr)

    def test_refuses_a_root_manifest_without_exactly_one_edition(self):
        for manifest in ('[workspace]\nmembers = []\n',
                         '[workspace.package]\nedition = "2021"\n\n[package]\nedition = "2024"\n'):
            with self.subTest(manifest=manifest):
                result = self.run_gate(manifest, "pub fn probe() {}\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("one edition", result.stderr)

    def test_allows_build_instructions_but_rejects_library_stdout(self):
        manifest = '[workspace]\nmembers = ["crates/probe"]\n\n[workspace.package]\nedition = "2024"\n'
        build = 'fn main() { println!("cargo:rerun-if-changed=src"); }\n'
        allowed = self.run_gate(manifest, "pub fn probe() {}\n", build)
        self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
        rejected = self.run_gate(manifest, 'pub fn probe() { println!("leak"); }\n', build)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("src/lib.rs", rejected.stdout)
        self.assertIn("production library source writes direct output", rejected.stdout)


if __name__ == "__main__":
    unittest.main()
