#!/usr/bin/env python3
"""Regression tests for the install-example SHA-256 gate."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import check_install_example_sha256 as gate


class InstallExampleSha256GateTests(unittest.TestCase):
    def test_agent_docs_gate_rejects_bad_guidance_without_ripgrep(self):
        source = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            root.mkdir()
            for name in (
                "Cargo.toml", "release.md", "integrations/README.md",
                "scripts/check_agent_install_docs.sh", "scripts/check_install_example_sha256.py",
            ):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source / name, target)
            workflow = root / ".github/workflows/fixture.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: fixture\n")
            subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
            tools = Path(temp) / "tools"
            tools.mkdir()
            for name in ("bash", "dirname", "sed", "head", "git"):
                target = shutil.which(name)
                self.assertIsNotNone(target, name)
                (tools / name).symlink_to(target)
            (tools / "python3").symlink_to(sys.executable)
            env = {**os.environ, "PATH": str(tools)}
            readme = root / "integrations/README.md"
            original = readme.read_text()
            for guidance, workflow_text, success in (
                (original, "name: fixture\n", True),
                (original + "\nreleases/download/wn-agent-latest/install-pi-marmot.sh\n", "name: fixture\n", False),
                (original + "\nwn-agent-v0.0.1/install-pi-marmot.sh\n", "name: fixture\n", False),
                (original, "# wn-agent-latest\n", False),
            ):
                readme.write_text(guidance)
                workflow.write_text(workflow_text)
                result = subprocess.run(
                    [str(tools / "bash"), "scripts/check_agent_install_docs.sh"],
                    cwd=root, env=env, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                self.assertNotIn("command not found", result.stderr)

    def resolve_fixture(self, pages: list[list[dict]]) -> tuple[str, int]:
        readme = (Path(__file__).resolve().parents[1] / "integrations/README.md").read_text()
        source = gate.release_resolver_source(readme)
        self.assertIsNotNone(source)
        calls = []

        def fetch(url, timeout):
            self.assertEqual(timeout, 30)
            self.assertTrue(url.startswith("https://api.github.com/repos/marmot-protocol/mdk/releases?per_page=100&page="))
            page = int(url.rsplit("=", 1)[1])
            calls.append(page)
            return io.StringIO(json.dumps(pages[page - 1]))

        output = io.StringIO()
        with patch("urllib.request.urlopen", side_effect=fetch), contextlib.redirect_stdout(output):
            exec(compile(source, "README release resolver", "exec"), {})
        return output.getvalue().strip(), len(calls)

    @staticmethod
    def release(tag, draft=False, published=True):
        return {"tag_name": tag, "draft": draft, "prerelease": True,
                "published_at": "2026-01-01T00:00:00Z" if published else None}

    def test_latest_resolver_chooses_numeric_cohort_and_excludes_unpublished(self):
        output, calls = self.resolve_fixture([[self.release("wn-agent-v1.9.0"),
            self.release("v99.0.0"), self.release("marmotkit-v99.0.0"),
            self.release("wn-agent-v1.10.0"), self.release("wn-agent-v2.0.0-rc1"),
            self.release("wn-agent-v3.0.0", draft=True),
            self.release("wn-agent-v4.0.0", published=False)]])
        self.assertEqual(output, "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v1.10.0")
        self.assertEqual(calls, 1)

    def test_latest_resolver_paginates_past_other_release_families(self):
        output, calls = self.resolve_fixture([[self.release("v1.0.0")] * 100,
                                             [self.release("wn-agent-v2.0.0")]])
        self.assertTrue(output.endswith("/wn-agent-v2.0.0"))
        self.assertEqual(calls, 2)

    def test_latest_resolver_fails_without_matching_release(self):
        with self.assertRaisesRegex(SystemExit, "No published"):
            self.resolve_fixture([[self.release("v1.0.0")]])

    def test_latest_resolver_fails_if_listing_cannot_be_completed(self):
        with self.assertRaisesRegex(SystemExit, "exceeded 1000"):
            self.resolve_fixture([[self.release("wn-agent-v1.0.0")] * 100] * 10)

    def test_latest_resolver_network_failure_has_no_fallback(self):
        source = gate.release_resolver_source((Path(__file__).resolve().parents[1] / "integrations/README.md").read_text())
        with patch("urllib.request.urlopen", side_effect=OSError("offline")):
            with self.assertRaisesRegex(OSError, "offline"):
                exec(compile(source, "README release resolver", "exec"), {})

    def test_optional_latest_gate_rejects_a_non_fail_closed_lookup(self):
        readme = (Path(__file__).resolve().parents[1] / "integrations/README.md").read_text()
        self.assertEqual(gate.optional_latest_release_errors(readme), [])
        self.assertTrue(gate.optional_latest_release_errors(readme.replace(')" && test -n "$base_url"; then', ')"; then', 1)))

    def test_failed_lookup_keeps_shell_alive_and_never_downloads(self):
        readme = (Path(__file__).resolve().parents[1] / "integrations/README.md").read_text()
        helper = gate.install_definition_block(readme)
        lookup = next(code for code in re.findall(r"```sh\n(.*?)\n```", readme, re.DOTALL)
                      if "python3 - <<'RELEASE'" in code)
        block = helper + '\nbase_url="https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v1.0.0"\n' + lookup
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / "python3"
            fake.write_text("#!/bin/sh\nexit 1\n")
            fake.chmod(0o700)
            curl = Path(temp) / "curl"
            marker = Path(temp) / "downloaded"
            curl.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n")
            curl.chmod(0o700)
            script = block + '\ntest -z "$base_url" || exit 2\ninstall_verified "$base_url/install-codex-marmot.sh" "$base_url/install-codex-marmot.sh.sha256"\nresult=$?\n[ "$result" -ne 0 ] || exit 3\nprintf "shell-alive\\n"\n'
            result = subprocess.run(["bash", "-c", script], text=True, capture_output=True,
                                    env={**os.environ, "PATH": temp + ":" + os.environ["PATH"]})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("shell-alive", result.stdout)
            self.assertFalse(marker.exists())

    def test_definition_fences_never_execute_installers(self):
        root = Path(__file__).resolve().parents[1]
        for relative in gate.DOCUMENTED_INSTALL_CALLS:
            text = (root / relative).read_text()
            for block in re.findall(r"```sh\n(.*?)\n```", text, re.DOTALL):
                if "install_verified() (" in block:
                    with self.subTest(path=relative):
                        self.assertIsNone(re.search(r"^install_verified ", block, re.MULTILINE))

    def test_unsafe_manual_installer_urls_never_download(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "downloaded"
            curl = Path(temp) / "curl"
            curl.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n")
            curl.chmod(0o700)
            helper = gate.install_definition_block((root / "integrations/README.md").read_text())
            for tag in ["v1/../../../../other/repo/releases/download/x", "v1.0.0-rc1", "vfoo", "v1.0.0\n"]:
                url = "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-" + tag + "/install-codex-marmot.sh"
                with self.subTest(tag=tag):
                    result = subprocess.run(["bash", "-c", helper + '\ninstall_verified "$1" "$1.sha256"', "fixture", url],
                        text=True, capture_output=True,
                        env={**os.environ, "PATH": temp + ":" + os.environ["PATH"]})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(marker.exists())

    def test_runtime_guides_link_the_canonical_helper(self):
        root = Path(__file__).resolve().parents[1]
        canonical = gate.install_definition_block((root / "integrations/README.md").read_text())
        self.assertIsNotNone(canonical)
        for relative, installers in gate.DOCUMENTED_INSTALL_CALLS.items():
            if relative == "integrations/README.md":
                continue
            with self.subTest(path=relative):
                readme = (root / relative).read_text()
                self.assertIsNone(gate.install_definition_block(readme))
                self.assertNotIn("python3 - <<'RELEASE'", readme)
                self.assertEqual(gate.documented_surface_errors(readme, installers, helper_text=canonical), [])
                mutated = readme.replace("(../../README.md#verified-installer-helper)", "(../../README.md)")
                self.assertTrue(gate.documented_surface_errors(mutated, installers, helper_text=canonical))
                self.assertTrue(gate.documented_surface_errors(readme, installers))

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
        helper = gate.install_definition_block((Path(__file__).resolve().parents[1] / "integrations/README.md").read_text())
        self.assertEqual(gate.documented_surface_errors(readme, installers, helper_text=helper), [])
        mutated = readme.replace(
            '"$base_url/install-codex-marmot.sh.sha256"',
            '"$base_url/install-codex-marmot.sh.sig"',
            1,
        )
        self.assertIn(
            "expected at least 1 companion checksums for install-codex-marmot.sh",
            gate.documented_surface_errors(mutated, installers, helper_text=helper),
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

    def test_quickstart_requires_a_verified_claude_installer_call(self) -> None:
        installers = gate.DOCUMENTED_INSTALL_CALLS["integrations/README.md"]
        self.assertEqual(installers["install-claude-marmot.sh"], 1)
        quickstart = (Path(__file__).resolve().parents[1] / "integrations/README.md").read_text(
            encoding="utf-8"
        )
        self.assertEqual(gate.documented_surface_errors(quickstart, installers), [])
        mutated = quickstart.replace(
            '"$base_url/install-claude-marmot.sh.sha256"',
            '"$base_url/install-claude-marmot.sh.sig"',
            1,
        )
        self.assertIn(
            "expected at least 1 companion checksums for install-claude-marmot.sh",
            gate.documented_surface_errors(mutated, installers),
        )

    def test_same_shell_notice_regression_is_rejected(self) -> None:
        readme = (Path(__file__).resolve().parents[1] / "integrations/hermes/marmot/README.md").read_text(
            encoding="utf-8"
        )
        self.assertEqual(gate.same_shell_notice_errors(readme), [])
        mutated = readme.replace(
            "Run this example in the same shell where `install_verified` was defined.",
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
            workflow.replace(
                'base_url="https://github.com/$GITHUB_REPOSITORY/releases/download/$tag"',
                'base_url="https://github.com/$GITHUB_REPOSITORY/releases/latest"',
                1,
            ),
            workflow.replace("Install this exact WN Agent release with:", "Install this WN Agent release with:", 1),
            workflow.replace(
                "WN Agent \\`$version\\` from MDK commit \\`$GITHUB_SHA\\`.",
                "WN Agent \\`$version\\` from the wn-agent-latest alias.",
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
