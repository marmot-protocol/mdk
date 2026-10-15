#!/usr/bin/env python3
"""Exercise dependency selection, smoke fallbacks and packaging result gates."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path

from select_ci_tests import ROOT, select, workspace_graph
from test_classify_ci_changes import LITERAL_INCLUDE


def workflow_step(filename: str, name: str) -> str:
    text = (ROOT / ".github/workflows" / filename).read_text()
    step = text.split(f"      - name: {name}\n", 1)[1].split("\n      - name:", 1)[0]
    body = step.split("        run: |\n", 1)[1]
    lines = []
    for line in body.splitlines():
        if line and not line.startswith("          "):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines))


class SelectCiTests(unittest.TestCase):
    def test_leaf_change_does_not_run_unrelated_product_suites(self):
        plan = select(["crates/agent-connector/src/lib.rs"])
        self.assertEqual(plan["test_packages"], ["agent-connector"])
        self.assertEqual(plan["test_profile"], "ci-pr")
        self.assertFalse(plan["run_cli"])
        self.assertFalse(plan["run_relay"])
        self.assertFalse(plan["run_simulator"])

    def test_app_change_includes_all_public_consumers_not_upstream_storage(self):
        plan = select(["crates/marmot-app/src/client/mod.rs"])
        self.assertTrue({"marmot-app", "marmot-uniffi", "marmot-c", "wn-cli", "agent-connector"}
                        <= set(plan["test_packages"]))
        self.assertNotIn("storage-sqlite", plan["test_packages"])
        self.assertTrue(plan["run_cli"])
        self.assertTrue(plan["run_relay"])
        self.assertTrue(plan["run_simulator"])
        self.assertEqual(plan["relay_profile"], "ci-full")
        self.assertEqual(plan["cli_profile"], "ci-pr")

    def test_direct_cli_edits_restore_cli_suite_but_dependency_edits_use_smoke(self):
        self.assertEqual(select(["crates/cli/src/main.rs"])["cli_profile"], "ci-full")
        plan = select(["crates/storage-sqlite/src/lib.rs"])
        self.assertTrue(plan["run_cli"] and plan["run_relay"])
        self.assertEqual(plan["cli_profile"], "ci-pr")
        self.assertEqual(plan["relay_profile"], "ci-pr")

    def test_test_source_changes_restore_full_affected_suites(self):
        for path in ["crates/cgka-engine/tests/capabilities.rs",
                     "crates/marmot-app/src/client/sync/projection_retry_tests.rs",
                     "crates/marmot-app/src/test_support.rs",
                     "crates/storage-sqlite/src/chat_list/pages/tests.rs",
                     "crates/cli/tests/cli/new_regression.rs"]:
            with self.subTest(path=path):
                self.assertEqual(select([path])["test_profile"], "ci-full")
        plan = select(["crates/agent-connector/src/tests.rs"])
        self.assertEqual(plan["test_packages"], ["agent-connector"])

    def test_shared_unknown_removed_and_manual_inputs_fail_open(self):
        for paths in [[], ["Cargo.lock"], [".config/nextest.toml"],
                      ["scripts/select_ci_tests.py"], ["crates/removed-crate/src/lib.rs"],
                      ["scripts/new-build-input.sh"], ["vendor/crypto/src/lib.rs"]]:
            with self.subTest(paths=paths):
                plan = select(paths)
                self.assertEqual(plan["test_profile"], "ci-full")
                self.assertIn("storage-sqlite", plan["test_packages"])
                self.assertTrue(plan["run_cli"] and plan["run_relay"] and plan["run_simulator"])
                self.assertEqual(plan["cli_profile"], "ci-full")
                self.assertEqual(plan["relay_profile"], "ci-full")
        self.assertEqual(select(["README.md"], full=True)["test_profile"], "ci-full")
        self.assertTrue(select(["README.md"], full=True)["run_tests"])

    def test_docs_and_plugins_do_not_select_native_tests(self):
        for path in ["README.md", "integrations/hermes/marmot/plugin.py"]:
            with self.subTest(path=path):
                self.assertFalse(select([path])["run_tests"])
        self.assertTrue(select(["crates/marmot-markdown/tests/golden/new.md"])["run_tests"])
        self.assertEqual(select(["docs/new-analysis-tool.py"])["test_profile"], "ci-full")

    def test_cross_crate_literal_fixtures_select_their_consumers(self):
        directories, _ = workspace_graph(ROOT)
        paths = subprocess.run(["git", "ls-files", "-z", "--", "crates/**/*.rs"],
                               cwd=ROOT, check=True, capture_output=True).stdout.split(b"\0")
        for path in paths:
            if not path:
                continue
            source = ROOT / path.decode()
            consumer = next(name for directory, name in directories.items()
                            if path.decode().startswith(directory + "/"))
            for literal in LITERAL_INCLUDE.findall(source.read_text()):
                fixture = (source.parent / literal).resolve()
                if not fixture.is_relative_to(ROOT):
                    continue
                relative = fixture.relative_to(ROOT).as_posix()
                owner = next((name for directory, name in directories.items()
                              if relative.startswith(directory + "/")), None)
                if owner is None or owner == consumer:
                    continue
                with self.subTest(source=path.decode(), fixture=relative):
                    plan = select([relative])
                    selected = set(plan["test_packages"])
                    if plan["run_simulator"]:
                        selected.add("cgka-conformance-simulator")
                    self.assertIn(consumer, selected)
        plan = select(["crates/marmot-forensics/tests/fixtures/v5/endpoints.json"])
        self.assertIn("transport-nostr-adapter", plan["test_packages"])

    def test_reverse_graph_handles_aliases_targets_build_dev_cycles_and_globs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text('''[workspace]
members = ["crates/*"]
[workspace.dependencies]
renamed = { package = "leaf", path = "crates/leaf" }
''')
            manifests = {
                "leaf": '[dev-dependencies]\nconsumer = { path = "../consumer" }',
                "consumer": '[target.\'cfg(unix)\'.build-dependencies]\nrenamed.workspace = true',
                "outer": '[dev-dependencies]\nconsumer = { path = "../consumer" }',
                "unrelated": "",
            }
            for name, deps in manifests.items():
                directory = root / "crates" / name
                directory.mkdir(parents=True)
                (directory / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.1.0"\n{deps}\n')
            self.assertEqual(select(["crates/leaf/src/lib.rs"], root=root)["test_packages"],
                             ["consumer", "leaf", "outer"])

    def test_profiles_keep_full_coverage_and_smoke_names_exist(self):
        config = tomllib.loads((ROOT / ".config/nextest.toml").read_text())
        self.assertEqual(config["profile"]["ci-full"]["default-filter"], "all()")
        self.assertEqual(config["profile"]["ci-full"],
                         {**config["profile"]["ci"], "default-filter": "all()"})
        smoke = config["profile"]["ci-pr"]["default-filter"]
        paths = subprocess.run(["git", "ls-files", "-z", "--", "crates/**/*.rs"],
                               cwd=ROOT, check=True, capture_output=True).stdout.split(b"\0")
        source = "\n".join((ROOT / path.decode()).read_text() for path in paths if path)
        for test in re.findall(r"test\(=([^()]+)\)", smoke):
            self.assertIsNotNone(re.search(rf"\bfn\s+{re.escape(test.split('::')[-1])}\s*\(", source), test)

class PackagingPolicyTests(unittest.TestCase):
    def test_label_events_cannot_replace_candidate_check_results(self):
        workflow = (ROOT / ".github/workflows/bindings-profile.yml").read_text()
        self.assertIn("types: [opened, synchronize, reopened]", workflow)
        self.assertNotIn("labeled", workflow)

    def test_label_lookup_failure_cannot_silently_skip_requested_coverage(self):
        script = workflow_step("bindings-profile.yml", "Select candidate packaging lanes")
        result = subprocess.run(
            ["bash", "-c", "gh() { return 1; }\n" + script],
            env={**os.environ, "EVENT_NAME": "pull_request", "PR_NUMBER": "123",
                 "REPO": "example/repo"}, capture_output=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_live_labels_select_only_requested_platforms_and_master_is_full(self):
        script = workflow_step("bindings-profile.yml", "Select candidate packaging lanes")
        for event, labels, expected in [
            ("pull_request", [], (False, False)),
            ("pull_request", ["unrelated"], (False, False)),
            ("pull_request", ["ci:android"], (True, False)),
            ("pull_request", ["ci:apple"], (False, True)),
            ("pull_request", ["ci:full"], (True, True)),
            ("push", [], (True, True)),
            ("schedule", [], (True, True)),
            ("workflow_dispatch", [], (True, True)),
        ]:
            with self.subTest(event=event, labels=labels), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                output = root / "output"
                env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                       "EVENT_NAME": event, "PR_NUMBER": "123" if event == "pull_request" else "",
                       "REPO": "example/repo", "TEST_LABELS": json.dumps(labels),
                       "GITHUB_OUTPUT": str(output)}
                subprocess.run(["bash", "-c", 'gh() { printf "%s\\n" "$TEST_LABELS"; }\n' + script],
                               env=env, check=True, capture_output=True, timeout=10)
                values = dict(line.split("=", 1) for line in output.read_text().splitlines())
                self.assertEqual((values["run_android"] == "true", values["run_apple"] == "true"), expected)

    def test_gate_rejects_failed_or_unexpectedly_skipped_selected_packages(self):
        script = workflow_step("bindings-profile.yml", "Require every candidate package")
        base = {**os.environ, "IDENTITY_RESULT": "success", "RUN_ANDROID": "false",
                "RUN_APPLE": "false", "ANDROID_RESULT": "skipped", "IOS_RESULT": "skipped",
                "MACOS_RESULT": "skipped", "SOURCE_SHA": "candidate"}
        cases = [({}, True), ({"IDENTITY_RESULT": "failure"}, False),
                 ({"RUN_ANDROID": "true"}, False),
                 ({"RUN_ANDROID": "true", "ANDROID_RESULT": "failure"}, False),
                 ({"RUN_ANDROID": "true", "ANDROID_RESULT": "success"}, True),
                 ({"RUN_APPLE": "true", "IOS_RESULT": "success"}, False),
                 ({"RUN_APPLE": "true", "IOS_RESULT": "success", "MACOS_RESULT": "success"}, True)]
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                result = subprocess.run(["bash", "-c", script], env={**base, **overrides}, capture_output=True)
                self.assertEqual(result.returncode == 0, expected)


if __name__ == "__main__":
    unittest.main()
