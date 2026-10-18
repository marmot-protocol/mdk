#!/usr/bin/env python3
"""Exercise the CI mode selection, Required CI gate and packaging result gates."""

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


ROOT = Path(__file__).resolve().parents[1]


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


class MergeGatePolicyTests(unittest.TestCase):
    def test_only_the_merge_queue_and_opt_ins_select_the_full_matrix(self):
        script = workflow_step("ci.yml", "Select CI mode")
        for event, full_label, expected in [
            ("pull_request", "false", "precheck"),
            ("pull_request", "true", "full"),
            ("merge_group", "false", "full"),
            ("workflow_dispatch", "false", "full"),
            ("push", "false", "warm"),
        ]:
            with self.subTest(event=event, full_label=full_label), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "output"
                subprocess.run(["bash", "-c", script], check=True, capture_output=True, timeout=10,
                               env={**os.environ, "EVENT_NAME": event, "FULL_CI": full_label,
                                    "GITHUB_OUTPUT": str(output)})
                self.assertEqual(output.read_text(), f"ci_mode={expected}\n")

    def test_required_ci_rejects_skipped_jobs_in_full_runs(self):
        script = workflow_step("ci.yml", "Require every selected core CI job to succeed")
        passed = {"changes": {"result": "success"}, "rust-test": {"result": "success"}}
        skipped = {**passed, "rust-test": {"result": "skipped"}}
        failed = {**passed, "rust-test": {"result": "failure"}}
        for event, mode, needs, expected in [
            ("pull_request", "precheck", skipped, True),
            ("pull_request", "precheck", failed, False),
            ("pull_request", "full", skipped, False),
            ("merge_group", "full", passed, True),
            ("merge_group", "full", skipped, False),
            ("merge_group", "precheck", skipped, False),
            ("merge_group", "", skipped, False),
            ("push", "warm", skipped, True),
        ]:
            with self.subTest(event=event, mode=mode, needs=needs):
                result = subprocess.run(["bash", "-c", script], capture_output=True, timeout=10,
                                        env={**os.environ, "EVENT_NAME": event, "CI_MODE": mode,
                                             "NEEDS": json.dumps(needs)})
                self.assertEqual(result.returncode == 0, expected)

    def test_full_runs_use_nextest_profiles_without_a_default_filter(self):
        # The merge queue is the only gate that runs tests, so a profile filter
        # would silently drop coverage from master.
        profiles = tomllib.loads((ROOT / ".config/nextest.toml").read_text())["profile"]
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        used = set(re.findall(r"--profile (\S+)", workflow)) - {"minimal"}
        self.assertEqual(used, {"ci", "default"})
        for profile in used:
            with self.subTest(profile=profile):
                config = profiles.get(profile, {})
                self.assertNotIn("default-filter", config)
                # Platform overrides can set their own default-filter.
                for override in config.get("overrides", []):
                    self.assertNotIn("default-filter", override)

    def test_required_ci_aggregates_every_job(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs = set(re.findall(r"(?m)^  ([a-z0-9-]+):$", workflow.split("\njobs:\n", 1)[1]))
        required = workflow.split("\n  required-ci:\n", 1)[1].split("\n    needs:\n", 1)[1]
        needs = set(re.findall(r"(?m)^      - ([a-z0-9-]+)$", required.split("\n    runs-on:", 1)[0]))
        self.assertEqual(needs, jobs - {"required-ci"})


if __name__ == "__main__":
    unittest.main()
