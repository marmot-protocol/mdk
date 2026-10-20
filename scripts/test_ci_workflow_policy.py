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
import datetime as dt
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import nightly_release  # noqa: E402
from check_install_example_sha256 import documented_release_version  # noqa: E402


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


def semver_key(version: str):
    """Semver 2.0 precedence key for X.Y.Z[-pre] (no build metadata)."""
    core, _, pre = version.partition("-")
    numbers = tuple(int(part) for part in core.split("."))
    if not pre:
        return numbers, (1,)
    fields = tuple((0, int(f), "") if f.isdigit() else (1, 0, f) for f in pre.split("."))
    return numbers, (0, fields)


class NightlyReleasePolicyTests(unittest.TestCase):
    DAY = dt.date(2026, 10, 20)

    def test_nightly_base_comes_only_from_a_dev_workspace_version(self):
        self.assertEqual(nightly_release.nightly_base_version("0.14.0-dev"), "0.14.0")
        for version in ("0.14.0", "0.14.0-rc.1", "0.14.0-dev.1", "v0.14.0-dev"):
            with self.subTest(version=version):
                self.assertIsNone(nightly_release.nightly_base_version(version))

    def test_names_are_dated_and_take_a_counter_when_any_track_used_the_day(self):
        choose = nightly_release.choose_nightly_version
        self.assertEqual(choose("0.14.0", self.DAY, []), "0.14.0-nightly.20261020")
        self.assertEqual(nightly_release.nightly_tags("0.14.0-nightly.20261020"), {
            "marmotkit": "marmotkit-v0.14.0-nightly.20261020",
            "marmotc": "marmotc-v0.14.0-nightly.20261020",
            "wn-agent": "wn-agent-v0.14.0-nightly.20261020",
        })
        taken = ["marmotc-v0.14.0-nightly.20261020"]
        self.assertEqual(choose("0.14.0", self.DAY, taken), "0.14.0-nightly.20261020.1")
        taken += ["wn-agent-v0.14.0-nightly.20261020.1"]
        self.assertEqual(choose("0.14.0", self.DAY, taken), "0.14.0-nightly.20261020.2")

    def test_nightly_versions_sort_between_releases_by_date_and_counter(self):
        ordered = ["0.13.0", "0.14.0-nightly.20261019", "0.14.0-nightly.20261020",
                   "0.14.0-nightly.20261020.1", "0.14.0-nightly.20261020.2",
                   "0.14.0-nightly.20261021", "0.14.0", "0.15.0-nightly.20261102"]
        self.assertEqual(sorted(reversed(ordered), key=semver_key), ordered)

    def test_source_is_the_newest_green_commit_and_never_older_than_the_last_nightly(self):
        shas = ["d", "c", "b", "a"]
        select = nightly_release.select_source
        self.assertEqual(select(shas, None, lambda sha: sha in {"c", "a"}), "c")
        # Unchanged master: the previous nightly's source is the answer, so the run skips.
        self.assertEqual(select(shas, "b", lambda sha: False), "b")
        # A green commit older than the previous nightly is never chosen.
        self.assertEqual(select(shas, "c", lambda sha: sha == "a"), "c")
        self.assertIsNone(select(shas, None, lambda sha: False))

    def test_retention_deletes_only_expired_unprotected_nightly_tags(self):
        tags = [
            "marmotkit-v0.14.0-nightly.20260919", "marmotc-v0.14.0-nightly.20260919.1",
            "wn-agent-v0.13.0-nightly.20260901", "marmotkit-v0.14.0-nightly.20260920",
            "marmotkit-v0.14.0-nightly.20261019", "marmotkit-v0.14.0-nightly.20260801",
            # Formal, snapshot, other pre-releases and malformed names are never touched.
            "v0.13.0", "marmotkit-v0.13.0", "marmotc-v0.12.0", "wn-agent-v0.13.0",
            "marmotkit-v0.14.0-rc.1", "marmotkit-snapshot-" + "a" * 40,
            "v0.14.0-nightly.20200101", "marmotkit-v0.14.0-nightly.20261399",
            "marmotkit-v0.14.0-nightly.2020010", "marmotkit-v0.14.0-nightly.20200101-x",
        ]
        expired = nightly_release.expired_nightly_tags(
            tags, self.DAY, protected=["marmotkit-v0.14.0-nightly.20260801"]
        )
        self.assertEqual(expired, [
            "marmotc-v0.14.0-nightly.20260919.1",
            "marmotkit-v0.14.0-nightly.20260919",
            "wn-agent-v0.13.0-nightly.20260901",
        ])

    def test_latest_json_names_each_track_asset_with_its_url_and_checksum(self):
        version = "0.14.0-nightly.20261020"
        releases = {
            prefix: {"assets": [{"name": f"{prefix}.zip", "size": 3, "digest": "sha256:" + "b" * 64}]}
            for prefix in nightly_release.TRACK_PREFIXES
        }
        document = nightly_release.latest_document(version, "a" * 40, releases, "o/r", "https://run")
        self.assertEqual((document["version"], document["source_sha"], document["date"]),
                         (version, "a" * 40, "2026-10-20"))
        self.assertEqual(document["tracks"]["marmotc"], {
            "tag": "marmotc-v" + version,
            "release_url": "https://github.com/o/r/releases/tag/marmotc-v" + version,
            "assets": [{"name": "marmotc.zip", "sha256": "b" * 64, "size": 3,
                        "url": f"https://github.com/o/r/releases/download/marmotc-v{version}/marmotc.zip"}],
        })
        releases["wn-agent"]["assets"][0]["digest"] = None
        with self.assertRaises(nightly_release.NightlyError):
            nightly_release.latest_document(version, "a" * 40, releases, "o/r", "https://run")

    def test_only_release_and_snapshot_runs_hold_the_lane(self):
        busy = nightly_release.busy_release_runs({
            "bindings.yaml": [{"id": 1, "status": "in_progress", "event": "workflow_dispatch"},
                              {"id": 2, "status": "completed", "event": "push"}],
            "c-bindings.yml": [{"id": 3, "status": "queued", "event": "push"}],
            "wn-agent-binaries.yml": [
                {"id": 4, "status": "in_progress", "event": "push", "head_branch": "master"},
                {"id": 5, "status": "waiting", "event": "push", "head_branch": "wn-agent-v0.14.0"},
                {"id": 6, "status": "in_progress", "event": "pull_request", "head_branch": "wn-agent-v-ish"},
            ],
        })
        self.assertEqual([run["id"] for run in busy], [1, 3, 5])

    def test_tag_pushed_release_workflows_ignore_nightly_tags(self):
        for workflow, prefix in [("bindings.yaml", "marmotkit"), ("c-bindings.yml", "marmotc"),
                                 ("wn-agent-binaries.yml", "wn-agent")]:
            with self.subTest(workflow=workflow):
                text = (ROOT / ".github/workflows" / workflow).read_text()
                self.assertIn(f'      - "!{prefix}-v*-nightly.*"\n', text)
                self.assertIn("  workflow_call:\n", text)
                self.assertIn("      nightly_version:\n", text)

    def test_nightlies_are_scheduled_pre_releases_that_never_become_latest(self):
        workflow = (ROOT / ".github/workflows/nightly-releases.yml").read_text()
        self.assertIn('    - cron: "17 0 * * *"\n', workflow)
        self.assertIn("  group: nightly-releases\n", workflow)
        self.assertNotIn("git push", workflow)
        script = (ROOT / "scripts/nightly_release.py").read_text()
        self.assertEqual(script.count('"make_latest": "false"'), 2)
        self.assertNotIn('"make_latest": "true"', script)
        self.assertEqual(nightly_release.RETENTION_DAYS, 30)
        bindings = (ROOT / ".github/workflows/bindings.yaml").read_text()
        self.assertIn(
            '          if [[ "$IS_NIGHTLY" == "true" ]]; then\n'
            '            title="v$version - MarmotKit"\n'
            '            release_flags=(--prerelease --latest=false --target "$SOURCE_SHA")\n',
            bindings,
        )

    def test_install_guidance_never_resolves_to_a_nightly(self):
        with tempfile.TemporaryDirectory() as tmp:
            notes = Path(tmp) / "docs/release"
            notes.mkdir(parents=True)
            for name in ("0.13.0.md", "0.14.0-nightly.20261020.md", "wn-homebrew.md"):
                (notes / name).write_text("notes\n")
            self.assertEqual(documented_release_version(Path(tmp), "0.14.0-dev"), "0.13.0")
        quickstart = (ROOT / "integrations/README.md").read_text()
        installer_pattern = re.search(r"grep -Eq '(\^https://github\[\.\]com/marmot-protocol/mdk/[^']+)'",
                                      quickstart).group(1)
        resolver = re.search(r'match = re\.fullmatch\(r"([^"]+)", tag\)', quickstart).group(1)
        nightly = "wn-agent-v0.14.0-nightly.20261020"
        url = f"https://github.com/marmot-protocol/mdk/releases/download/{nightly}/install-hermes-marmot.sh"
        self.assertIsNone(re.search(installer_pattern, url))
        self.assertIsNotNone(re.search(installer_pattern, url.replace(nightly, "wn-agent-v0.13.0")))
        self.assertIsNone(re.fullmatch(resolver, nightly))
        self.assertIsNotNone(re.fullmatch(resolver, "wn-agent-v0.13.0"))

    def test_binary_bundles_take_the_nightly_version_and_source_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src"
            root.mkdir()
            (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.14.0-dev"\n')
            (root / "Cargo.lock").write_text("# lock\n")
            git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com",
                   "-c", "commit.gpgsign=false"]
            subprocess.run([*git, "init", "-q"], check=True)
            subprocess.run([*git, "add", "."], check=True)
            subprocess.run([*git, "commit", "-qm", "source"], check=True)
            source_sha = subprocess.run([*git, "rev-parse", "HEAD"], check=True,
                                        capture_output=True, text=True).stdout.strip()
            binary = root / "target/x86_64-unknown-linux-gnu/release/wn-agent"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\n")
            env = {**os.environ, "RUNNER_TEMP": tmp, "GITHUB_SHA": "f" * 40, "GITHUB_REF_TYPE": "branch",
                   "RELEASE_SOURCE_SHA": source_sha, "NIGHTLY_VERSION": "0.14.0-nightly.20261020"}
            command = ["bash", str(ROOT / "scripts/package-binary-bundle.sh"), "wn-agent", "linux-x86_64",
                       "x86_64-unknown-linux-gnu"]
            subprocess.run(command, cwd=root, env=env, check=True, capture_output=True)
            asset = root / "dist/wn-agent-linux-x86_64/wn-agent-linux-x86_64-0.14.0-nightly.20261020.tar.gz"
            manifest = json.loads(subprocess.run(
                ["tar", "-xzOf", str(asset), "wn-agent-linux-x86_64/manifest.json"],
                check=True, capture_output=True).stdout)
            self.assertEqual(
                (manifest["artifact_version"], manifest["release_tag"], manifest["source_sha"]),
                ("0.14.0-nightly.20261020", "wn-agent-v0.14.0-nightly.20261020", source_sha))
            for overrides in ({"NIGHTLY_VERSION": "0.15.0-nightly.20261020"},
                              {"NIGHTLY_VERSION": "0.14.0-nightly.2026102"},
                              {"RELEASE_SOURCE_SHA": "e" * 40}):
                with self.subTest(overrides=overrides):
                    result = subprocess.run(command, cwd=root, env={**env, **overrides}, capture_output=True)
                    self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
