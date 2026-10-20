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
import unittest.mock
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

    def test_required_ci_is_read_from_the_merge_queue_run_for_the_master_commit(self):
        # Shape of run 39288024598: the merge-queue run that produced master commit 3cafb038
        # reports that same commit as head_sha, on its gh-readonly-queue branch.
        master = "3cafb03883832fb27f4fee178e9568be53acb1b8"
        gh = nightly_release.GitHub("o/r", "token")
        runs = {"workflow_runs": [{"id": 39288024598, "head_sha": master, "conclusion": "success",
                                   "event": "merge_group",
                                   "head_branch": "gh-readonly-queue/master/pr-2469-3188510989374e7b588717fc3d077c257f6a55ce"}]}
        jobs = [{"name": "Rust tests", "conclusion": "success"}, {"name": "Required CI", "conclusion": "success"}]
        with unittest.mock.patch.object(gh, "get", return_value=runs) as get, \
                unittest.mock.patch.object(gh, "paginate", return_value=jobs):
            self.assertTrue(gh.required_ci_passed(master))
        self.assertIn(f"event=merge_group&head_sha={master}&status=success", get.call_args.args[0])
        for wrong_jobs in ([{"name": "Required CI", "conclusion": "failure"}], [{"name": "Rust tests", "conclusion": "success"}]):
            with self.subTest(jobs=wrong_jobs), unittest.mock.patch.object(gh, "get", return_value=runs), \
                    unittest.mock.patch.object(gh, "paginate", return_value=wrong_jobs):
                self.assertFalse(gh.required_ci_passed(master))

    def test_nightly_jobs_require_their_dependencies_and_own_concurrency(self):
        workflow = (ROOT / ".github/workflows/nightly-releases.yml").read_text()
        self.assertIn("    if: success() && !inputs.build_only && !inputs.dry_run\n", workflow)
        self.assertEqual(workflow.count("    if: success() && needs.lane.outputs.lane_free == 'true'\n"), 3)
        bindings = (ROOT / ".github/workflows/bindings.yaml").read_text()
        # A nightly must not share a same-SHA snapshot's group, which waits for the nightly.
        self.assertIn("  group: marmotkit-bindings-${{ inputs.nightly_version || inputs.source_sha || github.ref }}-",
                      bindings)

    def test_tag_pushed_release_workflows_ignore_nightly_tags(self):
        for workflow, prefix in [("bindings.yaml", "marmotkit"), ("c-bindings.yml", "marmotc"),
                                 ("wn-agent-binaries.yml", "wn-agent")]:
            with self.subTest(workflow=workflow):
                text = (ROOT / ".github/workflows" / workflow).read_text()
                self.assertIn(f'      - "!{prefix}-v*-nightly.*"\n', text)
                self.assertIn("  workflow_call:\n", text)
                self.assertIn("      nightly_version:\n", text)
                # Tag pushes and dispatches have no nightly_version input at all (null), so
                # conditions must test truthiness rather than compare with ''.
                self.assertIsNone(re.search(r"inputs\.nightly_version\s*[!=]=", text))
                self.assertIn("inputs.nightly_version }}", text)

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


class FakeNightlyGitHub:
    """In-memory stand-in for the GitHub calls that publish_nightly makes."""

    SHA = "a" * 40

    def __init__(self, version: str, *, verified: bool = True):
        self.repository = "o/r"
        self.verified = verified
        self.fail_patch: set[str] = set()
        self.tags: dict[str, str] = {}
        self.meta_head: str | None = None
        self.meta: dict | None = None
        self.commits: dict[str, dict] = {}
        self.blobs: dict[str, str] = {}
        self.releases = {}
        for index, (prefix, title) in enumerate(nightly_release.TRACKS):
            tag = f"{prefix}-v{version}"
            self.releases[tag] = {
                "id": index, "tag_name": tag, "name": f"v{version} - {title}", "draft": True,
                "prerelease": True, "target_commitish": self.SHA, "immutable": False,
                "assets": [{"name": f"{prefix}.zip", "size": 1, "digest": "sha256:" + "c" * 64}],
            }

    def repo(self, suffix):
        return f"repos/o/r/{suffix}"

    def release_for_tag(self, tag):
        release = self.releases.get(tag)
        return dict(release) if release else None

    def tag_commit(self, tag):
        return self.tags.get(tag)

    def read_latest(self):
        return self.meta

    def get(self, path, *, allow_404=False):
        suffix = path.removeprefix("repos/o/r/")
        if suffix.startswith("releases/"):
            release = next(r for r in self.releases.values() if r["id"] == int(suffix.split("/")[1]))
            return dict(release)
        if suffix == f"git/ref/heads/{nightly_release.META_BRANCH}":
            return {"object": {"sha": self.meta_head}} if self.meta_head else None
        raise AssertionError(path)

    def request(self, method, path, body=None, **_):
        suffix = path.removeprefix("repos/o/r/")
        if method == "PATCH" and suffix.startswith("releases/"):
            release = next(r for r in self.releases.values() if r["id"] == int(suffix.split("/")[1]))
            if release["tag_name"] in self.fail_patch:
                self.fail_patch.discard(release["tag_name"])
                raise nightly_release.NightlyError(f"PATCH {path} failed with HTTP 502")
            assert body == {"draft": False, "prerelease": True, "make_latest": "false"}
            release.update(draft=False, immutable=True)
            self.tags[release["tag_name"]] = release["target_commitish"]
            return None, ""
        if suffix == "git/blobs":
            sha = f"blob{len(self.blobs)}"
            self.blobs[sha] = body["content"]
            return {"sha": sha}, ""
        if suffix == "git/trees":
            assert [entry["path"] for entry in body["tree"]] == [nightly_release.META_FILE]
            return {"sha": "tree-" + body["tree"][0]["sha"]}, ""
        if suffix == "git/commits":
            assert "author" not in body and "committer" not in body
            sha = f"commit{len(self.commits)}"
            self.commits[sha] = body
            return {"sha": sha, "verification": {"verified": self.verified, "reason": "valid"}}, ""
        if (method, suffix) in (("PATCH", f"git/refs/heads/{nightly_release.META_BRANCH}"), ("POST", "git/refs")):
            assert body.get("force") in (None, False)
            self.meta_head = body["sha"]
            tree = self.commits[body["sha"]]["tree"]
            self.meta = json.loads(self.blobs[tree.removeprefix("tree-")])
            return None, ""
        raise AssertionError((method, path))


class NightlyPublishTests(unittest.TestCase):
    VERSION = "0.14.0-nightly.20261020"

    def publish(self, gh):
        with unittest.mock.patch.object(nightly_release.time, "sleep"):
            return nightly_release.publish_nightly(gh, self.VERSION, FakeNightlyGitHub.SHA, "https://run")

    def test_publishes_all_three_tracks_then_latest_json_on_an_orphan_branch(self):
        gh = FakeNightlyGitHub(self.VERSION)
        self.publish(gh)
        self.assertTrue(all(not r["draft"] and r["immutable"] for r in gh.releases.values()))
        self.assertEqual(gh.meta["version"], self.VERSION)
        self.assertEqual(sorted(gh.meta["tracks"]), ["marmotc", "marmotkit", "wn-agent"])
        self.assertEqual(gh.commits[gh.meta_head]["parents"], [])

    def test_a_missing_or_wrong_track_publishes_nothing(self):
        for breakage in ("missing", "target", "title"):
            with self.subTest(breakage=breakage):
                gh = FakeNightlyGitHub(self.VERSION)
                tag = "wn-agent-v" + self.VERSION
                if breakage == "missing":
                    del gh.releases[tag]
                elif breakage == "target":
                    gh.releases[tag]["target_commitish"] = "b" * 40
                else:
                    gh.releases[tag]["name"] = "v0.14.0 - wn-agent"
                with self.assertRaises(nightly_release.NightlyError):
                    self.publish(gh)
                self.assertTrue(all(r["draft"] for r in gh.releases.values() if r["tag_name"] != tag))
                self.assertIsNone(gh.meta)

    def test_a_failed_publication_resumes_on_rerun_without_moving_latest_early(self):
        gh = FakeNightlyGitHub(self.VERSION)
        gh.meta = {"version": "0.14.0-nightly.20261019"}
        gh.fail_patch.add("marmotc-v" + self.VERSION)
        with self.assertRaisesRegex(nightly_release.NightlyError, "Published so far: marmotkit-v"):
            self.publish(gh)
        self.assertEqual(gh.meta, {"version": "0.14.0-nightly.20261019"})
        self.publish(gh)
        self.assertTrue(all(not r["draft"] for r in gh.releases.values()))
        self.assertEqual(gh.meta["version"], self.VERSION)
        # A further re-run finds everything done and writes nothing.
        commits = len(gh.commits)
        self.assertIsNone(self.publish(gh))
        self.assertEqual(len(gh.commits), commits)

    def test_an_unverified_metadata_commit_never_moves_the_branch(self):
        gh = FakeNightlyGitHub(self.VERSION, verified=False)
        with self.assertRaisesRegex(nightly_release.NightlyError, "not verified"):
            self.publish(gh)
        self.assertIsNone(gh.meta_head)
        gh.verified = True
        self.publish(gh)
        self.assertEqual(gh.meta["source_sha"], FakeNightlyGitHub.SHA)

    def test_releases_and_snapshots_wait_only_for_a_nightly_past_its_lane_wait(self):
        lane = nightly_release.LANE_JOB
        step = nightly_release.LANE_STEP
        building = nightly_release.nightly_is_building
        self.assertFalse(building([{"name": "Plan nightly", "conclusion": "success"}]))
        self.assertFalse(building([{"name": lane, "conclusion": None,
                                    "steps": [{"name": step, "status": "in_progress", "conclusion": None}]}]))
        self.assertTrue(building([{"name": lane, "conclusion": None,
                                   "steps": [{"name": step, "status": "completed", "conclusion": "success"}]}]))
        self.assertTrue(building([{"name": lane, "conclusion": "success"}]))
        workflow = (ROOT / ".github/workflows/nightly-releases.yml").read_text()
        self.assertIn(f"    name: {lane}\n", workflow)
        self.assertIn(f"      - name: {step}\n", workflow)

    def test_binding_jobs_never_inherit_a_skipped_ancestor(self):
        # A skipped job skips every job below it that uses the implicit success(), so the
        # lane job that nightly and build-only runs do not need must still run.
        bindings = (ROOT / ".github/workflows/bindings.yaml").read_text()
        lane = bindings.split("\n  release-lane:\n", 1)[1].split("\n    steps:\n", 1)[0]
        self.assertNotIn("\n    if:", lane)
        self.assertIn("\n    needs: release-lane\n", bindings.split("\n  metadata:\n", 1)[1].split("\n    steps:", 1)[0])


if __name__ == "__main__":
    unittest.main()
