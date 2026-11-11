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
import io
import sys
import unittest
import unittest.mock
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import nightly_release  # noqa: E402
import ci_runner  # noqa: E402
import ci_archive_layout as archive_layout  # noqa: E402
import check_pr_signatures as signatures  # noqa: E402
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


class SignaturePolicyTests(unittest.TestCase):
    def pr(self, head="head", count=2):
        return {"head": {"sha": head}, "base": {"sha": "base"}, "commits": count, "state": "open"}

    def commit(self, sha, verified):
        return {"sha": sha, "commit": {"verification": {"verified": verified}}}

    def test_checks_the_entire_paginated_fork_range_including_unsigned_ancestors(self):
        # More than 250 commits must use the comparison API rather than the
        # truncated PR-commits endpoint; the signed tip cannot hide an ancestor.
        commits = [self.commit(f"commit-{i}", i != 1) for i in range(300)]
        commits[-1]["sha"] = "head"
        pages = [{"commits": commits[i:i+100]} for i in range(0, 300, 100)]
        with unittest.mock.patch.object(signatures, "api", side_effect=[self.pr(count=300), pages,
                                                                      self.pr(count=300)]) as api:
            self.assertEqual(signatures.inspect_signatures("base/repo", 7, "head"), ["commit-1"])
        self.assertEqual(api.call_args_list[1], unittest.mock.call(
            "repos/base/repo/compare/base...head?per_page=100", paginate=True))

    def test_accepts_only_explicit_github_verification(self):
        for verified, expected in [(True, []), (False, ["head"]), (None, ["head"]),
                                   ("true", ["head"])]:
            with self.subTest(verified=verified), unittest.mock.patch.object(
                signatures, "api", side_effect=[self.pr(count=1),
                    [{"commits": [self.commit("head", verified)]}], self.pr(count=1)]):
                self.assertEqual(signatures.inspect_signatures("o/r", 7, "head"), expected)

    def test_accepts_clock_skewed_commit_order_but_rejects_duplicate_pages(self):
        for commits, expected in [([self.commit("head", True), self.commit("old", True)], []),
                                   ([self.commit("head", True), self.commit("head", True)], None)]:
            with unittest.mock.patch.object(signatures, "api", side_effect=[self.pr(),
                    [{"commits": commits}], self.pr()]):
                if expected is None:
                    with self.assertRaisesRegex(ValueError, "complete current PR commit list"):
                        signatures.inspect_signatures("o/r", 7, "head")
                else:
                    self.assertEqual(signatures.inspect_signatures("o/r", 7, "head"), expected)

    def test_build_gate_checks_metadata_before_any_checkout_and_needs_no_pr_permission(self):
        script = workflow_step("pr-signatures.yml", "Verify every PR commit")
        good = self.commit("head", True)
        for pages, count, expected in [
            ([{"commits": [good]}], 1, True),
            ([{"commits": [self.commit("old", False)]}, {"commits": [good]}], 2, False),
            ([{"commits": [good]}, {"commits": [self.commit("old", True)]}], 2, True),
            ([{"commits": [good, good]}], 2, False),
            ([{"commits": [good]}], 2, False),
            ([{"commits": []}], 0, False),
            ([{"commits": [self.commit("other", True)]}], 1, False),
        ]:
            with self.subTest(pages=pages, count=count):
                result = subprocess.run(["bash", "-c", 'gh() { printf "%s" "$RESPONSE"; }\n' + script],
                    capture_output=True, timeout=10, env={**os.environ, "RESPONSE": json.dumps(pages),
                        "REPO": "o/r", "BASE_SHA": "base", "HEAD_SHA": "head", "COMMIT_COUNT": str(count)})
                self.assertEqual(result.returncode == 0, expected)
        failed = subprocess.run(["bash", "-c", 'gh() { return 1; }\n' + script],
            capture_output=True, timeout=10, env={**os.environ, "REPO": "o/r", "BASE_SHA": "base",
                                                "HEAD_SHA": "head", "COMMIT_COUNT": "1"})
        self.assertNotEqual(failed.returncode, 0)
        gate = (ROOT / ".github/workflows/pr-signatures.yml").read_text()
        self.assertNotIn("actions/checkout", gate)
        self.assertNotIn("scripts/", gate)
        self.assertNotIn("pull-requests:", gate)

    def test_truncated_empty_or_moving_snapshots_fail_closed(self):
        complete = [{"commits": [self.commit("old", True), self.commit("head", True)]}]
        for before, pages, after in [
            (self.pr(), [{"commits": [self.commit("head", True)]}], self.pr()),
            (self.pr(count=0), [{"commits": []}], self.pr(count=0)),
            (self.pr(), complete, self.pr("replacement")),
            (self.pr(), complete, {**self.pr(), "base": {"sha": "new-base"}}),
            (self.pr(), complete, self.pr(count=3)),
        ]:
            with self.subTest(before=before, pages=pages, after=after), unittest.mock.patch.object(
                signatures, "api", side_effect=[before, pages, after]):
                with self.assertRaisesRegex(ValueError, "complete current PR commit list"):
                    signatures.inspect_signatures("o/r", 7, "head")
        with unittest.mock.patch.object(signatures, "api", return_value=self.pr("replacement")):
            with self.assertRaisesRegex(ValueError, "head changed"):
                signatures.inspect_signatures("o/r", 7, "head")

    def test_api_errors_never_admit_a_build(self):
        with unittest.mock.patch.object(signatures, "api", side_effect=subprocess.CalledProcessError(1, "gh")):
            with self.assertRaises(subprocess.CalledProcessError):
                signatures.inspect_signatures("o/r", 7, "head")

    def test_comment_is_reused_and_resolves_after_signing_without_touching_human_comments(self):
        human = {"id": 1, "user": {"login": "contributor"}, "body": signatures.COMMENT_MARKER}
        bot = {"id": 2, "user": {"login": "github-actions[bot]"},
               "body": signatures.COMMENT_MARKER + "\nold blocker"}
        for pages, unsigned, endpoint, method, expected in [
            ([[human]], ["head"], "repos/o/r/issues/7/comments", "POST", "remains open"),
            ([[human], [bot]], ["head"], "repos/o/r/issues/comments/2", "PATCH", "remains open"),
            ([[human], [bot]], [], "repos/o/r/issues/comments/2", "PATCH", "blocker is resolved"),
        ]:
            with self.subTest(unsigned=unsigned, pages=pages), unittest.mock.patch.object(
                signatures, "api", side_effect=[pages, self.pr(), {}]) as api:
                signatures.update_comment("o/r", 7, "head", unsigned)
            write = api.call_args_list[-1]
            self.assertEqual(write.args, (endpoint,))
            self.assertEqual(write.kwargs["method"], method)
            self.assertIn(expected, write.kwargs["body"]["body"])
            self.assertNotIn("state", write.kwargs["body"])
        with unittest.mock.patch.object(signatures, "api", return_value=[[human]]) as api:
            signatures.update_comment("o/r", 7, "head", [])
        self.assertEqual(api.call_count, 1)  # No success comment on an unaffected PR.

    def test_stale_comment_runs_do_not_overwrite_a_replacement_head(self):
        with unittest.mock.patch.object(signatures, "api", side_effect=[[], self.pr("replacement")]) as api:
            with self.assertRaisesRegex(ValueError, "PR changed"):
                signatures.update_comment("o/r", 7, "head", ["head"])
        self.assertTrue(all(call.kwargs.get("method", "GET") == "GET" for call in api.call_args_list))

    def test_comment_cli_reads_paginated_signatures_and_posts_guidance_without_closing_pr(self):
        # Exercise the actual CLI and gh boundary, including pagination flags,
        # JSON decoding, and the only write: the explanatory comment.
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / "event.json"
            event.write_text(json.dumps({"number": 7, "pull_request": self.pr()}))
            comparison = [{"commits": [self.commit("old", False), self.commit("head", True)]}]
            responses = [self.pr(), comparison, self.pr(), [], self.pr(), {}]
            with unittest.mock.patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event),
                    "GITHUB_REPOSITORY": "o/r", "GITHUB_EVENT_NAME": "pull_request_target"}), \
                 unittest.mock.patch.object(subprocess, "run", side_effect=[
                     subprocess.CompletedProcess([], 0, json.dumps(value)) for value in responses]) as run, \
                 unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                self.assertEqual(signatures.main(), 1)
                self.assertIn("must be signed", stderr.getvalue())
            self.assertIn("--paginate", run.call_args_list[1].args[0])
            self.assertIn("--slurp", run.call_args_list[1].args[0])
            write = run.call_args_list[-1]
            self.assertEqual(write.args[0][:5], ["gh", "api", "repos/o/r/issues/7/comments", "--method", "POST"])
            self.assertEqual(set(json.loads(write.kwargs["input"])), {"body"})

    def test_read_only_pr_context_cannot_request_comment_writes(self):
        with unittest.mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "pull_request"}), \
             unittest.mock.patch.object(signatures, "api") as api:
            with self.assertRaisesRegex(ValueError, "Only the trusted pull_request_target"):
                signatures.main()
        api.assert_not_called()

    def test_every_pr_build_workflow_depends_on_the_read_only_gate(self):
        for path in (ROOT / ".github/workflows").glob("*.y*ml"):
            text = path.read_text()
            if not re.search(r"^  pull_request:", text, re.M):
                continue
            with self.subTest(path=path):
                jobs = {match[1]: match[2] for match in re.finditer(
                    r"^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)",
                    text.split("\njobs:\n", 1)[1], re.M | re.S)}
                self.assertIn("uses: ./.github/workflows/pr-signatures.yml", jobs["signatures"])
                self.assertNotIn("write", jobs["signatures"])
                def gated(job, visited=frozenset()):
                    if job == "signatures":
                        return True
                    if job in visited:
                        return False
                    needs = re.search(r"^    needs:(.*(?:\n      - [a-z0-9-]+)*)", jobs[job], re.M)
                    return bool(needs) and any(gated(parent, visited | {job}) for parent in
                        re.findall(r"[a-z0-9][a-z0-9-]*", needs[1]))
                for job, body in jobs.items():
                    if job not in {"required-ci", "candidate-validation", "merge-group-fail-fast"}:
                        self.assertTrue(gated(job), f"{path.name}:{job} can run before signatures")
                        self.assertNotRegex(body, r"(?m)^    if:.*(?:always|failure|cancelled)\(")

    def test_comment_workflow_only_executes_trusted_default_branch_code(self):
        comment = (ROOT / ".github/workflows/pr-signature-comment.yml").read_text()
        self.assertIn("  pull_request_target:", comment)
        self.assertIn("ref: ${{ github.sha }}", comment)
        self.assertNotIn("github.event.pull_request.head", comment)
        self.assertNotIn("secrets.", comment)
        self.assertIn("persist-credentials: false", comment)
        self.assertIn("run: python3 scripts/check_pr_signatures.py", comment)
        gate = (ROOT / ".github/workflows/pr-signatures.yml").read_text()
        self.assertNotIn("write", gate)
        self.assertNotIn("--comment", gate)
        self.assertIn("if: github.event_name == 'pull_request'", gate)


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
        passed = {"signatures": {"result": "success"}, "changes": {"result": "success"},
                  "rust-test": {"result": "success"}}
        skipped = {**passed, "rust-test": {"result": "skipped"}}
        failed = {**passed, "rust-test": {"result": "failure"}}
        cancelled = {**passed, "rust-test": {"result": "cancelled"}}
        for event, mode, needs, expected in [
            ("pull_request", "precheck", skipped, True),
            ("pull_request", "precheck", failed, False),
            ("pull_request", "precheck", {**passed, "signatures": {"result": "skipped"}}, False),
            ("pull_request", "precheck", {**passed, "signatures": {"result": "failure"}}, False),
            ("pull_request", "precheck", cancelled, False),
            ("pull_request", "full", skipped, False),
            ("merge_group", "full", passed, True),
            ("merge_group", "full", skipped, False),
            ("merge_group", "full", cancelled, False),
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
        # The merge queue is the only gate that runs every test to the end, so a
        # profile filter would silently drop coverage from master.
        profiles = tomllib.loads((ROOT / ".config/nextest.toml").read_text())["profile"]
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        used = set(re.findall(r"--profile (\S+)", workflow)) - {"minimal"}
        self.assertEqual(used, {"ci", "default", "precheck"})
        for profile in used:
            with self.subTest(profile=profile):
                config = profiles.get(profile, {})
                self.assertNotIn("default-filter", config)
                # Platform overrides can set their own default-filter.
                for override in config.get("overrides", []):
                    self.assertNotIn("default-filter", override)

    def test_only_the_pre_check_counts_a_stopped_test_as_passed(self):
        # A test that passes on timeout never finishes, so only the pull-request
        # pre-check may select a profile that allows it.
        profiles = tomllib.loads((ROOT / ".config/nextest.toml").read_text())["profile"]
        for name, config in profiles.items():
            timeouts = [config.get("slow-timeout")]
            timeouts += [override.get("slow-timeout") for override in config.get("overrides", [])]
            passes = any(isinstance(t, dict) and t.get("on-timeout") == "pass" for t in timeouts)
            with self.subTest(profile=name):
                self.assertEqual(passes, name == "precheck")
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        steps = [step for step in workflow.split("\n      - name: ")[1:] if "--profile precheck" in step]
        self.assertEqual(len(steps), 1)
        self.assertIn("\n        if: needs.changes.outputs.ci_mode == 'precheck'\n", steps[0])
        # The job holding that step must still start for a pre-check, or the
        # pre-check silently loses its tests: it accepts skipped jobs.
        jobs = workflow.split("\njobs:\n", 1)[1]
        job = next(block for block in re.split(r"(?m)^  (?=[a-z0-9-]+:$)", jobs) if "--profile precheck" in block)
        self.assertRegex(job, r"(?m)^    if: needs\.changes\.outputs\.run_full == 'true'$")

    def test_only_the_merge_group_watcher_can_cancel_and_it_cannot_fail_the_run(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        watcher = workflow.split("\n  merge-group-fail-fast:\n", 1)[1].split("\n  required-ci:\n", 1)[0]
        self.assertIn("    if: github.event_name == 'merge_group'\n", watcher)
        self.assertIn("    continue-on-error: true\n    permissions:\n      actions: write\n      checks: read\n      contents: read\n\n",
                      watcher)
        # The branch lookup must name this run's own group and commit.
        self.assertIn("          HEAD_REF: ${{ github.ref }}\n          HEAD_SHA: ${{ github.sha }}\n", watcher)
        # Build and test jobs run third-party code; none of them may cancel or dispatch runs.
        self.assertEqual(len(re.findall(r"(?m)^ +actions: write$", workflow)), 1)
        # A job-level continue-on-error reads as success in `needs` but as a failed job to the watcher.
        self.assertEqual(len(re.findall(r"(?m)^ +continue-on-error:", workflow)), 1)
        timeout = int(re.search(r"(?m)^    timeout-minutes: (\d+)$", watcher).group(1))
        watch = int(re.search(r"deadline=\$\(\(SECONDS \+ (\d+) \* 60\)\)", watcher).group(1))
        self.assertLess(watch, timeout)
        # Required CI must still run, and fail, once the watcher cancels the run.
        self.assertIn("\n  required-ci:\n    name: Required CI\n", workflow)
        required = workflow.split("\n  required-ci:\n", 1)[1].split("\n    needs:\n", 1)[0]
        self.assertRegex(required, r"(?m)^    if: always\(\)$")

    def test_merge_group_watcher_cancels_a_failed_or_dropped_group(self):
        script = workflow_step("ci.yml", "Cancel the run when a job fails")
        # gh applies the trailing --jq filter itself; the fake runs it with jq.
        # Request n to an endpoint reads its response n, and later requests
        # repeat its last response.
        fakes = textwrap.dedent("""\
            gh() {
              if [[ "$1" == api ]]; then
                echo "gh ${*:1:$#-1}" >> "$STATE/calls"
                if [[ "$2" == */annotations ]]; then
                  printf '%s' '[{"annotation_level":"failure","message":"No space left on device"}]' | jq -r "${@: -1}"
                  return
                fi
                local kind=jobs
                [[ "$*" != *matching-refs* ]] || kind=refs
                local count=$(( $(cat "$STATE/$kind") + 1 ))
                echo "$count" > "$STATE/$kind"
                local last=$(ls "$STATE/$kind".*.json | wc -l)
                local response="$STATE/$kind.$(( count < last ? count : last )).json"
                [[ "$(cat "$response")" != error ]] || return 1
                jq -r "${@: -1}" "$response"
              else
                echo "gh $*" >> "$STATE/calls"
                local cancels=$(( $(cat "$STATE/cancels") + 1 ))
                echo "$cancels" > "$STATE/cancels"
                (( cancels > REFUSED_CANCELS ))
              fi
            }
            sleep() { echo "sleep $1" >> "$STATE/calls"; SECONDS=$((SECONDS + $1)); }
        """)

        def job(name, status, conclusion=None):
            return {"name": name, "status": status, "conclusion": conclusion}

        group = "refs/heads/gh-readonly-queue/master/pr-7-" + "b" * 40
        commit = "c" * 40

        def branch(sha, ref=group):
            return [{"ref": ref, "object": {"type": "commit", "sha": sha}}]

        live, gone, reused = branch(commit), [], branch("d" * 40)
        running = [job("Classify CI changes", "completed", "success"),
                   job("Rust tests (1/7)", "in_progress"), job("Rust WASM check", "completed", "skipped")]
        failed = running + [job("Relay runtime tests (2/2)", "completed", "failure")]
        finished = [job("Rust tests (1/7)", "completed", "success"), job("Required CI", "queued")]
        poll = "gh api --paginate repos/o/r/actions/runs/42/jobs?per_page=100 --jq"
        look = f"gh api repos/o/r/git/matching-refs/{group.removeprefix('refs/')} --jq"
        wait, cancel = "sleep 60", "gh run cancel 42"
        for name, jobs, refs, refused, expected, env in [
            ("failure cancels at once", [failed], [live], 0, [poll, cancel], {}),
            ("dead runner annotations survive cancellation",
             [running + [{**job("Rust tests (1/14)", "completed", "failure"),
                          "check_run_url": "https://api.github.com/repos/o/r/check-runs/7"}]],
             [live], 0, [poll, "gh api https://api.github.com/repos/o/r/check-runs/7/annotations --jq", cancel], {}),
            ("timeout or cancellation counts as a failure",
             [running + [job("Windows filesystem contracts", "completed", "cancelled")]], [live], 0,
             [poll, cancel], {}),
            ("success, skips and running jobs on a live branch keep watching", [running, finished], [live], 0,
             [poll, look, wait, poll], {}),
            ("Required CI means nothing is left to stop",
             [finished + [job("Rust tests (2/7)", "completed", "failure")]], [gone], 0, [poll], {}),
            ("failed request is retried", ["error", failed], [live], 0, [poll, wait, poll, cancel], {}),
            ("refused cancel is retried", [failed], [live], 1, [poll, cancel, wait, poll, cancel], {}),
            ("watching stops at the deadline", [running], [live], 0, [poll, look, wait] * 150, {}),
            # The queue deleted the group's branch, or gave its name to a later group on the same base.
            ("a branch gone for two lookups cancels", [running], [gone], 0,
             [poll, look, wait, poll, look, cancel], {}),
            ("a branch reused by another group cancels", [running], [reused], 0,
             [poll, look, wait, poll, look, cancel], {}),
            ("another branch sharing the prefix is not this group", [running],
             [branch(commit, group + "-other")], 0, [poll, look, wait, poll, look, cancel], {}),
            ("refused cancel of a dropped group is retried", [running], [gone], 1,
             [poll, look, wait, poll, look, cancel, wait, poll, look, cancel], {}),
            # A passed group's branch is deleted after Required CI appears, which wins.
            ("a passed group's deleted branch never cancels", [running, finished], [gone], 0,
             [poll, look, wait, poll], {}),
            ("one missing lookup is not enough", [running, running, running, finished], [gone, live, gone], 0,
             [poll, look, wait, poll, look, wait, poll, look, wait, poll], {}),
            ("a failed lookup proves nothing", [running, running, running, finished], [gone, "error", gone], 0,
             [poll, look, wait, poll, look, wait, poll, look, wait, poll], {}),
            ("a failed jobs request skips the lookup", [running, "error", finished], [gone], 0,
             [poll, look, wait, poll, wait, poll], {}),
            ("no group branch, no lookups", [running, finished], [gone], 0, [poll, wait, poll],
             {"HEAD_REF": ""}),
            ("a tag is not a group branch", [running, finished], [gone], 0, [poll, wait, poll],
             {"HEAD_REF": "refs/tags/v1"}),
            ("a malformed commit disables lookups", [running, finished], [gone], 0, [poll, wait, poll],
             {"HEAD_SHA": "HEAD"}),
        ]:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp)
                (state / "calls").write_text("")
                for counter in ("jobs", "refs", "cancels"):
                    (state / counter).write_text("0")
                for kind, responses in (("jobs", [{"jobs": r} if r != "error" else r for r in jobs]),
                                        ("refs", refs)):
                    for index, response in enumerate(responses, 1):
                        body = response if response == "error" else json.dumps(response)
                        (state / f"{kind}.{index}.json").write_text(body)
                # GitHub runs `run:` steps with `bash -e`.
                result = subprocess.run(["bash", "-e", "-c", fakes + script], capture_output=True, text=True,
                                        timeout=60, env={**os.environ, "STATE": tmp, "GH_REPO": "o/r",
                                                         "RUN_ID": "42", "HEAD_REF": group, "HEAD_SHA": commit,
                                                         "REFUSED_CANCELS": str(refused), **env})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((state / "calls").read_text().splitlines(), expected)
                if name == "dead runner annotations survive cancellation":
                    self.assertIn("No space left on device", result.stdout)


class CacheBudgetPolicyTests(unittest.TestCase):
    def test_only_ci_and_the_wn_agent_darwin_builds_save_rust_caches(self):
        # GitHub evicts the least recently used caches past 10 GB. Another
        # saving workflow would push out the caches CI restores (ci.yml header).
        saving = set()
        for workflow in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            for step in workflow.read_text().split("\n      - ")[1:]:
                if "uses: Swatinem/rust-cache@" not in step:
                    continue
                save_if = re.search(r"(?m)^          save-if: (.+)$", step)
                # rust-cache saves unless save-if says otherwise.
                save_if = save_if.group(1) if save_if else "true"
                with self.subTest(workflow=workflow.name, step=step.splitlines()[0]):
                    if save_if == "false":
                        continue
                    saving.add(workflow.name)
                    # Pull requests and merge groups only restore.
                    self.assertEqual(save_if, "${{ github.ref == 'refs/heads/master' }}")
                    if workflow.name == "wn-agent-binaries.yml":
                        self.assertRegex(step, r"(?m)^        if: runner\.os == 'macOS'$")
        self.assertEqual(saving, {"ci.yml", "wn-agent-binaries.yml"})

    def test_only_setup_odin_saves_an_actions_cache_and_only_from_master(self):
        # The pinned Odin archive is the one cache saved outside rust-cache.
        savers = [path.relative_to(ROOT).as_posix()
                  for path in sorted((ROOT / ".github").rglob("*.y*ml"))
                  if re.search(r"uses: actions/cache(/save)?@", path.read_text())]
        self.assertEqual(savers, [".github/actions/setup-odin/action.yml"])
        action = (ROOT / ".github/actions/setup-odin/action.yml").read_text()
        save = action.split("uses: actions/cache/save@", 1)[0].rsplit("\n    - ", 1)[1]
        self.assertIn("if: github.ref == 'refs/heads/master' && ", save)

    def test_binding_packages_build_from_a_clean_target_directory(self):
        for workflow in ("bindings.yaml", "bindings-profile.yml", "c-bindings.yml"):
            with self.subTest(workflow=workflow):
                text = (ROOT / ".github/workflows" / workflow).read_text()
                self.assertNotIn("Swatinem/rust-cache", text)
                self.assertNotIn("actions/cache", text)


class OdinArchiveCacheTests(unittest.TestCase):
    # install-odin.sh uses a kept archive (CI restores it from the Actions
    # cache) only if it matches the pinned sha256. Anything else downloads
    # again, and a download that misses the pin is neither kept nor installed.
    def install(self, kept, download):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            odin = tmp / "odin"
            odin.write_text("#!/bin/sh\necho 'odin version dev-2026-10-nightly:84bc3fc'\n")
            odin.chmod(0o755)
            archives = {"good": tmp / "good.tar.gz", "bad": tmp / "bad.tar.gz"}
            with tarfile.open(archives["good"], "w:gz") as archive:
                archive.add(odin, "odin-linux-amd64-dev-2026-10/odin")
            archives["bad"].write_bytes(b"not the pinned archive")
            # Pose as linux-amd64, treat only good.tar.gz as matching the pin,
            # and serve `download` from curl.
            stubs = tmp / "bin"
            stubs.mkdir()
            for name, body in {
                "uname": 'case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; esac',
                "sha256sum": 'read -r _ name && cmp -s "$name" "$GOOD"',
                "curl": 'echo call >> "$CALLS"; while [ "$1" != --output ]; do shift; done; cp "$DOWNLOAD" "$2"',
            }.items():
                (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
                (stubs / name).chmod(0o755)
            kept_dir = tmp / "kept"
            kept_file = kept_dir / "odin-linux-amd64-dev-2026-10.tar.gz"
            if kept:
                kept_dir.mkdir()
                kept_file.write_bytes(archives[kept].read_bytes())
            calls = tmp / "calls"
            result = subprocess.run(
                ["/bin/bash", str(ROOT / "scripts/install-odin.sh"), str(tmp / "odin-install")],
                env={**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}",
                     "ODIN_ARCHIVE_CACHE": str(kept_dir), "GOOD": str(archives["good"]),
                     "DOWNLOAD": str(archives[download]), "CALLS": str(calls)},
                capture_output=True, text=True)
            kept_bytes = kept_file.read_bytes() if kept_file.exists() else None
            return (result, len(calls.read_text().splitlines()) if calls.exists() else 0,
                    kept_bytes == archives["good"].read_bytes() if kept_bytes else None,
                    (tmp / "odin-install" / "odin").exists())

    def test_a_kept_archive_is_used_only_if_it_matches_the_pin(self):
        result, downloads, kept_good, installed = self.install(kept="good", download="bad")
        self.assertEqual((result.returncode, downloads, installed), (0, 0, True), result.stderr)

        result, downloads, kept_good, installed = self.install(kept="bad", download="good")
        self.assertEqual((result.returncode, downloads, kept_good, installed), (0, 1, True, True),
                         result.stderr)

        result, downloads, kept_good, installed = self.install(kept=None, download="bad")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match its pinned sha256", result.stderr)
        self.assertEqual((downloads, kept_good, installed), (1, None, False))


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

    def test_a_failed_scheduled_nightly_reports_to_one_open_issue(self):
        workflow = (ROOT / ".github/workflows/nightly-releases.yml").read_text()
        jobs = re.findall(r"^  ([a-z][a-z-]*):\n", workflow.split("\njobs:\n", 1)[1], re.MULTILINE)
        report = workflow.split("\n  report:\n", 1)[1].split("\n    steps:\n", 1)[0]
        # Skipped nights exit 0, so only real failures in any other job report. A job timeout
        # leaves that job cancelled rather than failed; a cancelled run reports nothing.
        self.assertIn(f"    needs: [{', '.join(job for job in jobs if job != 'report')}]\n", report)
        self.assertIn("    if: github.event_name == 'schedule' && !cancelled() && "
                      "(failure() || contains(needs.*.result, 'cancelled'))\n", report)
        self.assertIn("    permissions:\n      issues: write\n", report)
        self.assertEqual(workflow.count("issues: write"), 1)

        script = workflow_step("nightly-releases.yml", "Open or update the nightly failure issue")
        fake_gh = textwrap.dedent("""\
            gh() {
              if [[ "$1 $2" == "issue list" ]]; then
                while [[ "$1" != --jq ]]; do shift; done
                jq -r "$2" <<<"$ISSUES"
                return
              fi
              printf '%s\\n' "$*" >>"$LOG"
            }
        """)
        needs = json.dumps({"plan": {"result": "success"}, "marmotc": {"result": "failure"},
                            "wn-agent": {"result": "cancelled"}, "publish": {"result": "skipped"},
                            "retention": {"result": "failure"}})
        body = ("--body The scheduled nightly failed for abc123 "
                "(failed jobs: marmotc, wn-agent (cancelled), retention). Run: https://run")
        for issues, expected in [
            ([{"number": 9, "title": "Nightly release failed twice"}],
             f"issue create --repo o/r --title Nightly release failed {body}"),
            ([{"number": 9, "title": "Nightly release failed twice"}, {"number": 12, "title": "Nightly release failed"}],
             f"issue comment 12 --repo o/r {body}"),
        ]:
            with self.subTest(issues=issues), tempfile.TemporaryDirectory() as tmp:
                log = Path(tmp) / "gh.log"
                subprocess.run(
                    ["bash", "-c", fake_gh + script], check=True, timeout=10,
                    env={**os.environ, "ISSUES": json.dumps(issues), "LOG": str(log), "NEEDS": needs,
                         "REPO": "o/r", "RUN_URL": "https://run", "SOURCE_SHA": "abc123"},
                )
                self.assertEqual(log.read_text(), expected + "\n")

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


class ArchiveLayoutTests(unittest.TestCase):
    def test_partition_boundaries(self):
        for layout, number, expected in [
            ("slice", 1, (0, "slice:1/14")), ("slice", 14, (0, "slice:14/14")),
            ("binary-local", 1, (1, "slice:1/7")), ("binary-local", 7, (1, "slice:7/7")),
            ("binary-local", 8, (2, "slice:1/7")), ("binary-local", 14, (2, "slice:7/7")),
        ]:
            with self.subTest(layout=layout, number=number):
                self.assertEqual(archive_layout._partition(layout, number), expected)
        for layout, number in [("slice", 0), ("binary-local", 15), ("other", 1)]:
            with self.assertRaisesRegex(ValueError, "partition 1..14"):
                archive_layout._partition(layout, number)

    def test_whole_binary_balance(self):
        inventory = archive_layout.Counter({("large", "test"): 8, ("b", "test"): 4,
                                            ("a", "test"): 4, ("small", "test"): 1})
        groups, weights = archive_layout._groups(inventory)
        self.assertEqual(groups, [["large", "small"], ["a", "b"]])
        self.assertEqual([sum(weights[binary] for binary in group) for group in groups], [9, 8])
        reverse = archive_layout.Counter(dict(reversed(list(inventory.items()))))
        self.assertEqual(archive_layout._groups(reverse), (groups, weights))
        with self.assertRaisesRegex(ValueError, "two nonempty groups"):
            archive_layout._groups(archive_layout.Counter({("only", "test"): 3}))

    def test_selected_ignored_tests(self):
        document = {"rust-suites": {"pkg::suite": {"testcases": {
            "ignored": {"ignored": True, "filter-match": {"status": "matches"}},
            "ordinary": {"ignored": False, "filter-match": {"status": "matches"}},
            "excluded": {"ignored": False, "filter-match": {"status": "mismatch"}},
        }}}}
        self.assertEqual(archive_layout._inventory(document),
                         {("pkg::suite", "ignored"): 1, ("pkg::suite", "ordinary"): 1})

    def test_exact_once_coverage(self):
        expected = archive_layout.Counter({("a::b", "c"): 1, ("a", "b::c"): 1})
        archive_layout._coverage(expected, expected.copy())
        for actual in [archive_layout.Counter({("a::b", "c"): 2}),
                       expected + archive_layout.Counter({("a", "b::c"): 1}),
                       archive_layout.Counter()]:
            with self.assertRaisesRegex(ValueError, "partition coverage mismatch"):
                archive_layout._coverage(expected, actual)
        with self.assertRaisesRegex(ValueError, "partition coverage mismatch"):
            archive_layout._coverage(archive_layout.Counter(), archive_layout.Counter())

    def test_binary_id_dsl_escaping(self):
        self.assertEqual(archive_layout._binary_filter("pkg::test"), "binary_id(=pkg::test)")
        self.assertEqual(archive_layout._binary_filter("x\\,)\n\r\t/ *"),
                         r"binary_id(=x\u{5c}\u{2c}\u{29}\u{a}\u{d}\u{9}\u{2f}\u{20}\u{2a})")


class RunnerEvidenceTests(unittest.TestCase):
    def archive(self, root):
        raw = root / "fixture.tar"
        with tarfile.open(raw, "w") as tar:
            member = tarfile.TarInfo("target/debug/deps/fixture")
            member.size = 1001
            tar.addfile(member, io.BytesIO(b"x" * member.size))
        archive = root / "fixture.tar.zst"
        subprocess.run(["zstd", "--quiet", str(raw), "-o", str(archive)], check=True)
        return archive

    def test_manifest_checks_the_complete_compressed_stream_and_sizes_expanded_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = self.archive(Path(tmp))
            ci_runner.manifest(archive)
            document = json.loads(ci_runner.manifest_path(archive).read_text())
            self.assertEqual(document["expanded_bytes"], 8192)
            self.assertEqual(document["archive_bytes"], archive.stat().st_size)
            archive.write_bytes(archive.read_bytes()[:-1])
            ci_runner.manifest_path(archive).unlink()
            result = subprocess.run([sys.executable, str(ROOT / "scripts/ci_runner.py"),
                                     "manifest", str(archive)], capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"CI infrastructure error", result.stderr)
            self.assertFalse(ci_runner.manifest_path(archive).exists())

    def test_bad_transfer_and_insufficient_disk_refuse_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.archive(root)
            ci_runner.manifest(archive)
            contents = archive.read_bytes()
            archive.write_bytes(b"wrong transfer")
            with unittest.mock.patch.dict(os.environ, {"RUNNER_TEMP": tmp}):
                with self.assertRaisesRegex(ValueError, "checksum/size mismatch"):
                    ci_runner.extract(archive)
                archive.write_bytes(contents)
                # Boundary values exercise the actual admission calculation;
                # no unpacker is installed by this fixture.
                usage = type("Usage", (), {"total": 100, "used": 99, "free": 1})()
                with unittest.mock.patch.object(ci_runner.shutil, "disk_usage", return_value=usage):
                    with self.assertRaisesRegex(ValueError, "insufficient runner disk"):
                        ci_runner.extract(archive)
            self.assertTrue(archive.exists(), "a refused archive remains available for diagnosis")

    def test_command_failure_and_signal_survive_bounded_log_capture(self):
        cases = [("import sys; sys.stdout.write('x'*1100000); sys.exit(37)", 37),
                 ("import os,signal; os.kill(os.getpid(),signal.SIGTERM)", 143)]
        for program, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp:
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/ci_runner.py"), "run", "fixture",
                     "--", sys.executable, "-c", program], cwd=tmp,
                    env={**os.environ, "RUNNER_TEMP": tmp}, capture_output=True)
                self.assertEqual(result.returncode, expected, result.stderr)
                reports = Path(tmp) / "mdk-ci-reports"
                outcomes = [json.loads(p.read_text()) for p in reports.glob("fixture-*.json")]
                self.assertEqual(len(outcomes), 1)
                self.assertEqual(outcomes[0]["exit_code"], 37 if expected == 37 else -15)
                for log in reports.glob("*.log"):
                    self.assertEqual(log.stat().st_size, ci_runner.TAIL_BYTES)
                    self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_command_inherits_caller_umask_while_reports_stay_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/ci_runner.py"), "run", "umask",
                 "--", sys.executable, "-c",
                 "import os; os.mkdir('child-output'); assert os.stat('child-output').st_mode & 0o777 == 0o755"],
                cwd=tmp, env={**os.environ, "RUNNER_TEMP": tmp}, umask=0o022, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for report in (Path(tmp) / "mdk-ci-reports").iterdir():
                self.assertEqual(report.stat().st_mode & 0o777, 0o600)

    def test_evidence_write_error_preserves_the_command_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.dict(os.environ, {"RUNNER_TEMP": tmp}):
                with unittest.mock.patch.object(Path, "write_bytes", side_effect=OSError("No space left on device")):
                    code = ci_runner.run("full-disk", [sys.executable, "-c",
                                                  "print('command failure evidence'); raise SystemExit(37)"])
            self.assertEqual(code, 37)
            outcome = json.loads(next((Path(tmp) / "mdk-ci-reports").glob("full-disk-*.json")).read_text())
            self.assertEqual(outcome["exit_code"], 37)

    def test_wrapper_cancellation_drains_the_child_and_records_interruption(self):
        program = """import signal,sys
signal.signal(signal.SIGTERM, lambda *_: (print('last cancellation evidence', flush=True), sys.exit(0)))
print('ready for cancellation', flush=True)
signal.pause()
"""
        with tempfile.TemporaryDirectory() as tmp:
            with subprocess.Popen(
                [sys.executable, str(ROOT / "scripts/ci_runner.py"), "run", "cancelled",
                 "--", sys.executable, "-c", program], cwd=tmp,
                env={**os.environ, "RUNNER_TEMP": tmp}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True) as process:
                while "ready for cancellation" not in process.stdout.readline():
                    self.assertIsNone(process.poll(), "child must be ready before cancellation")
                process.terminate()
                output, error = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 143, error)
                self.assertIn("last cancellation evidence", output)
            reports = Path(tmp) / "mdk-ci-reports"
            self.assertIn("last cancellation evidence", next(reports.glob("*.log")).read_text())
            outcome = json.loads(next(reports.glob("cancelled-*.json")).read_text())
            self.assertEqual(outcome, {"label": "cancelled", "exit_code": 0, "signal": 15})

    def test_sdk_cleanup_refuses_non_hosted_invocation(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/ci_runner.py"), "prepare"],
                                env={**os.environ, "GITHUB_ACTIONS": "false"}, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"only for GitHub-hosted Linux CI runners", result.stderr)

    def test_archive_cleanup_budget(self):
        minimum = 32 * 1024**3
        for available, budget, removed in ((minimum, minimum, False),
                                           (minimum - 1, minimum, True),
                                           (minimum, None, True)):
            with self.subTest(available=available, budget=budget), tempfile.TemporaryDirectory() as tmp:
                sdk = Path(tmp) / "unused-sdk"
                sdk.mkdir()
                (sdk / "payload").write_text("keep unless space is needed")
                sudo = Path(tmp) / "sudo"
                sudo.write_text('#!/bin/sh\nexec "$@"\n')
                sudo.chmod(0o700)
                usage = type("Usage", (), {"total": minimum * 2, "used": minimum,
                                            "free": available})()

                with unittest.mock.patch.dict(os.environ, {
                    "RUNNER_TEMP": tmp, "GITHUB_ACTIONS": "true",
                    "MDK_RUNNER_ENVIRONMENT": "github-hosted",
                    "PATH": tmp + os.pathsep + os.environ["PATH"],
                }), unittest.mock.patch.object(sys, "platform", "linux"), \
                     unittest.mock.patch.object(ci_runner, "UNUSED_SDKS", (str(sdk),)), \
                     unittest.mock.patch.object(ci_runner.shutil, "disk_usage", return_value=usage):
                    ci_runner.prepare(budget)
                self.assertEqual(sdk.exists(), not removed)


class RunnerInfrastructurePolicyTests(unittest.TestCase):
    def test_producer_archives_carry_integrity_and_expanded_size_manifests(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs = re.split(r"\n  (?=[a-z][a-z0-9-]*:\n)", workflow.split("\njobs:\n", 1)[1])
        producers = [job for job in jobs if "cargo nextest archive" in job]
        self.assertTrue(producers)
        for job in producers:
            with self.subTest(job=job.splitlines()[0]):
                self.assertIn("ci_runner.py prepare", job)
                self.assertLess(job.index("ci_runner.py prepare"), job.index("uses: Swatinem/rust-cache@"))
                self.assertIn("ci_runner.py manifest", job)
                self.assertIn(".tar.zst.manifest.json", job)

    def test_formal_bootstrap_rejects_the_unsupported_distro_maude(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        formal = workflow.split("\n  formal:\n", 1)[1].split("\n  hermes-installer-auth:\n", 1)[0]
        self.assertNotIn("--no-install-recommends graphviz maude", formal)
        script = workflow_step("ci.yml", "Install Maude")
        self.assertIn("Maude3.5.1/Maude-3.5.1-linux-x86_64.zip", script)
        self.assertLess(script.index("sha256sum"), script.index("unzip"))
        self.assertIn("maude --version", script)

    def test_corrupt_maude_download_cannot_reach_installation(self):
        script = workflow_step("ci.yml", "Install Maude")
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(["bash", "-c", '''
curl() { printf 'corrupt transfer' > "$RUNNER_TEMP/maude.zip"; }
sha256sum() { shasum -a 256 "$@"; }
''' + script], env={**os.environ, "RUNNER_TEMP": tmp,
                    "GITHUB_PATH": tmp + "/path", "GITHUB_ENV": tmp + "/env"}, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"checksum", result.stderr)
            self.assertFalse((Path(tmp) / "maude-3.5.1").exists())

    def test_windows_nextest_download_tolerates_only_an_offline_revocation_check(self):
        # SChannel fails a handshake whose revocation server is offline; the
        # step skips only that check, and a bad archive still never installs.
        script = workflow_step("ci.yml", "Install pinned cargo-nextest")
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(["bash", "-c", '''
cygpath() { printf '%s\\n' "$2"; }
curl() {
  printf '%s\\n' "$@" > "$RUNNER_TEMP/curl-args"
  while [ "$1" != --output ]; do shift; done
  printf 'corrupt transfer' > "$2"
}
sha256sum() { shasum -a 256 "$@"; }
''' + script], env={**os.environ, "RUNNER_TEMP": tmp, "GITHUB_PATH": tmp + "/path"},
                capture_output=True)
            arguments = (Path(tmp) / "curl-args").read_text().splitlines()
            self.assertIn("--ssl-revoke-best-effort", arguments)
            self.assertFalse({"-k", "--insecure", "--ssl-no-revoke"} & set(arguments))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"checksum", result.stderr)
            self.assertFalse((Path(tmp) / "cargo-nextest-0.9.132").exists())
            self.assertFalse((Path(tmp) / "path").exists())


if __name__ == "__main__":
    unittest.main()
