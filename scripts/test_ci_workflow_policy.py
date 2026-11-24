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

import rc_release  # noqa: E402
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
                    if job not in {"required-ci", "merge-group-fail-fast"}:
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
    def test_packaging_workflows_do_not_trigger_on_master_push_or_core_crate_prs(self):
        bindings_profile = (ROOT / ".github/workflows/bindings-profile.yml").read_text()
        bp_trigger = bindings_profile.split("\npermissions:\n", 1)[0]
        self.assertIn("  workflow_dispatch:", bp_trigger)
        self.assertIn("  workflow_call:", bp_trigger)
        self.assertNotIn("  pull_request:", bp_trigger)
        self.assertNotIn("  push:", bp_trigger)
        self.assertNotIn("issues: write", bindings_profile)

        wn_agent = (ROOT / ".github/workflows/wn-agent-binaries.yml").read_text()
        wn_trigger = wn_agent.split("\npermissions:\n", 1)[0]
        self.assertIn("  workflow_dispatch:", wn_trigger)
        self.assertIn("  workflow_call:", wn_trigger)
        push_block = wn_trigger.split("\n  push:\n", 1)[1].split("\n  workflow_dispatch:\n", 1)[0]
        push_lines = [line.strip() for line in push_block.splitlines()
                      if line.strip() and not line.strip().startswith("#")]
        self.assertEqual(push_lines, ["tags:", "- wn-agent-v*", '- "!wn-agent-v*-nightly.*"', '- "!wn-agent-v*-rc.*"'])
        pr_block = wn_trigger.split("\n  pull_request:\n", 1)[1].split("\n  push:\n", 1)[0]
        for expected_path in (
            "crates/agent-control/**",
            "crates/agent-connector/**",
            "fixtures/agent-control-*.json",
            "Cargo.lock",
            "integrations/hermes/marmot/**",
            "integrations/openclaw/marmot/**",
        ):
            self.assertIn(f"- {expected_path}", pr_block)
        for excluded_crate in ("crates/cgka-engine/**", "crates/marmot-app/**", "crates/storage-sqlite/**"):
            self.assertNotIn(excluded_crate, pr_block)
        self.assertIn(
            "if: needs.changes.outputs.run_binaries == 'true' && github.event_name != 'pull_request'",
            wn_agent,
        )

    def test_gate_requires_every_candidate_package(self):
        script = workflow_step("bindings-profile.yml", "Require every candidate package")
        base = {**os.environ, "IDENTITY_RESULT": "success", "ANDROID_RESULT": "success",
                "IOS_RESULT": "success", "MACOS_RESULT": "success", "SOURCE_SHA": "candidate"}
        cases = [
            ({}, True),
            ({"IDENTITY_RESULT": "failure"}, False),
            ({"ANDROID_RESULT": "skipped"}, False),
            ({"ANDROID_RESULT": "failure"}, False),
            ({"IOS_RESULT": "skipped"}, False),
            ({"IOS_RESULT": "failure"}, False),
            ({"MACOS_RESULT": "skipped"}, False),
            ({"MACOS_RESULT": "failure"}, False),
            ({"ANDROID_RESULT": "", "IOS_RESULT": "", "MACOS_RESULT": ""}, False),
        ]
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                result = subprocess.run(["bash", "-c", script], env={**base, **overrides}, capture_output=True)
                self.assertEqual(result.returncode == 0, expected)


class MergeGatePolicyTests(unittest.TestCase):
    def test_pr_trust_only_marks_same_repo_collaborator_prs_as_team(self):
        script = workflow_step("ci.yml", "Classify PR trust")
        fake_gh = textwrap.dedent("""\
            gh() {
              if [[ "$FAKE_PERM" == "error" ]]; then return 1; fi
              printf '%s\\n' "$FAKE_PERM"
            }
        """)
        cases = [
            ("pull_request", "marmot-protocol/mdk", "marmot-protocol/mdk", "false", "alice", "admin", "true"),
            ("pull_request", "marmot-protocol/mdk", "marmot-protocol/mdk", "false", "alice", "maintain", "true"),
            ("pull_request", "marmot-protocol/mdk", "marmot-protocol/mdk", "false", "alice", "write", "true"),
            # Organization member without write access must fail closed into full CI.
            ("pull_request", "marmot-protocol/mdk", "marmot-protocol/mdk", "false", "org-reader", "read", "false"),
            ("pull_request", "marmot-protocol/mdk", "marmot-protocol/mdk", "false", "outsider", "none", "false"),
            ("pull_request", "marmot-protocol/mdk", "marmot-protocol/mdk", "false", "alice", "error", "false"),
            ("pull_request", "marmot-protocol/mdk", "external/mdk", "true", "alice", "admin", "false"),
            ("pull_request", "marmot-protocol/mdk", "marmot-protocol/mdk", "true", "alice", "admin", "false"),
            ("pull_request", "marmot-protocol/mdk", "", "false", "alice", "admin", "false"),
            ("push", "marmot-protocol/mdk", "marmot-protocol/mdk", "false", "alice", "admin", "false"),
        ]
        for event, repo, head_repo, head_fork, author, perm, expected in cases:
            with self.subTest(event=event, head_repo=head_repo, head_fork=head_fork, perm=perm), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "output"
                subprocess.run(
                    ["bash", "-c", fake_gh + script],
                    check=True,
                    capture_output=True,
                    timeout=10,
                    env={
                        **os.environ,
                        "EVENT_NAME": event,
                        "REPO": repo,
                        "HEAD_REPO": head_repo,
                        "HEAD_FORK": head_fork,
                        "PR_AUTHOR": author,
                        "FAKE_PERM": perm,
                        "GITHUB_OUTPUT": str(output),
                    },
                )
                self.assertEqual(output.read_text(), f"is_team_pr={expected}\n")

    def test_team_prs_select_fast_mode_while_external_prs_and_opt_ins_select_full(self):
        script = workflow_step("ci.yml", "Select CI mode")
        for event, full_label, is_team, requested_shards, expected_mode, expected_shards in [
            ("pull_request", "false", "true", "", "fast", "14"),
            ("pull_request", "true", "true", "6", "full", "14"),
            ("pull_request", "false", "false", "6", "full", "14"),
            ("pull_request", "false", "", "", "full", "14"),
            ("merge_group", "false", "false", "6", "full", "14"),
            ("workflow_dispatch", "false", "false", "", "full", "14"),
            ("workflow_dispatch", "false", "false", "6", "full", "6"),
            ("schedule", "false", "false", "6", "full", "6"),
            ("push", "false", "false", "", "warm", "14"),
        ]:
            with self.subTest(
                event=event,
                full_label=full_label,
                is_team=is_team,
                shards=requested_shards,
            ), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "output"
                subprocess.run(
                    ["bash", "-c", script],
                    check=True,
                    capture_output=True,
                    timeout=10,
                    env={
                        **os.environ,
                        "EVENT_NAME": event,
                        "FULL_CI": full_label,
                        "IS_TEAM_PR": is_team,
                        "REQUESTED_SHARDS": requested_shards,
                        "SOURCE_SHA": "",
                        "GITHUB_OUTPUT": str(output),
                    },
                )
                parsed = dict(line.split("=", 1) for line in output.read_text().splitlines() if "=" in line)
                self.assertEqual(parsed["ci_mode"], expected_mode)
                self.assertEqual(parsed["rust_test_shards"], expected_shards)
                self.assertEqual(
                    json.loads(parsed["rust_test_partitions"]),
                    list(range(1, int(expected_shards) + 1)),
                )

        # Invalid shard counts and malformed source_sha inputs must fail closed.
        for bad_env in (
            {"EVENT_NAME": "schedule", "REQUESTED_SHARDS": "9", "SOURCE_SHA": ""},
            {"EVENT_NAME": "schedule", "REQUESTED_SHARDS": "6", "SOURCE_SHA": "not-a-sha"},
        ):
            with self.subTest(bad_env=bad_env), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "output"
                result = subprocess.run(
                    ["bash", "-c", script],
                    capture_output=True,
                    timeout=10,
                    env={
                        **os.environ,
                        "FULL_CI": "false",
                        "IS_TEAM_PR": "false",
                        "GITHUB_OUTPUT": str(output),
                        **bad_env,
                    },
                )
                self.assertNotEqual(result.returncode, 0)

    def test_required_ci_enforces_fast_team_gate_and_full_external_gate(self):
        script = workflow_step("ci.yml", "Require every selected core CI job to succeed")
        passed = {
            "signatures": {"result": "success"},
            "changes": {"result": "success"},
            "rust-format": {"result": "success"},
            "rust-audit": {"result": "success"},
            "ios-account-clippy": {"result": "success"},
            "marmotkit-native-host": {"result": "success"},
            "rust-test": {"result": "success"},
        }
        skipped = {
            **passed,
            "ios-account-clippy": {"result": "skipped"},
            "marmotkit-native-host": {"result": "skipped"},
            "rust-test": {"result": "skipped"},
        }
        apple_passed = {
            **skipped,
            "ios-account-clippy": {"result": "success"},
            "marmotkit-native-host": {"result": "success"},
        }
        failed = {**passed, "rust-test": {"result": "failure"}}
        cancelled = {**passed, "rust-test": {"result": "cancelled"}}
        for event, mode, is_team, apple_opt_in, needs, expected in [
            ("pull_request", "fast", "true", "false", skipped, True),
            ("pull_request", "fast", "true", "true", apple_passed, True),
            ("pull_request", "fast", "true", "true", skipped, False),
            ("pull_request", "fast", "true", "true", {**apple_passed, "ios-account-clippy": {"result": "skipped"}}, False),
            ("pull_request", "fast", "true", "true", {**apple_passed, "marmotkit-native-host": {"result": "skipped"}}, False),
            ("pull_request", "fast", "true", "false", failed, False),
            ("pull_request", "fast", "true", "false", {**skipped, "signatures": {"result": "skipped"}}, False),
            ("pull_request", "fast", "true", "false", {**skipped, "changes": {"result": "skipped"}}, False),
            ("pull_request", "fast", "true", "false", {**skipped, "rust-format": {"result": "skipped"}}, False),
            ("pull_request", "fast", "true", "false", {**skipped, "rust-audit": {"result": "skipped"}}, False),
            ("pull_request", "fast", "true", "false", {**skipped, "rust-audit": {"result": "failure"}}, False),
            ("pull_request", "fast", "true", "false", {**skipped, "rust-format": {"result": "failure"}}, False),
            ("pull_request", "fast", "true", "false", cancelled, False),
            ("pull_request", "fast", "false", "false", skipped, False),
            ("pull_request", "full", "false", "false", passed, True),
            ("pull_request", "full", "false", "false", skipped, False),
            ("pull_request", "full", "true", "true", skipped, False),
            ("pull_request", "", "true", "false", skipped, False),
            ("merge_group", "full", "false", "false", passed, True),
            ("merge_group", "full", "false", "false", skipped, False),
            ("merge_group", "full", "false", "false", cancelled, False),
            ("merge_group", "fast", "true", "false", skipped, False),
            ("merge_group", "", "false", "false", skipped, False),
            ("push", "warm", "false", "false", skipped, True),
        ]:
            with self.subTest(event=event, mode=mode, is_team=is_team, apple=apple_opt_in, needs=needs):
                result = subprocess.run(
                    ["bash", "-c", script],
                    capture_output=True,
                    timeout=10,
                    env={
                        **os.environ,
                        "EVENT_NAME": event,
                        "CI_MODE": mode,
                        "IS_TEAM_PR": is_team,
                        "APPLE_OPT_IN": apple_opt_in,
                        "TREE_STATE": "green",
                        "TREE_STATE_REASON": "",
                        "TREE_FIX_OPT_IN": "false",
                        "NEEDS": json.dumps(needs),
                    },
                )
                self.assertEqual(result.returncode == 0, expected)

        # Meltdown freeze (tree_state=red) blocks PRs unless labelled `tree-fix` or `revert`.
        for tree_state, tree_fix, expected in [
            ("red", "false", False),
            ("red", "", False),
            ("red", "true", True),
            ("green", "false", True),
        ]:
            with self.subTest(tree_state=tree_state, tree_fix=tree_fix):
                result = subprocess.run(
                    ["bash", "-c", script],
                    capture_output=True,
                    timeout=10,
                    env={
                        **os.environ,
                        "EVENT_NAME": "pull_request",
                        "CI_MODE": "fast",
                        "IS_TEAM_PR": "true",
                        "APPLE_OPT_IN": "false",
                        "TREE_STATE": tree_state,
                        "TREE_STATE_REASON": "canary red",
                        "TREE_FIX_OPT_IN": tree_fix,
                        "NEEDS": json.dumps(skipped),
                    },
                )
                self.assertEqual(result.returncode == 0, expected)

    def test_read_tree_state_blocks_red_or_malformed_and_defaults_green_when_absent(self):
        script = workflow_step("ci.yml", "Read tree state")
        labels_script = workflow_step("ci.yml", "Check CI opt-in labels")
        self.assertIn('index("tree-fix") != null or index("revert") != null', labels_script)

        with tempfile.TemporaryDirectory() as tmp:
            origin = Path(tmp) / "origin.git"
            work = Path(tmp) / "work"
            subprocess.run(["git", "init", "--bare", str(origin)], check=True, capture_output=True)
            subprocess.run(["git", "init", "-b", "master", str(work)], check=True, capture_output=True)
            for args in (
                ("config", "user.name", "Test"),
                ("config", "user.email", "test@example.com"),
                ("config", "commit.gpgsign", "false"),
                ("remote", "add", "origin", str(origin)),
            ):
                subprocess.run(["git", "-C", str(work), *args], check=True, capture_output=True)
            (work / "README.md").write_text("hi\n")
            subprocess.run(["git", "-C", str(work), "add", "."], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "commit", "-m", "init"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "push", "origin", "master"], check=True, capture_output=True)

            def run_read(event="pull_request", repo="marmot-protocol/mdk"):
                out = Path(tmp) / "out"
                out.unlink(missing_ok=True)
                subprocess.run(
                    ["bash", "-c", script],
                    cwd=work,
                    check=True,
                    capture_output=True,
                    timeout=10,
                    env={**os.environ, "EVENT_NAME": event, "REPO": repo, "GITHUB_OUTPUT": str(out)},
                )
                return dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)

            # Missing tree-state branch defaults to green ONLY on standalone forks;
            # the canonical repository fails closed to red.
            self.assertEqual(run_read("pull_request", repo="someone/mdk")["tree_state"], "green")
            canonical_missing = run_read("pull_request", repo="marmot-protocol/mdk")
            self.assertEqual(canonical_missing["tree_state"], "red")
            self.assertIn("canonical origin/tree-state branch is missing", canonical_missing["tree_state_reason"])

            # Push orphan tree-state branch with green, red, and malformed JSON.
            ts = Path(tmp) / "ts"
            subprocess.run(["git", "init", "-b", "tree-state", str(ts)], check=True, capture_output=True)
            for args in (
                ("config", "user.name", "Test"),
                ("config", "user.email", "test@example.com"),
                ("config", "commit.gpgsign", "false"),
                ("remote", "add", "origin", str(origin)),
            ):
                subprocess.run(["git", "-C", str(ts), *args], check=True, capture_output=True)

            for payload, expected_state in [
                ('{"schema_version":1,"state":"green","reason":"ok"}\n', "green"),
                ('{"schema_version":1,"state":"red","reason":"broken canary"}\n', "red"),
                ('not-json\n', "red"),
            ]:
                (ts / "state.json").write_text(payload)
                subprocess.run(["git", "-C", str(ts), "add", "state.json"], check=True, capture_output=True)
                subprocess.run(["git", "-C", str(ts), "commit", "-m", "update"], check=True, capture_output=True)
                subprocess.run(["git", "-C", str(ts), "push", "-f", "origin", "tree-state"], check=True, capture_output=True)
                with self.subTest(payload=payload.strip()):
                    self.assertEqual(run_read("pull_request")["tree_state"], expected_state)
            # A colliding tag `refs/tags/tree-state` pointing to green must NOT shadow a red
            # `refs/heads/tree-state` branch (fetch must name `refs/heads/tree-state` explicitly).
            (ts / "state.json").write_text('{"schema_version":1,"state":"green","reason":"tag decoy"}\n')
            subprocess.run(["git", "-C", str(ts), "add", "state.json"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(ts), "commit", "-m", "tag green decoy"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(ts), "tag", "tree-state"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(ts), "push", "origin", "refs/tags/tree-state"], check=True, capture_output=True)
            (ts / "state.json").write_text('{"schema_version":1,"state":"red","reason":"real branch red"}\n')
            subprocess.run(["git", "-C", str(ts), "add", "state.json"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(ts), "commit", "-m", "branch red"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(ts), "push", "-f", "origin", "refs/heads/tree-state"], check=True, capture_output=True)
            colliding = run_read("pull_request")
            self.assertEqual(colliding["tree_state"], "red")
            self.assertEqual(colliding["tree_state_reason"].strip(), "real branch red")
            # Non-PR events skip freeze check.
            self.assertEqual(run_read("schedule")["tree_state"], "green")

            # Broken/unreachable remote must fail closed to red (never silently default green).
            subprocess.run(
                ["git", "-C", str(work), "remote", "set-url", "origin", str(Path(tmp) / "missing.git")],
                check=True,
                capture_output=True,
            )
            broken = run_read("pull_request")
            self.assertEqual(broken["tree_state"], "red")
            self.assertIn("unable to verify origin/tree-state", broken["tree_state_reason"])

    def test_fast_team_gate_skips_heavy_compile_jobs_and_honors_ci_apple(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs = workflow.split("\njobs:\n", 1)[1]
        blocks = {
            block.split(":\n", 1)[0]: block
            for block in re.split(r"(?m)^  (?=[a-z0-9-]+:$)", jobs)
            if ":\n" in block
        }
        for job_name in ("rust-wasm-check", "rust-android-check", "rust-clippy", "rust-test-build"):
            with self.subTest(job=job_name):
                self.assertIn("needs.changes.outputs.ci_mode != 'fast'", blocks[job_name])
        # `ci:apple` must trigger both macOS jobs even when changed paths leave run_ios=false.
        for job_name in ("ios-account-clippy", "marmotkit-native-host"):
            with self.subTest(job=job_name):
                self.assertIn(
                    "needs.changes.outputs.apple_opt_in == 'true'\n"
                    "      || (needs.changes.outputs.ci_mode != 'fast' && needs.changes.outputs.run_ios == 'true')",
                    blocks[job_name],
                )

    def test_android_check_and_workflow_call_contracts(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        justfile = (ROOT / "Justfile").read_text()
        self.assertIn("  workflow_call:\n", workflow)
        self.assertIn("ANDROID_NDK_VERSION: 27.2.12479018", workflow)
        android_job = workflow.split("\n  rust-android-check:\n", 1)[1].split("\n  rust-clippy:\n", 1)[0]
        # `ci_runner.py prepare` deletes /usr/local/lib/android, so android-check must skip it.
        self.assertNotIn("ci_runner.py prepare", android_job)
        self.assertNotIn("Upload runner diagnostics", android_job)
        # CI and local development share the single `just android-check` recipe.
        self.assertIn("run: just android-check", android_job)
        self.assertIn("cargo check --locked --target aarch64-linux-android -p marmot-uniffi", justfile)
        self.assertIn("aarch64-linux-android26-clang", justfile)
        # Every checkout in ci.yml must honor optional inputs.source_sha for Canary pinning.
        checkouts = workflow.count("uses: actions/checkout@")
        pinned = workflow.count("ref: ${{ inputs.source_sha }}")
        self.assertEqual(checkouts, pinned)
        self.assertGreaterEqual(checkouts, 24)

    def test_required_ci_needs_every_gating_job(self):
        # Required CI is the only required check, so a job missing from its
        # needs can fail without blocking a merge.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs = set(re.findall(r"(?m)^  ([a-z0-9-]+):\n", workflow.split("\njobs:\n", 1)[1]))
        required = workflow.split("\n  required-ci:\n", 1)[1].split("\n    runs-on:", 1)[0]
        needs = re.findall(r"(?m)^      - ([a-z0-9-]+)$", required)
        # The layout experiment runs only on request; the watcher must never fail a run.
        self.assertEqual(sorted(needs),
                         sorted(jobs - {"archive-layout-experiment", "merge-group-fail-fast", "required-ci"}))

    def test_full_runs_use_nextest_profiles_without_a_default_filter(self):
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

    def test_no_nextest_profile_counts_a_stopped_test_as_passed(self):
        profiles = tomllib.loads((ROOT / ".config/nextest.toml").read_text())["profile"]
        for name, config in profiles.items():
            timeouts = [config.get("slow-timeout")]
            timeouts += [override.get("slow-timeout") for override in config.get("overrides", [])]
            passes = any(isinstance(t, dict) and t.get("on-timeout") == "pass" for t in timeouts)
            with self.subTest(profile=name):
                self.assertFalse(passes)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertNotIn("--profile precheck", workflow)

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
        self.assertEqual(len(re.findall(r"(?m)^    continue-on-error:", workflow)), 1)
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
                    if workflow.name == "wn-agent-binaries.yml":
                        # Release tags, RCs, and promoted releases publish these binaries,
                        # so they never restore a cache (binding packages below).
                        self.assertRegex(step, r"(?m)^        if: runner\.os == 'macOS' && "
                                               r"!startsWith\(github\.ref, 'refs/tags/'\) && !inputs\.release_version$")
                    if save_if == "false":
                        continue
                    saving.add(workflow.name)
                    # Pull requests and merge groups only restore.
                    self.assertEqual(save_if, "${{ github.ref == 'refs/heads/master' }}")
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

    def test_windows_download_tolerates_only_an_offline_revocation_check(self):
        # SChannel fails a handshake whose revocation server is offline; the
        # Windows download skips only that check, and the pin still decides.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            stubs = tmp / "bin"
            stubs.mkdir()
            for name, body in {
                "uname": 'case "$1" in -s) echo MINGW64_NT-10.0 ;; -m) echo x86_64 ;; esac',
                "sha256sum": "exit 1",
                "curl": 'printf "%s\\n" "$@" > "$ARGS"; while [ "$1" != --output ]; do shift; done; '
                        'printf corrupt > "$2"',
            }.items():
                (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
                (stubs / name).chmod(0o755)
            result = subprocess.run(
                ["/bin/bash", str(ROOT / "scripts/install-odin.sh"), str(tmp / "odin-install")],
                env={**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "ARGS": str(tmp / "args")},
                capture_output=True, text=True)
            arguments = (tmp / "args").read_text().splitlines()
            self.assertIn("--ssl-revoke-best-effort", arguments)
            self.assertFalse({"-k", "--insecure", "--ssl-no-revoke"} & set(arguments))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match its pinned sha256", result.stderr)
            self.assertFalse((tmp / "odin-install").exists())


class RcReleasePolicyTests(unittest.TestCase):
    DAY = dt.date(2026, 11, 26)

    def test_rc_latest_json_names_each_track_asset_with_its_url_and_checksum(self):
        version = "0.20.0-rc.1"
        releases = {
            prefix: {"assets": [{"name": f"{prefix}.zip", "size": 3, "digest": "sha256:" + "b" * 64}]}
            for prefix in rc_release.TRACK_PREFIXES
        }
        document = rc_release.latest_rc_document(
            version, "a" * 40, releases, "o/r", "https://run", today=self.DAY
        )
        self.assertEqual((document["version"], document["source_sha"], document["date"]),
                         (version, "a" * 40, "2026-11-26"))
        self.assertEqual(document["tracks"]["marmotc"], {
            "tag": "marmotc-v" + version,
            "release_url": "https://github.com/o/r/releases/tag/marmotc-v" + version,
            "assets": [{"name": "marmotc.zip", "sha256": "b" * 64, "size": 3,
                        "url": f"https://github.com/o/r/releases/download/marmotc-v{version}/marmotc.zip"}],
        })
        releases["wn-agent"]["assets"][0]["digest"] = None
        with self.assertRaises(rc_release.ReleaseError):
            rc_release.latest_rc_document(version, "a" * 40, releases, "o/r", "https://run", today=self.DAY)

    def test_only_release_promotion_and_snapshot_runs_hold_the_lane(self):
        busy = rc_release.busy_release_runs({
            "bindings.yaml": [{"id": 1, "status": "in_progress", "event": "workflow_dispatch"},
                              {"id": 2, "status": "completed", "event": "push"}],
            "c-bindings.yml": [{"id": 3, "status": "queued", "event": "push"}],
            "promote-release.yml": [{"id": 7, "status": "in_progress", "event": "workflow_dispatch"}],
            "wn-agent-binaries.yml": [
                {"id": 4, "status": "in_progress", "event": "push", "head_branch": "master"},
                {"id": 5, "status": "waiting", "event": "push", "head_branch": "wn-agent-v0.19.0"},
                {"id": 6, "status": "in_progress", "event": "pull_request", "head_branch": "wn-agent-v-ish"},
            ],
        })
        self.assertEqual([run["id"] for run in busy], [1, 3, 7, 5])

    def test_rc_workflow_gates_publish_on_all_five_parallel_lanes_and_owns_concurrency(self):
        workflow = (ROOT / ".github/workflows/rc-releases.yml").read_text()
        self.assertIn(
            "    needs: [plan, lane, simulator-nightly, convergence-hardening, marmotkit, marmotc, wn-agent]\n",
            workflow,
        )
        self.assertIn("needs.lane.outputs.lane_free == 'true'", workflow)
        self.assertIn("needs.simulator-nightly.result == 'success'", workflow)
        self.assertIn("needs.convergence-hardening.result == 'success'", workflow)
        # Hardening/simulator gates run before acquiring the shared macOS release lane.
        self.assertIn("    needs: [plan, simulator-nightly, convergence-hardening]\n", workflow)
        self.assertEqual(workflow.count("    if: success() && needs.lane.outputs.lane_free == 'true'\n"), 3)
        self.assertEqual(
            workflow.count("    if: success() && needs.plan.outputs.skip != 'true' && !inputs.dry_run && !inputs.build_only\n"),
            2,
        )
        # cleanup-drafts runs only when publish was skipped, never deleting drafts after publish starts.
        cleanup_block = workflow.split("\n  cleanup-drafts:\n", 1)[1].split("\n  retention:\n", 1)[0]
        self.assertIn("needs.publish.result == 'skipped'", cleanup_block)
        # Never gate runner.temp uploads with hashFiles() (which only matches GITHUB_WORKSPACE).
        self.assertNotIn("hashFiles(", workflow)
        self.assertIn("uses: ./.github/workflows/simulator-nightly.yml", workflow)
        self.assertIn("uses: ./.github/workflows/convergence-hardening.yml", workflow)
        self.assertIn("  group: rc-releases\n", workflow)
        self.assertNotIn("git push", workflow)
        bindings = (ROOT / ".github/workflows/bindings.yaml").read_text()
        # RCs and promotions must not share a same-SHA snapshot's concurrency group.
        self.assertIn("  group: marmotkit-bindings-${{ inputs.release_version || inputs.source_sha || github.ref }}-",
                      bindings)
        # Simulator nightly and convergence hardening must pin inputs.source_sha on workflow_call.
        for wf in ("simulator-nightly.yml", "convergence-hardening.yml"):
            text = (ROOT / ".github/workflows" / wf).read_text()
            self.assertIn("  workflow_call:\n", text)
            self.assertIn("      source_sha:\n", text)
            self.assertIn("ref: ${{ inputs.source_sha }}", text)
        sim_text = (ROOT / ".github/workflows/simulator-nightly.yml").read_text()
        self.assertNotIn("\n  schedule:\n", sim_text)

    def test_promote_workflow_skips_test_lanes_and_requires_metadata_diff_guard(self):
        workflow = (ROOT / ".github/workflows/promote-release.yml").read_text()
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertIn("      rc_version:\n", workflow)
        self.assertIn("      override_version:\n", workflow)
        self.assertNotIn("publish_crates_io", workflow)
        self.assertIn("Preflight release credentials", workflow)
        self.assertIn("META_GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}", workflow)
        self.assertIn("PR_GH_TOKEN: ${{ secrets.RELEASE_TOKEN }}", workflow)
        self.assertIn("validate-published-ios:", workflow)
        self.assertIn("validate-published-macos:", workflow)
        self.assertIn("\n  open-sync-pr:\n", workflow)
        self.assertIn("python3 scripts/promote_release.py verify-metadata-diff", workflow)
        self.assertIn("uses: ./.github/workflows/bindings.yaml", workflow)
        self.assertIn("uses: ./.github/workflows/c-bindings.yml", workflow)
        self.assertIn("uses: ./.github/workflows/wn-agent-binaries.yml", workflow)
        self.assertNotIn("simulator-nightly.yml", workflow)
        self.assertNotIn("convergence-hardening.yml", workflow)
        self.assertNotIn("cargo test", workflow)
        self.assertNotIn("cargo nextest", workflow)

    def test_a_failed_scheduled_rc_reports_to_one_open_issue(self):
        workflow = (ROOT / ".github/workflows/rc-releases.yml").read_text()
        jobs = re.findall(r"^  ([a-z][a-z-]*):\n", workflow.split("\njobs:\n", 1)[1], re.MULTILINE)
        report = workflow.split("\n  report:\n", 1)[1].split("\n    steps:\n", 1)[0]
        self.assertIn(f"    needs: [{', '.join(job for job in jobs if job != 'report')}]\n", report)
        self.assertIn("    if: github.event_name == 'schedule' && !cancelled() && "
                      "(failure() || contains(needs.*.result, 'cancelled'))\n", report)
        self.assertIn("    permissions:\n      issues: write\n", report)

        script = workflow_step("rc-releases.yml", "Open or update the RC failure issue")
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
        body = ("--body The scheduled RC (0.20.0-rc.1) failed for abc123 "
                "(failed jobs: marmotc, wn-agent (cancelled), retention). Run: https://run")
        for issues, expected in [
            ([{"number": 9, "title": "RC release failed twice"}],
             f"issue create --repo o/r --title RC release failed {body}"),
            ([{"number": 9, "title": "RC release failed twice"}, {"number": 12, "title": "RC release failed"}],
             f"issue comment 12 --repo o/r {body}"),
        ]:
            with self.subTest(issues=issues), tempfile.TemporaryDirectory() as tmp:
                log = Path(tmp) / "gh.log"
                subprocess.run(
                    ["bash", "-c", fake_gh + script], check=True, timeout=10,
                    env={**os.environ, "ISSUES": json.dumps(issues), "LOG": str(log), "NEEDS": needs,
                         "REPO": "o/r", "RUN_URL": "https://run", "SOURCE_SHA": "abc123",
                         "RC_VERSION": "0.20.0-rc.1"},
                )
                self.assertEqual(log.read_text(), expected + "\n")

    def test_tag_pushed_release_workflows_ignore_rc_and_nightly_tags(self):
        for workflow, prefix in [("bindings.yaml", "marmotkit"), ("c-bindings.yml", "marmotc"),
                                 ("wn-agent-binaries.yml", "wn-agent")]:
            with self.subTest(workflow=workflow):
                text = (ROOT / ".github/workflows" / workflow).read_text()
                self.assertIn(f'      - "!{prefix}-v*-nightly.*"\n', text)
                self.assertIn(f'      - "!{prefix}-v*-rc.*"\n', text)
                self.assertIn("  workflow_call:\n", text)
                self.assertIn("      release_version:\n", text)
                # Tag pushes and dispatches have no release_version input at all (null), so
                # conditions must test truthiness rather than compare with ''.
                self.assertIsNone(re.search(r"inputs\.release_version\s*[!=]=", text))
                self.assertIn("inputs.release_version }}", text)

    def test_rcs_are_scheduled_pre_releases_that_never_become_latest(self):
        workflow = (ROOT / ".github/workflows/rc-releases.yml").read_text()
        self.assertIn('    - cron: "17 0 * * *"\n', workflow)
        script = (ROOT / "scripts/rc_release.py").read_text()
        self.assertIn('"make_latest": "false"', script)
        self.assertNotIn('"make_latest": "true"', script)
        self.assertEqual(rc_release.RETENTION_DAYS, 30)
        bindings = (ROOT / ".github/workflows/bindings.yaml").read_text()
        self.assertIn(
            '          if [[ "$IS_RC" == "true" ]]; then\n'
            '            title="v$version - MarmotKit"\n'
            '            release_flags=(--prerelease --latest=false --target "$SOURCE_SHA")\n',
            bindings,
        )

    def test_install_guidance_never_resolves_to_an_rc_or_nightly(self):
        with tempfile.TemporaryDirectory() as tmp:
            notes = Path(tmp) / "docs/release"
            notes.mkdir(parents=True)
            for name in ("0.19.0.md", "0.20.0-rc.1.md", "0.20.0-nightly.20261126.md", "wn-homebrew.md"):
                (notes / name).write_text("notes\n")
            self.assertEqual(documented_release_version(Path(tmp), "0.20.0-dev"), "0.19.0")
        quickstart = (ROOT / "integrations/README.md").read_text()
        installer_pattern = re.search(r"grep -Eq '(\^https://github\[\.\]com/marmot-protocol/mdk/[^']+)'",
                                      quickstart).group(1)
        resolver = re.search(r'match = re\.fullmatch\(r"([^"]+)", tag\)', quickstart).group(1)
        for prerelease in ("wn-agent-v0.20.0-rc.1", "wn-agent-v0.20.0-nightly.20261126"):
            url = f"https://github.com/marmot-protocol/mdk/releases/download/{prerelease}/install-hermes-marmot.sh"
            self.assertIsNone(re.search(installer_pattern, url))
            self.assertIsNone(re.fullmatch(resolver, prerelease))
        stable_url = "https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v0.19.0/install-hermes-marmot.sh"
        self.assertIsNotNone(re.search(installer_pattern, stable_url))
        self.assertIsNotNone(re.fullmatch(resolver, "wn-agent-v0.19.0"))

    def test_binary_bundles_accept_minor_rc_patch_rc_and_stable_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src"
            root.mkdir()
            (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.20.0-dev"\n')
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
            command = ["bash", str(ROOT / "scripts/package-binary-bundle.sh"), "wn-agent", "linux-x86_64",
                       "x86_64-unknown-linux-gnu"]
            for rc_ver in ("0.20.0-rc.1", "0.19.1-rc.2"):
                env = {**os.environ, "RUNNER_TEMP": tmp, "GITHUB_SHA": "f" * 40, "GITHUB_REF_TYPE": "branch",
                       "RELEASE_SOURCE_SHA": source_sha, "RELEASE_VERSION": rc_ver}
                subprocess.run(command, cwd=root, env=env, check=True, capture_output=True)
                asset = root / f"dist/wn-agent-linux-x86_64/wn-agent-linux-x86_64-{rc_ver}.tar.gz"
                manifest = json.loads(subprocess.run(
                    ["tar", "-xzOf", str(asset), "wn-agent-linux-x86_64/manifest.json"],
                    check=True, capture_output=True).stdout)
                self.assertEqual(
                    (manifest["artifact_version"], manifest["release_tag"], manifest["source_sha"]),
                    (rc_ver, f"wn-agent-v{rc_ver}", source_sha))
            base_env = {**os.environ, "RUNNER_TEMP": tmp, "GITHUB_SHA": "f" * 40, "GITHUB_REF_TYPE": "branch",
                        "RELEASE_SOURCE_SHA": source_sha}
            for overrides in ({"RELEASE_VERSION": "0.21.0-rc.1"},
                              {"RELEASE_VERSION": "0.20.0-rc.0"},
                              {"RELEASE_VERSION": "0.20.0"},
                              {"RELEASE_VERSION": "0.20.0-rc.1", "RELEASE_SOURCE_SHA": "e" * 40}):
                with self.subTest(overrides=overrides):
                    result = subprocess.run(command, cwd=root, env={**base_env, **overrides}, capture_output=True)
                    self.assertNotEqual(result.returncode, 0)


class FlakeReportPolicyTests(unittest.TestCase):
    def test_reads_actions_and_writes_only_issues(self):
        workflow = (ROOT / ".github/workflows/flake-report.yml").read_text()
        self.assertIn("permissions:\n  actions: read\n  contents: read\n  issues: write\n\n", workflow)
        self.assertNotIn("pull_request", workflow)
        # GITHUB_TOKEN's hourly budget is shared with CI; leave most of it.
        self.assertIn("--reserve 600", workflow_step("flake-report.yml", "Build the leaderboard"))

    def test_replaces_the_body_of_one_open_leaderboard_issue(self):
        script = workflow_step("flake-report.yml", "Replace the leaderboard issue body")
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
        for issues, expected in [
            ([{"number": 9, "title": "Flaky test leaderboard (old)"}],
             "issue create --repo o/r --title Flaky test leaderboard --body-file board.md"),
            ([{"number": 9, "title": "Flaky test leaderboard (old)"}, {"number": 12, "title": "Flaky test leaderboard"}],
             "issue edit 12 --repo o/r --body-file board.md"),
        ]:
            with self.subTest(issues=issues), tempfile.TemporaryDirectory() as tmp:
                log = Path(tmp) / "gh.log"
                subprocess.run(
                    ["bash", "-c", fake_gh + script], check=True, timeout=10,
                    env={**os.environ, "ISSUES": json.dumps(issues), "LOG": str(log), "REPO": "o/r",
                         "LEADERBOARD": "board.md"},
                )
                self.assertEqual(log.read_text(), expected + "\n")


class FakeRcGitHub:
    """In-memory stand-in for the GitHub calls that publish_rc makes."""

    SHA = "a" * 40

    def __init__(self, version: str, *, verified: bool = True):
        self.repository = "o/r"
        self.verified = verified
        self.fail_patch: set[str] = set()
        self.tags: dict[str, str] = {}
        self.meta_head: str | None = None
        self.meta_files: dict[str, str] = {}
        self.commits: dict[str, dict] = {}
        self.trees: dict[str, dict[str, str]] = {}
        self.blobs: dict[str, str] = {}
        self.releases = {}
        for index, (prefix, title) in enumerate(rc_release.TRACKS):
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

    def read_latest_rc(self):
        raw = self.meta_files.get(rc_release.RC_LATEST_FILE)
        return json.loads(raw) if raw else None

    def read_rc_counters(self):
        raw = self.meta_files.get(rc_release.RC_COUNTERS_FILE)
        return json.loads(raw).get("highest_rc", {}) if raw else {}

    def get(self, path, *, allow_404=False):
        suffix = path.removeprefix("repos/o/r/")
        if suffix.startswith("releases/"):
            release = next(r for r in self.releases.values() if r["id"] == int(suffix.split("/")[1]))
            return dict(release)
        if suffix == f"git/ref/heads/{rc_release.META_BRANCH}":
            return {"object": {"sha": self.meta_head}} if self.meta_head else None
        if suffix.startswith("git/commits/"):
            sha = suffix.removeprefix("git/commits/")
            return {"sha": sha, "tree": {"sha": self.commits[sha]["tree"]}}
        raise AssertionError(path)

    def request(self, method, path, body=None, **_):
        suffix = path.removeprefix("repos/o/r/")
        if method == "DELETE" and suffix.startswith("releases/"):
            rid = int(suffix.split("/")[1])
            tag = next(t for t, r in self.releases.items() if r["id"] == rid)
            del self.releases[tag]
            return None, ""
        if method == "PATCH" and suffix.startswith("releases/"):
            release = next(r for r in self.releases.values() if r["id"] == int(suffix.split("/")[1]))
            if release["tag_name"] in self.fail_patch:
                self.fail_patch.discard(release["tag_name"])
                raise rc_release.ReleaseError(f"PATCH {path} failed with HTTP 502")
            assert body == {"draft": False, "prerelease": True, "make_latest": "false"}
            release.update(draft=False, immutable=True)
            self.tags[release["tag_name"]] = release["target_commitish"]
            return None, ""
        if suffix == "git/blobs":
            sha = f"blob{len(self.blobs)}"
            self.blobs[sha] = body["content"]
            return {"sha": sha}, ""
        if suffix == "git/trees":
            base = dict(self.trees.get(body.get("base_tree", ""), {}))
            for entry in body["tree"]:
                base[entry["path"]] = self.blobs[entry["sha"]]
            tree_sha = f"tree{len(self.trees)}"
            self.trees[tree_sha] = base
            return {"sha": tree_sha}, ""
        if suffix == "git/commits":
            assert "author" not in body and "committer" not in body
            sha = f"commit{len(self.commits)}"
            self.commits[sha] = body
            return {"sha": sha, "verification": {"verified": self.verified, "reason": "valid"}}, ""
        if (method, suffix) in (("PATCH", f"git/refs/heads/{rc_release.META_BRANCH}"), ("POST", "git/refs")):
            assert body.get("force") in (None, False)
            self.meta_head = body["sha"]
            tree = self.commits[body["sha"]]["tree"]
            self.meta_files = dict(self.trees[tree])
            return None, ""
        raise AssertionError((method, path))


class RcPublishTests(unittest.TestCase):
    VERSION = "0.20.0-rc.1"
    DAY = dt.date(2026, 11, 26)

    def publish(self, gh, *, impact=None, delta=None, notes=None):
        with unittest.mock.patch.object(rc_release.time, "sleep"):
            return rc_release.publish_rc(
                gh, self.VERSION, FakeRcGitHub.SHA, "https://run",
                impact_report=impact, signature_delta=delta, integration_notes=notes, today=self.DAY,
            )

    def test_publishes_all_three_tracks_then_rc_meta_files_on_orphan_branch(self):
        gh = FakeRcGitHub(self.VERSION)
        self.publish(
            gh,
            impact={"impact": "minor", "baseline_tag": "v0.19.0", "baseline_sha": "b" * 40, "triggers": ["mig"]},
            delta={"schema": 1, "uniffi": {"breaking": []}},
            notes="# Notes\n",
        )
        self.assertTrue(all(not r["draft"] and r["immutable"] for r in gh.releases.values()))
        latest = gh.read_latest_rc()
        self.assertEqual(latest["version"], self.VERSION)
        self.assertEqual(sorted(latest["tracks"]), ["marmotc", "marmotkit", "wn-agent"])
        self.assertIn(rc_release.RC_DELTA_FILE, gh.meta_files)
        self.assertIn(rc_release.RC_IMPACT_FILE, gh.meta_files)
        self.assertIn(rc_release.RC_NOTES_FILE, gh.meta_files)
        self.assertIn(f"{rc_release.RC_RELEASES_DIR}/{self.VERSION}.json", gh.meta_files)
        self.assertEqual(gh.commits[gh.meta_head]["parents"], [])

    def test_a_missing_or_wrong_track_publishes_nothing(self):
        for breakage in ("missing", "target", "title"):
            with self.subTest(breakage=breakage):
                gh = FakeRcGitHub(self.VERSION)
                tag = "wn-agent-v" + self.VERSION
                if breakage == "missing":
                    del gh.releases[tag]
                elif breakage == "target":
                    gh.releases[tag]["target_commitish"] = "b" * 40
                else:
                    gh.releases[tag]["name"] = "v0.20.0 - wn-agent"
                with self.assertRaises(rc_release.ReleaseError):
                    self.publish(gh)
                self.assertTrue(all(r["draft"] for r in gh.releases.values() if r["tag_name"] != tag))
                self.assertIsNone(gh.read_latest_rc())

    def test_a_failed_publication_resumes_after_cleanup_without_moving_latest_early(self):
        gh = FakeRcGitHub(self.VERSION)
        gh.meta_files[rc_release.RC_LATEST_FILE] = json.dumps({"version": "0.19.1-rc.1"})
        gh.fail_patch.add("marmotc-v" + self.VERSION)
        with self.assertRaisesRegex(rc_release.ReleaseError, "Published so far: marmotkit-v"):
            self.publish(gh)
        self.assertEqual(gh.read_latest_rc(), {"version": "0.19.1-rc.1"})
        # Workflow cleanup-drafts runs after publish fails: since marmotkit is already
        # published, cleanup MUST preserve marmotc and wn-agent drafts so re-run resumes.
        self.assertEqual(rc_release.cleanup_unpublished_drafts(gh, self.VERSION), [])
        self.publish(gh)
        self.assertTrue(all(not r["draft"] for r in gh.releases.values()))
        self.assertEqual(gh.read_latest_rc()["version"], self.VERSION)
        self.assertEqual(gh.read_rc_counters(), {"0.20.0": 1})
        commits = len(gh.commits)
        self.assertIsNone(self.publish(gh))
        self.assertEqual(len(gh.commits), commits)

    def test_cleanup_drops_all_drafts_when_zero_tracks_were_published(self):
        gh = FakeRcGitHub(self.VERSION)
        deleted = rc_release.cleanup_unpublished_drafts(gh, self.VERSION)
        self.assertEqual(len(deleted), 3)
        self.assertEqual(gh.releases, {})

    def test_an_unverified_metadata_commit_never_moves_the_branch(self):
        gh = FakeRcGitHub(self.VERSION, verified=False)
        with self.assertRaisesRegex(rc_release.ReleaseError, "not verified"):
            self.publish(gh)
        self.assertIsNone(gh.meta_head)
        gh.verified = True
        self.publish(gh)
        self.assertEqual(gh.read_latest_rc()["source_sha"], FakeRcGitHub.SHA)

    def test_releases_and_snapshots_wait_only_for_an_rc_past_its_lane_wait(self):
        lane = rc_release.LANE_JOB
        step = rc_release.LANE_STEP
        building = rc_release.rc_is_building
        self.assertFalse(building([{"name": "Plan SemVer RC", "conclusion": "success"}]))
        # Pre-lane simulator/convergence gates must NOT hold the macOS release lane.
        self.assertFalse(building([
            {"name": "Plan SemVer RC", "status": "completed", "conclusion": "success"},
            {"name": "Simulator Nightly gate / Full simulator, campaigns, and vectors", "status": "in_progress", "conclusion": None},
            {"name": "Convergence Hardening gate / Weekly or release convergence hardening", "status": "in_progress", "conclusion": None},
        ]))
        self.assertFalse(building([{"name": lane, "conclusion": None,
                                    "steps": [{"name": step, "status": "in_progress", "conclusion": None}]}]))
        self.assertTrue(building([{"name": lane, "conclusion": None,
                                   "steps": [{"name": step, "status": "completed", "conclusion": "success"}]}]))
        self.assertTrue(building([{"name": lane, "conclusion": "success"}]))
        self.assertTrue(building([
            {"name": lane, "status": "completed", "conclusion": "success"},
            {"name": "MarmotKit / Build Apple libraries", "status": "in_progress", "conclusion": None},
        ]))
        # Once all packaging tracks finish, publish/retention on Ubuntu do not hold the macOS lane.
        self.assertFalse(building([
            {"name": lane, "status": "completed", "conclusion": "success"},
            {"name": "MarmotKit / Create GitHub release", "status": "completed", "conclusion": "success"},
            {"name": "Marmot C / Publish Marmot C", "status": "completed", "conclusion": "success"},
            {"name": "wn-agent / Stage wn-agent RC or promoted release", "status": "completed", "conclusion": "success"},
            {"name": "Publish SemVer RC and rc-meta", "status": "in_progress", "conclusion": None},
        ]))
        workflow = (ROOT / ".github/workflows/rc-releases.yml").read_text()
        self.assertIn(f"    name: {lane}\n", workflow)
        self.assertIn(f"      - name: {step}\n", workflow)

    def test_binding_jobs_never_inherit_a_skipped_ancestor(self):
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
        # SIGTERM can arrive before the readiness write returns. Neither write
        # may hold a buffered stdout lock that the signal handler could reenter.
        program = """import os,signal,sys
signal.signal(signal.SIGTERM, lambda *_: (os.write(1, b'last cancellation evidence\\n'), sys.exit(0)))
os.write(1, b'ready for cancellation\\n')
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

    def test_sdk_cleanup_budgets(self):
        archive_minimum = 32 * 1024**3
        precheck_minimum = 64 * 1024**3
        for command, available, removed in (
            ("prepare-archive", archive_minimum, False),
            ("prepare-archive", archive_minimum - 1, True),
            ("prepare-precheck", precheck_minimum, False),
            ("prepare-precheck", precheck_minimum - 1, True),
            ("prepare", precheck_minimum, True),
        ):
            with self.subTest(command=command, available=available), tempfile.TemporaryDirectory() as tmp:
                sdk = Path(tmp) / "unused-sdk"
                sdk.mkdir()
                (sdk / "payload").write_text("keep unless space is needed")
                sudo = Path(tmp) / "sudo"
                sudo.write_text('#!/bin/sh\nexec "$@"\n')
                sudo.chmod(0o700)
                total = 2 * precheck_minimum
                usage = type("Usage", (), {"total": total, "used": total - available,
                                            "free": available})()

                with unittest.mock.patch.dict(os.environ, {
                    "RUNNER_TEMP": tmp, "GITHUB_ACTIONS": "true",
                    "MDK_RUNNER_ENVIRONMENT": "github-hosted",
                    "PATH": tmp + os.pathsep + os.environ["PATH"],
                }), unittest.mock.patch.object(sys, "platform", "linux"), \
                     unittest.mock.patch.object(sys, "argv", ["ci_runner.py", command]), \
                     unittest.mock.patch.object(os, "umask", return_value=0o22), \
                     unittest.mock.patch.object(ci_runner, "UNUSED_SDKS", (str(sdk),)), \
                     unittest.mock.patch.object(ci_runner.shutil, "disk_usage", return_value=usage):
                    self.assertEqual(ci_runner.main(), 0)
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

    def test_consumer_archive_downloads_are_bounded_and_retried_once(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs = re.split(r"\n  (?=[a-z][a-z0-9-]*:\n)", workflow.split("\njobs:\n", 1)[1])
        consumers = [job for job in jobs if "actions/download-artifact@" in job]
        extractors = [job for job in jobs if "ci_runner.py extract " in job]
        self.assertTrue(consumers)
        self.assertEqual(
            {job.splitlines()[0].rstrip(":") for job in consumers},
            {job.splitlines()[0].rstrip(":") for job in extractors},
        )
        # Only a retried archive download may use step-level continue-on-error, so no test step can swallow failures.
        self.assertEqual(len(re.findall(r"(?m)^        continue-on-error:", workflow)), len(consumers))
        for job in consumers:
            job_name = job.splitlines()[0].rstrip(":")
            with self.subTest(job=job_name):
                job_timeout = int(re.search(r"(?m)^    timeout-minutes: (\d+)$", job).group(1))
                steps = re.split(r"\n      - (?=name: )", job.split("\n    steps:\n", 1)[1])
                downloads = [(i, step) for i, step in enumerate(steps) if "actions/download-artifact@" in step]
                self.assertEqual(len(downloads), 2, "expected one bounded download and one bounded retry")
                (first_idx, first), (retry_idx, retry) = downloads
                self.assertEqual(retry_idx, first_idx + 1, "retry must follow the first download immediately")

                first_id = re.search(r"(?m)^        id: ([a-z0-9-]+)$", first)
                self.assertIsNotNone(first_id, "first download must declare an id")
                self.assertNotIn("\n        if:", first, "first download must run under the default success condition")
                self.assertIn("\n        continue-on-error: true\n", first)
                first_timeout = int(re.search(r"(?m)^        timeout-minutes: (\d+)$", first).group(1))

                self.assertIn(f"\n        if: steps.{first_id.group(1)}.outcome == 'failure'\n", retry)
                self.assertNotIn("continue-on-error:", retry)
                retry_timeout = int(re.search(r"(?m)^        timeout-minutes: (\d+)$", retry).group(1))
                if job_name == "rust-test":
                    # A retry restarts from byte 0, so it keeps the full 25-minute slow-runner budget (#2568).
                    self.assertGreaterEqual(retry_timeout, 25)

                other_timeouts = sum(
                    int(m.group(1))
                    for i, step in enumerate(steps)
                    if i not in (first_idx, retry_idx)
                    for m in [re.search(r"(?m)^        timeout-minutes: (\d+)$", step)]
                    if m
                )
                self.assertLess(first_timeout + retry_timeout + other_timeouts, job_timeout)

    def test_formal_bootstrap_rejects_the_unsupported_distro_maude(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        formal = workflow.split("\n  formal:\n", 1)[1].split("\n  hermes-installer-auth:\n", 1)[0]
        self.assertNotIn("--no-install-recommends graphviz maude", formal)
        # The proofs need nothing from the Ubuntu archives, so an archive
        # outage cannot stop the formal job (Canonical DDoS, 2026-11-11).
        self.assertNotIn("apt-get", formal)
        script = workflow_step("ci.yml", "Install Maude")
        self.assertIn("Maude3.5.1/Maude-3.5.1-linux-x86_64.zip", script)
        self.assertLess(script.index("sha256sum"), script.index("python3 -m zipfile -e"))
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

    def test_pr_trailer_contract_and_advisory_step_resolve_pr_refs(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        changes = workflow.split("\n  changes:\n", 1)[1].split("\n  rust-format:\n", 1)[0]
        rust_format = workflow.split("\n  rust-format:\n", 1)[1].split("\n  rust-audit:\n", 1)[0]
        self.assertIn("fetch-depth: 0", changes)
        self.assertIn("run: python3 scripts/test_check_pr_trailers.py", rust_format)

        script = workflow_step("ci.yml", "PR commit trailers (advisory)")
        self.assertIn("python3 scripts/check_pr_trailers.py --advisory", script)
        self.assertIn('|| echo "::warning title=PR trailers::', script)
        self.assertNotIn("${{", script)

        # Execute the exact workflow step in a synthetic PR merge-ref checkout
        # (matching `actions/checkout` with `fetch-depth: 0` on pull_request).
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            def git(*args):
                return subprocess.run(
                    ["git", "-C", str(repo), *args],
                    check=True, capture_output=True, text=True,
                ).stdout.strip()

            git("init", "-b", "master")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.com")
            git("config", "commit.gpgsign", "false")
            scripts_dir = repo / "scripts"
            scripts_dir.mkdir()
            for name in ("check_pr_trailers.py", "changelog.py"):
                (scripts_dir / name).write_text((ROOT / "scripts" / name).read_text())
            git("add", "scripts")
            git("commit", "-m", "Base commit")
            git("checkout", "-b", "pr-branch")
            (repo / "feature.txt").write_text("ok\n")
            git("add", "feature.txt")
            git(
                "commit", "-m",
                "Add feature\n\n"
                "Local-Checks: cargo fmt\n"
                "Local-Review: claude + codex merge @ 1234567\n"
                "Release-Impact: patch\n",
            )
            head_sha = git("rev-parse", "HEAD")

            git("checkout", "master")
            (repo / "master.txt").write_text("advanced\n")
            git("add", "master.txt")
            git("commit", "-m", "Advance master")
            base_sha = git("rev-parse", "HEAD")
            git("merge", "--no-ff", "pr-branch", "-m", "Synthetic refs/pull/1/merge")

            result = subprocess.run(
                ["bash", "-c", script],
                cwd=repo,
                env={
                    **os.environ,
                    "EVENT_NAME": "pull_request",
                    "BASE_SHA": base_sha,
                    "HEAD_SHA": head_sha,
                },
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("pr-trailers: OK (Release-Impact: patch)", result.stdout)
            self.assertNotIn("::warning", result.stdout)


class CanaryWorkflowPolicyTests(unittest.TestCase):
    @staticmethod
    def _permissions_union(text: str) -> dict[str, str]:
        rank = {"none": 0, "read": 1, "write": 2}
        merged: dict[str, str] = {}
        for match in re.finditer(r"(?m)^([ ]*)permissions:\n((?:\1  [a-z-]+: [a-z]+\n)+)", text):
            for scope, level in re.findall(r"([a-z-]+): ([a-z]+)", match.group(2)):
                if rank.get(level, -1) > rank.get(merged.get(scope, "none"), -1):
                    merged[scope] = level
        return merged

    def test_canary_workflow_structure_permissions_and_concurrency(self):
        workflow = (ROOT / ".github/workflows/canary.yml").read_text()
        ci_workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        bp_workflow = (ROOT / ".github/workflows/bindings-profile.yml").read_text()

        self.assertIn('    - cron: "7 * * * *"\n', workflow)
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertNotIn("  pull_request:", workflow)
        self.assertIn("permissions:\n  actions: read\n  contents: read\n", workflow)
        self.assertIn("concurrency:\n  group: canary\n  cancel-in-progress: false\n", workflow)
        self.assertIn("uses: ./.github/workflows/ci.yml", workflow)
        self.assertIn("rust_test_shards: 6", workflow)
        self.assertIn("uses: ./.github/workflows/bindings-profile.yml", workflow)

        # `verify-ci` must cover the full permission union requested by `ci.yml`
        # (GitHub validates nested permissions before evaluating job `if:`s),
        # while no other Canary job may hold write permissions.
        verify_ci = workflow.split("\n  verify-ci:\n", 1)[1].split("\n  # Serialization", 1)[0]
        verify_bp = workflow.split("\n  verify-bindings-profile:\n", 1)[1].split("\n  summary:\n", 1)[0]
        plan_block = workflow.split("\n  plan:\n", 1)[1].split("\n  # GitHub validates", 1)[0]
        summary_block = workflow.split("\n  summary:\n", 1)[1]

        rank = {"none": 0, "read": 1, "write": 2}
        ci_required = self._permissions_union(ci_workflow)
        verify_ci_granted = self._permissions_union(verify_ci)
        for scope, level in ci_required.items():
            with self.subTest(scope=scope, required=level):
                self.assertGreaterEqual(rank[verify_ci_granted.get(scope, "none")], rank[level])

        bp_required = self._permissions_union(bp_workflow)
        verify_bp_granted = self._permissions_union(verify_bp)
        for scope, level in bp_required.items():
            with self.subTest(bp_scope=scope, required=level):
                self.assertGreaterEqual(rank[verify_bp_granted.get(scope, "none")], rank[level])

        for readonly_name, block in (("plan", plan_block), ("verify-bindings-profile", verify_bp), ("summary", summary_block)):
            with self.subTest(job=readonly_name):
                self.assertNotIn(": write", block)

        # Avoid nested concurrency deadlock: `bindings-profile.yml` owns `macos-packaging`.
        self.assertNotIn("concurrency:", verify_bp)
        self.assertIn("group: macos-packaging", bp_workflow)

    def test_canary_plan_skips_unchanged_master_and_triggers_packaging_only_on_binding_diffs(self):
        script = workflow_step("canary.yml", "Resolve Canary target and packaging trigger")
        fake_gh = textwrap.dedent("""\
            gh() {
              local endpoint=""
              for arg in "$@"; do
                case "$arg" in
                  repos/*) endpoint="$arg" ;;
                esac
              done
              if [[ -n "${FAKE_GH_LOG:-}" ]]; then
                printf '%s\\n' "$*" >> "$FAKE_GH_LOG"
              fi
              if [[ "$endpoint" == *"/jobs"* ]]; then
                if [[ "$FAKE_JOBS_JSON" == "error" ]]; then return 1; fi
                if [[ "$FAKE_JOBS_JSON" == "error_body" ]]; then
                  printf '{"message":"Internal Server Error"}\\n'
                  return 1
                fi
                printf '%s\\n' "$FAKE_JOBS_JSON"
                return 0
              fi
              if [[ "$FAKE_RUNS_JSON" == "error" ]]; then return 1; fi
              if [[ "$FAKE_RUNS_JSON" == "error_body" ]]; then
                printf '{"message":"Internal Server Error"}\\n'
                return 1
              fi
              printf '%s\\n' "$FAKE_RUNS_JSON"
            }
        """)
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            def git(*args):
                return subprocess.run(
                    ["git", "-C", str(repo), *args],
                    check=True, capture_output=True, text=True,
                ).stdout.strip()

            git("init", "-b", "master")
            git("config", "user.name", "Test")
            git("config", "user.email", "test@example.com")
            git("config", "commit.gpgsign", "false")
            (repo / "crates/cgka-engine/src").mkdir(parents=True)
            (repo / "crates/cgka-engine/src/lib.rs").write_text("// base\n")
            git("add", ".")
            git("commit", "-m", "c0")
            c0 = git("rev-parse", "HEAD")

            (repo / "crates/cgka-engine/src/lib.rs").write_text("// core change\n")
            git("add", ".")
            git("commit", "-m", "c1")
            c1 = git("rev-parse", "HEAD")

            (repo / "crates/marmot-uniffi/src").mkdir(parents=True)
            (repo / "crates/marmot-uniffi/src/lib.rs").write_text("// binding change\n")
            git("add", ".")
            git("commit", "-m", "c2")
            c2 = git("rev-parse", "HEAD")

            (repo / ".github/actions/setup-odin").mkdir(parents=True)
            (repo / ".github/actions/setup-odin/action.yml").write_text("name: setup-odin\n")
            git("add", ".")
            git("commit", "-m", "c3")
            c3 = git("rev-parse", "HEAD")

            (repo / ".cargo").mkdir(parents=True)
            (repo / ".cargo/config.toml").write_text("[build]\n")
            git("add", ".")
            git("commit", "-m", "c4")
            c4 = git("rev-parse", "HEAD")

            (repo / "crates/marmot-uniffi-macros/src").mkdir(parents=True)
            (repo / "crates/marmot-uniffi-macros/src/lib.rs").write_text("// macro change\n")
            git("add", ".")
            git("commit", "-m", "c5")
            c5 = git("rev-parse", "HEAD")

            # Simulate bare-metal Canary already sitting at c2.
            git("update-ref", "refs/remotes/origin/canary", c2)

            def job(name, conclusion="success", status="completed"):
                return {"name": name, "status": status, "conclusion": conclusion}

            def run_plan(checkout_sha, runs, force="false", force_bp="false", jobs="error"):
                git("checkout", "-q", checkout_sha)
                out = repo / "gh_out"
                gh_log = repo / "gh_calls.log"
                out.unlink(missing_ok=True)
                gh_log.unlink(missing_ok=True)
                if isinstance(runs, str):
                    runs_json = runs
                elif isinstance(runs, dict):
                    runs_json = json.dumps(runs)
                else:
                    runs_json = json.dumps({"workflow_runs": runs})
                if isinstance(jobs, str):
                    jobs_json = jobs
                elif isinstance(jobs, list) and jobs and all(isinstance(p, dict) and "jobs" in p for p in jobs):
                    jobs_json = json.dumps(jobs)
                elif isinstance(jobs, dict):
                    jobs_json = json.dumps(jobs)
                else:
                    jobs_json = json.dumps([{"jobs": jobs}])
                subprocess.run(
                    ["bash", "-c", fake_gh + script],
                    cwd=repo,
                    check=True,
                    capture_output=True,
                    timeout=10,
                    env={
                        **os.environ,
                        "REPO": "marmot-protocol/mdk",
                        "RUN_ID": "999",
                        "FAKE_RUNS_JSON": runs_json,
                        "FAKE_JOBS_JSON": jobs_json,
                        "FAKE_GH_LOG": str(gh_log),
                        "FORCE": force,
                        "FORCE_BINDINGS_PROFILE": force_bp,
                        "GITHUB_OUTPUT": str(out),
                    },
                )
                result = dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)
                result["_gh_calls"] = gh_log.read_text().splitlines() if gh_log.exists() else []
                return result

            def green(sha, run_id=100, updated_at="2026-11-26T15:00:00Z", run_attempt=1):
                return {
                    "id": run_id,
                    "run_attempt": run_attempt,
                    "head_sha": sha,
                    "conclusion": "success",
                    "updated_at": updated_at,
                }

            def failed(sha, run_id=101, updated_at="2026-11-26T15:30:00Z", run_attempt=1):
                return {
                    "id": run_id,
                    "run_attempt": run_attempt,
                    "head_sha": sha,
                    "conclusion": "failure",
                    "updated_at": updated_at,
                }

            ci_only_failed_jobs = [
                job("Plan Canary batch", "success"),
                job("Full cross-platform CI (6 shards) / Relay runtime tests (1/2)", "failure"),
                job("Full cross-platform CI (6 shards) / Required CI", "failure"),
                job("Record Canary summary", "failure"),
            ]
            packaging_failed_jobs = [
                job("Plan Canary batch", "success"),
                job("Full cross-platform CI (6 shards) / Required CI", "success"),
                job("MarmotKit Release Profile / Resolve exact candidate identity", "success"),
                job("MarmotKit Release Profile / Build Apple candidate input (ios-device)", "failure"),
                job("Record Canary summary", "failure"),
            ]
            packaging_passed_ci_failed_jobs = [
                job("Plan Canary batch", "success"),
                job("Full cross-platform CI (6 shards) / Relay runtime tests (1/2)", "failure"),
                job("MarmotKit Release Profile / Resolve exact candidate identity", "success"),
                job("MarmotKit Release Profile / Build Apple candidate input (ios-device)", "success"),
                job("Record Canary summary", "failure"),
            ]

            # Unchanged master whose latest completed run succeeded skips quickly.
            self.assertEqual(run_plan(c1, [green(c1)])["should_run"], "false")
            # Force overrides skip.
            forced = run_plan(c1, [green(c1)], force="true")
            self.assertEqual((forced["should_run"], forced["run_bindings_profile"]), ("true", "false"))
            # Manual run_bindings_profile=true also bypasses early skip on an already-green SHA.
            forced_bp = run_plan(c1, [green(c1)], force="false", force_bp="true")
            self.assertEqual((forced_bp["should_run"], forced_bp["run_bindings_profile"]), ("true", "true"))
            # Core-only diff whose previous attempt failed in CI only does NOT force packaging on retry.
            core_ci_retry = run_plan(
                c1,
                [failed(c1, 102, run_attempt=2), green(c0, 100)],
                jobs=ci_only_failed_jobs,
            )
            self.assertEqual((core_ci_retry["should_run"], core_ci_retry["run_bindings_profile"]), ("true", "false"))
            self.assertTrue(
                any("repos/marmot-protocol/mdk/actions/runs/102/attempts/2/jobs?per_page=100" in c for c in core_ci_retry["_gh_calls"]),
                core_ci_retry["_gh_calls"],
            )
            # An older green run followed by a newer failed packaging run on the same SHA must NOT skip
            # and must retry packaging rather than letting the older green run bury the failure.
            failed_bp_after_green = run_plan(
                c1,
                [failed(c1, 102), green(c1, 100)],
                jobs=packaging_failed_jobs,
            )
            self.assertEqual(
                (failed_bp_after_green["should_run"], failed_bp_after_green["run_bindings_profile"]),
                ("true", "true"),
            )
            # If a newer failed run on an already-green SHA passed packaging and only failed CI,
            # the retry reruns CI without repeating 60-minute packaging.
            failed_ci_bp_passed = run_plan(
                c1,
                [failed(c1, 102), green(c1, 100)],
                jobs=packaging_passed_ci_failed_jobs,
            )
            self.assertEqual(
                (failed_ci_bp_passed["should_run"], failed_ci_bp_passed["run_bindings_profile"]),
                ("true", "false"),
            )
            # A rerun of an older run ID sits behind a newer ID in GitHub's creation-ordered list,
            # but has a newer updated_at; ordering by completion recency must inspect its exact attempt.
            rerun_failed_bp = run_plan(
                c1,
                [
                    green(c1, 105, updated_at="2026-11-26T15:10:00Z"),
                    failed(c1, 100, updated_at="2026-11-26T15:45:00Z", run_attempt=2),
                ],
                jobs=packaging_failed_jobs,
            )
            self.assertEqual(
                (rerun_failed_bp["should_run"], rerun_failed_bp["run_bindings_profile"]),
                ("true", "true"),
            )
            self.assertTrue(
                any("repos/marmot-protocol/mdk/actions/runs/100/attempts/2/jobs?per_page=100" in c for c in rerun_failed_bp["_gh_calls"]),
                rerun_failed_bp["_gh_calls"],
            )
            rerun_failed_ci_only = run_plan(
                c1,
                [
                    green(c1, 105, updated_at="2026-11-26T15:10:00Z"),
                    failed(c1, 100, updated_at="2026-11-26T15:45:00Z", run_attempt=2),
                ],
                jobs=ci_only_failed_jobs,
            )
            self.assertEqual(
                (rerun_failed_ci_only["should_run"], rerun_failed_ci_only["run_bindings_profile"]),
                ("true", "false"),
            )
            # Multi-page jobs response still catches a packaging failure on page 2.
            paginated_bp_fail = run_plan(
                c1,
                [failed(c1, 102), green(c0, 100)],
                jobs=[
                    {"jobs": [job("Plan Canary batch", "success"), job("Full cross-platform CI (6 shards) / Required CI", "failure")]},
                    {"jobs": [job("MarmotKit Release Profile / Build Apple candidate input (ios-device)", "failure"), job("Record Canary summary", "failure")]},
                ],
            )
            self.assertEqual((paginated_bp_fail["should_run"], paginated_bp_fail["run_bindings_profile"]), ("true", "true"))
            # Uninspectable, cancelled, plan-failed, or zero-job packaging failures fail safe to retrying packaging.
            for unsafe_jobs in (
                "error",
                "error_body",
                {"message": "bad payload"},
                [],
                [job("Plan Canary batch", "failure")],
                [
                    job("Plan Canary batch", "success"),
                    job("Full cross-platform CI (6 shards) / Required CI", "failure"),
                    job("Record Canary summary", "cancelled"),
                ],
                [
                    job("Plan Canary batch", "success"),
                    job("Full cross-platform CI (6 shards) / Required CI", "success"),
                    job("Record Canary summary", "failure"),
                ],
            ):
                with self.subTest(unsafe_jobs=unsafe_jobs):
                    res = run_plan(c1, [failed(c1, 102), green(c0, 100)], jobs=unsafe_jobs)
                    self.assertEqual((res["should_run"], res["run_bindings_profile"]), ("true", "true"))
            # Binding diff whose latest attempt failed in CI only STILL requires packaging because c1..c2 touched bindings.
            binding_ci_retry = run_plan(
                c2,
                [failed(c2, 102), green(c1, 100)],
                jobs=ci_only_failed_jobs,
            )
            self.assertEqual((binding_ci_retry["should_run"], binding_ci_retry["run_bindings_profile"]), ("true", "true"))
            # Core-only diff runs CI without heavy macOS bindings-profile packaging.
            core = run_plan(c1, [green(c0)])
            self.assertEqual((core["should_run"], core["run_bindings_profile"]), ("true", "false"))
            # Binding diff triggers bindings-profile packaging.
            binding = run_plan(c2, [green(c1)])
            self.assertEqual((binding["should_run"], binding["run_bindings_profile"]), ("true", "true"))
            # Tooling-only diff (setup-odin) also triggers bindings-profile packaging.
            odin_tooling = run_plan(c3, [green(c2)])
            self.assertEqual((odin_tooling["should_run"], odin_tooling["run_bindings_profile"]), ("true", "true"))
            # Cargo config diff (.cargo/config.toml) also triggers bindings-profile packaging.
            cargo_cfg = run_plan(c4, [green(c3)])
            self.assertEqual((cargo_cfg["should_run"], cargo_cfg["run_bindings_profile"]), ("true", "true"))
            # Binding proc-macro diff (crates/marmot-uniffi-macros/) also triggers packaging.
            macro_diff = run_plan(c5, [green(c4)])
            self.assertEqual((macro_diff["should_run"], macro_diff["run_bindings_profile"]), ("true", "true"))
            # API failure (empty, error JSON on stdout with nonzero exit, or malformed payload)
            # and missing hosted baseline all fail safe to running CI + packaging even if
            # bare-metal `origin/canary` already sits at `source_sha`.
            for bad_runs in ("error", "error_body", {"message": "bad payload"}, []):
                with self.subTest(bad_runs=bad_runs):
                    res = run_plan(c2, bad_runs)
                    self.assertEqual((res["should_run"], res["run_bindings_profile"]), ("true", "true"))

    def test_canary_summary_records_json_and_enforces_gate(self):
        write_script = workflow_step("canary.yml", "Write Canary summary artifact")
        gate_script = workflow_step("canary.yml", "Enforce Canary gate")
        cases = [
            ("success", "false", "false", "skipped", "skipped", "skipped", True),
            ("success", "true", "false", "success", "skipped", "success", True),
            ("success", "true", "true", "success", "success", "success", True),
            ("success", "true", "false", "failure", "skipped", "failure", False),
            ("success", "true", "true", "success", "failure", "failure", False),
            ("failure", "true", "false", "skipped", "skipped", "failure", False),
        ]
        for plan_res, should_run, run_bp, ci_res, bp_res, expected_overall, gate_ok in cases:
            with self.subTest(plan=plan_res, should_run=should_run, run_bp=run_bp, ci=ci_res, bp=bp_res), \
                    tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                out = tmp_path / "out"
                summary_md = tmp_path / "summary.md"
                subprocess.run(
                    ["bash", "-c", write_script],
                    check=True,
                    capture_output=True,
                    timeout=10,
                    env={
                        **os.environ,
                        "RUNNER_TEMP": tmp,
                        "GITHUB_OUTPUT": str(out),
                        "GITHUB_STEP_SUMMARY": str(summary_md),
                        "PLAN_RESULT": plan_res,
                        "SHOULD_RUN": should_run,
                        "SOURCE_SHA": "a" * 40,
                        "PREVIOUS_SHA": "b" * 40,
                        "RUN_BINDINGS_PROFILE": run_bp,
                        "CI_RESULT": ci_res,
                        "BINDINGS_PROFILE_RESULT": bp_res,
                        "RUN_ID": "42",
                        "RUN_URL": "https://github.com/marmot-protocol/mdk/actions/runs/42",
                    },
                )
                doc = json.loads((tmp_path / "canary-summary.json").read_text())
                self.assertEqual(doc["overall"], expected_overall)
                gate = subprocess.run(
                    ["bash", "-c", gate_script],
                    capture_output=True,
                    timeout=10,
                    env={**os.environ, "OVERALL": doc["overall"]},
                )
                self.assertEqual(gate.returncode == 0, gate_ok)


if __name__ == "__main__":
    unittest.main()
