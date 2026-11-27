#!/usr/bin/env python3
"""Unit and synthetic-repo tests for the MDK revert-only Bisect Agent."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.bisect_agent.classifier import (
    HOSTED_STEP_COMMANDS,
    classify_failure,
    evaluate_command_result,
    extract_bare_metal_signal,
    extract_bare_metal_signals,
    extract_hosted_signal,
    extract_hosted_signals,
    match_known_flake_issue,
    nextest_command_for_test,
    parse_first_nextest_failure,
    parse_nextest_failures,
    stress_command,
)
from scripts.bisect_agent.controller import (
    BisectController,
    GitHubOps,
    build_sanitized_predicate_env,
    default_worktree_runner,
    is_wrapper_job,
    main as cli_main,
    selftest,
)
from scripts.bisect_agent.models import (
    AgentState,
    Bucket,
    FailureSignal,
    IncidentRecord,
    RunVerdict,
    load_state,
    save_state,
)
from scripts.bisect_agent.notify import ManualFreezeError, MarmotAlerter, Roster, TreeStateController
from scripts.bisect_agent.reverter import attempt_clean_revert, bisect_culprit
from scripts.check_pr_trailers import validate_range


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _init_repo(tmp: Path, *, with_bare_origin: bool = False) -> tuple[Path, Path | None]:
    repo = tmp / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-b", "master")
    _git(repo, "config", "user.name", "Test Bot")
    _git(repo, "config", "user.email", "bot@example.com")
    _git(repo, "config", "commit.gpgsign", "false")
    origin: Path | None = None
    if with_bare_origin:
        origin = tmp / "origin.git"
        subprocess.run(["git", "init", "--bare", str(origin)], check=True, capture_output=True)
        _git(repo, "remote", "add", "origin", str(origin))
    return repo, origin


def _commit_file(repo: Path, rel: str, content: str, msg: str) -> str:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", rel)
    _git(repo, "commit", "-m", msg)
    return _git(repo, "rev-parse", "HEAD")


def _seed_tree_state(tmp: Path, origin: Path, state: str = "green") -> None:
    ts_work = tmp / "ts-init"
    ts_work.mkdir()
    _git(ts_work, "init", "-b", "tree-state")
    _git(ts_work, "config", "user.name", "Test Bot")
    _git(ts_work, "config", "user.email", "bot@example.com")
    _git(ts_work, "config", "commit.gpgsign", "false")
    _git(ts_work, "remote", "add", "origin", str(origin))
    (ts_work / "state.json").write_text(json.dumps({"schema_version": 1, "state": state}) + "\n")
    _git(ts_work, "add", "state.json")
    _git(ts_work, "commit", "-m", f"init tree-state {state}")
    _git(ts_work, "push", "origin", "tree-state")


class StubGitHub:
    def __init__(
        self,
        *,
        open_issues: list[dict] | None = None,
        author: str = "dev-author",
        runs_by_workflow: dict[str, list[dict]] | None = None,
        verification_status_by_run: dict[int, str] | None = None,
        failed_jobs_by_run: dict[int, list[dict] | None] | None = None,
        logs_by_job: dict[int, str] | None = None,
        open_pr_by_branch: dict[str, str] | None = None,
        fail_pr_create: bool = False,
        fail_pr_lookup: bool = False,
        fail_rerun: bool = False,
        fail_issue_create: bool = False,
    ) -> None:
        self._open_issues = list(open_issues or [])
        self._author = author
        self.runs_by_workflow = runs_by_workflow or {}
        self.verification_status_by_run = dict(verification_status_by_run or {})
        self.failed_jobs_by_run = dict(failed_jobs_by_run or {})
        self.logs_by_job = dict(logs_by_job or {})
        self.open_pr_by_branch = dict(open_pr_by_branch or {})
        self.fail_pr_create = fail_pr_create
        self.fail_pr_lookup = fail_pr_lookup
        self.fail_rerun = fail_rerun
        self.fail_issue_create = fail_issue_create
        self.reruns: list[str] = []
        self.recorded_attempts: list[tuple[str, int, int | None]] = []
        self.dispatches: int = 0
        self.issues: list[dict] = []
        self.prs: list[dict] = []

    def open_flake_issues(self):
        return self._open_issues

    def recent_workflow_runs(self, workflow: str, *, limit: int = 10):
        return list(self.runs_by_workflow.get(workflow, []))[:limit]

    def hosted_run_verification_status(self, run_id: int, *, attempt: int | None = None) -> str:
        self.recorded_attempts.append(("verify", run_id, attempt))
        return self.verification_status_by_run.get(run_id, "skipped")

    def jobs_for_run(self, run_id: int, *, attempt: int | None = None):
        return self.failed_jobs_by_run.get(run_id, [])

    def failed_jobs_for_run(self, run_id: int, *, attempt: int | None = None):
        self.recorded_attempts.append(("failed_jobs", run_id, attempt))
        if run_id in self.failed_jobs_by_run:
            return self.failed_jobs_by_run[run_id]
        return []

    def job_log(self, _run_id: int, job_id: int) -> str | None:
        if job_id in self.logs_by_job:
            return self.logs_by_job[job_id]
        return ""

    def job_log_tail(self, _run_id: int, job_id: int, *, lines: int = 120) -> str | None:
        log = self.job_log(_run_id, job_id)
        if log is None:
            return None
        return "\n".join(log.splitlines()[-lines:])

    def commit_author_login(self, _sha: str) -> str:
        return self._author

    def find_open_revert_pr(self, branch: str) -> str | None:
        if self.fail_pr_lookup:
            return None
        return self.open_pr_by_branch.get(branch, "")

    def rerun_failed_jobs(self, run_id: str) -> bool:
        if self.fail_rerun:
            return False
        self.reruns.append(run_id)
        return True

    def dispatch_canary(self) -> None:
        self.dispatches += 1

    def open_or_comment_issue(self, *, title: str, body: str, issue_number: int | None = None) -> int | None:
        if self.fail_issue_create:
            raise TimeoutError("simulated GitHub issue API timeout")
        if issue_number is not None:
            self.issues.append({"title": title, "body": body, "issue_number": issue_number, "comment": True})
            return issue_number
        num = 500 + len(self.issues)
        self.issues.append({"title": title, "body": body, "issue_number": num, "comment": False})
        self._open_issues.append({"number": num, "title": title, "body": body})
        return num

    def open_revert_pr(self, branch: str, title: str, body: str) -> str:
        if self.fail_pr_create:
            return ""
        url = f"https://github.com/marmot-protocol/mdk/pull/{900 + len(self.prs)}"
        self.prs.append({"branch": branch, "title": title, "body": body, "url": url})
        self.open_pr_by_branch[branch] = url
        return url


class ClassifierTests(unittest.TestCase):
    def test_nextest_command_and_wrapper_job_matching(self):
        cmd = nextest_command_for_test("cgka-engine", "crash_recovery_sqlite", "replays::epoch")
        self.assertIn("binary_id(=cgka-engine::crash_recovery_sqlite) & test(=replays::epoch)", cmd)
        self.assertIn("--no-tests=fail", cmd)
        self.assertNotIn("--test", cmd)
        self.assertIn("binary_id(=wn-cli::bin/wn) & test(=cli::smoke)", nextest_command_for_test("wn-cli", "bin/wn", "cli::smoke"))
        self.assertIn("binary_id(=cgka-engine) & test(=epoch::advance)", nextest_command_for_test("cgka-engine", None, "epoch::advance"))
        self.assertIn("--stress-count", stress_command(cmd, 10))
        self.assertEqual(stress_command(("just", "fast-ci"), 10), ("just", "fast-ci"))

        # Wrapper filter matches both top-level and nested reusable workflow names.
        self.assertTrue(is_wrapper_job("Required CI"))
        self.assertTrue(is_wrapper_job("Full cross-platform CI (6 shards) / Required CI"))
        self.assertTrue(is_wrapper_job("Plan Canary batch"))
        self.assertFalse(is_wrapper_job("Full cross-platform CI (6 shards) / Rust tests (1/6)"))

    def test_evaluate_command_result_prioritizes_nextest_fail_over_network_strings(self):
        cmd = nextest_command_for_test("transport-nostr", "relay", "handles_disconnect")
        # Relay/network test failure output often contains `Connection reset by peer` or `HTTP 502`.
        # Because a real nextest FAIL line is present, it MUST be FAIL, not INCONCLUSIVE/infra!
        verdict, _ = evaluate_command_result(
            100,
            "Connection reset by peer\nHTTP 502 Bad Gateway\nFAIL [ 0.42s] transport-nostr::relay handles_disconnect\n",
            cmd,
        )
        self.assertEqual(verdict, RunVerdict.FAIL)
        self.assertEqual(
            evaluate_command_result(0, "PASS [ 0.12s] transport-nostr::relay handles_disconnect\n", cmd)[0],
            RunVerdict.PASS,
        )
        self.assertEqual(
            evaluate_command_result(4, "error: no tests to run\n", cmd)[0],
            RunVerdict.TEST_ABSENT,
        )
        verdict_err, detail = evaluate_command_result(101, "error[E0425]: cannot find value `secret_token`\n", cmd)
        self.assertEqual(verdict_err, RunVerdict.INCONCLUSIVE)
        self.assertNotIn("secret_token", detail)

    def test_hosted_step_mapping_and_gh_log_prefix_parsing(self):
        # Captured `gh run view --job <id> --log` format with ANSI, RFC3339, `TRY 2`, and `( 988/1564)` progress.
        gh_log = (
            "Full cross-platform CI (6 shards) / Rust tests (4/6)\tRun archived workspace tests\t"
            "\ufeff2026-11-26T16:20:08.3090695Z \x1b[31m  TRY 2 FAIL\x1b[0m [   1.432s] ( 988/1564) "
            "marmot-session::runtime an_overdue_component_recheck_is_owed_not_due_now\n"
        )
        hosted = extract_hosted_signal(
            source="hosted_canary",
            run_id="45851410192:1",
            run_url="https://github.com/marmot-protocol/mdk/actions/runs/45851410192",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / Rust tests (4/6)",
            log_text=gh_log,
        )
        self.assertTrue(hosted.reproducible_locally)
        self.assertEqual(
            hosted.failed_test,
            "marmot-session::runtime::an_overdue_component_recheck_is_owed_not_due_now",
        )

        # Mixed retry outcomes: a test that fails TRY 1 and passes TRY 2 must NOT shadow a terminal failure.
        mixed_log = (
            "  TRY 1 FAIL [ 0.500s] ( 1/10) cgka-engine::a flaky_then_passed\n"
            "  TRY 2 PASS [ 0.400s] ( 1/10) cgka-engine::a flaky_then_passed\n"
            "  TRY 1 FAIL [ 0.300s] ( 2/10) cgka-engine::b real_regression\n"
            "  TRY 2 FAIL [ 0.310s] ( 2/10) cgka-engine::b real_regression\n"
        )
        self.assertEqual(parse_first_nextest_failure(mixed_log), ("cgka-engine", "b", "real_regression"))

        # Contract: every step name in HOSTED_STEP_COMMANDS must exist in `.github/workflows/ci.yml`.
        ci_text = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        for step_name in HOSTED_STEP_COMMANDS:
            self.assertIn(f"- name: {step_name}", ci_text)

        # Multi-step `Rust format` job resolves by failed step, NEVER silently falling back to `just fmt-check`.
        naming_sig = extract_hosted_signal(
            source="hosted_canary",
            run_id="45851410192:1",
            run_url="https://example.com/1",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / Rust format",
            failed_step="Naming gate (retired legacy tokens)",
            log_text="legacy token found\n",
        )
        self.assertEqual(naming_sig.command, ("just", "naming-gate"))

        unknown_step_sig = extract_hosted_signal(
            source="hosted_canary",
            run_id="45851410192:1",
            run_url="https://example.com/1",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / Rust format",
            failed_step="Some future unmapped gate",
            log_text="gate failed\n",
        )
        self.assertFalse(unknown_step_sig.reproducible_locally)
        self.assertEqual(unknown_step_sig.command, ())
        cls_unknown = classify_failure(unknown_step_sig, run_on_sha=lambda _s, _c: (RunVerdict.PASS, ""))
        self.assertEqual(cls_unknown.bucket, Bucket.UNREPRODUCIBLE)
        self.assertIn("Some future unmapped gate", cls_unknown.reason)

        # Bare-metal signal never exposes local `/srv/mdk/...` paths in public `run_url`.
        bm = extract_bare_metal_signal(
            {
                "state": "red",
                "sha": "a" * 40,
                "canary_sha": "b" * 40,
                "failed_step": "workspace-nextest",
                "updated_at": "2026-11-26T12:00:00Z",
                "log": "/srv/mdk/state/logs/canary-secret-host.log",
            },
            "FAIL [ 0.42s] cgka-engine::crash_recovery_sqlite replays_pending_commit\n",
        )
        self.assertEqual(bm.run_url, "")

    def test_classification_buckets_missing_baseline_and_stress_rules(self):
        sig = FailureSignal(
            source="bare_metal_canary",
            run_id="r1",
            run_url="",
            tip_sha="1" * 40,
            baseline_sha="0" * 40,
            failed_job="mdk-canary:workspace-nextest",
            failed_test="cgka-engine::foo::bar",
            command=nextest_command_for_test("cgka-engine", "foo", "bar"),
        )

        # Missing baseline stays UNREPRODUCIBLE (never immediately freezes master on 1 red run).
        no_base = classify_failure(
            FailureSignal(**{**sig.__dict__, "baseline_sha": ""}),
            run_on_sha=lambda _s, _c: (RunVerdict.FAIL, "fail"),
        )
        self.assertEqual(no_base.bucket, Bucket.UNREPRODUCIBLE)

        # Deterministic failure on BOTH tip and baseline -> INFRA_ERROR ops alert (not KNOWN_FLAKE).
        baseline_break = classify_failure(
            FailureSignal(**{**sig.__dict__, "failed_job": "mdk-canary:cargo-audit", "failed_test": None, "command": ("cargo", "--locked", "audit")}),
            run_on_sha=lambda _s, _c: (RunVerdict.FAIL, "advisory"),
        )
        self.assertEqual(baseline_break.bucket, Bucket.INFRA_ERROR)
        self.assertIn("baseline break:", baseline_break.reason)

        # Non-nextest command passing single retry skips stress loop (1 call only).
        calls: list[str] = []
        non_nextest = classify_failure(
            FailureSignal(**{**sig.__dict__, "failed_job": "mdk-canary:fast-ci", "failed_test": None, "command": ("just", "fast-ci")}),
            run_on_sha=lambda sha, _c: (calls.append(sha) or RunVerdict.PASS, "ok"),
            stress_count=10,
        )
        self.assertEqual(non_nextest.bucket, Bucket.NEW_INTERMITTENT)
        self.assertEqual(len(calls), 1)

        # Intermittent stress hit on tip only stays NEW_INTERMITTENT without fabricated counts.
        inter_stress = classify_failure(
            sig,
            run_on_sha=lambda sha, cmd: (
                RunVerdict.FAIL if "--stress-count" in cmd and sha == sig.tip_sha else RunVerdict.PASS,
                "target test failed",
            ),
            stress_count=5,
        )
        self.assertEqual(inter_stress.bucket, Bucket.NEW_INTERMITTENT)
        self.assertIn("never auto-reverted", inter_stress.reason)
        self.assertNotIn("1/5", inter_stress.reason)

    def test_sanitized_predicate_env_and_live_mode_requires_isolation_prefix(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            cleaned = build_sanitized_predicate_env(
                sandbox_home=tmp / "sandbox",
                cargo_target_dir=tmp / "target",
                source_env={"PATH": "/usr/bin", "GH_TOKEN": "secret", "SSH_AUTH_SOCK": "/tmp/sock", "HOME": "/home/mdk-bot"},
            )
            for forbidden in ("GH_TOKEN", "GITHUB_TOKEN", "SSH_AUTH_SOCK"):
                self.assertNotIn(forbidden, cleaned)
            self.assertEqual(cleaned["HOME"], str(tmp / "sandbox"))

            old_tok = os.environ.get("GH_TOKEN")
            os.environ["GH_TOKEN"] = "do-not-expose"
            try:
                verdict, _ = default_worktree_runner(
                    ("python3", "-c", "import os, sys; sys.exit(0 if 'GH_TOKEN' not in os.environ else 1)")
                )(tmp)
                self.assertEqual(verdict, RunVerdict.PASS)
            finally:
                if old_tok is None:
                    os.environ.pop("GH_TOKEN", None)
                else:
                    os.environ["GH_TOKEN"] = old_tok

            # `--live` without `--predicate-runner-prefix` must refuse to run (exit 2).
            rc = cli_main(["poll", "--live", "--repo-dir", str(tmp), "--no-fetch"])
            self.assertEqual(rc, 2)

    def test_predicate_nextest_store_lands_in_the_sandbox_target_dir(self):
        # nextest keeps its store at `<workspace>/target/nextest` whatever `CARGO_TARGET_DIR`
        # says. The `mdk-runner` sandbox cannot write the bot-owned worktree, so every live
        # replay exited 96 before running its test. The store must land in the target dir
        # the sandbox owns.
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            wt = tmp / "wt"
            wt.mkdir()
            target = tmp / "target-bisect"
            write_store = (
                "python3",
                "-c",
                "import pathlib; p = pathlib.Path('target/nextest/ci'); "
                "p.mkdir(parents=True, exist_ok=True); (p / 'probe').write_text('ok')",
            )
            verdict, _ = default_worktree_runner(write_store, cargo_target_dir=target)(wt)
            self.assertEqual(verdict, RunVerdict.PASS)
            self.assertEqual((target / "nextest" / "ci" / "probe").read_text(), "ok")

    def test_selftest_flags_an_empty_hosted_job_log(self):
        # Every live hosted job log came back empty and nothing noticed. `selftest` is the
        # deploy check that must, while a non-empty log raises no log problem.
        job = {"id": 70, "name": "Full cross-platform CI (6 shards) / Rust tests (5/6)", "conclusion": "failure"}
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            for log, flagged in (("", True), ("  FAIL [ 0.1s] marmot-app a::b\n", False)):
                with self.subTest(log=log):
                    gh = StubGitHub(
                        runs_by_workflow={"canary.yml": [{"id": 7}]},
                        failed_jobs_by_run={7: [job]},
                        logs_by_job={70: log},
                    )
                    problems = selftest(
                        gh,
                        repo_dir=tmp,
                        worktree_root=tmp / "wt",
                        cargo_target_dir=tmp / "target",
                        runner_prefix=("env",),
                        timeout_secs=30,
                    )
                    self.assertEqual("hosted job log came back empty (run 7, job 70)" in problems, flagged)

    def test_job_log_reads_called_workflow_jobs_through_the_jobs_logs_api(self):
        # `gh run view --job <id> --log` prints nothing and exits 0 for jobs of the reusable
        # `ci.yml` call ("Full cross-platform CI (6 shards) / ..."), which turned every hosted
        # Canary failure into an unparsed, unreproducible freeze.
        gh_ops = GitHubOps("marmot-protocol/mdk", dry_run=True)
        log = "  TRY 2 FAIL [   4.443s] ( 382/1567) marmot-app client::push::tests::push_batch_delivery\n"
        with mock.patch.object(
            gh_ops, "_run_gh_safe", return_value=subprocess.CompletedProcess([], 0, stdout=log, stderr="")
        ) as mocked_gh:
            self.assertEqual(gh_ops.job_log(45980601156, 140455972327), log)
            mocked_gh.assert_called_once_with("api", "repos/marmot-protocol/mdk/actions/jobs/140455972327/logs")


class SyntheticRepoBisectAndMeltdownTests(unittest.TestCase):
    def test_bisect_budget_enforcement_and_detached_dry_run_branch_safety(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, _ = _init_repo(tmp, with_bare_origin=True)
            c0 = _commit_file(repo, "app.txt", "good\n", "c0")
            c1 = _commit_file(repo, "app.txt", "bad\n", "c1")
            c2 = _commit_file(repo, "other.txt", "ok\n", "c2")
            _git(repo, "push", "origin", "master")

            # Exceeded wall-clock budget aborts bisect cleanly instead of looping until SIGTERM.
            culprit, reason = bisect_culprit(
                repo,
                c0,
                c2,
                lambda _wt: (RunVerdict.FAIL, "fail"),
                worktree_root=tmp / "wts",
                deadline=100.0,
                now_fn=lambda: 101.0,
            )
            self.assertIsNone(culprit)
            self.assertIn("bisect wall-clock budget exceeded", reason)

            # Dry-run revert never creates, resets, or deletes an existing local `revert/<sha>` branch.
            branch_name = f"revert/{c1[:9]}"
            _git(repo, "branch", branch_name, c0)
            outcome = attempt_clean_revert(
                repo,
                c1,
                "origin/master",
                lambda wt: (
                    RunVerdict.PASS if (wt / "app.txt").read_text(encoding="utf-8").strip() == "good" else RunVerdict.FAIL,
                    "",
                ),
                checks_summary="just fast-ci",
                sign_commits=False,
                dry_run=True,
                worktree_root=tmp / "wts",
            )
            self.assertTrue(outcome.clean_revert and outcome.revert_verified)
            self.assertEqual(_git(repo, "rev-parse", branch_name), c0)

    def test_bisect_clean_revert_trailers_retry_cap_and_quiet_period_skipped_baseline(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, _ = _init_repo(tmp, with_bare_origin=True)
            c0 = _commit_file(repo, "app.txt", "good\n", "c0: healthy baseline")
            c1 = _commit_file(repo, "app.txt", "broken\n", "c1: break invariant")
            _git(repo, "push", "origin", "master")

            # Hosted Canary had 10 skipped-green quiet-hour runs on c0, then failed on c1.
            # Baseline resolver must still pick c0 (not empty!) and isolate c1 cleanly.
            gh = StubGitHub(
                author="alice",
                runs_by_workflow={
                    "canary.yml": [
                        {
                            "id": 200,
                            "run_attempt": 1,
                            "conclusion": "failure",
                            "head_sha": c1,
                            "html_url": "https://github.com/marmot-protocol/mdk/actions/runs/200",
                            "updated_at": "2026-11-26T16:00:00Z",
                        },
                        {
                            "id": 199,
                            "run_attempt": 1,
                            "conclusion": "success",
                            "head_sha": c0,
                            "html_url": "https://github.com/marmot-protocol/mdk/actions/runs/199",
                            "updated_at": "2026-11-26T15:00:00Z",
                        },
                    ]
                },
                verification_status_by_run={199: "skipped"},
                failed_jobs_by_run={
                    200: [
                        {
                            "id": 9001,
                            "name": "Full cross-platform CI (6 shards) / Rust format",
                            "conclusion": "failure",
                            "steps": [{"name": "Check formatting", "conclusion": "failure"}],
                        }
                    ]
                },
            )
            state = AgentState()
            ctrl = BisectController(
                repo=repo,
                state=state,
                github=gh,
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
                worktree_root=tmp / "wts",
                run_in_wt=lambda wt, _cmd: (
                    RunVerdict.PASS if (wt / "app.txt").read_text(encoding="utf-8").strip() == "good" else RunVerdict.FAIL,
                    "",
                ),
            )
            summary = ctrl.poll_once(hosted_workflows=("canary.yml",), master_ref="origin/master", fetch_remote=False)
            self.assertEqual(summary["actions"][0]["bucket"], Bucket.DETERMINISTIC_REGRESSION.value)
            self.assertEqual(summary["actions"][0]["culprit"], c1)
            self.assertEqual(len(gh.prs), 1)

            _git(repo, "fetch", "origin", f"revert/{c1[:9]}")
            impact, errors = validate_range(repo, c1, _git(repo, "rev-parse", "FETCH_HEAD"))
            self.assertEqual(errors, [])
            self.assertEqual(impact, "none")

            # Retry cap: multiple infra attempts on the SAME base run_id trigger at most 1 rerun.
            gh_infra = StubGitHub()
            state_infra = AgentState()
            ctrl_infra = BisectController(
                repo=repo,
                state=state_infra,
                github=gh_infra,
                alerter=MarmotAlerter(Roster(engineering_group_id="eng"), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
            )
            for attempt in (1, 2, 3):
                ctrl_infra.handle_failure(
                    FailureSignal(
                        source="hosted_canary",
                        run_id=f"555:{attempt}",
                        run_url="https://example.com/555",
                        tip_sha=c1,
                        baseline_sha=c0,
                        failed_job="Rust audit",
                        log_excerpt="No space left on device",
                    )
                )
            self.assertEqual(gh_infra.reruns, ["555:1"])

    def test_persist_before_notification_and_jobs_api_error_retry_recovery(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, origin = _init_repo(tmp, with_bare_origin=True)
            assert origin is not None
            c0 = _commit_file(repo, "app.txt", "good\n", "c0")
            c1 = _commit_file(repo, "app.txt", "bad\n", "c1")
            c2 = _commit_file(repo, "app.txt", "fixed\n", "c2")
            _git(repo, "push", "origin", "master")
            _seed_tree_state(tmp, origin, state="green")

            state_file = tmp / "state.json"
            tree_ctrl = TreeStateController(repo, dry_run=False, sign_commits=False)
            # Simulate crash/timeout during GitHub issue creation AFTER tree-state=red succeeded.
            gh_crash = StubGitHub(fail_issue_create=True)
            state1 = AgentState()
            ctrl1 = BisectController(
                repo=repo,
                state=state1,
                github=gh_crash,
                alerter=MarmotAlerter(Roster(engineering_group_id="eng"), dry_run=True),
                tree_state=tree_ctrl,
                dry_run=False,
                sign_commits=False,
                worktree_root=tmp / "wts",
                on_state_change=lambda s: save_state(state_file, s),
                run_in_wt=lambda wt, _cmd: (
                    RunVerdict.PASS if (wt / "app.txt").read_text(encoding="utf-8").strip() == "good" else RunVerdict.FAIL,
                    "",
                ),
            )
            # c2 conflicts with reverting c1 -> triggers Meltdown; issue API raises TimeoutError.
            with self.assertRaises(TimeoutError):
                ctrl1.handle_failure(
                    FailureSignal(
                        source="hosted_canary",
                        run_id="800:1",
                        run_url="https://example.com/800",
                        tip_sha=c1,
                        baseline_sha=c0,
                        failed_job="Rust audit",
                        command=("cargo", "--locked", "audit"),
                    ),
                    master_ref="origin/master",
                )
            # Even though notification/issue raised, remote is RED AND local persisted state ALREADY saved the incident!
            self.assertEqual(tree_ctrl.read_remote_status(), "red")
            reloaded = load_state(state_file)
            self.assertEqual(reloaded.tree_state, "red")
            self.assertIn("hosted_canary", reloaded.active_incidents)

            # Now test transient jobs API error on green run 801: must stay UNSEEN and recover on next poll!
            gh_recover = StubGitHub(
                runs_by_workflow={
                    "canary.yml": [
                        {
                            "id": 801,
                            "run_attempt": 1,
                            "conclusion": "success",
                            "head_sha": c2,
                            "html_url": "https://example.com/801",
                            "updated_at": "2026-11-26T17:00:00Z",
                        }
                    ]
                },
                verification_status_by_run={801: "error"},
            )
            ctrl2 = BisectController(
                repo=repo,
                state=reloaded,
                github=gh_recover,
                alerter=MarmotAlerter(Roster(engineering_group_id="eng"), dry_run=True),
                tree_state=tree_ctrl,
                dry_run=False,
                sign_commits=False,
                worktree_root=tmp / "wts",
                on_state_change=lambda s: save_state(state_file, s),
            )
            res_err = ctrl2.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            self.assertEqual(res_err["actions"][0]["result"], "jobs_api_error")
            self.assertNotIn("green:hosted_canary:801:1", reloaded.seen_runs)
            self.assertEqual(tree_ctrl.read_remote_status(), "red")

            # Next poll: jobs API recovers AND a newer skipped hourly run on the same SHA arrived on top ->
            # controller still discovers verified run 801 on c2 and clears tree-state to GREEN!
            gh_recover.verification_status_by_run[801] = "verified"
            gh_recover.verification_status_by_run[802] = "skipped"
            gh_recover.runs_by_workflow["canary.yml"].insert(
                0,
                {
                    "id": 802,
                    "run_attempt": 1,
                    "conclusion": "success",
                    "head_sha": c2,
                    "html_url": "https://example.com/802",
                    "updated_at": "2026-11-26T18:00:00Z",
                },
            )
            res_ok = ctrl2.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            self.assertTrue(res_ok["actions"][0]["cleared_meltdown"])
            self.assertEqual(tree_ctrl.read_remote_status(), "green")

            # Stale failed rerun on older c0 after newer c2 already passed green is ignored cleanly.
            gh_recover.runs_by_workflow["canary.yml"].insert(
                0,
                {
                    "id": 790,
                    "run_attempt": 2,
                    "conclusion": "failure",
                    "head_sha": c0,
                    "html_url": "https://example.com/790",
                    "updated_at": "2026-11-26T18:05:00Z",
                },
            )
            res_stale = ctrl2.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            self.assertEqual(res_stale["actions"][0]["result"], "stale_failure_ignored")
            self.assertEqual(tree_ctrl.read_remote_status(), "green")

            # Red-side jobs API failure (`failed_jobs_for_run -> None`) stays retryable without counting toward freeze.
            c3 = _commit_file(repo, "more.txt", "x\n", "c3")
            gh_recover.runs_by_workflow["canary.yml"].insert(
                0,
                {
                    "id": 805,
                    "run_attempt": 1,
                    "conclusion": "failure",
                    "head_sha": c3,
                    "html_url": "https://example.com/805",
                    "updated_at": "2026-11-26T18:10:00Z",
                },
            )
            gh_recover.failed_jobs_by_run[805] = None
            res_red_err = ctrl2.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            self.assertEqual(res_red_err["actions"][0]["result"], "jobs_api_error")
            self.assertNotIn("fail:hosted_canary:805:1", reloaded.seen_runs)
            self.assertEqual(reloaded.consecutive_unreproducible_reds.get("hosted_canary", 0), 0)

    def test_unreproducible_counter_isolated_from_infra_and_overlapping_incidents(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, origin = _init_repo(tmp, with_bare_origin=True)
            assert origin is not None
            c0 = _commit_file(repo, "app.txt", "good\n", "c0")
            c1 = _commit_file(repo, "app.txt", "bad\n", "c1")
            c2 = _commit_file(repo, "app.txt", "fixed\n", "c2")
            _git(repo, "push", "origin", "master")
            _seed_tree_state(tmp, origin, state="green")

            tree_ctrl = TreeStateController(repo, dry_run=False, sign_commits=False)
            gh = StubGitHub()
            state = AgentState()
            ctrl = BisectController(
                repo=repo,
                state=state,
                github=gh,
                alerter=MarmotAlerter(Roster(engineering_group_id="eng"), dry_run=True),
                tree_state=tree_ctrl,
                dry_run=False,
                sign_commits=False,
                worktree_root=tmp / "wts",
                run_in_wt=lambda _wt, _cmd: (RunVerdict.FAIL, "fail"),
            )

            # 1 infra failure followed by 1 macOS failure must NOT freeze (counter is isolated!).
            ctrl.handle_failure(
                FailureSignal(
                    source="hosted_canary",
                    run_id="100:1",
                    run_url="https://example.com/100",
                    tip_sha=c1,
                    baseline_sha=c0,
                    failed_job="Rust audit",
                    log_excerpt="No space left on device",
                )
            )
            _, out1 = ctrl.handle_failure(
                FailureSignal(
                    source="hosted_canary",
                    run_id="101:1",
                    run_url="https://example.com/101",
                    tip_sha=c1,
                    baseline_sha=c0,
                    failed_job="iOS keychain and Swift cancellation",
                    reproducible_locally=False,
                )
            )
            assert out1 is not None
            self.assertFalse(out1.meltdown_triggered)
            self.assertEqual(tree_ctrl.read_remote_status(), "green")

            # Second consecutive unreproducible macOS failure freezes hosted_canary.
            _, out2 = ctrl.handle_failure(
                FailureSignal(
                    source="hosted_canary",
                    run_id="101:2",
                    run_url="https://example.com/101",
                    tip_sha=c1,
                    baseline_sha=c0,
                    failed_job="iOS keychain and Swift cancellation",
                    reproducible_locally=False,
                )
            )
            assert out2 is not None
            self.assertTrue(out2.meltdown_triggered)
            self.assertEqual(tree_ctrl.read_remote_status(), "red")

            # Older-SHA green c0 does NOT clear hosted incident on c1.
            self.assertFalse(ctrl.handle_green_canary(source="hosted_canary", sha=c0, run_id="102:1", run_url=""))
            self.assertEqual(tree_ctrl.read_remote_status(), "red")

            # Open a second active incident (`bare_metal_canary`) while `hosted_canary` is frozen:
            # recovering `hosted_canary` alone must leave remote `tree-state=red`, and recovering
            # `bare_metal_canary` afterwards must clear remote `tree-state=green`.
            ctrl._trigger_meltdown(
                reason="bare-metal failure",
                signal=FailureSignal(
                    source="bare_metal_canary",
                    run_id="bare-metal:c1:1",
                    run_url="",
                    tip_sha=c1,
                    baseline_sha=c0,
                    failed_job="mdk-canary:fast-ci",
                ),
                culprit_sha=None,
                notified=[],
                seen_key="fail:bare_metal_canary:bare-metal:c1:1",
            )
            self.assertFalse(ctrl.handle_green_canary(source="hosted_canary", sha=c2, run_id="103:1", run_url=""))
            self.assertEqual(tree_ctrl.read_remote_status(), "red")
            self.assertIn("bare_metal_canary", state.active_incidents)
            self.assertNotIn("hosted_canary", state.active_incidents)

            self.assertTrue(ctrl.handle_green_canary(source="bare_metal_canary", sha=c2, run_id="bm-green:1", run_url=""))
            self.assertEqual(tree_ctrl.read_remote_status(), "green")

    def test_exact_step_replay_nextest_statuses_flake_identity_and_stress_reasons(self):
        # 1. C bindings smoke & Tamarin proofs map ONLY exact reproducible steps;
        # Header diff gate, Tamarin/pairing proofs, and Relay CLI E2E stay UNREPRODUCIBLE.
        c_alloc = extract_hosted_signal(
            source="hosted_canary",
            run_id="1:1",
            run_url="https://example.com/1",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / C bindings smoke",
            failed_step="Alloc-audit tests",
            log_text="assertion failed\n",
        )
        self.assertEqual(c_alloc.command, ("cargo", "test", "-p", "marmot-c", "--features", "alloc-audit", "--locked"))

        c_header = extract_hosted_signal(
            source="hosted_canary",
            run_id="1:1",
            run_url="https://example.com/1",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / C bindings smoke",
            failed_step="Header diff gate",
            log_text="diff --git a/crates/marmot-c/include/marmot.h\n",
        )
        self.assertFalse(c_header.reproducible_locally)
        self.assertEqual(c_header.command, ())

        pairing_proof = extract_hosted_signal(
            source="hosted_canary",
            run_id="1:1",
            run_url="https://example.com/1",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / Tamarin proofs",
            failed_step="Verify pairing authentication and model controls",
            log_text="lemma falsified\n",
        )
        self.assertFalse(pairing_proof.reproducible_locally)

        pairing_unit = extract_hosted_signal(
            source="hosted_canary",
            run_id="1:1",
            run_url="https://example.com/1",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / Tamarin proofs",
            failed_step="Check pairing verifier timeout handling",
            log_text="FAIL: test_timeout\n",
        )
        self.assertEqual(
            pairing_unit.command,
            ("python3", "-B", "-m", "unittest", "discover", "-s", "formal/pairing", "-p", "test_*.py"),
        )

        # Relay CLI E2E requires Docker relays + MDK_E2E_REQUIRE_RELAYS=1 -> NEVER replay as bare nextest!
        relay_e2e = extract_hosted_signal(
            source="hosted_canary",
            run_id="1:1",
            run_url="https://example.com/1",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / Relay CLI E2E",
            failed_step="Run real relay CLI E2E",
            log_text="  FAIL [ 5.100s] wn-cli::cli real_local_relays_deliver_cli_messages_over_sdk_path\n",
        )
        self.assertFalse(relay_e2e.reproducible_locally)
        self.assertEqual(relay_e2e.command, ())
        self.assertEqual(relay_e2e.failed_test, "wn-cli::cli::real_local_relays_deliver_cli_messages_over_sdk_path")

        # Device linking at production timing runs WITHOUT test-policy-overrides!
        dev_link = extract_hosted_signal(
            source="hosted_canary",
            run_id="1:1",
            run_url="https://example.com/1",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / Build CLI tests",
            failed_step="Device linking at production timing",
            log_text="  FAIL [ 2.000s] wn-cli::cli devices_link_across_daemon_commands_at_production_timing\n",
        )
        self.assertTrue(dev_link.reproducible_locally)
        self.assertNotIn("test-policy-overrides", " ".join(dev_link.command))

        # 2. Nextest terminal statuses (TIMEOUT / ABORT / LEAK-FAIL) and strict exit-4 TEST_ABSENT.
        cmd = nextest_command_for_test("marmot-app", "relay_runtime", "hangs_forever")
        timeout_log = "  TRY 2 TIMEOUT [ 120.004s] ( 12/100) marmot-app::relay_runtime hangs_forever\n"
        self.assertEqual(parse_first_nextest_failure(timeout_log), ("marmot-app", "relay_runtime", "hangs_forever"))
        self.assertEqual(evaluate_command_result(100, timeout_log, cmd)[0], RunVerdict.FAIL)
        # Exit 100 with FAIL + "error: no tests to run" in stdout MUST remain FAIL, NEVER TEST_ABSENT!
        tricky_fail = "error: no tests to run\n  FAIL [ 0.25s] marmot-app::relay_runtime hangs_forever\n"
        self.assertEqual(evaluate_command_result(100, tricky_fail, cmd)[0], RunVerdict.FAIL)
        self.assertEqual(evaluate_command_result(4, "error: no tests to run\n", cmd)[0], RunVerdict.TEST_ABSENT)

        # 3. Full log parsed before tail truncation; tail network noise does not override parsed test failure.
        long_log = (
            "  FAIL [ 0.500s] ( 1/50) cgka-engine::state real_failure\n"
            + "".join(f"diag line {i}\n" for i in range(200))
            + "Connection reset by peer\n"
        )
        long_sig = extract_hosted_signal(
            source="hosted_canary",
            run_id="2:1",
            run_url="https://example.com/2",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / Rust tests (4/6)",
            failed_step="Run workspace tests",
            log_text=long_log,
        )
        self.assertEqual(long_sig.failed_test, "cgka-engine::state::real_failure")
        self.assertFalse(long_sig.infra_hint)
        self.assertTrue(long_sig.reproducible_locally)

        # 4. Known-flake matching rejects substrings (`connect` vs `reconnect` or `other::connect`).
        self.assertIsNone(
            match_known_flake_issue("core::jobs::connect", [{"number": 10, "title": "Flaky: reconnect", "body": ""}])
        )
        self.assertIsNone(
            match_known_flake_issue("core::jobs::connect", [{"number": 11, "title": "Flaky: other::connect", "body": ""}])
        )
        self.assertEqual(
            match_known_flake_issue(
                "core::jobs::connect",
                [{"number": 12, "title": "Flaky test leaderboard", "body": "| `core::jobs::connect` | 3 |"}],
            ),
            12,
        )
        self.assertEqual(
            match_known_flake_issue("core::jobs::connect", [{"number": 13, "title": "Flaky: connect", "body": ""}]),
            13,
        )
        # Ambiguous legacy short-name matches do not auto-classify as known flake.
        self.assertIsNone(
            match_known_flake_issue(
                "core::jobs::connect",
                [
                    {"number": 13, "title": "Flaky: connect", "body": ""},
                    {"number": 14, "title": "Flaky: `connect`", "body": ""},
                ],
            )
        )

        # 5. Stress classification reports exact observed outcomes (skipped baseline, baseline-only failure, TEST_ABSENT).
        base_sig = FailureSignal(
            source="hosted_canary",
            run_id="3:1",
            run_url="https://example.com/3",
            tip_sha="1" * 40,
            baseline_sha="",
            failed_job="Rust tests (1/6)",
            failed_test="cgka-engine::a::t",
            command=nextest_command_for_test("cgka-engine", "a", "t"),
        )
        no_base_stress = classify_failure(
            base_sig,
            run_on_sha=lambda _s, c: (RunVerdict.FAIL if "--stress-count" in c else RunVerdict.PASS, ""),
            stress_count=5,
        )
        self.assertIn("baseline stress skipped", no_base_stress.reason)
        self.assertNotIn("passed baseline", no_base_stress.reason)

        base_only_fail = classify_failure(
            FailureSignal(**{**base_sig.__dict__, "baseline_sha": "0" * 40}),
            run_on_sha=lambda s, c: (
                RunVerdict.FAIL if "--stress-count" in c and s == "0" * 40 else RunVerdict.PASS,
                "",
            ),
            stress_count=5,
        )
        self.assertIn("on baseline 000000000", base_only_fail.reason)
        self.assertNotIn("on both tip", base_only_fail.reason)

        # 6. Tracked systemd unit enforces `--predicate-runner-prefix` even in dry-run mode.
        unit_text = (REPO_ROOT / "scripts/bisect_agent/deploy/mdk-bisect-agent.service").read_text(encoding="utf-8")
        self.assertIn("--predicate-runner-prefix", unit_text)

    def test_multi_failed_jobs_attempt_binding_rerun_rejection_and_flake_streaks(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, _ = _init_repo(tmp, with_bare_origin=True)
            c0 = _commit_file(repo, "app.txt", "good\n", "c0")
            c1 = _commit_file(repo, "app.txt", "bad\n", "c1")
            _git(repo, "push", "origin", "master")

            # Run 300 has TWO failed shards: shard 4 is a known flake, shard 6 is a deterministic regression.
            # Both MUST be processed so shard 4's known flake never hides shard 6's regression!
            gh = StubGitHub(
                open_issues=[{"number": 77, "title": "Flaky: cgka-engine::net::known_flake", "body": ""}],
                author="dev",
                runs_by_workflow={
                    "canary.yml": [
                        {
                            "id": 300,
                            "run_attempt": 2,
                            "conclusion": "failure",
                            "head_sha": c1,
                            "html_url": "https://example.com/300",
                            "updated_at": "2026-11-26T16:00:00Z",
                        },
                        {
                            "id": 299,
                            "run_attempt": 1,
                            "conclusion": "success",
                            "head_sha": c0,
                            "html_url": "https://example.com/299",
                            "updated_at": "2026-11-26T15:00:00Z",
                        },
                    ]
                },
                failed_jobs_by_run={
                    300: [
                        {"id": 1001, "name": "Full cross-platform CI (6 shards) / Rust tests (4/6)", "conclusion": "failure", "steps": [{"name": "Run workspace tests", "conclusion": "failure"}]},
                        {"id": 1002, "name": "Full cross-platform CI (6 shards) / Rust tests (6/6)", "conclusion": "failure", "steps": [{"name": "Run workspace tests", "conclusion": "failure"}]},
                    ]
                },
                logs_by_job={
                    1001: "  FAIL [ 0.40s] cgka-engine::net known_flake\n",
                    1002: "  FAIL [ 0.40s] cgka-engine::core deterministic_bug\n",
                },
                fail_pr_lookup=True,  # Shard 6 defers on first poll due to lookup failure!
            )
            state = AgentState()
            ctrl = BisectController(
                repo=repo,
                state=state,
                github=gh,
                alerter=MarmotAlerter(Roster(engineering_group_id="eng"), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
                worktree_root=tmp / "wts",
                run_in_wt=lambda wt, _cmd: (
                    RunVerdict.PASS if (wt / "app.txt").read_text(encoding="utf-8").strip() == "good" else RunVerdict.FAIL,
                    "",
                ),
            )
            res1 = ctrl.poll_once(hosted_workflows=("canary.yml",), master_ref="origin/master", fetch_remote=False)
            self.assertEqual([a["bucket"] for a in res1["actions"]], ["known_flake", "deterministic_regression"])
            # Attempt number 2 was passed to failed_jobs_for_run!
            self.assertIn(("failed_jobs", 300, 2), gh.recorded_attempts)
            # Because shard 6 deferred on PR lookup error, the run attempt stays PENDING (unseen),
            # while shard 4 IS already marked seen so it won't re-run on the next poll!
            self.assertIn("fail:hosted_canary:300:2:job:1001", state.seen_runs)
            self.assertNotIn("fail:hosted_canary:300:2:job:1002", state.seen_runs)
            self.assertNotIn("fail:hosted_canary:300:2", state.seen_runs)
            self.assertEqual(len(gh.prs), 0)

            # Next poll: PR lookup succeeds -> only shard 6 runs, opens revert PR, and marks run 300:2 seen!
            gh.fail_pr_lookup = False
            res2 = ctrl.poll_once(hosted_workflows=("canary.yml",), master_ref="origin/master", fetch_remote=False)
            self.assertEqual(len(res2["actions"]), 1)
            self.assertEqual(res2["actions"][0]["culprit"], c1)
            self.assertEqual(len(gh.prs), 1)
            self.assertIn("fail:hosted_canary:300:2", state.seen_runs)

            # Flake streaks are keyed per source and reset on that source's green recovery.
            self.assertEqual(state.consecutive_flake_blocks.get("hosted_canary:cgka-engine::net::known_flake"), 1)
            state.consecutive_flake_blocks["bare_metal_canary:cgka-engine::net::known_flake"] = 1
            ctrl.handle_green_canary(source="hosted_canary", sha=c1, run_id="301:1", run_url="")
            self.assertNotIn("hosted_canary:cgka-engine::net::known_flake", state.consecutive_flake_blocks)
            self.assertEqual(state.consecutive_flake_blocks.get("bare_metal_canary:cgka-engine::net::known_flake"), 1)

            # Rejected `gh run rerun` leaves `retried_runs` and `seen_runs` unrecorded so next poll retries!
            gh_rej = StubGitHub(fail_rerun=True)
            state_rej = AgentState()
            ctrl_rej = BisectController(
                repo=repo,
                state=state_rej,
                github=gh_rej,
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
            )
            sig_infra = FailureSignal(
                source="hosted_canary",
                run_id="600:1",
                run_url="https://example.com/600",
                tip_sha=c1,
                baseline_sha=c0,
                failed_job="Rust audit",
                log_excerpt="No space left on device",
            )
            ctrl_rej.handle_failure(sig_infra)
            self.assertEqual(state_rej.retried_runs, [])
            self.assertNotIn("fail:hosted_canary:600:1", state_rej.seen_runs)
            gh_rej.fail_rerun = False
            ctrl_rej.handle_failure(sig_infra)
            self.assertEqual(state_rej.retried_runs, ["600"])
            self.assertIn("fail:hosted_canary:600:1", state_rej.seen_runs)

            # Two unreproducible macOS jobs in ONE single hosted run count as only 1 red run (not 2!).
            gh_mac = StubGitHub(
                runs_by_workflow={
                    "canary.yml": [
                        {
                            "id": 310,
                            "run_attempt": 1,
                            "conclusion": "failure",
                            "head_sha": c1,
                            "html_url": "https://example.com/310",
                            "updated_at": "2026-11-26T16:30:00Z",
                        }
                    ]
                },
                failed_jobs_by_run={
                    310: [
                        {"id": 2001, "name": "iOS keychain and Swift cancellation", "conclusion": "failure"},
                        {"id": 2002, "name": "MarmotKit native host lifecycle", "conclusion": "failure"},
                    ]
                },
            )
            state_mac = AgentState()
            ctrl_mac = BisectController(
                repo=repo,
                state=state_mac,
                github=gh_mac,
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
            )
            res_mac = ctrl_mac.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            self.assertEqual(len(res_mac["actions"]), 2)
            self.assertFalse(any(a["meltdown"] for a in res_mac["actions"]))
            self.assertEqual(state_mac.consecutive_unreproducible_reds.get("hosted_canary"), 1)
            self.assertEqual(gh_mac.reruns, ["310:1:job:2001"])

            # GitHubOps.jobs_for_run binds to `/attempts/{attempt}/jobs` when attempt is supplied.
            gh_ops = GitHubOps("marmot-protocol/mdk", dry_run=True)
            with mock.patch.object(gh_ops, "_run_gh_safe") as mocked_gh:
                mocked_gh.return_value = subprocess.CompletedProcess([], 0, stdout='{"jobs":[]}', stderr="")
                gh_ops.jobs_for_run(42, attempt=3)
                mocked_gh.assert_called_once_with(
                    "api", "repos/marmot-protocol/mdk/actions/runs/42/attempts/3/jobs?per_page=100"
                )

    def test_fresh_master_recheck_post_bisect_budget_first_parent_and_merge_culprit(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, origin = _init_repo(tmp, with_bare_origin=True)
            assert origin is not None
            c0 = _commit_file(repo, "app.txt", "good\n", "c0")
            c1 = _commit_file(repo, "app.txt", "broken\n", "c1")
            _git(repo, "push", "origin", "master")

            # Clone a second checkout to push a human fix to origin/master DURING bisect!
            pusher = tmp / "pusher"
            subprocess.run(["git", "clone", str(origin), str(pusher)], check=True, capture_output=True)
            _git(pusher, "config", "user.name", "Human")
            _git(pusher, "config", "user.email", "human@example.com")
            _git(pusher, "config", "commit.gpgsign", "false")

            pushed_fix = {"done": False}
            clock = {"t": 1000.0}

            def slow_bisect_then_master_fix(wt: Path, _cmd: tuple[str, ...]) -> tuple[RunVerdict, str]:
                val = (wt / "app.txt").read_text(encoding="utf-8").strip()
                # Advance clock during bisect near the 100s bisect budget, AND push a fix to origin/master!
                if not pushed_fix["done"] and val == "broken":
                    clock["t"] = 1095.0
                    _commit_file(pusher, "app.txt", "good\n", "human fix landed")
                    _git(pusher, "push", "origin", "master")
                    pushed_fix["done"] = True
                return (RunVerdict.PASS if val == "good" else RunVerdict.FAIL), ""

            gh = StubGitHub(author="dev")
            state = AgentState()
            ctrl = BisectController(
                repo=repo,
                state=state,
                github=gh,
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
                timeout_secs=60,
                bisect_budget_secs=100,
                now_fn=lambda: clock["t"],
                worktree_root=tmp / "wts",
                run_in_wt=slow_bisect_then_master_fix,
            )
            _cls, out = ctrl.handle_failure(
                FailureSignal(
                    source="hosted_canary",
                    run_id="400:1",
                    run_url="https://example.com/400",
                    tip_sha=c1,
                    baseline_sha=c0,
                    failed_job="Rust format",
                    failed_step="Check formatting",
                    command=("just", "fmt-check"),
                ),
                master_ref="origin/master",
                poll_deadline=1100.0,
                fetch_remote=True,
            )
            assert out is not None
            # Agent refreshed origin/master before recheck, saw the human fix, and skipped reverting!
            self.assertTrue(out.already_healed)
            self.assertFalse(out.meltdown_triggered)
            self.assertEqual(len(gh.prs), 0)

            # Side-branch baseline rejection & merge-commit culprit handling.
            repo2, _ = _init_repo(tmp / "m2", with_bare_origin=False)
            m0 = _commit_file(repo2, "main.txt", "v0\n", "m0")
            _git(repo2, "checkout", "-b", "side")
            side_c = _commit_file(repo2, "side.txt", "side\n", "side commit")
            _git(repo2, "checkout", "master")
            _commit_file(repo2, "main.txt", "v1\n", "m1")
            _git(repo2, "merge", "--no-ff", "side", "-m", "merge side")
            merge_sha = _git(repo2, "rev-parse", "HEAD")

            # `side_c` is on second-parent history, NOT first-parent chain -> bisect refuses cleanly!
            culp, reason = bisect_culprit(repo2, side_c, merge_sha, lambda _wt: (RunVerdict.FAIL, ""))
            self.assertIsNone(culp)
            self.assertIn("not on the first-parent chain", reason)

            # Attempting revert of a merge commit returns explicit merge-culprit reason (not revert conflict).
            merge_out = attempt_clean_revert(
                repo2,
                merge_sha,
                "HEAD",
                lambda _wt: (RunVerdict.FAIL, ""),
                checks_summary="just fmt-check",
                sign_commits=False,
                dry_run=True,
                worktree_root=tmp / "wts2",
            )
            self.assertTrue(merge_out.meltdown_triggered)
            self.assertIn("merge commit culprit", merge_out.reason)
            self.assertNotIn("tangled revert", merge_out.reason)

            # Post-bisect revert budget: even when bisect finishes right at `poll_deadline`
            # (leaving 0s on the poll budget), live-master recheck + revert check STILL get
            # their own post-bisect budget (`2 * timeout_secs`) and succeed without Meltdown!
            c_good_base = _git(pusher, "rev-parse", "HEAD")
            c_fix = _commit_file(pusher, "app.txt", "broken2\n", "c_broken2")
            _git(pusher, "push", "origin", "master")
            _git(repo, "fetch", "origin", "+refs/heads/master:refs/remotes/origin/master")
            t_state = {"now": 2000.0}

            def finish_late_predicate(wt: Path, _cmd: tuple[str, ...]) -> tuple[RunVerdict, str]:
                val = (wt / "app.txt").read_text(encoding="utf-8").strip()
                t_state["now"] += 30.0
                return (RunVerdict.PASS if val == "good" else RunVerdict.FAIL), ""

            ctrl_budget = BisectController(
                repo=repo,
                state=AgentState(),
                github=StubGitHub(author="dev"),
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=True,
                sign_commits=False,
                timeout_secs=60,
                bisect_budget_secs=120,
                now_fn=lambda: t_state["now"],
                worktree_root=tmp / "wts3",
                run_in_wt=finish_late_predicate,
            )
            _cls_b, out_b = ctrl_budget.handle_failure(
                FailureSignal(
                    source="hosted_canary",
                    run_id="401:1",
                    run_url="https://example.com/401",
                    tip_sha=c_fix,
                    baseline_sha=c_good_base,
                    failed_job="Rust format",
                    failed_step="Check formatting",
                    command=("just", "fmt-check"),
                ),
                master_ref="origin/master",
                poll_deadline=2120.0,
                fetch_remote=False,
            )
            assert out_b is not None
            self.assertGreater(t_state["now"], 2120.0)
            self.assertTrue(out_b.revert_verified)
            self.assertFalse(out_b.meltdown_triggered)

            # Worktree checkout timeout inside bisect aborts cleanly as inconclusive with bounded cleanup.
            real_run = subprocess.run

            def timeout_on_wt_add(argv, *args, **kwargs):
                if isinstance(argv, list) and "worktree" in argv and "add" in argv:
                    raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 1))
                return real_run(argv, *args, **kwargs)

            with mock.patch("scripts.bisect_agent.reverter.subprocess.run", side_effect=timeout_on_wt_add):
                culp_to, reason_to = bisect_culprit(
                    repo,
                    c0,
                    c_fix,
                    lambda _wt: (RunVerdict.FAIL, ""),
                    worktree_root=tmp / "wts4",
                    deadline=5000.0,
                    now_fn=lambda: 4995.0,
                )
            self.assertIsNone(culp_to)
            self.assertIn("budget exceeded during checkout", reason_to)

            # Confirm master advancing DURING revert verification triggers re-check instead of stale push.
            _commit_file(pusher, "app.txt", "good\n", "restore good before c_bad3")
            c_bad3 = _commit_file(pusher, "app.txt", "broken3\n", "c_broken3")
            _git(pusher, "push", "origin", "master")
            _git(repo, "fetch", "origin", "+refs/heads/master:refs/remotes/origin/master")
            moved_during_verify = {"done": False}

            def verify_while_master_moves(wt: Path) -> tuple[RunVerdict, str]:
                val = (wt / "app.txt").read_text(encoding="utf-8").strip()
                if val == "good" and not moved_during_verify["done"]:
                    _commit_file(pusher, "app.txt", "good\n", "human fix during revert test")
                    _git(pusher, "push", "origin", "master")
                    moved_during_verify["done"] = True
                return (RunVerdict.PASS if val == "good" else RunVerdict.FAIL), ""

            out_moved = attempt_clean_revert(
                repo,
                c_bad3,
                "origin/master",
                verify_while_master_moves,
                checks_summary="just fmt-check",
                sign_commits=False,
                dry_run=False,
                open_revert_pr=lambda _b, _t, _body: "https://example.com/should-not-open",
                refresh_master=ctrl._refresh_master,
                worktree_root=tmp / "wts5",
            )
            self.assertTrue(out_moved.already_healed)
            self.assertEqual(out_moved.revert_pr_url, "")

    def test_durable_remote_incident_recovery_manual_freeze_skipped_error_and_resilience(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, origin = _init_repo(tmp, with_bare_origin=True)
            assert origin is not None
            c0 = _commit_file(repo, "app.txt", "good\n", "c0")
            c1 = _commit_file(repo, "app.txt", "bad\n", "c1")
            c2 = _commit_file(repo, "app.txt", "fixed\n", "c2")
            _git(repo, "push", "origin", "master")
            _seed_tree_state(tmp, origin, state="green")

            tree_ctrl = TreeStateController(repo, dry_run=False, sign_commits=False)

            # 1. Simulate crash AFTER remote `tree-state=red` push with durable `incidents`,
            # BEFORE local `bisect-state.json` was saved (fresh empty AgentState on restart!).
            tree_ctrl.set_state(
                "red",
                reason="hosted_canary failed on c1",
                run_url="https://example.com/500",
                incidents={
                    "hosted_canary": {
                        "source": "hosted_canary",
                        "tip_sha": c1,
                        "started_at": 100.0,
                        "reason": "hosted_canary failed on c1",
                        "run_url": "https://example.com/500",
                        "culprit_sha": None,
                    }
                },
            )
            restarted_state = AgentState()
            gh_restart = StubGitHub(
                runs_by_workflow={
                    "canary.yml": [
                        {"id": 802, "run_attempt": 1, "conclusion": "success", "head_sha": c2, "html_url": "https://example.com/802", "updated_at": "2026-11-26T18:00:00Z"},
                        {"id": 801, "run_attempt": 1, "conclusion": "success", "head_sha": c2, "html_url": "https://example.com/801", "updated_at": "2026-11-26T17:00:00Z"},
                    ]
                },
                verification_status_by_run={802: "skipped", 801: "error"},
            )
            ctrl_restart = BisectController(
                repo=repo,
                state=restarted_state,
                github=gh_restart,
                alerter=MarmotAlerter(Roster(engineering_group_id="eng"), dry_run=True),
                tree_state=tree_ctrl,
                dry_run=False,
                sign_commits=False,
                now_fn=lambda: 200.0,
            )
            # An older green on c0 or a green from `bare_metal_canary` MUST NOT clear hosted_canary's freeze!
            self.assertFalse(ctrl_restart.handle_green_canary(source="hosted_canary", sha=c0, run_id="old:1", run_url=""))
            self.assertEqual(tree_ctrl.read_remote_status(), "red")
            self.assertFalse(ctrl_restart.handle_green_canary(source="bare_metal_canary", sha=c2, run_id="bm:1", run_url=""))
            self.assertEqual(tree_ctrl.read_remote_status(), "red")

            # Skipped run 802 with candidate 801 returning `error` MUST leave 802 unseen!
            res_err = ctrl_restart.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            self.assertEqual(res_err["actions"][0]["result"], "jobs_api_error")
            self.assertNotIn("green:hosted_canary:802:1", restarted_state.seen_runs)
            self.assertEqual(tree_ctrl.read_remote_status(), "red")

            # Once 801 resolves as `verified`, next poll discovers 801 and clears the hydrated freeze!
            gh_restart.verification_status_by_run[801] = "verified"
            res_ok = ctrl_restart.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            self.assertTrue(res_ok["actions"][0]["cleared_meltdown"])
            self.assertEqual(tree_ctrl.read_remote_status(), "green")

            # 2. Manual freeze (`state="red"` with NO `incidents` metadata): automated green MUST NOT clear it!
            tree_ctrl.set_state("red", reason="manual release freeze", incidents={})
            manual_ctrl = BisectController(
                repo=repo,
                state=AgentState(),
                github=StubGitHub(),
                alerter=MarmotAlerter(Roster(engineering_group_id="eng"), dry_run=True),
                tree_state=tree_ctrl,
                dry_run=False,
                sign_commits=False,
            )
            self.assertFalse(manual_ctrl.handle_green_canary(source="hosted_canary", sha=c2, run_id="man:1", run_url=""))
            self.assertEqual(tree_ctrl.read_remote_status(), "red")

            # 3. Escalation stays pending when White Noise fails/times out, and alert-log OSError never aborts send!
            unwritable_log = tmp / "not-a-dir"
            unwritable_log.write_text("file blocking dir", encoding="utf-8")
            roster = Roster(engineering_group_id="eng-group", wn_bin="wn", alert_log_path=str(unwritable_log / "alerts.jsonl"))
            alerter = MarmotAlerter(roster, dry_run=False)
            esc_state = AgentState(
                tree_state="red",
                active_incidents={
                    "hosted_canary": IncidentRecord(
                        started_at=100.0,
                        reason="frozen",
                        run_url="https://example.com/1",
                        tip_sha=c1,
                        source="hosted_canary",
                    )
                },
            )
            esc_ctrl = BisectController(
                repo=repo,
                state=esc_state,
                github=StubGitHub(),
                alerter=alerter,
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                now_fn=lambda: 5000.0,
            )
            with mock.patch("scripts.bisect_agent.notify.shutil.which", return_value="/usr/bin/wn"), \
                 mock.patch("scripts.bisect_agent.notify.subprocess.run", side_effect=subprocess.TimeoutExpired("wn", 60)):
                self.assertFalse(esc_ctrl.check_escalation())
                self.assertIsNone(esc_state.active_incidents["hosted_canary"].escalated_at)
            with mock.patch("scripts.bisect_agent.notify.shutil.which", return_value="/usr/bin/wn"), \
                 mock.patch(
                     "scripts.bisect_agent.notify.subprocess.run",
                     return_value=subprocess.CompletedProcess([], 0, stdout="sent", stderr=""),
                 ):
                self.assertTrue(esc_ctrl.check_escalation())
                self.assertEqual(esc_state.active_incidents["hosted_canary"].escalated_at, 5000.0)

            # 4. Invalid tree-state JSON shapes and git timeouts return `error` instead of crashing.
            with mock.patch("scripts.bisect_agent.notify.subprocess.run") as mock_git:
                mock_git.side_effect = [
                    subprocess.CompletedProcess([], 0, stdout="a" * 40 + "\trefs/heads/tree-state\n", stderr=""),
                    subprocess.CompletedProcess([], 0, stdout="", stderr=""),
                    subprocess.CompletedProcess([], 0, stdout="a" * 40 + "\n", stderr=""),
                    subprocess.CompletedProcess([], 0, stdout='{"state":[]}', stderr=""),
                ]
                self.assertEqual(tree_ctrl.read_remote_status(), "error")
            with mock.patch(
                "scripts.bisect_agent.notify.subprocess.run",
                side_effect=subprocess.TimeoutExpired("git", 60),
            ):
                self.assertEqual(tree_ctrl.read_remote_status(), "error")

            # Push timeout during tree-state write raises RuntimeError cleanly (retryable failure).
            real_notify_run = subprocess.run

            def timeout_on_push(argv, *args, **kwargs):
                if isinstance(argv, list) and "push" in argv:
                    raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 60))
                return real_notify_run(argv, *args, **kwargs)

            with mock.patch("scripts.bisect_agent.notify.subprocess.run", side_effect=timeout_on_push):
                with self.assertRaisesRegex(RuntimeError, "failed to update origin/tree-state"):
                    tree_ctrl.set_state("green", reason="should fail on push timeout", allow_manual_override=True)

            # 5. Best-effort `refresh_repo` catches TimeoutExpired per branch and still completes escalation!
            with mock.patch(
                "scripts.bisect_agent.controller.subprocess.run",
                side_effect=subprocess.TimeoutExpired("git", 120),
            ):
                errs = esc_ctrl.refresh_repo()
                self.assertEqual(len(errs), 3)

            # 6. Early escalation runs BEFORE failure classification/bisect, and open revert PRs
            # short-circuit subsequent failures on descendants without running predicates or dispatching Canary.
            gh_open = StubGitHub(author="dev")
            state_open = AgentState(
                tree_state="red",
                active_incidents={
                    "hosted_canary": IncidentRecord(
                        started_at=100.0,
                        reason="existing tangled meltdown",
                        run_url="https://example.com/old",
                        tip_sha=c1,
                        source="hosted_canary",
                    )
                },
            )
            pred_calls: list[tuple[str, bool]] = []
            bm_status = tmp / "bm-status.json"
            bm_status.write_text(
                json.dumps(
                    {
                        "state": "red",
                        "sha": c1,
                        "canary_sha": c0,
                        "failed_step": "cargo-audit",
                        "updated_at": "2026-11-26T17:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            # Push a clean-revertable commit c_rev onto master so revert succeeds.
            c_clean_base = _commit_file(repo, "rev.txt", "ok\n", "rev base")
            c_rev = _commit_file(repo, "rev.txt", "broken\n", "rev break")
            _git(repo, "push", "origin", "master")
            bm_status.write_text(
                json.dumps(
                    {
                        "state": "red",
                        "sha": c_rev,
                        "canary_sha": c_clean_base,
                        "failed_step": "cargo-audit",
                        "updated_at": "2026-11-26T17:00:00Z",
                    }
                ),
                encoding="utf-8",
            )

            def track_pred(wt: Path, _cmd: tuple[str, ...]) -> tuple[RunVerdict, str]:
                # Assert overdue incident was ALREADY escalated before predicate ran!
                already_esc = state_open.active_incidents["hosted_canary"].escalated_at is not None
                pred_calls.append((str(wt), already_esc))
                ok = (wt / "rev.txt").read_text(encoding="utf-8").strip() == "ok"
                return (RunVerdict.PASS if ok else RunVerdict.FAIL), ""

            ctrl_open = BisectController(
                repo=repo,
                state=state_open,
                github=gh_open,
                alerter=MarmotAlerter(Roster(engineering_group_id="eng"), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
                now_fn=lambda: 5000.0,
                worktree_root=tmp / "wts-open",
                run_in_wt=track_pred,
            )
            poll_res = ctrl_open.poll_once(
                bare_metal_status_path=bm_status,
                hosted_workflows=(),
                master_ref="origin/master",
                fetch_remote=False,
            )
            self.assertTrue(poll_res["escalated"])
            self.assertTrue(pred_calls)
            self.assertTrue(all(was_esc for _, was_esc in pred_calls))
            self.assertEqual(len(gh_open.prs), 1)
            # No premature hosted Canary dispatch before a human merges the revert PR!
            self.assertEqual(gh_open.dispatches, 0)

            # A subsequent failure on a descendant commit with the same command while the revert PR
            # is still open MUST short-circuit with ZERO predicate calls!
            c_desc = _commit_file(repo, "unrelated.txt", "note\n", "unrelated commit")
            _git(repo, "push", "origin", "master")
            calls_before = len(pred_calls)
            _cls_dup, out_dup = ctrl_open.handle_failure(
                FailureSignal(
                    source="hosted_canary",
                    run_id="901:1",
                    run_url="https://example.com/901",
                    tip_sha=c_desc,
                    baseline_sha=c_clean_base,
                    failed_job="Rust audit",
                    failed_step="Audit Rust dependencies",
                    command=("cargo", "--locked", "audit"),
                ),
                master_ref="origin/master",
            )
            assert out_dup is not None
            self.assertTrue(out_dup.duplicate_pr)
            self.assertEqual(len(pred_calls), calls_before)
            self.assertIn("fail:hosted_canary:901:1", state_open.seen_runs)

    def test_pinned_nextest_stress_terminal_statuses_and_profile_preservation(self):
        # 1. Exact captured stress output from pinned cargo-nextest (`[1/2]` AFTER `[   0.003s]`):
        cmd = nextest_command_for_test("marmot-session", None, "error::tests::kp", profile="ci")
        self.assertIn("--profile", cmd)
        self.assertEqual(cmd[cmd.index("--profile") + 1], "ci")
        stress_pass = (
            " Stress test iteration 1/2 (00:00:00 elapsed so far, 2 iterations remaining)\n"
            "        PASS [   0.003s] [1/2] (1/1) marmot-session error::tests::kp\n"
            " Stress test iteration 2/2 (00:00:00 elapsed so far, 1 iteration remaining)\n"
            "        PASS [   0.003s] [2/2] (1/1) marmot-session error::tests::kp\n"
            "     Summary [   0.006s] 2/2 stress run iterations: 2 passed\n"
        )
        self.assertEqual(evaluate_command_result(0, stress_pass, stress_command(cmd, 2))[0], RunVerdict.PASS)

        stress_fail = (
            "        PASS [   0.003s] [1/2] (1/1) marmot-session error::tests::kp\n"
            "     SIGSEGV [   0.012s] [2/2] (1/1) marmot-session error::tests::kp\n"
        )
        self.assertEqual(evaluate_command_result(100, stress_fail, stress_command(cmd, 2))[0], RunVerdict.FAIL)

        # 2. Pinned nextest terminal statuses (SIGSEGV, XFAIL, retry TMT, LKFL, ABRT) + `(─────────)` progress:
        pinned_log = (
            "  TRY 1 TMT [ 240.001s] (─────────) wn-cli::cli hangs_once\n"
            "  TRY 2 PASS [   1.200s] (  1/20) wn-cli::cli hangs_once\n"
            "   FLAKY 2/2 [   1.200s] wn-cli::cli hangs_once\n"
            "  TRY 1 TMT [ 240.004s] (─────────) wn-cli::cli hangs_always\n"
            "  TRY 2 TMT [ 240.005s] (  2/20) wn-cli::cli hangs_always\n"
            "     SIGSEGV [   0.012s] (  3/20) marmot-c::ffi crash_case\n"
            "  TRY 1 XFAIL [   0.001s] (─────────) cgka-engine::a exec_fail_case\n"
        )
        self.assertEqual(
            parse_nextest_failures(pinned_log),
            [
                ("wn-cli", "cli", "hangs_always"),
                ("marmot-c", "ffi", "crash_case"),
                ("cgka-engine", "a", "exec_fail_case"),
            ],
        )

        # 3. Originating nextest profile is preserved for CLI e2e (mock relay), Rust tests, Relay runtime,
        # and bare-metal workspace-nextest so `--profile ci` timeout backstops remain active on replay.
        cli_sig = extract_hosted_signal(
            source="hosted_canary",
            run_id="10:1",
            run_url="https://example.com/10",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / CLI e2e (mock relay, 1/2)",
            failed_step="Run CLI end-to-end tests",
            log_text="  TRY 2 TMT [ 240.004s] (  2/20) wn-cli::cli hangs_always\n",
        )
        self.assertIn("--profile", cli_sig.command)
        self.assertEqual(cli_sig.command[cli_sig.command.index("--profile") + 1], "ci")
        self.assertIn("--retries", cli_sig.command)
        self.assertEqual(cli_sig.command[cli_sig.command.index("--retries") + 1], "0")

        relay_serial = extract_hosted_signal(
            source="hosted_canary",
            run_id="11:1",
            run_url="https://example.com/11",
            tip_sha="a" * 40,
            baseline_sha="b" * 40,
            failed_job="Full cross-platform CI (6 shards) / Relay runtime tests (1/2)",
            failed_step="Run relay runtime tests serially",
            log_text="  FAIL [ 1.0s] marmot-app::relay_runtime foo\n",
        )
        self.assertEqual(relay_serial.command[relay_serial.command.index("--profile") + 1], "ci")
        self.assertEqual(relay_serial.command[relay_serial.command.index("--test-threads") + 1], "1")

        bm_sig = extract_bare_metal_signal(
            {"state": "red", "sha": "a" * 40, "canary_sha": "b" * 40, "failed_step": "workspace-nextest", "updated_at": "t"},
            "  FAIL [ 1.0s] marmot-session::runtime foo\n",
        )
        self.assertEqual(bm_sig.command[bm_sig.command.index("--profile") + 1], "ci")

    def test_multi_terminal_failures_per_shard_bare_metal_and_job_log_retry(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, _ = _init_repo(tmp, with_bare_origin=True)
            c0 = _commit_file(repo, "app.txt", "good\n", "c0")
            c1 = _commit_file(repo, "app.txt", "bad\n", "c1")
            _git(repo, "push", "origin", "master")

            # 1. Single hosted shard with TWO terminal failures: test 1 is a known flake,
            # test 2 is a deterministic regression. Test 1 MUST NOT hide test 2!
            shard_log = (
                "  TRY 2 FAIL [ 0.40s] ( 1/10) cgka-engine::net known_flake\n"
                "  TRY 2 FAIL [ 0.41s] ( 2/10) cgka-engine::core hidden_regression\n"
            )
            gh = StubGitHub(
                open_issues=[{"number": 77, "title": "Flaky: cgka-engine::net::known_flake", "body": ""}],
                author="dev",
                runs_by_workflow={
                    "canary.yml": [
                        {"id": 500, "run_attempt": 1, "conclusion": "failure", "head_sha": c1, "html_url": "https://example.com/500", "updated_at": "2026-11-26T16:00:00Z"},
                        {"id": 499, "run_attempt": 1, "conclusion": "success", "head_sha": c0, "html_url": "https://example.com/499", "updated_at": "2026-11-26T15:00:00Z"},
                    ]
                },
                failed_jobs_by_run={
                    500: [{"id": 5001, "name": "Full cross-platform CI (6 shards) / Rust tests (1/6)", "conclusion": "failure", "steps": [{"name": "Run workspace tests", "conclusion": "failure"}]}]
                },
                logs_by_job={5001: shard_log},
                fail_pr_lookup=True,
            )
            state = AgentState()
            ctrl = BisectController(
                repo=repo,
                state=state,
                github=gh,
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
                worktree_root=tmp / "wts",
                run_in_wt=lambda wt, _cmd: (
                    RunVerdict.PASS if (wt / "app.txt").read_text(encoding="utf-8").strip() == "good" else RunVerdict.FAIL,
                    "",
                ),
            )
            res1 = ctrl.poll_once(hosted_workflows=("canary.yml",), master_ref="origin/master", fetch_remote=False)
            self.assertEqual([a["bucket"] for a in res1["actions"]], ["known_flake", "deterministic_regression"])
            # Flake is marked seen, regression deferred -> job and run attempt MUST remain pending!
            self.assertIn("fail:hosted_canary:500:1:job:5001:test:cgka-engine::net::known_flake", state.seen_runs)
            self.assertNotIn("fail:hosted_canary:500:1:job:5001:test:cgka-engine::core::hidden_regression", state.seen_runs)
            self.assertNotIn("fail:hosted_canary:500:1:job:5001", state.seen_runs)
            self.assertNotIn("fail:hosted_canary:500:1", state.seen_runs)

            gh.fail_pr_lookup = False
            res2 = ctrl.poll_once(hosted_workflows=("canary.yml",), master_ref="origin/master", fetch_remote=False)
            self.assertEqual(len(res2["actions"]), 1)
            self.assertEqual(res2["actions"][0]["culprit"], c1)
            self.assertIn("fail:hosted_canary:500:1:job:5001", state.seen_runs)
            self.assertIn("fail:hosted_canary:500:1", state.seen_runs)

            # 2. Bare-metal extractor also emits one signal per terminal failure.
            bm_log = tmp / "bm.log"
            bm_log.write_text(shard_log, encoding="utf-8")
            bm_doc = {
                "state": "red",
                "sha": c1,
                "canary_sha": c0,
                "failed_step": "workspace-nextest",
                "updated_at": "2026-11-26T16:05:00Z",
                "log": str(bm_log),
            }
            bm_signals = extract_bare_metal_signals(bm_doc, shard_log)
            self.assertEqual(
                [s.failed_test for s in bm_signals],
                ["cgka-engine::net::known_flake", "cgka-engine::core::hidden_regression"],
            )

            # 3. Unavailable job log (`None`) defers cleanly without counting toward unreproducible freeze.
            gh_log_err = StubGitHub(
                runs_by_workflow={
                    "canary.yml": [
                        {"id": 510, "run_attempt": 1, "conclusion": "failure", "head_sha": c1, "html_url": "https://example.com/510", "updated_at": "2026-11-26T16:10:00Z"},
                        {"id": 511, "run_attempt": 1, "conclusion": "failure", "head_sha": c1, "html_url": "https://example.com/511", "updated_at": "2026-11-26T16:11:00Z"},
                    ]
                },
                failed_jobs_by_run={
                    510: [{"id": 5101, "name": "Full cross-platform CI (6 shards) / Rust tests (1/6)", "conclusion": "failure", "steps": [{"name": "Run workspace tests", "conclusion": "failure"}]}],
                    511: [{"id": 5111, "name": "Full cross-platform CI (6 shards) / Rust tests (1/6)", "conclusion": "failure", "steps": [{"name": "Run workspace tests", "conclusion": "failure"}]}],
                },
                logs_by_job={5101: None, 5111: None},
            )
            state_log_err = AgentState()
            ctrl_log_err = BisectController(
                repo=repo,
                state=state_log_err,
                github=gh_log_err,
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
            )
            res_log_err = ctrl_log_err.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            self.assertEqual([a["result"] for a in res_log_err["actions"]], ["job_log_error", "job_log_error"])
            self.assertEqual(state_log_err.consecutive_unreproducible_reds.get("hosted_canary", 0), 0)
            self.assertNotIn("fail:hosted_canary:510:1", state_log_err.seen_runs)
            self.assertNotIn("fail:hosted_canary:511:1", state_log_err.seen_runs)

            # GitHubOps.job_log returns None (not "") when the jobs logs API call fails.
            gh_ops = GitHubOps("marmot-protocol/mdk", dry_run=True)
            with mock.patch.object(gh_ops, "_run_gh_safe", return_value=subprocess.CompletedProcess([], 1, stdout="", stderr="err")):
                self.assertIsNone(gh_ops.job_log(510, 5101))

    def test_manual_freeze_both_directions_authoritative_remote_and_cas(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, origin = _init_repo(tmp, with_bare_origin=True)
            assert origin is not None
            c0 = _commit_file(repo, "app.txt", "good\n", "c0")
            c1 = _commit_file(repo, "app.txt", "bad\n", "c1")
            c2 = _commit_file(repo, "app.txt", "fixed\n", "c2")
            _git(repo, "push", "origin", "master")
            _seed_tree_state(tmp, origin, state="green")

            tree_ctrl = TreeStateController(repo, dry_run=False, sign_commits=False)
            state = AgentState()
            ctrl = BisectController(
                repo=repo,
                state=state,
                github=StubGitHub(),
                alerter=MarmotAlerter(Roster(engineering_group_id="eng"), dry_run=True),
                tree_state=tree_ctrl,
                dry_run=False,
                sign_commits=False,
            )

            # 1. Agent freezes hosted_canary -> remote has agent incident.
            sig_hosted = FailureSignal(
                source="hosted_canary",
                run_id="600:1",
                run_url="https://example.com/600",
                tip_sha=c1,
                baseline_sha=c0,
                failed_job="iOS",
            )
            self.assertTrue(
                ctrl._trigger_meltdown(
                    reason="agent freeze",
                    signal=sig_hosted,
                    culprit_sha=None,
                    notified=[],
                    seen_key="fail:hosted_canary:600:1",
                )
            )
            self.assertIn("hosted_canary", state.active_incidents)

            # 2. Operator replaces active agent freeze with a MANUAL red (`incidents: {}`).
            # Hydration MUST drop the stale local incident and green MUST NOT clear the manual freeze!
            tree_ctrl.set_state("red", reason="operator manual freeze", incidents={}, allow_manual_override=True)
            self.assertFalse(ctrl.handle_green_canary(source="hosted_canary", sha=c2, run_id="601:1", run_url=""))
            self.assertEqual(tree_ctrl.read_remote_status(), "red")
            self.assertEqual(state.active_incidents, {})

            # 3. Red writer direction: a new Meltdown trigger while remote is under a manual freeze
            # MUST NOT replace the manual freeze with an agent-clearable incident!
            self.assertTrue(
                ctrl._trigger_meltdown(
                    reason="agent meltdown during manual freeze",
                    signal=FailureSignal(
                        source="bare_metal_canary",
                        run_id="bm:2",
                        run_url="",
                        tip_sha=c1,
                        baseline_sha=c0,
                        failed_job="mdk-canary:fast-ci",
                    ),
                    culprit_sha=None,
                    notified=[],
                    seen_key="fail:bare_metal_canary:bm:2",
                )
            )
            # Remote MUST still hold the operator's manual freeze, and a subsequent green MUST NOT clear it!
            status, doc, rev_manual = tree_ctrl.read_remote_snapshot()
            self.assertEqual(status, "red")
            assert doc is not None
            self.assertEqual(doc.get("incidents"), {})
            self.assertFalse(ctrl.handle_green_canary(source="bare_metal_canary", sha=c2, run_id="bm-green:2", run_url=""))
            self.assertEqual(tree_ctrl.read_remote_status(), "red")
            with self.assertRaises(ManualFreezeError):
                tree_ctrl.set_state("green", reason="unauthorized auto clear")

            # 4. Authoritative remote membership + CAS: operator unfreezes manually, then agent opens
            # two incidents, remote drops hosted_canary (simulating crash after partial clear while
            # stale local state still remembers both). Next transition MUST NOT resurrect hosted_canary!
            tree_ctrl.set_state("green", reason="operator unfreeze", allow_manual_override=True)
            self.assertEqual(tree_ctrl.read_remote_status(), "green")
            tree_ctrl.set_state(
                "red",
                reason="bare_metal only",
                incidents={
                    "bare_metal_canary": {
                        "source": "bare_metal_canary",
                        "tip_sha": c1,
                        "started_at": 100.0,
                        "reason": "bm only",
                        "run_url": "",
                        "culprit_sha": None,
                    }
                },
            )
            # Stale local state still has BOTH incidents.
            state.active_incidents = {
                "hosted_canary": IncidentRecord(started_at=90.0, reason="stale", run_url="", tip_sha=c1, source="hosted_canary"),
                "bare_metal_canary": IncidentRecord(started_at=100.0, reason="bm only", run_url="", tip_sha=c1, source="bare_metal_canary"),
            }
            # Recovering bare_metal_canary hydrates authoritatively (dropping stale hosted_canary) and clears tree!
            self.assertTrue(ctrl.handle_green_canary(source="bare_metal_canary", sha=c2, run_id="bm-green:3", run_url=""))
            self.assertEqual(tree_ctrl.read_remote_status(), "green")

            # 5. CAS (`expected_rev`): passing a stale revision raises RuntimeError instead of clobbering.
            with self.assertRaisesRegex(RuntimeError, "changed concurrently"):
                tree_ctrl.set_state("red", reason="stale write", incidents={}, expected_rev=rev_manual)

    def test_unknown_ancestry_keeps_recovery_pending_and_drains_deferred_runs(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, origin = _init_repo(tmp, with_bare_origin=True)
            assert origin is not None
            c0 = _commit_file(repo, "app.txt", "good\n", "c0")
            c1 = _commit_file(repo, "app.txt", "bad\n", "c1")
            _git(repo, "push", "origin", "master")
            _seed_tree_state(tmp, origin, state="green")

            # Push c2 from a separate clone so `repo` does NOT have c2 locally yet!
            pusher = tmp / "pusher"
            subprocess.run(["git", "clone", str(origin), str(pusher)], check=True, capture_output=True)
            _git(pusher, "config", "user.name", "Human")
            _git(pusher, "config", "user.email", "human@example.com")
            _git(pusher, "config", "commit.gpgsign", "false")
            c2_missing = _commit_file(pusher, "app.txt", "good\n", "c2 fix")
            _git(pusher, "push", "origin", "master")

            tree_ctrl = TreeStateController(repo, dry_run=False, sign_commits=False)
            state = AgentState()
            ctrl = BisectController(
                repo=repo,
                state=state,
                github=StubGitHub(),
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=tree_ctrl,
                dry_run=False,
                sign_commits=False,
            )
            ctrl._trigger_meltdown(
                reason="frozen on c1",
                signal=FailureSignal(source="bare_metal_canary", run_id="bm:1", run_url="", tip_sha=c1, baseline_sha=c0, failed_job="mdk-canary:fast-ci"),
                culprit_sha=None,
                notified=[],
                seen_key="fail:bare_metal_canary:bm:1",
            )
            # 1. Green on `c2_missing` while commit is absent locally MUST NOT be marked seen!
            bm_green = tmp / "bm-green.json"
            bm_green.write_text(json.dumps({"state": "green", "sha": c2_missing, "updated_at": "2026-11-26T18:00:00Z"}))
            ctrl.poll_once(bare_metal_status_path=bm_green, hosted_workflows=(), fetch_remote=False)
            self.assertEqual(tree_ctrl.read_remote_status(), "red")
            self.assertNotIn(f"green:bare_metal_canary:bare-metal:{c2_missing[:12]}:2026-11-26T18:00:00Z", state.seen_runs)

            # Once `git fetch` brings `c2_missing` locally, the next poll clears the freeze!
            _git(repo, "fetch", "origin", "+refs/heads/master:refs/remotes/origin/master")
            res_bm = ctrl.poll_once(bare_metal_status_path=bm_green, hosted_workflows=(), fetch_remote=False)
            self.assertTrue(res_bm["actions"][0]["cleared_meltdown"])
            self.assertEqual(tree_ctrl.read_remote_status(), "green")

            # 2. Deferred hosted run 2 (`jobs_api_error`) + newer red run 3 + rerun of older SHA c0:
            # Poll MUST drain BOTH run 2 and run 3 and NOT let older-SHA green c0 supersede c1!
            c3 = _commit_file(pusher, "other.txt", "x\n", "c3")
            _git(pusher, "push", "origin", "master")
            _git(repo, "fetch", "origin", "+refs/heads/master:refs/remotes/origin/master")
            gh_drain = StubGitHub(
                open_issues=[
                    {"number": 81, "title": "Flaky: cgka-engine::a::flake_run2", "body": ""},
                    {"number": 82, "title": "Flaky: cgka-engine::b::flake_run3", "body": ""},
                ],
                runs_by_workflow={
                    "canary.yml": [
                        {"id": 2, "run_attempt": 1, "conclusion": "failure", "head_sha": c1, "html_url": "https://example.com/2", "updated_at": "2026-11-26T18:01:00Z"},
                    ]
                },
                failed_jobs_by_run={2: None},
            )
            state_drain = AgentState()
            ctrl_drain = BisectController(
                repo=repo,
                state=state_drain,
                github=gh_drain,
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
            )
            r_err = ctrl_drain.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            self.assertEqual(r_err["actions"][0]["result"], "jobs_api_error")
            self.assertNotIn("fail:hosted_canary:2:1", state_drain.seen_runs)

            # Now API recovers for run 2, red run 3 arrives on c3, AND an older-SHA rerun of c0
            # finishes green with the NEWEST updated_at! Both run 2 and run 3 MUST still be drained!
            gh_drain.failed_jobs_by_run[2] = [
                {"id": 201, "name": "Full cross-platform CI (6 shards) / Rust tests (1/6)", "conclusion": "failure", "steps": [{"name": "Run workspace tests", "conclusion": "failure"}]}
            ]
            gh_drain.failed_jobs_by_run[3] = [
                {"id": 301, "name": "Full cross-platform CI (6 shards) / Rust tests (2/6)", "conclusion": "failure", "steps": [{"name": "Run workspace tests", "conclusion": "failure"}]}
            ]
            gh_drain.logs_by_job[201] = "  FAIL [ 0.1s] cgka-engine::a flake_run2\n"
            gh_drain.logs_by_job[301] = "  FAIL [ 0.1s] cgka-engine::b flake_run3\n"
            gh_drain.verification_status_by_run[1] = "verified"
            gh_drain.runs_by_workflow["canary.yml"] = [
                {"id": 1, "run_attempt": 2, "conclusion": "success", "head_sha": c0, "html_url": "https://example.com/1", "updated_at": "2026-11-26T18:10:00Z"},
                {"id": 3, "run_attempt": 1, "conclusion": "failure", "head_sha": c3, "html_url": "https://example.com/3", "updated_at": "2026-11-26T18:05:00Z"},
                {"id": 2, "run_attempt": 1, "conclusion": "failure", "head_sha": c1, "html_url": "https://example.com/2", "updated_at": "2026-11-26T18:01:00Z"},
            ]
            r_drained = ctrl_drain.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            drained_runs = [a.get("run_id") for a in r_drained["actions"]]
            self.assertEqual(drained_runs, ["2:1", "3:1"])
            self.assertIn("fail:hosted_canary:2:1", state_drain.seen_runs)
            self.assertIn("fail:hosted_canary:3:1", state_drain.seen_runs)

    def test_fresh_master_before_freeze_stale_revert_second_command_and_budget_defer(self):
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            repo, origin = _init_repo(tmp, with_bare_origin=True)
            assert origin is not None
            c0 = _commit_file(repo, "a.txt", "good\n", "c0")
            _commit_file(repo, "b.txt", "good\n", "c0b")
            c0_full = _git(repo, "rev-parse", "HEAD")
            c1 = _commit_file(repo, "a.txt", "bad\n", "c1 breaks A")
            c2_conflict = _commit_file(repo, "a.txt", "still-bad-conflict\n", "c2 conflicts with c1")
            _git(repo, "push", "origin", "master")
            _seed_tree_state(tmp, origin, state="green")

            pusher = tmp / "pusher"
            subprocess.run(["git", "clone", str(origin), str(pusher)], check=True, capture_output=True)
            _git(pusher, "config", "user.name", "Human")
            _git(pusher, "config", "user.email", "human@example.com")
            _git(pusher, "config", "commit.gpgsign", "false")

            # 1. Manual repair lands while candidate revert conflicts against old master ->
            # `attempt_clean_revert` rechecks fresh master and returns `already_healed=True` (NO freeze!).
            repaired_once = {"done": False}
            ctrl_helper = BisectController(
                repo=repo,
                state=AgentState(),
                github=StubGitHub(),
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
            )

            def push_fix_on_live_check(wt: Path) -> tuple[RunVerdict, str]:
                val = (wt / "a.txt").read_text(encoding="utf-8").strip()
                if val == "still-bad-conflict" and not repaired_once["done"]:
                    _commit_file(pusher, "a.txt", "good\n", "manual repair")
                    _git(pusher, "push", "origin", "master")
                    repaired_once["done"] = True
                return (RunVerdict.PASS if val == "good" else RunVerdict.FAIL), ""

            out_healed = attempt_clean_revert(
                repo,
                c1,
                "origin/master",
                push_fix_on_live_check,
                checks_summary="cmd-a",
                sign_commits=False,
                dry_run=True,
                refresh_master=ctrl_helper._refresh_master,
                worktree_root=tmp / "wts-heal",
            )
            self.assertTrue(out_healed.already_healed)
            self.assertFalse(out_healed.meltdown_triggered)

            # 2. Verification passes right at deadline while master advances -> DEFERS instead of freezing!
            c_base2 = _git(pusher, "rev-parse", "HEAD")
            c_bad2 = _commit_file(pusher, "a.txt", "bad2\n", "c_bad2")
            _git(pusher, "push", "origin", "master")
            _git(repo, "fetch", "origin", "+refs/heads/master:refs/remotes/origin/master")
            t_clock = {"now": 1000.0}
            moved_at_deadline = {"done": False}

            def verify_near_deadline(wt: Path) -> tuple[RunVerdict, str]:
                val = (wt / "a.txt").read_text(encoding="utf-8").strip()
                if val == "good" and not moved_at_deadline["done"]:
                    t_clock["now"] = 1050.0  # Deadline reached!
                    _commit_file(pusher, "other.txt", "advance\n", "master advanced")
                    _git(pusher, "push", "origin", "master")
                    moved_at_deadline["done"] = True
                return (RunVerdict.PASS if val == "good" else RunVerdict.FAIL), ""

            out_defer = attempt_clean_revert(
                repo,
                c_bad2,
                "origin/master",
                verify_near_deadline,
                checks_summary="cmd-a",
                sign_commits=False,
                dry_run=True,
                refresh_master=ctrl_helper._refresh_master,
                worktree_root=tmp / "wts-deadline",
                deadline=1050.0,
                now_fn=lambda: t_clock["now"],
            )
            self.assertTrue(out_defer.pr_creation_failed)
            self.assertFalse(out_defer.meltdown_triggered)

            # 3. Stale open revert PR before a newer green baseline MUST NOT suppress a new regression!
            c_green_new = _commit_file(pusher, "a.txt", "good\n", "fixed a")
            c_reg_new = _commit_file(pusher, "a.txt", "bad-again\n", "broke a again")
            _git(pusher, "push", "origin", "master")
            _git(repo, "fetch", "origin", "+refs/heads/master:refs/remotes/origin/master")
            gh_stale = StubGitHub(open_pr_by_branch={f"revert/{c_bad2[:9]}": "https://example.com/pr/old"})
            state_stale = AgentState(
                open_revert_prs={c_bad2: "https://example.com/pr/old"},
                open_revert_commands={c_bad2: [["just", "fmt-check"]]},
            )
            ctrl_stale = BisectController(
                repo=repo,
                state=state_stale,
                github=gh_stale,
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
                worktree_root=tmp / "wts-stale",
                run_in_wt=lambda wt, _cmd: (
                    RunVerdict.PASS if (wt / "a.txt").read_text(encoding="utf-8").strip() == "good" else RunVerdict.FAIL,
                    "",
                ),
            )
            _cls_new, out_new = ctrl_stale.handle_failure(
                FailureSignal(
                    source="hosted_canary",
                    run_id="700:1",
                    run_url="https://example.com/700",
                    tip_sha=c_reg_new,
                    baseline_sha=c_green_new,
                    failed_job="Rust format",
                    failed_step="Check formatting",
                    command=("just", "fmt-check"),
                ),
                master_ref="origin/master",
            )
            assert out_new is not None
            self.assertEqual(out_new.culprit_sha, c_reg_new)
            self.assertFalse(out_new.duplicate_pr)
            self.assertEqual(len(gh_stale.prs), 1)

            # 4. Second failing command B bisecting to the same culprit with an open revert PR:
            # published revert fixed A, but B still fails on that candidate tree -> MUST NOT mark verified!
            c_ab_base = _commit_file(pusher, "a.txt", "good\n", "restore a good")
            (pusher / "a.txt").write_text("bad-a\n", encoding="utf-8")
            (pusher / "b.txt").write_text("bad-b\n", encoding="utf-8")
            _git(pusher, "add", "a.txt", "b.txt")
            _git(pusher, "commit", "-m", "break A and B")
            c_ab_culprit = _git(pusher, "rev-parse", "HEAD")
            _git(pusher, "push", "origin", "master")
            _git(repo, "fetch", "origin", "+refs/heads/master:refs/remotes/origin/master")

            # Publish a revert PR branch where A is fixed (`good`) but B is STILL broken (`bad-b`).
            rev_branch = f"revert/{c_ab_culprit[:9]}"
            _git(pusher, "checkout", "-b", rev_branch, c_ab_culprit)
            _commit_file(pusher, "a.txt", "good\n", "partial revert fixing A only")
            _git(pusher, "push", "origin", rev_branch)
            _git(pusher, "checkout", "master")

            tree_ab = TreeStateController(repo, dry_run=False, sign_commits=False)
            gh_ab = StubGitHub(open_pr_by_branch={rev_branch: "https://example.com/pr/ab"})
            state_ab = AgentState(
                open_revert_prs={c_ab_culprit: "https://example.com/pr/ab"},
                open_revert_commands={c_ab_culprit: [["cmd-a"]]},
            )
            ctrl_ab = BisectController(
                repo=repo,
                state=state_ab,
                github=gh_ab,
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=tree_ab,
                dry_run=False,
                sign_commits=False,
                worktree_root=tmp / "wts-ab",
                run_in_wt=lambda wt, cmd: (
                    (RunVerdict.PASS if (wt / "b.txt").read_text(encoding="utf-8").strip() == "good" else RunVerdict.FAIL, "")
                    if cmd == ("cmd-b",)
                    else (RunVerdict.PASS if (wt / "a.txt").read_text(encoding="utf-8").strip() == "good" else RunVerdict.FAIL, "")
                ),
            )
            _cls_b, out_b = ctrl_ab.handle_failure(
                FailureSignal(
                    source="hosted_canary",
                    run_id="705:1",
                    run_url="https://example.com/705",
                    tip_sha=c_ab_culprit,
                    baseline_sha=c_ab_base,
                    failed_job="Check B",
                    command=("cmd-b",),
                ),
                master_ref="origin/master",
                fetch_remote=False,
            )
            assert out_b is not None
            self.assertFalse(out_b.revert_verified)
            self.assertTrue(out_b.meltdown_triggered)
            self.assertNotIn(["cmd-b"], state_ab.open_revert_commands.get(c_ab_culprit, []))

            # 5. Exhausted shared poll budget defers sibling job instead of marking it seen!
            budget_clock = {"t": 100.0}
            gh_bud = StubGitHub(
                runs_by_workflow={
                    "canary.yml": [
                        {"id": 720, "run_attempt": 1, "conclusion": "failure", "head_sha": c_ab_culprit, "html_url": "https://example.com/720", "updated_at": "2026-11-26T19:00:00Z"},
                        {"id": 719, "run_attempt": 1, "conclusion": "success", "head_sha": c_ab_base, "html_url": "https://example.com/719", "updated_at": "2026-11-26T18:50:00Z"},
                    ]
                },
                failed_jobs_by_run={
                    720: [
                        {"id": 7201, "name": "Full cross-platform CI (6 shards) / Rust format", "conclusion": "failure", "steps": [{"name": "Check formatting", "conclusion": "failure"}]},
                        {"id": 7202, "name": "Full cross-platform CI (6 shards) / Rust audit", "conclusion": "failure", "steps": [{"name": "Audit Rust dependencies", "conclusion": "failure"}]},
                    ]
                },
            )
            state_bud = AgentState()

            def exhaust_budget_on_job1(_wt: Path, cmd: tuple[str, ...]) -> tuple[RunVerdict, str]:
                if cmd == ("just", "fmt-check"):
                    budget_clock["t"] = 250.0  # Exceeds poll_deadline (100 + 60 = 160)!
                    return RunVerdict.INCONCLUSIVE, "bisect wall-clock budget exceeded"
                raise AssertionError("sibling job 2 must not execute once budget is exhausted")

            ctrl_bud = BisectController(
                repo=repo,
                state=state_bud,
                github=gh_bud,
                alerter=MarmotAlerter(Roster(), dry_run=True),
                tree_state=TreeStateController(repo, dry_run=True, sign_commits=False),
                dry_run=False,
                sign_commits=False,
                bisect_budget_secs=60,
                now_fn=lambda: budget_clock["t"],
                worktree_root=tmp / "wts-bud",
                run_in_wt=exhaust_budget_on_job1,
            )
            res_bud = ctrl_bud.poll_once(hosted_workflows=("canary.yml",), fetch_remote=False)
            self.assertEqual(res_bud["actions"][1]["result"], "budget_exhausted_deferred")
            self.assertNotIn("fail:hosted_canary:720:1:job:7201", state_bud.seen_runs)
            self.assertNotIn("fail:hosted_canary:720:1:job:7202", state_bud.seen_runs)
            self.assertNotIn("fail:hosted_canary:720:1", state_bud.seen_runs)
            self.assertEqual(state_bud.consecutive_infra_failures.get("hosted_canary", 0), 0)

            # 6. Budget exhaustion during stress replay preserves the budget detail so the signal
            # defers without marking seen or incrementing infra counters.
            stress_cls = classify_failure(
                FailureSignal(
                    source="hosted_canary",
                    run_id="725:1",
                    run_url="https://example.com/725",
                    tip_sha=c_ab_culprit,
                    baseline_sha=c_ab_base,
                    failed_job="Rust tests (1/6)",
                    failed_test="cgka-engine::a::flaky_under_stress",
                    command=nextest_command_for_test("cgka-engine", "a", "flaky_under_stress", profile="ci"),
                ),
                run_on_sha=lambda _sha, cmd: (
                    (RunVerdict.INCONCLUSIVE, "bisect wall-clock budget exceeded")
                    if "--stress-count" in cmd
                    else (RunVerdict.PASS, "passed single shot")
                ),
                stress_count=5,
            )
            self.assertEqual(stress_cls.bucket, Bucket.INFRA_ERROR)
            self.assertIn("bisect wall-clock budget exceeded", stress_cls.reason)


if __name__ == "__main__":
    unittest.main()
