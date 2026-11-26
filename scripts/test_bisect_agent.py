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

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.bisect_agent.classifier import (
    HOSTED_STEP_COMMANDS,
    classify_failure,
    evaluate_command_result,
    extract_bare_metal_signal,
    extract_hosted_signal,
    nextest_command_for_test,
    parse_first_nextest_failure,
    stress_command,
)
from scripts.bisect_agent.controller import (
    BisectController,
    build_sanitized_predicate_env,
    default_worktree_runner,
    is_wrapper_job,
    main as cli_main,
)
from scripts.bisect_agent.models import (
    AgentState,
    Bucket,
    FailureSignal,
    RunVerdict,
    load_state,
    save_state,
)
from scripts.bisect_agent.notify import MarmotAlerter, Roster, TreeStateController
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
    repo.mkdir()
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
        failed_jobs_by_run: dict[int, list[dict]] | None = None,
        logs_by_job: dict[int, str] | None = None,
        open_pr_by_branch: dict[str, str] | None = None,
        fail_pr_create: bool = False,
        fail_issue_create: bool = False,
    ) -> None:
        self._open_issues = list(open_issues or [])
        self._author = author
        self.runs_by_workflow = runs_by_workflow or {}
        self.verification_status_by_run = dict(verification_status_by_run or {})
        self.failed_jobs_by_run = failed_jobs_by_run or {}
        self.logs_by_job = logs_by_job or {}
        self.open_pr_by_branch = dict(open_pr_by_branch or {})
        self.fail_pr_create = fail_pr_create
        self.fail_issue_create = fail_issue_create
        self.reruns: list[str] = []
        self.dispatches: int = 0
        self.issues: list[dict] = []
        self.prs: list[dict] = []

    def open_flake_issues(self):
        return self._open_issues

    def recent_workflow_runs(self, workflow: str, *, limit: int = 10):
        return list(self.runs_by_workflow.get(workflow, []))[:limit]

    def hosted_run_verification_status(self, run_id: int) -> str:
        return self.verification_status_by_run.get(run_id, "skipped")

    def failed_jobs_for_run(self, run_id: int):
        if run_id in self.failed_jobs_by_run:
            return self.failed_jobs_by_run[run_id]
        return []

    def job_log_tail(self, _run_id: int, job_id: int, *, lines: int = 120) -> str:
        return "\n".join(self.logs_by_job.get(job_id, "").splitlines()[-lines:])

    def commit_author_login(self, _sha: str) -> str:
        return self._author

    def find_open_revert_pr(self, branch: str) -> str:
        return self.open_pr_by_branch.get(branch, "")

    def rerun_failed_jobs(self, run_id: str) -> None:
        self.reruns.append(run_id)

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

            # Newer-SHA green c2 clears hosted incident and restores tree-state=green.
            self.assertTrue(ctrl.handle_green_canary(source="hosted_canary", sha=c2, run_id="103:1", run_url=""))
            self.assertEqual(tree_ctrl.read_remote_status(), "green")


if __name__ == "__main__":
    unittest.main()
