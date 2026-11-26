"""Always-on revert-only Bisect Agent controller and CLI."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

from .classifier import (
    classify_failure,
    evaluate_command_result,
    extract_bare_metal_signal,
    extract_hosted_signal,
    is_non_linux_job,
    match_issue_by_title,
)
from .models import (
    AgentState,
    BisectOutcome,
    Bucket,
    ClassificationResult,
    FailureSignal,
    IncidentRecord,
    RunVerdict,
    load_state,
    save_state,
)
from .notify import MarmotAlerter, Roster, TreeStateController, sanitize_single_line
from .reverter import (
    attempt_clean_revert,
    bisect_culprit,
    cleanup_stale_worktrees,
    is_ancestor_or_equal,
    resolve_commit,
    run_in_detached_worktree,
)

ESCALATION_WINDOW_SECS = 30 * 60
DEFAULT_COMMAND_TIMEOUT_SECS = 1800
DEFAULT_BISECT_BUDGET_SECS = 3600

# Wrapper/planner jobs in hosted Canary (may appear directly or nested as `.../ Required CI`).
HOSTED_WRAPPER_JOBS = ("Plan Canary batch", "Record Canary summary", "Required CI")

# Safe environment keys passed to build/test predicates. Explicitly excludes bot
# credentials (GH_TOKEN, GITHUB_TOKEN, SSH_AUTH_SOCK, GIT_SSH_COMMAND, HOME, etc.).
PREDICATE_ENV_ALLOWLIST = (
    "PATH",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "ODIN",
    "ANDROID_NDK_HOME",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "CARGO_TERM_COLOR",
    "CARGO_INCREMENTAL",
    "CARGO_PROFILE_DEV_DEBUG",
    "CARGO_PROFILE_TEST_DEBUG",
    "RUST_MIN_STACK",
    "CC_wasm32_unknown_unknown",
    "CC_aarch64_linux_android",
    "AR_aarch64_linux_android",
    "RANLIB_aarch64_linux_android",
    "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER",
    "CARGO_TARGET_AARCH64_LINUX_ANDROID_AR",
)


def is_wrapper_job(job_name: str) -> bool:
    """Return True when `job_name` is a Canary planner/summary/gate wrapper job."""
    return any(job_name == w or job_name.endswith(f"/ {w}") for w in HOSTED_WRAPPER_JOBS)


def first_failed_step_name(job: dict[str, Any]) -> str:
    """Return the first failed step name from a GitHub Actions job object, if present."""
    steps = job.get("steps")
    if not isinstance(steps, list):
        return ""
    for step in steps:
        if isinstance(step, dict) and step.get("conclusion") in {"failure", "timed_out"}:
            return str(step.get("name") or "")
    return ""


class GitHubOps:
    """Minimal `gh`-backed GitHub client (mockable in tests, read-only in dry-run)."""

    def __init__(self, repo: str, *, dry_run: bool = True) -> None:
        self.repo = repo
        self.dry_run = dry_run

    def _run_gh(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["gh", *args],
            check=check,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def open_flake_issues(self) -> list[dict[str, Any]]:
        res = self._run_gh(
            "issue",
            "list",
            "--repo",
            self.repo,
            "--state",
            "open",
            "--limit",
            "200",
            "--json",
            "number,title,body,labels",
            check=False,
        )
        if res.returncode != 0:
            return []
        try:
            data = json.loads(res.stdout)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []

    def recent_workflow_runs(self, workflow: str, *, limit: int = 10) -> list[dict[str, Any]]:
        res = self._run_gh(
            "api",
            f"repos/{self.repo}/actions/workflows/{workflow}/runs?branch=master&status=completed&per_page={limit}",
            check=False,
        )
        if res.returncode != 0:
            return []
        try:
            doc = json.loads(res.stdout)
            runs = doc.get("workflow_runs")
            return runs if isinstance(runs, list) else []
        except json.JSONDecodeError:
            return []

    def jobs_for_run(self, run_id: int) -> list[dict[str, Any]] | None:
        """Return the jobs list for `run_id`, or `None` when the GitHub API call fails."""
        res = self._run_gh(
            "api",
            f"repos/{self.repo}/actions/runs/{run_id}/jobs?per_page=100",
            check=False,
        )
        if res.returncode != 0:
            return None
        try:
            doc = json.loads(res.stdout)
            jobs = doc.get("jobs")
            return jobs if isinstance(jobs, list) else None
        except json.JSONDecodeError:
            return None

    def failed_jobs_for_run(self, run_id: int) -> list[dict[str, Any]] | None:
        jobs = self.jobs_for_run(run_id)
        if jobs is None:
            return None
        return [
            job
            for job in jobs
            if job.get("conclusion") in {"failure", "timed_out", "cancelled"}
            and not is_wrapper_job(str(job.get("name") or ""))
        ]

    def hosted_run_verification_status(self, run_id: int) -> str:
        """Return `verified`, `skipped`, or `error` for a completed hosted Canary run."""
        jobs = self.jobs_for_run(run_id)
        if jobs is None:
            return "error"
        verified_jobs = [
            job
            for job in jobs
            if not is_wrapper_job(str(job.get("name") or ""))
            and job.get("conclusion") == "success"
        ]
        return "verified" if verified_jobs else "skipped"

    def job_log_tail(self, run_id: int, job_id: int, *, lines: int = 120) -> str:
        res = self._run_gh(
            "run",
            "view",
            str(run_id),
            "--repo",
            self.repo,
            "--job",
            str(job_id),
            "--log",
            check=False,
        )
        if res.returncode != 0:
            return ""
        return "\n".join(res.stdout.splitlines()[-lines:])

    def commit_author_login(self, sha: str) -> str:
        res = self._run_gh(
            "api",
            f"repos/{self.repo}/commits/{sha}",
            "--jq",
            '.author.login // .commit.author.name // ""',
            check=False,
        )
        return res.stdout.strip() if res.returncode == 0 else ""

    def find_open_revert_pr(self, branch: str) -> str:
        """Return URL of an existing open PR for `branch`, or empty string if none."""
        res = self._run_gh(
            "pr",
            "list",
            "--repo",
            self.repo,
            "--state",
            "open",
            "--head",
            branch,
            "--json",
            "url",
            "--jq",
            '.[0].url // ""',
            check=False,
        )
        return res.stdout.strip() if res.returncode == 0 else ""

    def rerun_failed_jobs(self, run_id: str) -> None:
        base_id = run_id.split(":", 1)[0]
        if self.dry_run or not base_id.isdigit():
            return
        self._run_gh("run", "rerun", base_id, "--failed", "--repo", self.repo, check=False)

    def dispatch_canary(self) -> None:
        if self.dry_run:
            return
        self._run_gh(
            "workflow",
            "run",
            "canary.yml",
            "--repo",
            self.repo,
            "--ref",
            "master",
            "-f",
            "force=true",
            check=False,
        )

    def open_or_comment_issue(
        self,
        *,
        title: str,
        body: str,
        issue_number: int | None = None,
    ) -> int | None:
        if self.dry_run:
            return issue_number
        if issue_number is not None:
            self._run_gh(
                "issue",
                "comment",
                str(issue_number),
                "--repo",
                self.repo,
                "--body",
                body,
                check=False,
            )
            return issue_number
        res = self._run_gh(
            "issue",
            "create",
            "--repo",
            self.repo,
            "--title",
            title,
            "--body",
            body,
            check=False,
        )
        if res.returncode == 0:
            tail = res.stdout.strip().rsplit("/", 1)[-1]
            if tail.isdigit():
                return int(tail)
        return None

    def open_revert_pr(self, branch: str, title: str, body: str) -> str:
        if self.dry_run:
            return f"dry-run://pr/{branch}"
        res = self._run_gh(
            "pr",
            "create",
            "--repo",
            self.repo,
            "--base",
            "master",
            "--head",
            branch,
            "--label",
            "revert",
            "--title",
            title,
            "--body",
            body,
            check=False,
        )
        return res.stdout.strip() if res.returncode == 0 else ""


def build_sanitized_predicate_env(
    *,
    sandbox_home: Path,
    cargo_target_dir: Path | None = None,
    source_env: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build a minimal environment for running repo build/test predicates without bot secrets."""
    src = os.environ if source_env is None else source_env
    env: dict[str, str] = {}
    for key in PREDICATE_ENV_ALLOWLIST:
        if key in src:
            env[key] = src[key]
    env["HOME"] = str(sandbox_home)
    env["XDG_CONFIG_HOME"] = str(sandbox_home / ".config")
    if cargo_target_dir is not None:
        cargo_target_dir.mkdir(parents=True, exist_ok=True)
        env["CARGO_TARGET_DIR"] = str(cargo_target_dir)
    return env


def default_worktree_runner(
    command: tuple[str, ...],
    *,
    timeout_secs: int = DEFAULT_COMMAND_TIMEOUT_SECS,
    cargo_target_dir: Path | None = None,
    runner_prefix: tuple[str, ...] = (),
) -> Callable[[Path], tuple[RunVerdict, str]]:
    """Return a WorktreePredicate executing `command` with scrubbed env, timeout, and optional OS isolation."""

    def _run(wt: Path) -> tuple[RunVerdict, str]:
        with tempfile.TemporaryDirectory(prefix="mdk-pred-home-") as home_tmp:
            sandbox = Path(home_tmp)
            env = build_sanitized_predicate_env(
                sandbox_home=sandbox,
                cargo_target_dir=cargo_target_dir,
            )
            if runner_prefix:
                # Pass scrubbed env explicitly after `runner_prefix` so `sudo`'s default
                # `env_reset` does not drop `CARGO_TARGET_DIR`, `ODIN`, or `ANDROID_NDK_HOME`.
                os.chmod(sandbox, 0o777)
                env_pairs = [f"{k}={v}" for k, v in sorted(env.items())]
                argv = [*runner_prefix, "env", "-i", *env_pairs, *command]
            else:
                argv = list(command)
            try:
                proc = subprocess.run(
                    argv,
                    cwd=wt,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=timeout_secs,
                )
            except subprocess.TimeoutExpired:
                return RunVerdict.INCONCLUSIVE, f"command timed out after {timeout_secs}s"
            output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            return evaluate_command_result(proc.returncode, output, command)

    return _run


class BisectController:
    """Stateful revert-only Bisect Agent with Meltdown freeze & auto-recovery."""

    def __init__(
        self,
        *,
        repo: Path,
        state: AgentState,
        github: Any,
        alerter: MarmotAlerter,
        tree_state: TreeStateController,
        dry_run: bool = True,
        sign_commits: bool = True,
        stress_count: int = 10,
        timeout_secs: int = DEFAULT_COMMAND_TIMEOUT_SECS,
        bisect_budget_secs: int = DEFAULT_BISECT_BUDGET_SECS,
        cargo_target_dir: Path | None = None,
        runner_prefix: tuple[str, ...] = (),
        now_fn: Callable[[], float] = time.time,
        worktree_root: Path | None = None,
        on_state_change: Callable[[AgentState], None] | None = None,
        run_in_wt: Callable[[Path, tuple[str, ...]], tuple[RunVerdict, str]] | None = None,
    ) -> None:
        self.repo = repo
        self.state = state
        self.github = github
        self.alerter = alerter
        self.tree_state = tree_state
        self.dry_run = dry_run
        self.sign_commits = sign_commits
        self.stress_count = stress_count
        self.timeout_secs = timeout_secs
        self.bisect_budget_secs = bisect_budget_secs
        self.cargo_target_dir = cargo_target_dir
        self.runner_prefix = runner_prefix
        self.now_fn = now_fn
        self.worktree_root = worktree_root
        self._on_state_change = on_state_change
        self._run_in_wt = run_in_wt

    def _persist(self) -> None:
        if self._on_state_change is not None:
            self._on_state_change(self.state)

    def _rerun_once(self, run_id: str) -> bool:
        """Request a GitHub Actions failed-job rerun at most once per base run_id."""
        base_id = run_id.split(":", 1)[0]
        if not base_id or base_id in self.state.retried_runs:
            return False
        self.state.mark_retried(base_id)
        self.github.rerun_failed_jobs(run_id)
        return True

    def _exec_in_wt(
        self,
        wt: Path,
        command: tuple[str, ...],
        *,
        deadline: float | None = None,
    ) -> tuple[RunVerdict, str]:
        if deadline is not None:
            remaining = int(deadline - self.now_fn())
            if remaining <= 0:
                return RunVerdict.INCONCLUSIVE, "bisect wall-clock budget exceeded"
            effective_timeout = min(self.timeout_secs, remaining)
        else:
            effective_timeout = self.timeout_secs
        if self._run_in_wt is not None:
            return self._run_in_wt(wt, command)
        return default_worktree_runner(
            command,
            timeout_secs=effective_timeout,
            cargo_target_dir=self.cargo_target_dir,
            runner_prefix=self.runner_prefix,
        )(wt)

    def _run_on_sha(self, sha: str, command: tuple[str, ...]) -> tuple[RunVerdict, str]:
        return run_in_detached_worktree(
            self.repo,
            sha,
            lambda wt: self._exec_in_wt(wt, command),
            worktree_root=self.worktree_root,
        )

    def refresh_repo(self) -> None:
        """Fetch latest master, canary, and tree-state refs from origin (best-effort)."""
        for branch in ("master", "canary", "tree-state"):
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.repo),
                    "fetch",
                    "--no-tags",
                    "origin",
                    f"+refs/heads/{branch}:refs/remotes/origin/{branch}",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )

    def handle_green_canary(
        self,
        *,
        source: str,
        sha: str,
        run_id: str,
        run_url: str,
    ) -> bool:
        """Clear a source's incident on a green at/after its failing SHA; unfreeze once all sources recover."""
        seen_key = f"green:{source}:{run_id}"
        inc = self.state.active_incidents.get(source)

        # A green run on an older SHA than the active incident cannot clear that incident.
        if inc is not None and not is_ancestor_or_equal(self.repo, inc.tip_sha, sha):
            self.state.mark_seen(seen_key)
            self._persist()
            return False

        remaining = {k: v for k, v in self.state.active_incidents.items() if k != source}
        remote_needs_reconcile = (
            not remaining
            and self.state.tree_state != "red"
            and inc is None
            and not self.dry_run
            and self.tree_state.read_remote_status() == "red"
        )
        would_clear_tree = not remaining and (
            self.state.tree_state == "red" or inc is not None or remote_needs_reconcile
        )

        # Perform remote tree-state write BEFORE marking the green run seen so a
        # transient git/network failure is retried cleanly on the next poll.
        if would_clear_tree:
            reason = f"{source} recovered green on {sha[:9]}"
            try:
                self.tree_state.set_state("green", reason=reason, run_url=run_url)
            except Exception as exc:
                self.alerter.notify_engineering_group(
                    f"MDK ops alert: failed to clear tree-state to GREEN ({source} @ {sha[:9]}): "
                    f"{sanitize_single_line(str(exc))}"
                )
                return False

        self.state.consecutive_unreproducible_reds[source] = 0
        self.state.consecutive_infra_failures[source] = 0
        self.state.active_incidents = remaining
        self.state.mark_seen(seen_key)
        if would_clear_tree:
            self.state.tree_state = "green"
            self.state.open_revert_prs.clear()
        # Persist recovered state BEFORE best-effort issue comments / alerts.
        self._persist()

        if inc is not None and inc.issue_number is not None:
            run_line = f" ({run_url})" if run_url else ""
            self.github.open_or_comment_issue(
                title=f"Recovered {source}",
                body=f"{source} recovered green on `{sha[:9]}`{run_line}.",
                issue_number=inc.issue_number,
            )

        if would_clear_tree:
            ref_suffix = f": {run_url}" if run_url else ""
            self.alerter.notify_engineering_group(
                f"MDK tree-state cleared to GREEN ({source} @ {sha[:9]}){ref_suffix}"
            )
        return would_clear_tree

    def check_escalation(self) -> bool:
        """Escalate any active Meltdown incident still open after 30 minutes."""
        now = self.now_fn()
        escalated = False
        for inc in self.state.active_incidents.values():
            if inc.escalated_at is not None:
                continue
            if now - inc.started_at < ESCALATION_WINDOW_SECS:
                continue
            inc.escalated_at = now
            self._persist()
            ref_suffix = f", run {inc.run_url}" if inc.run_url else ""
            self.alerter.notify_engineering_group(
                f"ESCALATION (>30m): MDK tree-state=RED ({inc.source}) — {inc.reason} "
                f"(tip {inc.tip_sha[:9]}{ref_suffix})"
            )
            escalated = True
        return escalated

    def _find_open_revert_pr(self, culprit_sha: str, branch: str) -> str:
        cached = self.state.open_revert_prs.get(culprit_sha, "")
        live = self.github.find_open_revert_pr(branch)
        if live:
            self.state.open_revert_prs[culprit_sha] = live
            return live
        if cached and not self.dry_run:
            self.state.open_revert_prs.pop(culprit_sha, None)
            return ""
        return cached

    def _trigger_meltdown(
        self,
        *,
        reason: str,
        signal: FailureSignal,
        culprit_sha: str | None,
        notified: list[str],
        seen_key: str,
        issue_title: str | None = None,
        issue_body: str | None = None,
    ) -> bool:
        """Freeze `origin/tree-state` to red, persist the incident immediately, then notify.

        Persisting the incident BEFORE opening issues or delivering alerts ensures a
        timeout/crash during notification can never leave `origin/tree-state` red with
        local state green.
        """
        clean_reason = sanitize_single_line(reason, max_len=240)
        try:
            self.tree_state.set_state(
                "red",
                reason=clean_reason,
                run_url=signal.run_url or None,
            )
        except Exception as exc:
            self.alerter.notify_engineering_group(
                f"MDK ops alert: FAILED to set tree-state=RED ({signal.source} @ {signal.tip_sha[:9]}): "
                f"{sanitize_single_line(str(exc))}"
            )
            return False

        self.state.tree_state = "red"
        existing = self.state.active_incidents.get(signal.source)
        if existing is None or is_ancestor_or_equal(self.repo, existing.tip_sha, signal.tip_sha):
            self.state.active_incidents[signal.source] = IncidentRecord(
                started_at=existing.started_at if existing is not None else self.now_fn(),
                reason=clean_reason,
                run_url=signal.run_url,
                tip_sha=signal.tip_sha,
                source=signal.source,
                culprit_sha=culprit_sha,
                issue_number=existing.issue_number if existing else None,
                escalated_at=existing.escalated_at if existing is not None else None,
            )
        self.state.mark_seen(seen_key)
        self._persist()

        if issue_title and issue_body:
            issue_number = self.github.open_or_comment_issue(title=issue_title, body=issue_body)
            if issue_number is not None and signal.source in self.state.active_incidents:
                self.state.active_incidents[signal.source].issue_number = issue_number
                self._persist()

        ref_suffix = f" Run: {signal.run_url}" if signal.run_url else ""
        self.alerter.notify_authors(
            notified,
            f"MELTDOWN (MDK tree-state=RED, {signal.source}): {clean_reason}. "
            f"Culprit: {culprit_sha[:9] if culprit_sha else 'unknown'}.{ref_suffix}",
        )
        return True

    def handle_failure(
        self,
        signal: FailureSignal,
        *,
        master_ref: str = "origin/master",
        poll_deadline: float | None = None,
    ) -> tuple[ClassificationResult, BisectOutcome | None]:
        """Classify and respond to a single Canary failure signal."""
        seen_key = f"fail:{signal.source}:{signal.run_id}"
        open_issues = self.github.open_flake_issues()
        effective_deadline = poll_deadline if poll_deadline is not None else (self.now_fn() + self.bisect_budget_secs)
        classification = classify_failure(
            signal,
            run_on_sha=lambda sha, cmd: run_in_detached_worktree(
                self.repo,
                sha,
                lambda wt: self._exec_in_wt(wt, cmd, deadline=effective_deadline),
                worktree_root=self.worktree_root,
            ),
            open_flake_issues=open_issues,
            stress_count=self.stress_count,
        )

        # Bucket 1: Infra / baseline environment error -> retry at most once per base run; alert ops.
        if classification.bucket == Bucket.INFRA_ERROR:
            self.state.consecutive_unreproducible_reds[signal.source] = 0
            infra_count = self.state.consecutive_infra_failures.get(signal.source, 0) + 1
            self.state.consecutive_infra_failures[signal.source] = infra_count
            self.state.mark_seen(seen_key)
            self._rerun_once(signal.run_id)
            self._persist()
            if infra_count >= 2 or "baseline break:" in classification.reason:
                ref_suffix = f" ({signal.run_url})" if signal.run_url else ""
                self.alerter.notify_engineering_group(
                    f"MDK ops alert ({signal.source}): {classification.reason}{ref_suffix}"
                )
            return classification, None

        self.state.consecutive_infra_failures[signal.source] = 0

        # Bucket 2: Known flake -> comment on existing issue, retry at most once per base run, alert on 2 blocks.
        if classification.bucket == Bucket.KNOWN_FLAKE:
            self.state.consecutive_unreproducible_reds[signal.source] = 0
            self.state.mark_seen(seen_key)
            flake_key = signal.failed_test or signal.failed_job
            hits = self.state.consecutive_flake_blocks.get(flake_key, 0) + 1
            self.state.consecutive_flake_blocks[flake_key] = hits
            self._rerun_once(signal.run_id)
            self._persist()
            run_line = f"\n\nRun: {signal.run_url}" if signal.run_url else ""
            self.github.open_or_comment_issue(
                title=f"Flaky: {flake_key}",
                body=(
                    f"Canary hit known flake `{flake_key}` on `{signal.tip_sha[:9]}`: "
                    f"{sanitize_single_line(classification.reason)}{run_line}"
                ),
                issue_number=classification.matched_issue,
            )
            if hits >= 2:
                ref_suffix = f": {signal.run_url}" if signal.run_url else ""
                self.alerter.notify_engineering_group(
                    f"MDK known flake `{flake_key}` blocked {signal.source} {hits} times in a row{ref_suffix}"
                )
            return classification, None

        # Bucket 3: Suspected new intermittent race -> comment on existing issue (or open once) and notify.
        if classification.bucket == Bucket.NEW_INTERMITTENT:
            self.state.consecutive_unreproducible_reds[signal.source] = 0
            self.state.mark_seen(seen_key)
            key = signal.failed_test or signal.failed_job
            hits = self.state.intermittent_hits.get(key, 0) + 1
            self.state.intermittent_hits[key] = hits
            self._persist()
            issue_title = f"New-Intermittent: {key}"
            existing_issue = match_issue_by_title(issue_title, open_issues)
            run_line = f"\n\nRun: {signal.run_url}" if signal.run_url else ""
            body = (
                f"Suspected new intermittent failure in `{key}` across "
                f"`{signal.baseline_sha[:9]}..{signal.tip_sha[:9]}` "
                f"(hit #{hits}; {sanitize_single_line(classification.reason)}).{run_line}"
            )
            self.github.open_or_comment_issue(
                title=issue_title,
                body=body,
                issue_number=existing_issue,
            )
            ref_suffix = f": {signal.run_url}" if signal.run_url else ""
            self.alerter.notify_engineering_group(
                f"MDK New-Intermittent ({key}, hit #{hits}) in {signal.baseline_sha[:9]}..{signal.tip_sha[:9]}{ref_suffix}"
            )
            return classification, None

        # Bucket 5: Non-Linux, unparsed, or missing-baseline failure -> rerun once, Meltdown on 2 consecutive.
        if classification.bucket == Bucket.UNREPRODUCIBLE:
            unrepro_reds = self.state.consecutive_unreproducible_reds.get(signal.source, 0) + 1
            if unrepro_reds >= 2:
                author = self.github.commit_author_login(signal.tip_sha)
                step_note = f" (step `{signal.failed_step}`)" if signal.failed_step else ""
                kind = "non-Linux job" if is_non_linux_job(signal.failed_job) else "unreproducible job"
                reason = f"2 consecutive red {signal.source} runs on {kind} `{signal.failed_job}`{step_note}"
                self.state.consecutive_unreproducible_reds[signal.source] = unrepro_reds
                frozen = self._trigger_meltdown(
                    reason=reason,
                    signal=signal,
                    culprit_sha=None,
                    notified=[author] if author else [],
                    seen_key=seen_key,
                )
                return classification, BisectOutcome(
                    culprit_sha=None,
                    meltdown_triggered=frozen,
                    reason=reason if frozen else f"failed to freeze tree-state for {signal.failed_job}",
                )
            self.state.consecutive_unreproducible_reds[signal.source] = unrepro_reds
            self.state.mark_seen(seen_key)
            self._rerun_once(signal.run_id)
            self._persist()
            return classification, BisectOutcome(
                culprit_sha=None,
                meltdown_triggered=False,
                reason=classification.reason,
            )

        # Bucket 4: Deterministic regression -> bounded bisect + strictly revert-only recovery.
        # Reserve up to one timeout window after bisect for live-master recheck + revert verification.
        self.state.consecutive_unreproducible_reds[signal.source] = 0
        bisect_deadline = effective_deadline
        revert_deadline = max(effective_deadline, self.now_fn() + self.timeout_secs)
        bisect_predicate = lambda wt: self._exec_in_wt(wt, signal.command, deadline=bisect_deadline)
        revert_predicate = lambda wt: self._exec_in_wt(wt, signal.command, deadline=revert_deadline)
        culprit_sha, bisect_reason = bisect_culprit(
            self.repo,
            signal.baseline_sha,
            signal.tip_sha,
            bisect_predicate,
            worktree_root=self.worktree_root,
            deadline=bisect_deadline,
            now_fn=self.now_fn,
        )
        if culprit_sha is None:
            reason = sanitize_single_line(f"unisolatable failure: {bisect_reason}")
            frozen = self._trigger_meltdown(
                reason=reason,
                signal=signal,
                culprit_sha=None,
                notified=[],
                seen_key=seen_key,
            )
            return classification, BisectOutcome(
                culprit_sha=None,
                meltdown_triggered=frozen,
                reason=reason,
            )

        branch_name = f"revert/{culprit_sha[:9]}"
        existing_pr = self._find_open_revert_pr(culprit_sha, branch_name)
        if existing_pr:
            self.state.mark_seen(seen_key)
            self._persist()
            return classification, BisectOutcome(
                culprit_sha=culprit_sha,
                clean_revert=True,
                revert_verified=True,
                revert_branch=branch_name,
                revert_pr_url=existing_pr,
                duplicate_pr=True,
                meltdown_triggered=False,
                reason=f"revert PR already open for {culprit_sha[:9]}: {existing_pr}",
            )

        checks_summary = " ".join(signal.command)
        outcome = attempt_clean_revert(
            self.repo,
            culprit_sha,
            master_ref,
            revert_predicate,
            checks_summary=checks_summary,
            run_url=signal.run_url,
            sign_commits=self.sign_commits,
            dry_run=self.dry_run,
            open_revert_pr=self.github.open_revert_pr,
            find_existing_pr=self.github.find_open_revert_pr,
            worktree_root=self.worktree_root,
        )
        if outcome.already_healed:
            self.state.mark_seen(seen_key)
            self._persist()
            return classification, outcome

        if outcome.pr_creation_failed:
            ref_suffix = f" ({signal.run_url})" if signal.run_url else ""
            self.alerter.notify_engineering_group(
                f"MDK Bisect Agent verified revert for {culprit_sha[:9]} but PR creation failed; will retry{ref_suffix}"
            )
            return classification, outcome

        author = self.github.commit_author_login(culprit_sha) or outcome.culprit_author_login
        if outcome.clean_revert and outcome.revert_verified:
            self.state.mark_seen(seen_key)
            if outcome.revert_pr_url:
                self.state.open_revert_prs[culprit_sha] = outcome.revert_pr_url
            self._persist()
            run_line = f"\n- Canary run: {signal.run_url}" if signal.run_url else ""
            self.github.open_or_comment_issue(
                title=f"Reverted {culprit_sha[:9]}: {outcome.culprit_subject}",
                body=(
                    f"Bisect Agent isolated `{culprit_sha}` (`{outcome.culprit_subject}`) "
                    f"for `{signal.failed_job}` and verified a clean revert.\n\n"
                    f"- Revert PR: {outcome.revert_pr_url or outcome.revert_branch}\n"
                    f"- Command: `{checks_summary}`{run_line}"
                ),
            )
            self.github.dispatch_canary()
            self.alerter.notify_authors(
                [author] if author else [],
                f"MDK Bisect Agent reverted {culprit_sha[:9]} ({outcome.culprit_subject}) "
                f"after {signal.failed_job} failed: {outcome.revert_pr_url or outcome.revert_branch}",
            )
            return classification, outcome

        # Tangled revert or revert failed to restore green -> Meltdown Mode.
        safe_reason = sanitize_single_line(outcome.reason)
        run_line = f"\n\nRun: {signal.run_url}" if signal.run_url else ""
        frozen = self._trigger_meltdown(
            reason=safe_reason,
            signal=signal,
            culprit_sha=culprit_sha,
            notified=[author] if author else [],
            seen_key=seen_key,
            issue_title=f"Meltdown: {signal.failed_job} failed on {culprit_sha[:9]}",
            issue_body=(
                f"Bisect Agent isolated `{culprit_sha}` (`{outcome.culprit_subject}`) "
                f"but could not apply a clean verified revert: {safe_reason}\n\n"
                f"Tree state is frozen (`tree-state=red`). Apply `tree-fix` or `revert` label "
                f"to the recovery PR.{run_line}"
            ),
        )
        return classification, BisectOutcome(
            culprit_sha=outcome.culprit_sha,
            culprit_subject=outcome.culprit_subject,
            culprit_author_login=outcome.culprit_author_login,
            clean_revert=outcome.clean_revert,
            revert_verified=outcome.revert_verified,
            revert_branch=outcome.revert_branch,
            meltdown_triggered=frozen,
            reason=safe_reason,
        )

    def _resolve_hosted_baseline(self, ordered_runs: list[dict[str, Any]], tip_sha: str) -> str:
        """Pick the newest distinct ancestor green baseline SHA for a failed hosted run.

        Skipped hosted Canary `success` runs only occur when the prior run on that SHA
        already passed, so any `success` run's SHA that is a strict ancestor of `tip_sha`
        is a valid baseline. Falls back to `origin/canary` if all recent runs are red.
        """
        for cand in ordered_runs:
            if cand.get("conclusion") != "success":
                continue
            sha = str(cand.get("head_sha") or "")
            if sha and sha != tip_sha and is_ancestor_or_equal(self.repo, sha, tip_sha):
                return sha
        canary_sha = resolve_commit(self.repo, "origin/canary")
        if canary_sha and canary_sha != tip_sha and is_ancestor_or_equal(self.repo, canary_sha, tip_sha):
            return canary_sha
        return ""

    def _has_newer_green_for(self, ordered_runs: list[dict[str, Any]], failed_sha: str) -> bool:
        """Return True when a recent `success` run already passed on a strict descendant of `failed_sha`."""
        for cand in ordered_runs:
            if cand.get("conclusion") != "success":
                continue
            sha = str(cand.get("head_sha") or "")
            if sha and sha != failed_sha and is_ancestor_or_equal(self.repo, failed_sha, sha):
                return True
        return False

    def poll_once(
        self,
        *,
        bare_metal_status_path: Path | None = None,
        hosted_workflows: tuple[str, ...] = ("canary.yml",),
        master_ref: str = "origin/master",
        fetch_remote: bool = True,
    ) -> dict[str, Any]:
        """Run one poll cycle across bare-metal status and hosted Canary runs."""
        actions: list[dict[str, Any]] = []
        poll_deadline = self.now_fn() + self.bisect_budget_secs
        cleanup_stale_worktrees(self.repo, self.worktree_root)
        if fetch_remote:
            self.refresh_repo()

        # 1. Inspect local bare-metal Canary status if present.
        if bare_metal_status_path and bare_metal_status_path.is_file():
            try:
                doc = json.loads(bare_metal_status_path.read_text(encoding="utf-8"))
                state_str = str(doc.get("state") or "")
                sha = str(doc.get("sha") or "")
                run_key = f"bare-metal:{sha[:12]}:{doc.get('updated_at', '')}"
                if state_str == "green" and f"green:bare_metal_canary:{run_key}" not in self.state.seen_runs:
                    cleared = self.handle_green_canary(
                        source="bare_metal_canary",
                        sha=sha,
                        run_id=run_key,
                        run_url="",
                    )
                    actions.append({"source": "bare_metal_canary", "result": "green", "cleared_meltdown": cleared})
                elif state_str == "red" and f"fail:bare_metal_canary:{run_key}" not in self.state.seen_runs:
                    log_path = Path(str(doc.get("log") or ""))
                    log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
                    signal = extract_bare_metal_signal(doc, log_text)
                    classification, outcome = self.handle_failure(
                        signal, master_ref=master_ref, poll_deadline=poll_deadline
                    )
                    actions.append(
                        {
                            "source": "bare_metal_canary",
                            "bucket": classification.bucket.value,
                            "reason": classification.reason,
                            "culprit": outcome.culprit_sha if outcome else None,
                            "meltdown": outcome.meltdown_triggered if outcome else False,
                        }
                    )
            except Exception as exc:
                actions.append(
                    {
                        "source": "bare_metal_canary",
                        "error": sanitize_single_line(f"{type(exc).__name__}: {exc}"),
                    }
                )

        # 2. Inspect recent completed hosted Canary runs on master.
        for workflow in hosted_workflows:
            source = "hosted_canary"
            try:
                runs = self.github.recent_workflow_runs(workflow, limit=10)
                if not runs:
                    continue
                ordered = sorted(
                    runs,
                    key=lambda r: (str(r.get("updated_at") or r.get("created_at") or ""), int(r.get("id") or 0)),
                    reverse=True,
                )
                latest = ordered[0]
                raw_id = str(latest.get("id") or "")
                attempt = int(latest.get("run_attempt") or 1)
                attempt_key = f"{raw_id}:{attempt}"
                conclusion = str(latest.get("conclusion") or "")
                head_sha = str(latest.get("head_sha") or "")
                run_url = str(latest.get("html_url") or "")

                if conclusion == "success" and f"green:{source}:{attempt_key}" not in self.state.seen_runs:
                    status = (
                        self.github.hosted_run_verification_status(int(raw_id))
                        if raw_id.isdigit()
                        else "error"
                    )
                    if status == "error":
                        actions.append({"source": workflow, "result": "jobs_api_error", "cleared_meltdown": False})
                    elif status == "skipped":
                        # If a skipped run arrived after an earlier verified green on the exact
                        # same SHA (e.g. a transient jobs API error delayed recovery), recover
                        # using that verified green run rather than losing it behind the skip.
                        recovered_via: dict[str, Any] | None = None
                        if source in self.state.active_incidents:
                            for cand in ordered[1:]:
                                if cand.get("conclusion") != "success" or str(cand.get("head_sha") or "") != head_sha:
                                    continue
                                cid = cand.get("id")
                                if isinstance(cid, int) and self.github.hosted_run_verification_status(cid) == "verified":
                                    recovered_via = cand
                                    break
                        if recovered_via is not None:
                            cleared = self.handle_green_canary(
                                source=source,
                                sha=head_sha,
                                run_id=attempt_key,
                                run_url=str(recovered_via.get("html_url") or run_url),
                            )
                            actions.append({"source": workflow, "result": "green", "cleared_meltdown": cleared})
                        else:
                            self.state.mark_seen(f"green:{source}:{attempt_key}")
                            self._persist()
                            actions.append({"source": workflow, "result": "skipped_green", "cleared_meltdown": False})
                    else:
                        cleared = self.handle_green_canary(
                            source=source, sha=head_sha, run_id=attempt_key, run_url=run_url
                        )
                        actions.append({"source": workflow, "result": "green", "cleared_meltdown": cleared})
                elif conclusion in {"failure", "timed_out"} and f"fail:{source}:{attempt_key}" not in self.state.seen_runs:
                    # Ignore a stale failed rerun on an older commit when a newer commit already passed green.
                    if self._has_newer_green_for(ordered, head_sha):
                        self.state.mark_seen(f"fail:{source}:{attempt_key}")
                        self._persist()
                        actions.append({"source": workflow, "result": "stale_failure_ignored"})
                        continue
                    failed_jobs = self.github.failed_jobs_for_run(int(raw_id)) if raw_id.isdigit() else None
                    if failed_jobs is None:
                        # Transient GitHub API failure: leave unseen so the next poll retries cleanly.
                        actions.append({"source": workflow, "result": "jobs_api_error"})
                        continue
                    first_job = failed_jobs[0] if failed_jobs else {"id": 0, "name": workflow, "conclusion": conclusion}
                    failed_step = first_failed_step_name(first_job)
                    log_text = (
                        self.github.job_log_tail(int(raw_id), int(first_job["id"]))
                        if raw_id.isdigit() and first_job.get("id")
                        else ""
                    )
                    prev_green = self._resolve_hosted_baseline(ordered, head_sha)
                    signal = extract_hosted_signal(
                        source=source,
                        run_id=attempt_key,
                        run_url=run_url,
                        tip_sha=head_sha,
                        baseline_sha=prev_green,
                        failed_job=str(first_job.get("name") or workflow),
                        failed_step=failed_step,
                        log_text=log_text,
                        conclusion=str(first_job.get("conclusion") or conclusion),
                    )
                    classification, outcome = self.handle_failure(
                        signal, master_ref=master_ref, poll_deadline=poll_deadline
                    )
                    actions.append(
                        {
                            "source": workflow,
                            "bucket": classification.bucket.value,
                            "reason": classification.reason,
                            "culprit": outcome.culprit_sha if outcome else None,
                            "meltdown": outcome.meltdown_triggered if outcome else False,
                        }
                    )
            except Exception as exc:
                actions.append(
                    {
                        "source": workflow,
                        "error": sanitize_single_line(f"{type(exc).__name__}: {exc}"),
                    }
                )

        escalated = self.check_escalation()
        return {
            "dry_run": self.dry_run,
            "actions": actions,
            "escalated": escalated,
            "tree_state": self.state.tree_state,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MDK always-on revert-only Bisect Agent")
    sub = parser.add_subparsers(dest="command", required=True)

    poll = sub.add_parser("poll", help="Run one poll pass across bare-metal and hosted Canary")
    poll.add_argument("--repo", default="marmot-protocol/mdk")
    poll.add_argument("--repo-dir", type=Path, default=Path("/srv/mdk/repo"))
    poll.add_argument("--state-file", type=Path, default=Path("/srv/mdk/state/bisect-state.json"))
    poll.add_argument("--canary-status", type=Path, default=Path("/srv/mdk/state/canary-status.json"))
    poll.add_argument("--roster", type=Path, default=Path("/srv/mdk/bisect-roster.json"))
    poll.add_argument("--worktree-root", type=Path, default=Path("/srv/mdk/worktrees/bisect"))
    poll.add_argument("--cargo-target-dir", type=Path, default=Path("/srv/mdk/target-bisect"))
    poll.add_argument("--timeout-secs", type=int, default=DEFAULT_COMMAND_TIMEOUT_SECS)
    poll.add_argument("--bisect-budget-secs", type=int, default=DEFAULT_BISECT_BUDGET_SECS)
    poll.add_argument("--stress-count", type=int, default=10)
    poll.add_argument(
        "--predicate-runner-prefix",
        default="",
        help="Command prefix isolating build/test predicates from the signing bot UID (e.g. 'sudo -n -u mdk-runner --'); required for --live",
    )
    poll.add_argument("--no-fetch", action="store_true", help="Skip git fetch before polling")
    poll.add_argument("--live", action="store_true", help="Execute real pushes/PRs/alerts (default: dry-run)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    dry_run = not args.live
    runner_prefix = tuple(shlex.split(args.predicate_runner_prefix)) if args.predicate_runner_prefix else ()
    if not dry_run and not runner_prefix:
        print(
            "error: --live requires --predicate-runner-prefix (e.g. 'sudo -n -u mdk-runner --') "
            "so build/test predicates never run under the signing bot's UID",
            file=sys.stderr,
        )
        return 2

    state = load_state(args.state_file)
    roster = Roster.load(args.roster)
    alerter = MarmotAlerter(roster, dry_run=dry_run)
    tree_ctrl = TreeStateController(args.repo_dir, dry_run=dry_run)
    gh = GitHubOps(args.repo, dry_run=dry_run)
    ctrl = BisectController(
        repo=args.repo_dir,
        state=state,
        github=gh,
        alerter=alerter,
        tree_state=tree_ctrl,
        dry_run=dry_run,
        stress_count=args.stress_count,
        timeout_secs=args.timeout_secs,
        bisect_budget_secs=args.bisect_budget_secs,
        cargo_target_dir=args.cargo_target_dir,
        runner_prefix=runner_prefix,
        worktree_root=args.worktree_root,
        on_state_change=(None if dry_run else (lambda s: save_state(args.state_file, s))),
    )
    summary = ctrl.poll_once(
        bare_metal_status_path=args.canary_status,
        fetch_remote=not args.no_fetch,
    )
    print(json.dumps(summary, indent=2))
    return 0
