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
    extract_bare_metal_signals,
    extract_hosted_signal,
    extract_hosted_signals,
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
from .notify import (
    MarmotAlerter,
    Roster,
    TreeStateController,
    is_manual_freeze_document,
    sanitize_single_line,
)
from .reverter import (
    attempt_clean_revert,
    bisect_culprit,
    cleanup_stale_worktrees,
    commit_ancestry,
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

    def _run_gh_safe(self, *args: str) -> subprocess.CompletedProcess[str] | None:
        try:
            return self._run_gh(*args, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return None

    def open_flake_issues(self) -> list[dict[str, Any]]:
        res = self._run_gh_safe(
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
        )
        if res is None or res.returncode != 0:
            return []
        try:
            data = json.loads(res.stdout)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []

    def recent_workflow_runs(self, workflow: str, *, limit: int = 10) -> list[dict[str, Any]]:
        res = self._run_gh_safe(
            "api",
            f"repos/{self.repo}/actions/workflows/{workflow}/runs?branch=master&status=completed&per_page={limit}",
        )
        if res is None or res.returncode != 0:
            return []
        try:
            doc = json.loads(res.stdout)
            runs = doc.get("workflow_runs")
            return runs if isinstance(runs, list) else []
        except json.JSONDecodeError:
            return []

    def jobs_for_run(self, run_id: int, *, attempt: int | None = None) -> list[dict[str, Any]] | None:
        """Return the jobs list for `run_id` (bound to `attempt` when given), or `None` on API failure."""
        if attempt is not None:
            endpoint = f"repos/{self.repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"
        else:
            endpoint = f"repos/{self.repo}/actions/runs/{run_id}/jobs?per_page=100"
        res = self._run_gh_safe("api", endpoint)
        if res is None or res.returncode != 0:
            return None
        try:
            doc = json.loads(res.stdout)
            jobs = doc.get("jobs")
            return jobs if isinstance(jobs, list) else None
        except json.JSONDecodeError:
            return None

    def failed_jobs_for_run(self, run_id: int, *, attempt: int | None = None) -> list[dict[str, Any]] | None:
        jobs = self.jobs_for_run(run_id, attempt=attempt)
        if jobs is None:
            return None
        return [
            job
            for job in jobs
            if job.get("conclusion") in {"failure", "timed_out", "cancelled"}
            and not is_wrapper_job(str(job.get("name") or ""))
        ]

    def hosted_run_verification_status(self, run_id: int, *, attempt: int | None = None) -> str:
        """Return `verified`, `skipped`, or `error` for a completed hosted Canary run attempt."""
        jobs = self.jobs_for_run(run_id, attempt=attempt)
        if jobs is None:
            return "error"
        verified_jobs = [
            job
            for job in jobs
            if not is_wrapper_job(str(job.get("name") or ""))
            and job.get("conclusion") == "success"
        ]
        return "verified" if verified_jobs else "skipped"

    def job_log(self, _run_id: int, job_id: int) -> str | None:
        """Fetch full job log so failure records earlier than the tail remain detectable.

        Reads the jobs logs API: `gh run view --job <id> --log` prints nothing (exit 0) for
        jobs of a called workflow, and every hosted Canary test job runs inside `ci.yml`.
        Returns `None` on GitHub API/CLI failure or timeout so callers defer and retry
        rather than treating an unavailable log as an empty unparsed job.
        """
        res = self._run_gh_safe("api", f"repos/{self.repo}/actions/jobs/{job_id}/logs")
        if res is None or res.returncode != 0:
            return None
        return res.stdout

    def job_log_tail(self, run_id: int, job_id: int, *, lines: int = 120) -> str | None:
        full_log = self.job_log(run_id, job_id)
        if full_log is None:
            return None
        if not full_log:
            return ""
        return "\n".join(full_log.splitlines()[-lines:])

    def commit_author_login(self, sha: str) -> str:
        res = self._run_gh_safe(
            "api",
            f"repos/{self.repo}/commits/{sha}",
            "--jq",
            '.author.login // .commit.author.name // ""',
        )
        return res.stdout.strip() if res is not None and res.returncode == 0 else ""

    def find_open_revert_pr(self, branch: str) -> str | None:
        """Return open PR URL for `branch`, `""` when confirmed absent, or `None` on lookup error."""
        res = self._run_gh_safe(
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
        )
        if res is None or res.returncode != 0:
            return None
        return res.stdout.strip()

    def rerun_failed_jobs(self, run_id: str) -> bool:
        """Request a failed-jobs rerun on GitHub; return True only when accepted (or dry-run)."""
        base_id = run_id.split(":", 1)[0]
        if not base_id.isdigit():
            return False
        if self.dry_run:
            return True
        res = self._run_gh_safe("run", "rerun", base_id, "--failed", "--repo", self.repo)
        return res is not None and res.returncode == 0

    def dispatch_canary(self) -> None:
        if self.dry_run:
            return
        self._run_gh_safe(
            "workflow",
            "run",
            "canary.yml",
            "--repo",
            self.repo,
            "--ref",
            "master",
            "-f",
            "force=true",
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
            self._run_gh_safe(
                "issue",
                "comment",
                str(issue_number),
                "--repo",
                self.repo,
                "--body",
                body,
            )
            return issue_number
        res = self._run_gh_safe(
            "issue",
            "create",
            "--repo",
            self.repo,
            "--title",
            title,
            "--body",
            body,
        )
        if res is not None and res.returncode == 0:
            tail = res.stdout.strip().rsplit("/", 1)[-1]
            if tail.isdigit():
                return int(tail)
        return None

    def open_revert_pr(self, branch: str, title: str, body: str) -> str:
        if self.dry_run:
            return f"dry-run://pr/{branch}"
        res = self._run_gh_safe(
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
        )
        return res.stdout.strip() if res is not None and res.returncode == 0 else ""


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
        if cargo_target_dir is not None:
            # nextest keeps its store at `<workspace>/target/nextest` whatever
            # `CARGO_TARGET_DIR` says, and the isolated runner cannot write the bot-owned
            # worktree. Point the worktree's `target` at the target dir the runner owns.
            cargo_target_dir.mkdir(parents=True, exist_ok=True)
            worktree_target = wt / "target"
            if not worktree_target.exists() and not worktree_target.is_symlink():
                worktree_target.symlink_to(cargo_target_dir.resolve(), target_is_directory=True)
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

    def _rerun_once(self, run_id: str) -> str:
        """Request a GitHub Actions failed-job rerun at most once per base run_id.

        Returns one of:
          - `not_applicable`: non-GitHub run id (e.g. bare-metal)
          - `already_retried`: base run id was already retried
          - `retried`: GitHub accepted the rerun request (recorded in `retried_runs`)
          - `failed`: GitHub rejected or timed out the rerun request (left unrecorded)
        """
        base_id = run_id.split(":", 1)[0]
        if not base_id or not base_id.isdigit():
            return "not_applicable"
        if base_id in self.state.retried_runs:
            return "already_retried"
        accepted = bool(self.github.rerun_failed_jobs(run_id))
        if not accepted:
            return "failed"
        self.state.mark_retried(base_id)
        return "retried"

    @staticmethod
    def _attempt_key_from_run_id(run_id: str) -> str:
        if ":job:" in run_id:
            return run_id.split(":job:", 1)[0]
        return run_id

    @staticmethod
    def _serialize_incidents(incidents: dict[str, IncidentRecord]) -> dict[str, dict[str, Any]]:
        serialized: dict[str, dict[str, Any]] = {}
        for source, inc in sorted(incidents.items()):
            serialized[source] = {
                "source": inc.source,
                "tip_sha": inc.tip_sha,
                "started_at": inc.started_at,
                "reason": sanitize_single_line(inc.reason, max_len=240),
                "run_url": inc.run_url if inc.run_url.startswith(("http://", "https://")) else "",
                "culprit_sha": inc.culprit_sha,
            }
        return serialized

    @staticmethod
    def _is_full_sha(value: Any) -> bool:
        return isinstance(value, str) and len(value) == 40 and all(ch in "0123456789abcdefABCDEF" for ch in value)

    @classmethod
    def _parse_remote_incidents(cls, doc: dict[str, Any] | None) -> dict[str, IncidentRecord]:
        if not isinstance(doc, dict):
            return {}
        raw = doc.get("incidents")
        if not isinstance(raw, dict):
            return {}
        parsed: dict[str, IncidentRecord] = {}
        for key, item in raw.items():
            if not isinstance(item, dict):
                continue
            source = str(item.get("source") or key).strip()
            tip_sha = item.get("tip_sha")
            if not source or not cls._is_full_sha(tip_sha):
                continue
            started_raw = item.get("started_at")
            started_at = float(started_raw) if isinstance(started_raw, (int, float)) else 0.0
            reason = str(item.get("reason") or doc.get("reason") or "remote freeze")
            run_url = str(item.get("run_url") or "")
            culprit_raw = item.get("culprit_sha")
            culprit_sha = str(culprit_raw) if cls._is_full_sha(culprit_raw) else None
            parsed[source] = IncidentRecord(
                started_at=started_at,
                reason=reason,
                run_url=run_url,
                tip_sha=str(tip_sha),
                source=source,
                culprit_sha=culprit_sha,
            )
        return parsed

    def _hydrate_remote_incidents(self) -> tuple[str, bool, str]:
        """Reconcile authoritative freeze membership and manual state from `origin/tree-state:state.json`.

        Returns `(remote_status, manual_freeze, remote_rev)`:
          - Uses the remote document as the source of truth for active incident membership
            and manual freeze status (never keeping stale local incidents after a remote
            unfreeze, remote partial recovery, or operator manual freeze).
          - Preserves local-only UI metadata (`issue_number`, `escalated_at`, earlier
            `started_at`) only for incidents that remain present remotely.
          - Returns `remote_rev` so subsequent transitions bind compare-and-swap to the exact
            remote revision that was inspected.
        """
        if self.dry_run or self.tree_state.dry_run:
            return self.state.tree_state, False, ""
        remote_status, remote_doc, remote_rev = self.tree_state.read_remote_snapshot()
        if remote_status in {"error", "absent"}:
            return remote_status, False, ""
        if remote_status == "green":
            changed = self.state.tree_state != "green" or bool(self.state.active_incidents)
            self.state.tree_state = "green"
            self.state.active_incidents = {}
            if changed:
                self._persist()
            return "green", False, remote_rev

        # remote_status == "red"
        remote_incidents = self._parse_remote_incidents(remote_doc)
        manual_freeze = is_manual_freeze_document(remote_doc)
        synced: dict[str, IncidentRecord] = {}
        for source, remote_inc in remote_incidents.items():
            local_inc = self.state.active_incidents.get(source)
            if local_inc is not None and (
                local_inc.tip_sha == remote_inc.tip_sha
                or commit_ancestry(self.repo, local_inc.tip_sha, remote_inc.tip_sha) is True
            ):
                remote_inc.issue_number = local_inc.issue_number
                remote_inc.escalated_at = local_inc.escalated_at
                if local_inc.started_at:
                    remote_inc.started_at = min(
                        local_inc.started_at,
                        remote_inc.started_at or local_inc.started_at,
                    )
            synced[source] = remote_inc

        changed = self.state.tree_state != "red" or synced != self.state.active_incidents
        self.state.tree_state = "red"
        self.state.active_incidents = synced
        if changed:
            self._persist()
        return "red", manual_freeze, remote_rev

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

    def refresh_repo(self) -> list[str]:
        """Fetch latest master, canary, and tree-state refs from origin (best-effort)."""
        errors: list[str] = []
        for branch in ("master", "canary", "tree-state"):
            try:
                res = subprocess.run(
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
                if res.returncode != 0:
                    errors.append(f"fetch {branch}: exit {res.returncode}")
            except subprocess.TimeoutExpired:
                errors.append(f"fetch {branch}: timed out after 120s")
            except OSError as exc:
                errors.append(f"fetch {branch}: {sanitize_single_line(str(exc), max_len=120)}")
        return errors

    def _refresh_master(self) -> bool:
        """Fetch `origin/master` before live-master recheck and revert publication."""
        try:
            res = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.repo),
                    "fetch",
                    "--no-tags",
                    "origin",
                    "+refs/heads/master:refs/remotes/origin/master",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
            return res.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def handle_green_canary(
        self,
        *,
        source: str,
        sha: str,
        run_id: str,
        run_url: str,
    ) -> bool:
        """Clear a source's recorded incident on a green at/after its failing SHA; unfreeze once all clear."""
        seen_key = f"green:{source}:{run_id}"
        remote_status, manual_freeze, remote_rev = self._hydrate_remote_incidents()
        live_tree_state = not (self.dry_run or self.tree_state.dry_run)
        if live_tree_state and remote_status in {"error", "absent"}:
            # Cannot verify remote tree-state or incidents; leave unseen so next poll retries.
            return False
        inc = self.state.active_incidents.get(source)

        # Keep recovery pending when commit ancestry is unknown (e.g. git fetch failed and `sha`
        # is missing locally); only mark seen and skip when `sha` is confirmed older than `inc.tip_sha`.
        if inc is not None:
            ancestry = commit_ancestry(self.repo, inc.tip_sha, sha)
            if ancestry is None:
                return False
            if not ancestry:
                self.state.mark_seen(seen_key)
                self._persist()
                return False

        remaining = {k: v for k, v in self.state.active_incidents.items() if k != source}
        # Only a recorded incident with matching source and qualifying SHA can clear a freeze.
        # A manual or unknown-boundary remote freeze (`manual_freeze=True`) is never cleared automatically.
        would_clear_tree = (inc is not None) and (not remaining) and (not manual_freeze)
        partial_recovery = (inc is not None) and bool(remaining) and (not manual_freeze)
        expected_rev = remote_rev if (live_tree_state and remote_rev) else None

        # Perform remote tree-state write BEFORE marking the green run seen so a
        # transient git/network failure or concurrent CAS mismatch is retried cleanly.
        if would_clear_tree:
            reason = f"{source} recovered green on {sha[:9]}"
            try:
                self.tree_state.set_state(
                    "green",
                    reason=reason,
                    run_url=run_url,
                    incidents={},
                    expected_rev=expected_rev,
                )
            except Exception as exc:
                self.alerter.notify_engineering_group(
                    f"MDK ops alert: failed to clear tree-state to GREEN ({source} @ {sha[:9]}): "
                    f"{sanitize_single_line(str(exc))}"
                )
                return False
        elif partial_recovery:
            # Keep remote durable incidents in sync while other frozen sources remain active.
            remaining_sources = ", ".join(sorted(remaining))
            reason = f"{source} recovered on {sha[:9]}; still frozen for {remaining_sources}"
            try:
                self.tree_state.set_state(
                    "red",
                    reason=reason,
                    run_url=run_url,
                    incidents=self._serialize_incidents(remaining),
                    expected_rev=expected_rev,
                )
            except Exception as exc:
                self.alerter.notify_engineering_group(
                    f"MDK ops alert: failed to update tree-state incidents after {source} recovery: "
                    f"{sanitize_single_line(str(exc))}"
                )
                return False

        self.state.consecutive_unreproducible_reds[source] = 0
        self.state.consecutive_infra_failures[source] = 0
        self.state.last_unreproducible_attempt.pop(source, None)
        self.state.last_infra_attempt.pop(source, None)
        flake_prefix = f"{source}:"
        for key in [k for k in self.state.consecutive_flake_blocks if k.startswith(flake_prefix)]:
            self.state.consecutive_flake_blocks.pop(key, None)

        if not manual_freeze:
            self.state.active_incidents = remaining
        self.state.mark_seen(seen_key)
        if would_clear_tree:
            self.state.tree_state = "green"
            self.state.open_revert_prs.clear()
            self.state.open_revert_commands.clear()
        # Persist recovered state BEFORE best-effort issue comments / alerts.
        self._persist()

        if inc is not None and inc.issue_number is not None and not manual_freeze:
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
        elif manual_freeze:
            self.alerter.notify_engineering_group(
                f"MDK ops notice: {source} passed green on {sha[:9]}, but remote tree-state=RED "
                "is a manual/external freeze; leaving tree frozen for manual reconciliation"
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
            ref_suffix = f", run {inc.run_url}" if inc.run_url else ""
            accepted = self.alerter.notify_engineering_group(
                f"ESCALATION (>30m): MDK tree-state=RED ({inc.source}) — {inc.reason} "
                f"(tip {inc.tip_sha[:9]}{ref_suffix})"
            )
            if not accepted:
                continue
            inc.escalated_at = now
            self._persist()
            escalated = True
        return escalated

    def _record_open_revert_command(self, culprit_sha: str, command: tuple[str, ...]) -> None:
        if not command:
            return
        cmd_list = list(command)
        recorded = self.state.open_revert_commands.setdefault(culprit_sha, [])
        if cmd_list not in recorded:
            recorded.append(cmd_list)

    def _find_open_revert_pr(self, culprit_sha: str, branch: str) -> str | None:
        """Return open PR URL, `""` when confirmed absent, or `None` when lookup failed."""
        cached = self.state.open_revert_prs.get(culprit_sha, "")
        live = self.github.find_open_revert_pr(branch)
        if live is None:
            return None
        if live:
            self.state.open_revert_prs[culprit_sha] = live
            return live
        if cached and not self.dry_run:
            self.state.open_revert_prs.pop(culprit_sha, None)
            self.state.open_revert_commands.pop(culprit_sha, None)
            return ""
        return cached

    def _resolve_open_revert_branch_sha(self, branch_name: str, *, fetch_remote: bool) -> str | None:
        """Resolve the pinned head SHA of an open revert PR branch."""
        if fetch_remote:
            try:
                res = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.repo),
                        "fetch",
                        "--no-tags",
                        "origin",
                        f"+refs/heads/{branch_name}:refs/remotes/origin/{branch_name}",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except (subprocess.TimeoutExpired, OSError):
                return None
            if res.returncode != 0:
                return None
            return resolve_commit(self.repo, f"refs/remotes/origin/{branch_name}")

        sha = resolve_commit(self.repo, f"refs/remotes/origin/{branch_name}")
        if sha is not None:
            return sha
        sha = resolve_commit(self.repo, f"refs/heads/{branch_name}")
        if sha is not None:
            return sha
        # Offline synthetic tests push to a local bare `origin`; fetch that single branch if needed.
        try:
            res = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.repo),
                    "fetch",
                    "--no-tags",
                    "origin",
                    f"+refs/heads/{branch_name}:refs/remotes/origin/{branch_name}",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
        if res.returncode != 0:
            return None
        return resolve_commit(self.repo, f"refs/remotes/origin/{branch_name}")

    def _recheck_fresh_master_before_freeze(
        self,
        *,
        master_ref: str,
        command: tuple[str, ...],
        fetch_remote: bool,
    ) -> tuple[str, str]:
        """Re-check fresh `master_ref` before triggering Meltdown on an unverified failure.

        Returns `(status, detail)` where `status` is:
          - `healed`: refreshed master now passes (`PASS` / `TEST_ABSENT`)
          - `still_broken`: refreshed master still fails
          - `deferred`: fetch failed or check was inconclusive (caller should retry next poll)
        """
        if fetch_remote and not self._refresh_master():
            return "deferred", f"failed to refresh {master_ref} before freezing; will retry"
        master_sha = resolve_commit(self.repo, master_ref)
        if master_sha is None:
            return "deferred", f"could not resolve {master_ref} before freezing; will retry"
        verify_deadline = self.now_fn() + self.timeout_secs
        verdict, detail = run_in_detached_worktree(
            self.repo,
            master_sha,
            lambda wt: self._exec_in_wt(wt, command, deadline=verify_deadline),
            worktree_root=self.worktree_root,
            deadline=verify_deadline,
            now_fn=self.now_fn,
        )
        if verdict in {RunVerdict.PASS, RunVerdict.TEST_ABSENT}:
            return "healed", f"master {master_sha[:9]} already passes ({verdict.value}); freeze skipped"
        if verdict == RunVerdict.INCONCLUSIVE:
            return "deferred", f"inconclusive fresh-master recheck on {master_sha[:9]} ({detail}); will retry"
        if fetch_remote:
            if not self._refresh_master():
                return "deferred", f"failed to reconfirm {master_ref} after fresh-master check; will retry"
            latest_sha = resolve_commit(self.repo, master_ref)
            if latest_sha != master_sha:
                return (
                    "deferred",
                    f"{master_ref} advanced during fresh-master recheck ({master_sha[:9]} -> "
                    f"{latest_sha[:9] if latest_sha else 'unknown'}); will retry",
                )
        return "still_broken", detail

    def _check_covered_by_open_revert_pr(
        self,
        signal: FailureSignal,
        seen_key: str,
    ) -> tuple[ClassificationResult, BisectOutcome] | None:
        """Short-circuit before classification/bisect when an open revert PR already covers this failure.

        Only matches when `culprit_sha` lies strictly inside `(signal.baseline_sha, signal.tip_sha]`
        and the exact failing command was already verified against that open revert PR, so an old
        open revert PR from before a newer green baseline can never suppress a new regression.
        """
        if not signal.command or not signal.baseline_sha or not self.state.open_revert_prs:
            return None
        target_cmd = list(signal.command)
        for culprit_sha in list(self.state.open_revert_prs):
            recorded_cmds = self.state.open_revert_commands.get(culprit_sha, [])
            if target_cmd not in recorded_cmds:
                continue
            if culprit_sha == signal.baseline_sha:
                continue
            if commit_ancestry(self.repo, signal.baseline_sha, culprit_sha) is not True:
                continue
            if commit_ancestry(self.repo, culprit_sha, signal.tip_sha) is not True:
                continue
            branch_name = f"revert/{culprit_sha[:9]}"
            existing = self._find_open_revert_pr(culprit_sha, branch_name)
            if existing is None:
                return (
                    ClassificationResult(
                        bucket=Bucket.DETERMINISTIC_REGRESSION,
                        reason=f"deferred duplicate check for open revert PR covering {culprit_sha[:9]}",
                    ),
                    BisectOutcome(
                        culprit_sha=culprit_sha,
                        revert_branch=branch_name,
                        pr_creation_failed=True,
                        meltdown_triggered=False,
                        reason=f"failed to confirm open revert PR status for {culprit_sha[:9]}; will retry",
                    ),
                )
            if existing:
                self.state.mark_seen(seen_key)
                self._persist()
                return (
                    ClassificationResult(
                        bucket=Bucket.DETERMINISTIC_REGRESSION,
                        reason=f"skipped duplicate bisect: open revert PR {existing} already covers {culprit_sha[:9]}",
                    ),
                    BisectOutcome(
                        culprit_sha=culprit_sha,
                        clean_revert=True,
                        revert_verified=True,
                        revert_branch=branch_name,
                        revert_pr_url=existing,
                        duplicate_pr=True,
                        meltdown_triggered=False,
                        reason=f"revert PR already open for {culprit_sha[:9]}: {existing}",
                    ),
                )
        return None

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
        """Freeze `origin/tree-state` to red with durable incident metadata, persist locally, then notify.

        Re-hydrates authoritative remote state first and binds the push with compare-and-swap
        (`expected_rev`) so removed incidents are never resurrected and an operator's manual
        freeze is never overwritten with an agent-clearable incident.
        """
        clean_reason = sanitize_single_line(reason, max_len=240)
        remote_status, manual_freeze, remote_rev = self._hydrate_remote_incidents()
        live_tree_state = not (self.dry_run or self.tree_state.dry_run)
        if live_tree_state and remote_status in {"error", "absent"}:
            self.alerter.notify_engineering_group(
                f"MDK ops alert: FAILED to read origin/tree-state before freezing ({signal.source} @ {signal.tip_sha[:9]}): "
                f"remote status={remote_status}"
            )
            return False

        if manual_freeze:
            # Remote already holds a manual/operator freeze; keep it intact so a subsequent
            # automated green can never clear it, while still recording alerts/issues.
            self.state.tree_state = "red"
            self.state.mark_seen(seen_key)
            self._persist()
            if issue_title and issue_body:
                self.github.open_or_comment_issue(title=issue_title, body=issue_body)
            ref_suffix = f" Run: {signal.run_url}" if signal.run_url else ""
            self.alerter.notify_authors(
                notified,
                f"MELTDOWN (MDK tree-state=RED [manual freeze preserved], {signal.source}): {clean_reason}. "
                f"Culprit: {culprit_sha[:9] if culprit_sha else 'unknown'}.{ref_suffix}",
            )
            return True

        next_incidents = dict(self.state.active_incidents)
        existing = next_incidents.get(signal.source)
        if existing is None or commit_ancestry(self.repo, existing.tip_sha, signal.tip_sha) is not False:
            next_incidents[signal.source] = IncidentRecord(
                started_at=existing.started_at if existing is not None else self.now_fn(),
                reason=clean_reason,
                run_url=signal.run_url,
                tip_sha=signal.tip_sha,
                source=signal.source,
                culprit_sha=culprit_sha,
                issue_number=existing.issue_number if existing else None,
                escalated_at=existing.escalated_at if existing is not None else None,
            )

        expected_rev = remote_rev if (live_tree_state and remote_rev) else None
        try:
            self.tree_state.set_state(
                "red",
                reason=clean_reason,
                run_url=signal.run_url or None,
                incidents=self._serialize_incidents(next_incidents),
                expected_rev=expected_rev,
            )
        except Exception as exc:
            self.alerter.notify_engineering_group(
                f"MDK ops alert: FAILED to set tree-state=RED ({signal.source} @ {signal.tip_sha[:9]}): "
                f"{sanitize_single_line(str(exc))}"
            )
            return False

        self.state.tree_state = "red"
        self.state.active_incidents = next_incidents
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
        fetch_remote: bool = False,
        attempt_key: str | None = None,
        reset_sibling_counters: bool = True,
    ) -> tuple[ClassificationResult, BisectOutcome | None]:
        """Classify and respond to a single Canary failure signal."""
        seen_key = f"fail:{signal.source}:{signal.run_id}"
        covered = self._check_covered_by_open_revert_pr(signal, seen_key)
        if covered is not None:
            return covered
        eff_attempt = attempt_key or self._attempt_key_from_run_id(signal.run_id)
        open_issues = self.github.open_flake_issues()
        effective_deadline = poll_deadline if poll_deadline is not None else (self.now_fn() + self.bisect_budget_secs)
        classification = classify_failure(
            signal,
            run_on_sha=lambda sha, cmd: run_in_detached_worktree(
                self.repo,
                sha,
                lambda wt: self._exec_in_wt(wt, cmd, deadline=effective_deadline),
                worktree_root=self.worktree_root,
                deadline=effective_deadline,
                now_fn=self.now_fn,
            ),
            open_flake_issues=open_issues,
            stress_count=self.stress_count,
        )

        # Shared poll-budget exhaustion during reproduction/stress is NOT a real failure or
        # infrastructure outage: defer without marking seen, rerunning, or incrementing counters.
        if (
            classification.bucket == Bucket.INFRA_ERROR
            and "bisect wall-clock budget exceeded" in classification.reason
        ):
            return classification, BisectOutcome(
                culprit_sha=None,
                pr_creation_failed=True,
                meltdown_triggered=False,
                reason=classification.reason,
            )

        # Bucket 1: Infra / baseline environment error -> retry at most once per base run; alert ops.
        if classification.bucket == Bucket.INFRA_ERROR:
            rerun_status = self._rerun_once(signal.run_id)
            if rerun_status == "failed":
                return classification, None
            if reset_sibling_counters:
                self.state.consecutive_unreproducible_reds[signal.source] = 0
                self.state.last_unreproducible_attempt.pop(signal.source, None)
            if self.state.last_infra_attempt.get(signal.source) != eff_attempt:
                infra_count = self.state.consecutive_infra_failures.get(signal.source, 0) + 1
                self.state.consecutive_infra_failures[signal.source] = infra_count
                self.state.last_infra_attempt[signal.source] = eff_attempt
            else:
                infra_count = self.state.consecutive_infra_failures.get(signal.source, 0)
            self.state.mark_seen(seen_key)
            self._persist()
            if infra_count >= 2 or "baseline break:" in classification.reason:
                ref_suffix = f" ({signal.run_url})" if signal.run_url else ""
                self.alerter.notify_engineering_group(
                    f"MDK ops alert ({signal.source}): {classification.reason}{ref_suffix}"
                )
            return classification, None

        if reset_sibling_counters:
            self.state.consecutive_infra_failures[signal.source] = 0
            self.state.last_infra_attempt.pop(signal.source, None)

        # Bucket 2: Known flake -> comment on existing issue, retry at most once per base run, alert on 2 blocks.
        if classification.bucket == Bucket.KNOWN_FLAKE:
            rerun_status = self._rerun_once(signal.run_id)
            if rerun_status == "failed":
                return classification, None
            if reset_sibling_counters:
                self.state.consecutive_unreproducible_reds[signal.source] = 0
                self.state.last_unreproducible_attempt.pop(signal.source, None)
            self.state.mark_seen(seen_key)
            flake_key = signal.failed_test or signal.failed_job
            counter_key = f"{signal.source}:{flake_key}"
            hits = self.state.consecutive_flake_blocks.get(counter_key, 0) + 1
            self.state.consecutive_flake_blocks[counter_key] = hits
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
            if reset_sibling_counters:
                self.state.consecutive_unreproducible_reds[signal.source] = 0
                self.state.last_unreproducible_attempt.pop(signal.source, None)
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

        # Bucket 5: Non-Linux, unparsed, or missing-baseline failure -> rerun once, Meltdown on 2 consecutive runs.
        if classification.bucket == Bucket.UNREPRODUCIBLE:
            already_counted = self.state.last_unreproducible_attempt.get(signal.source) == eff_attempt
            unrepro_reds = self.state.consecutive_unreproducible_reds.get(signal.source, 0) + (
                0 if already_counted else 1
            )
            if unrepro_reds >= 2:
                author = self.github.commit_author_login(signal.tip_sha)
                step_note = f" (step `{signal.failed_step}`)" if signal.failed_step else ""
                kind = "non-Linux job" if is_non_linux_job(signal.failed_job) else "unreproducible job"
                reason = f"2 consecutive red {signal.source} runs on {kind} `{signal.failed_job}`{step_note}"
                self.state.consecutive_unreproducible_reds[signal.source] = unrepro_reds
                self.state.last_unreproducible_attempt[signal.source] = eff_attempt
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
            rerun_status = self._rerun_once(signal.run_id)
            if rerun_status == "failed":
                return classification, BisectOutcome(
                    culprit_sha=None,
                    meltdown_triggered=False,
                    reason=f"failed to request rerun for {signal.failed_job}; will retry",
                )
            self.state.consecutive_unreproducible_reds[signal.source] = unrepro_reds
            self.state.last_unreproducible_attempt[signal.source] = eff_attempt
            self.state.mark_seen(seen_key)
            self._persist()
            return classification, BisectOutcome(
                culprit_sha=None,
                meltdown_triggered=False,
                reason=classification.reason,
            )

        # Bucket 4: Deterministic regression -> bounded bisect + strictly revert-only recovery.
        if reset_sibling_counters:
            self.state.consecutive_unreproducible_reds[signal.source] = 0
            self.state.last_unreproducible_attempt.pop(signal.source, None)
        bisect_deadline = effective_deadline
        bisect_predicate = lambda wt: self._exec_in_wt(wt, signal.command, deadline=bisect_deadline)
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
            if "bisect wall-clock budget exceeded" in bisect_reason:
                return classification, BisectOutcome(
                    culprit_sha=None,
                    pr_creation_failed=True,
                    meltdown_triggered=False,
                    reason=sanitize_single_line(f"deferred bisect: {bisect_reason}"),
                )
            if fetch_remote:
                recheck_status, recheck_detail = self._recheck_fresh_master_before_freeze(
                    master_ref=master_ref,
                    command=signal.command,
                    fetch_remote=True,
                )
                if recheck_status == "healed":
                    self.state.mark_seen(seen_key)
                    self._persist()
                    return classification, BisectOutcome(
                        culprit_sha=None,
                        already_healed=True,
                        meltdown_triggered=False,
                        reason=recheck_detail,
                    )
                if recheck_status == "deferred":
                    return classification, BisectOutcome(
                        culprit_sha=None,
                        pr_creation_failed=True,
                        meltdown_triggered=False,
                        reason=recheck_detail,
                    )
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
        if existing_pr is None:
            # Lookup failed transiently: keep cached URL, leave unseen, and defer publication.
            return classification, BisectOutcome(
                culprit_sha=culprit_sha,
                revert_branch=branch_name,
                pr_creation_failed=True,
                meltdown_triggered=False,
                reason=f"failed to query existing revert PRs for {culprit_sha[:9]}; will retry",
            )
        if existing_pr:
            already_verified_cmd = list(signal.command) in self.state.open_revert_commands.get(culprit_sha, [])
            if not already_verified_cmd:
                # A second failing command bisecting to the same culprit must be verified against
                # the open revert PR's pinned tree before reusing that PR as a verified fix.
                revert_head = self._resolve_open_revert_branch_sha(branch_name, fetch_remote=fetch_remote)
                if revert_head is None:
                    return classification, BisectOutcome(
                        culprit_sha=culprit_sha,
                        revert_branch=branch_name,
                        revert_pr_url=existing_pr,
                        pr_creation_failed=True,
                        meltdown_triggered=False,
                        reason=f"could not resolve head of open revert PR {branch_name}; will retry",
                    )
                verify_deadline = self.now_fn() + self.timeout_secs
                verdict, verify_detail = run_in_detached_worktree(
                    self.repo,
                    revert_head,
                    lambda wt: self._exec_in_wt(wt, signal.command, deadline=verify_deadline),
                    worktree_root=self.worktree_root,
                    deadline=verify_deadline,
                    now_fn=self.now_fn,
                )
                if verdict == RunVerdict.INCONCLUSIVE:
                    return classification, BisectOutcome(
                        culprit_sha=culprit_sha,
                        revert_branch=branch_name,
                        revert_pr_url=existing_pr,
                        pr_creation_failed=True,
                        meltdown_triggered=False,
                        reason=f"inconclusive verification of {signal.failed_job} on {branch_name} ({verify_detail}); will retry",
                    )
                if verdict not in {RunVerdict.PASS, RunVerdict.TEST_ABSENT}:
                    if fetch_remote:
                        recheck_status, recheck_detail = self._recheck_fresh_master_before_freeze(
                            master_ref=master_ref,
                            command=signal.command,
                            fetch_remote=True,
                        )
                        if recheck_status == "healed":
                            self.state.mark_seen(seen_key)
                            self._persist()
                            return classification, BisectOutcome(
                                culprit_sha=culprit_sha,
                                revert_branch=branch_name,
                                revert_pr_url=existing_pr,
                                already_healed=True,
                                meltdown_triggered=False,
                                reason=recheck_detail,
                            )
                        if recheck_status == "deferred":
                            return classification, BisectOutcome(
                                culprit_sha=culprit_sha,
                                revert_branch=branch_name,
                                revert_pr_url=existing_pr,
                                pr_creation_failed=True,
                                meltdown_triggered=False,
                                reason=recheck_detail,
                            )
                    author = self.github.commit_author_login(culprit_sha)
                    safe_reason = sanitize_single_line(
                        f"open revert PR {existing_pr} for {culprit_sha[:9]} did not fix {signal.failed_job} "
                        f"(verdict={verdict.value})"
                    )
                    run_line = f"\n\nRun: {signal.run_url}" if signal.run_url else ""
                    frozen = self._trigger_meltdown(
                        reason=safe_reason,
                        signal=signal,
                        culprit_sha=culprit_sha,
                        notified=[author] if author else [],
                        seen_key=seen_key,
                        issue_title=f"Meltdown: {signal.failed_job} still fails on {branch_name}",
                        issue_body=(
                            f"Bisect Agent isolated `{culprit_sha}` for `{signal.failed_job}`, "
                            f"but existing revert PR {existing_pr} (`{revert_head[:9]}`) did not fix it.\n\n"
                            f"Tree state is frozen (`tree-state=red`). Apply `tree-fix` or `revert` label "
                            f"to the recovery PR.{run_line}"
                        ),
                    )
                    return classification, BisectOutcome(
                        culprit_sha=culprit_sha,
                        clean_revert=True,
                        revert_verified=False,
                        revert_branch=branch_name,
                        revert_pr_url=existing_pr,
                        meltdown_triggered=frozen,
                        reason=safe_reason,
                    )
            self._record_open_revert_command(culprit_sha, signal.command)
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

        # Allocate explicit verification budget AFTER bisect completes so a slow search
        # cannot starve either the live-master recheck or the reverted-tree verification.
        revert_deadline = self.now_fn() + (2 * self.timeout_secs)
        revert_predicate = lambda wt: self._exec_in_wt(wt, signal.command, deadline=revert_deadline)
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
            refresh_master=(self._refresh_master if fetch_remote else None),
            worktree_root=self.worktree_root,
            deadline=revert_deadline,
            now_fn=self.now_fn,
        )
        if outcome.already_healed:
            self.state.mark_seen(seen_key)
            self._persist()
            return classification, outcome

        if outcome.pr_creation_failed:
            ref_suffix = f" ({signal.run_url})" if signal.run_url else ""
            self.alerter.notify_engineering_group(
                f"MDK Bisect Agent deferred revert publication for {culprit_sha[:9]} "
                f"({sanitize_single_line(outcome.reason)}){ref_suffix}"
            )
            return classification, outcome

        author = self.github.commit_author_login(culprit_sha) or outcome.culprit_author_login
        if outcome.clean_revert and outcome.revert_verified:
            self.state.mark_seen(seen_key)
            if outcome.revert_pr_url:
                self.state.open_revert_prs[culprit_sha] = outcome.revert_pr_url
                self._record_open_revert_command(culprit_sha, signal.command)
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
            self.alerter.notify_authors(
                [author] if author else [],
                f"MDK Bisect Agent reverted {culprit_sha[:9]} ({outcome.culprit_subject}) "
                f"after {signal.failed_job} failed: {outcome.revert_pr_url or outcome.revert_branch}",
            )
            return classification, outcome

        # Tangled revert, merge culprit, or revert failed to restore green -> Meltdown Mode.
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
            if sha and sha != tip_sha and commit_ancestry(self.repo, sha, tip_sha) is True:
                return sha
        canary_sha = resolve_commit(self.repo, "origin/canary")
        if canary_sha and canary_sha != tip_sha and commit_ancestry(self.repo, canary_sha, tip_sha) is True:
            return canary_sha
        return ""

    def _hosted_run_verify_status(
        self,
        run: dict[str, Any],
        cache: dict[tuple[int, int], str],
    ) -> str:
        raw_id = str(run.get("id") or "")
        attempt = int(run.get("run_attempt") or 1)
        if not raw_id.isdigit():
            return "error"
        key = (int(raw_id), attempt)
        if key not in cache:
            cache[key] = self.github.hosted_run_verification_status(int(raw_id), attempt=attempt)
        return cache[key]

    def _has_newer_verified_green_for(
        self,
        ordered_runs: list[dict[str, Any]],
        failed_sha: str,
        verify_cache: dict[tuple[int, int], str],
    ) -> str:
        """Return `verified`, `error`, or `none` for whether a strict descendant passed a verified green.

        Uses commit ancestry (never `updated_at`) so rerunning an older SHA cannot supersede
        a failed descendant, and checks `hosted_run_verification_status` so an unverified or
        skipped green without a confirmed verified run on that SHA never drops a failure.
        """
        saw_error = False
        for cand in ordered_runs:
            if cand.get("conclusion") != "success":
                continue
            sha = str(cand.get("head_sha") or "")
            if not sha or sha == failed_sha:
                continue
            if commit_ancestry(self.repo, failed_sha, sha) is not True:
                continue
            status = self._hosted_run_verify_status(cand, verify_cache)
            if status == "verified":
                return "verified"
            if status == "error":
                saw_error = True
        return "error" if saw_error else "none"

    def _has_failed_descendant(self, ordered_runs: list[dict[str, Any]], sha: str) -> bool:
        """Return True when a completed failing run exists on a strict descendant of `sha`."""
        if not sha:
            return False
        for cand in ordered_runs:
            if cand.get("conclusion") not in {"failure", "timed_out"}:
                continue
            other = str(cand.get("head_sha") or "")
            if other and other != sha and commit_ancestry(self.repo, sha, other) is True:
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
        budget_exhausted = False
        cleanup_stale_worktrees(self.repo, self.worktree_root)
        refresh_errors = self.refresh_repo() if fetch_remote else []
        _remote_status, unknown_remote_freeze, _remote_rev = self._hydrate_remote_incidents()
        # Check overdue 30-minute escalations BEFORE running any long classification/bisect
        # so an already-overdue incident is never delayed by another source's bisect budget.
        escalated_early = self.check_escalation()

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
                    signals = extract_bare_metal_signals(doc, log_text)
                    sig_seen_keys: list[str] = []
                    for signal in signals:
                        sig_seen_key = f"fail:bare_metal_canary:{signal.run_id}"
                        sig_seen_keys.append(sig_seen_key)
                        if sig_seen_key in self.state.seen_runs:
                            continue
                        if budget_exhausted and signal.reproducible_locally:
                            actions.append(
                                {
                                    "source": "bare_metal_canary",
                                    "test": signal.failed_test,
                                    "result": "budget_exhausted_deferred",
                                }
                            )
                            continue
                        classification, outcome = self.handle_failure(
                            signal,
                            master_ref=master_ref,
                            poll_deadline=poll_deadline,
                            fetch_remote=fetch_remote,
                            attempt_key=run_key,
                            reset_sibling_counters=False,
                        )
                        if (
                            outcome is not None
                            and outcome.pr_creation_failed
                            and "budget exceeded" in outcome.reason
                        ):
                            budget_exhausted = True
                        actions.append(
                            {
                                "source": "bare_metal_canary",
                                "test": signal.failed_test,
                                "bucket": classification.bucket.value,
                                "reason": classification.reason,
                                "culprit": outcome.culprit_sha if outcome else None,
                                "meltdown": outcome.meltdown_triggered if outcome else False,
                            }
                        )
                    if all(key in self.state.seen_runs for key in sig_seen_keys):
                        if self.state.last_infra_attempt.get("bare_metal_canary") != run_key:
                            self.state.consecutive_infra_failures["bare_metal_canary"] = 0
                            self.state.last_infra_attempt.pop("bare_metal_canary", None)
                        if self.state.last_unreproducible_attempt.get("bare_metal_canary") != run_key:
                            self.state.consecutive_unreproducible_reds["bare_metal_canary"] = 0
                            self.state.last_unreproducible_attempt.pop("bare_metal_canary", None)
                        self.state.mark_seen(f"fail:bare_metal_canary:{run_key}")
                        self._persist()
            except Exception as exc:
                actions.append(
                    {
                        "source": "bare_metal_canary",
                        "error": sanitize_single_line(f"{type(exc).__name__}: {exc}"),
                    }
                )

        # 2. Inspect recent completed hosted Canary runs on master.
        # Process qualifying green recoveries first, then drain ALL unseen failing attempts
        # until each signal has a disposition or a verified descendant green supersedes it.
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
                verify_cache: dict[tuple[int, int], str] = {}

                # 2a. Qualifying unseen green runs (skip historical baseline greens that have a
                # failing descendant in `ordered` so rerunning an older SHA never masks a failure).
                for run in ordered:
                    if str(run.get("conclusion") or "") != "success":
                        continue
                    raw_id = str(run.get("id") or "")
                    attempt = int(run.get("run_attempt") or 1)
                    attempt_key = f"{raw_id}:{attempt}"
                    if f"green:{source}:{attempt_key}" in self.state.seen_runs:
                        continue
                    head_sha = str(run.get("head_sha") or "")
                    run_url = str(run.get("html_url") or "")
                    if self._has_failed_descendant(ordered, head_sha):
                        continue

                    status = self._hosted_run_verify_status(run, verify_cache)
                    if status == "error":
                        actions.append({"source": workflow, "result": "jobs_api_error", "cleared_meltdown": False})
                    elif status == "skipped":
                        recovered_via: dict[str, Any] | None = None
                        candidate_error = False
                        if source in self.state.active_incidents:
                            for cand in ordered:
                                if cand is run:
                                    continue
                                if cand.get("conclusion") != "success" or str(cand.get("head_sha") or "") != head_sha:
                                    continue
                                cstatus = self._hosted_run_verify_status(cand, verify_cache)
                                if cstatus == "verified":
                                    recovered_via = cand
                                    break
                                if cstatus == "error":
                                    candidate_error = True
                        if recovered_via is not None:
                            cleared = self.handle_green_canary(
                                source=source,
                                sha=head_sha,
                                run_id=attempt_key,
                                run_url=str(recovered_via.get("html_url") or run_url),
                            )
                            actions.append({"source": workflow, "result": "green", "cleared_meltdown": cleared})
                        elif candidate_error:
                            actions.append({"source": workflow, "result": "jobs_api_error", "cleared_meltdown": False})
                        else:
                            self.state.mark_seen(f"green:{source}:{attempt_key}")
                            self._persist()
                            actions.append({"source": workflow, "result": "skipped_green", "cleared_meltdown": False})
                    else:
                        cleared = self.handle_green_canary(
                            source=source, sha=head_sha, run_id=attempt_key, run_url=run_url
                        )
                        actions.append({"source": workflow, "result": "green", "cleared_meltdown": cleared})

                # 2b. Drain all unseen failed runs oldest-first so a newer red run or an older-SHA
                # rerun can never strand a previously deferred failed run.
                pending_failures = [
                    run
                    for run in reversed(ordered)
                    if str(run.get("conclusion") or "") in {"failure", "timed_out"}
                    and f"fail:{source}:{run.get('id') or ''}:{int(run.get('run_attempt') or 1)}"
                    not in self.state.seen_runs
                ]
                for run in pending_failures:
                    raw_id = str(run.get("id") or "")
                    attempt = int(run.get("run_attempt") or 1)
                    attempt_key = f"{raw_id}:{attempt}"
                    conclusion = str(run.get("conclusion") or "")
                    head_sha = str(run.get("head_sha") or "")
                    run_url = str(run.get("html_url") or "")

                    superseded = self._has_newer_verified_green_for(ordered, head_sha, verify_cache)
                    if superseded == "verified":
                        self.state.mark_seen(f"fail:{source}:{attempt_key}")
                        self._persist()
                        actions.append({"source": workflow, "run_id": attempt_key, "result": "stale_failure_ignored"})
                        continue
                    if superseded == "error":
                        actions.append({"source": workflow, "run_id": attempt_key, "result": "jobs_api_error"})
                        continue

                    failed_jobs = (
                        self.github.failed_jobs_for_run(int(raw_id), attempt=attempt)
                        if raw_id.isdigit()
                        else None
                    )
                    if failed_jobs is None:
                        # Transient GitHub API failure: leave unseen so the next poll retries cleanly.
                        actions.append({"source": workflow, "run_id": attempt_key, "result": "jobs_api_error"})
                        continue
                    jobs_to_process = (
                        sorted(
                            failed_jobs,
                            key=lambda j: (int(j.get("id") or 0), str(j.get("name") or "")),
                        )
                        if failed_jobs
                        else [{"id": 0, "name": workflow, "conclusion": conclusion}]
                    )
                    prev_green = self._resolve_hosted_baseline(ordered, head_sha)
                    job_seen_keys: list[str] = []
                    for idx, job in enumerate(jobs_to_process):
                        job_id = int(job.get("id") or 0)
                        job_key = f"{attempt_key}:job:{job_id if job_id else idx}"
                        job_seen_key = f"fail:{source}:{job_key}"
                        job_seen_keys.append(job_seen_key)
                        if job_seen_key in self.state.seen_runs:
                            continue
                        failed_step = first_failed_step_name(job)
                        if raw_id.isdigit() and job_id:
                            if hasattr(self.github, "job_log"):
                                log_text = self.github.job_log(int(raw_id), job_id)
                            else:
                                log_text = self.github.job_log_tail(int(raw_id), job_id)
                        else:
                            log_text = ""
                        if log_text is None:
                            # Unavailable job log: leave job and run attempt unseen so next poll retries.
                            actions.append(
                                {
                                    "source": workflow,
                                    "run_id": attempt_key,
                                    "job": str(job.get("name") or workflow),
                                    "result": "job_log_error",
                                }
                            )
                            continue
                        signals = extract_hosted_signals(
                            source=source,
                            run_id=job_key,
                            run_url=run_url,
                            tip_sha=head_sha,
                            baseline_sha=prev_green,
                            failed_job=str(job.get("name") or workflow),
                            failed_step=failed_step,
                            log_text=log_text,
                            conclusion=str(job.get("conclusion") or conclusion),
                        )
                        sig_seen_keys: list[str] = []
                        for signal in signals:
                            sig_seen_key = f"fail:{source}:{signal.run_id}"
                            sig_seen_keys.append(sig_seen_key)
                            if sig_seen_key in self.state.seen_runs:
                                continue
                            if budget_exhausted and signal.reproducible_locally:
                                actions.append(
                                    {
                                        "source": workflow,
                                        "run_id": attempt_key,
                                        "job": signal.failed_job,
                                        "test": signal.failed_test,
                                        "result": "budget_exhausted_deferred",
                                    }
                                )
                                continue
                            classification, outcome = self.handle_failure(
                                signal,
                                master_ref=master_ref,
                                poll_deadline=poll_deadline,
                                fetch_remote=fetch_remote,
                                attempt_key=attempt_key,
                                reset_sibling_counters=False,
                            )
                            if (
                                outcome is not None
                                and outcome.pr_creation_failed
                                and "budget exceeded" in outcome.reason
                            ):
                                budget_exhausted = True
                            actions.append(
                                {
                                    "source": workflow,
                                    "run_id": attempt_key,
                                    "job": signal.failed_job,
                                    "test": signal.failed_test,
                                    "bucket": classification.bucket.value,
                                    "reason": classification.reason,
                                    "culprit": outcome.culprit_sha if outcome else None,
                                    "meltdown": outcome.meltdown_triggered if outcome else False,
                                }
                            )
                        if all(key in self.state.seen_runs for key in sig_seen_keys):
                            if job_seen_key not in self.state.seen_runs:
                                self.state.mark_seen(job_seen_key)
                                self._persist()
                    # Mark the run attempt seen ONLY after every failed job (and every signal in it) has a disposition.
                    if all(key in self.state.seen_runs for key in job_seen_keys):
                        if self.state.last_infra_attempt.get(source) != attempt_key:
                            self.state.consecutive_infra_failures[source] = 0
                            self.state.last_infra_attempt.pop(source, None)
                        if self.state.last_unreproducible_attempt.get(source) != attempt_key:
                            self.state.consecutive_unreproducible_reds[source] = 0
                            self.state.last_unreproducible_attempt.pop(source, None)
                        self.state.mark_seen(f"fail:{source}:{attempt_key}")
                        self._persist()
            except Exception as exc:
                actions.append(
                    {
                        "source": workflow,
                        "error": sanitize_single_line(f"{type(exc).__name__}: {exc}"),
                    }
                )

        escalated = escalated_early or self.check_escalation()
        result: dict[str, Any] = {
            "dry_run": self.dry_run,
            "actions": actions,
            "escalated": escalated,
            "tree_state": self.state.tree_state,
        }
        if unknown_remote_freeze:
            result["reconciliation_needed"] = True
        if refresh_errors:
            result["refresh_errors"] = refresh_errors
        return result


SELFTEST_REPLAY_COMMAND: tuple[str, ...] = ("cargo", "nextest", "run", "--locked", "-p", "cgka-traits", "--profile", "ci")


def selftest(
    github: GitHubOps,
    *,
    repo_dir: Path,
    worktree_root: Path,
    cargo_target_dir: Path,
    runner_prefix: tuple[str, ...],
    timeout_secs: int,
) -> list[str]:
    """Exercise the live hosted log fetch and sandboxed replay the unit tests fake; return problems found."""
    problems: list[str] = []
    job_ref: tuple[int, int] | None = None
    for run in github.recent_workflow_runs("canary.yml", limit=10):
        jobs = github.jobs_for_run(int(run.get("id") or 0)) or []
        called = [
            job
            for job in jobs
            if " / " in str(job.get("name") or "") and job.get("conclusion") in {"success", "failure"}
        ]
        if called:
            job_ref = (int(run["id"]), int(called[0]["id"]))
            break
    if job_ref is None:
        problems.append("no completed ci.yml job found in the last 10 hosted Canary runs")
    elif not (github.job_log(*job_ref) or "").strip():
        problems.append(f"hosted job log came back empty (run {job_ref[0]}, job {job_ref[1]})")

    sha = resolve_commit(repo_dir, "origin/master")
    if sha is None:
        problems.append("origin/master is not available in --repo-dir")
    else:
        verdict, detail = run_in_detached_worktree(
            repo_dir,
            sha,
            default_worktree_runner(
                SELFTEST_REPLAY_COMMAND,
                timeout_secs=timeout_secs,
                cargo_target_dir=cargo_target_dir,
                runner_prefix=runner_prefix,
            ),
            worktree_root=worktree_root,
        )
        if verdict != RunVerdict.PASS:
            problems.append(f"sandboxed replay on {sha[:9]} was {verdict.value}: {detail}")
    return problems


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MDK always-on revert-only Bisect Agent")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo", default="marmot-protocol/mdk")
    common.add_argument("--repo-dir", type=Path, default=Path("/srv/mdk/repo"))
    common.add_argument("--worktree-root", type=Path, default=Path("/srv/mdk/worktrees/bisect"))
    common.add_argument("--cargo-target-dir", type=Path, default=Path("/srv/mdk/target-bisect"))
    common.add_argument("--timeout-secs", type=int, default=DEFAULT_COMMAND_TIMEOUT_SECS)
    common.add_argument(
        "--predicate-runner-prefix",
        default="",
        help="Command prefix isolating build/test predicates from the signing bot UID (e.g. 'sudo -n -u mdk-runner --'); required for --live and selftest",
    )

    poll = sub.add_parser("poll", parents=[common], help="Run one poll pass across bare-metal and hosted Canary")
    poll.add_argument("--state-file", type=Path, default=Path("/srv/mdk/state/bisect-state.json"))
    poll.add_argument("--canary-status", type=Path, default=Path("/srv/mdk/state/canary-status.json"))
    poll.add_argument("--roster", type=Path, default=Path("/srv/mdk/bisect-roster.json"))
    poll.add_argument("--bisect-budget-secs", type=int, default=DEFAULT_BISECT_BUDGET_SECS)
    poll.add_argument("--stress-count", type=int, default=10)
    poll.add_argument("--no-fetch", action="store_true", help="Skip git fetch before polling")
    poll.add_argument("--live", action="store_true", help="Execute real pushes/PRs/alerts (default: dry-run)")

    sub.add_parser(
        "selftest",
        parents=[common],
        help="Fetch a real hosted Canary job log and replay a small nextest suite in the predicate sandbox",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner_prefix = tuple(shlex.split(args.predicate_runner_prefix)) if args.predicate_runner_prefix else ()
    if args.command == "selftest":
        if not runner_prefix:
            print("error: selftest requires --predicate-runner-prefix to replay as the live agent does", file=sys.stderr)
            return 2
        problems = selftest(
            GitHubOps(args.repo, dry_run=True),
            repo_dir=args.repo_dir,
            worktree_root=args.worktree_root,
            cargo_target_dir=args.cargo_target_dir,
            runner_prefix=runner_prefix,
            timeout_secs=args.timeout_secs,
        )
        for problem in problems:
            print(f"selftest: FAIL: {problem}", file=sys.stderr)
        if not problems:
            print("selftest: ok")
        return 1 if problems else 0

    dry_run = not args.live
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
