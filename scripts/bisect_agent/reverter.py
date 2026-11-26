"""First-parent binary-search bisect and strictly revert-only recovery."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Callable

from .models import BisectOutcome, RunVerdict

# Predicate over a checked-out worktree directory: returns (RunVerdict, concise_detail).
WorktreePredicate = Callable[[Path], tuple[RunVerdict, str]]


GIT_LOCAL_TIMEOUT_SECS = 120
GIT_REMOTE_TIMEOUT_SECS = 120
GIT_CLEANUP_TIMEOUT_SECS = 30
MAX_REVERT_MASTER_RETRIES = 2


def _git(
    repo: Path,
    *args: str,
    check: bool = True,
    timeout: float | None = GIT_LOCAL_TIMEOUT_SECS,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _budget_timeout(
    deadline: float | None,
    now_fn: Callable[[], float],
    default: float = GIT_LOCAL_TIMEOUT_SECS,
) -> float:
    """Return bounded seconds remaining before `deadline`, raising TimeoutError if exhausted."""
    if deadline is None:
        return default
    remaining = deadline - now_fn()
    if remaining <= 0:
        raise TimeoutError("bisect wall-clock budget exceeded")
    return min(default, remaining)


def resolve_commit(
    repo: Path,
    rev: str,
    *,
    timeout: float | None = GIT_LOCAL_TIMEOUT_SECS,
) -> str | None:
    """Resolve `rev` to a full 40-char commit SHA, or None if absent/invalid."""
    if not rev:
        return None
    res = _git(repo, "rev-parse", "--verify", f"{rev}^{{commit}}", check=False, timeout=timeout)
    return res.stdout.strip() if res.returncode == 0 else None


def commit_parents(
    repo: Path,
    sha: str,
    *,
    timeout: float | None = GIT_LOCAL_TIMEOUT_SECS,
) -> list[str]:
    """Return the parent commit SHAs of `sha` in order (first parent at index 0)."""
    res = _git(repo, "rev-list", "--parents", "-n", "1", sha, check=False, timeout=timeout)
    if res.returncode != 0:
        return []
    parts = res.stdout.strip().split()
    return parts[1:] if len(parts) > 1 else []


def commit_ancestry(repo: Path, older_sha: str, newer_sha: str) -> bool | None:
    """Return `True` if `older_sha` is an ancestor of (or equal to) `newer_sha`,
    `False` if both commits exist locally and `older_sha` is not an ancestor,
    or `None` when commit ancestry cannot be determined (missing local objects or git error).
    """
    if not older_sha or not newer_sha:
        return None
    if older_sha == newer_sha:
        return True
    if resolve_commit(repo, older_sha) is None or resolve_commit(repo, newer_sha) is None:
        return None
    res = _git(repo, "merge-base", "--is-ancestor", older_sha, newer_sha, check=False)
    if res.returncode == 0:
        return True
    if res.returncode == 1:
        return False
    return None


def is_ancestor_or_equal(repo: Path, older_sha: str, newer_sha: str) -> bool:
    """Return True when `older_sha` is confirmed equal to or an ancestor of `newer_sha`."""
    return commit_ancestry(repo, older_sha, newer_sha) is True


def cleanup_stale_worktrees(repo: Path, worktree_root: Path | None) -> None:
    """Prune stale git worktree metadata and leftover bisect/revert directories."""
    try:
        _git(repo, "worktree", "prune", check=False, timeout=GIT_CLEANUP_TIMEOUT_SECS)
    except (subprocess.TimeoutExpired, OSError):
        pass
    if worktree_root is None or not worktree_root.is_dir():
        return
    for entry in worktree_root.iterdir():
        if entry.is_dir() and entry.name.startswith(("mdk-bisect-", "mdk-revert-")):
            try:
                _git(repo, "worktree", "remove", "--force", str(entry), check=False, timeout=GIT_CLEANUP_TIMEOUT_SECS)
            except (subprocess.TimeoutExpired, OSError):
                pass
            shutil.rmtree(entry, ignore_errors=True)
    try:
        _git(repo, "worktree", "prune", check=False, timeout=GIT_CLEANUP_TIMEOUT_SECS)
    except (subprocess.TimeoutExpired, OSError):
        pass


def first_parent_commits(
    repo: Path,
    baseline_sha: str,
    tip_sha: str,
    *,
    deadline: float | None = None,
    now_fn: Callable[[], float] = time.time,
) -> list[str]:
    """Return first-parent commits in `(baseline_sha, tip_sha]` oldest-first.

    Requires `baseline_sha` to lie on `tip_sha`'s first-parent chain (not a merge's
    side-branch second parent) so bisect predicates and parent checks remain aligned.
    Raises ValueError on invalid/non-first-parent range, TimeoutError if `deadline`
    expires.
    """
    if not baseline_sha or not tip_sha:
        raise ValueError("baseline_sha and tip_sha must both be non-empty")
    resolved_base = resolve_commit(repo, baseline_sha, timeout=_budget_timeout(deadline, now_fn))
    if resolved_base is None:
        raise ValueError(f"baseline commit {baseline_sha[:9]} is not present locally")
    resolved_tip = resolve_commit(repo, tip_sha, timeout=_budget_timeout(deadline, now_fn))
    if resolved_tip is None:
        raise ValueError(f"tip commit {tip_sha[:9]} is not present locally")
    if resolved_base == resolved_tip:
        return []
    anc = _git(
        repo,
        "merge-base",
        "--is-ancestor",
        resolved_base,
        resolved_tip,
        check=False,
        timeout=_budget_timeout(deadline, now_fn),
    )
    if anc.returncode != 0:
        raise ValueError(f"baseline {baseline_sha[:9]} is not an ancestor of {tip_sha[:9]}")
    out = _git(
        repo,
        "rev-list",
        "--first-parent",
        "--reverse",
        f"{resolved_base}..{resolved_tip}",
        timeout=_budget_timeout(deadline, now_fn),
    ).stdout
    commits = [line.strip() for line in out.splitlines() if line.strip()]
    if not commits:
        return []
    # Verify `baseline_sha` lies on `tip_sha`'s actual first-parent chain:
    # `commits[0]` is the oldest first-parent commit after `baseline_sha`, so its
    # first parent must equal `resolved_base`. If `baseline_sha` was on a merge's
    # second-parent side branch, `commits[0]^1` is either absent or a different commit.
    first_parent_of_oldest = resolve_commit(
        repo,
        f"{commits[0]}^1",
        timeout=_budget_timeout(deadline, now_fn),
    )
    if first_parent_of_oldest != resolved_base:
        raise ValueError(
            f"baseline {baseline_sha[:9]} is not on the first-parent chain of {tip_sha[:9]}"
        )
    return commits


def commit_metadata(repo: Path, sha: str) -> tuple[str, str]:
    """Return `(subject, author_name_or_login)` for `sha`."""
    subject = _git(repo, "show", "-s", "--format=%s", sha, check=False).stdout.strip()
    author = _git(repo, "show", "-s", "--format=%an", sha, check=False).stdout.strip()
    return subject, author


def run_in_detached_worktree(
    repo: Path,
    sha: str,
    predicate: WorktreePredicate,
    *,
    worktree_root: Path | None = None,
    deadline: float | None = None,
    now_fn: Callable[[], float] = time.time,
) -> tuple[RunVerdict, str]:
    """Check out `sha` in a clean detached worktree, run `predicate`, and remove it."""
    try:
        resolve_timeout = _budget_timeout(deadline, now_fn)
        if resolve_commit(repo, sha, timeout=resolve_timeout) is None:
            return RunVerdict.INCONCLUSIVE, f"commit {sha[:9] if sha else '<empty>'} not found locally"
    except (TimeoutError, subprocess.TimeoutExpired):
        return RunVerdict.INCONCLUSIVE, "bisect wall-clock budget exceeded"

    parent = worktree_root or Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    wt_dir = Path(tempfile.mkdtemp(prefix=f"mdk-bisect-{sha[:9]}-", dir=parent))
    wt_dir.rmdir()
    try:
        try:
            add_timeout = _budget_timeout(deadline, now_fn)
            add = _git(
                repo,
                "worktree",
                "add",
                "--detach",
                str(wt_dir),
                sha,
                check=False,
                timeout=add_timeout,
            )
        except (TimeoutError, subprocess.TimeoutExpired):
            return RunVerdict.INCONCLUSIVE, f"bisect wall-clock budget exceeded during checkout of {sha[:9]}"
        if add.returncode != 0:
            return RunVerdict.INCONCLUSIVE, f"git worktree add failed for {sha[:9]}"
        return predicate(wt_dir)
    finally:
        try:
            _git(repo, "worktree", "remove", "--force", str(wt_dir), check=False, timeout=GIT_CLEANUP_TIMEOUT_SECS)
        except (subprocess.TimeoutExpired, OSError):
            pass
        shutil.rmtree(wt_dir, ignore_errors=True)


def bisect_culprit(
    repo: Path,
    baseline_sha: str,
    tip_sha: str,
    predicate: WorktreePredicate,
    *,
    worktree_root: Path | None = None,
    deadline: float | None = None,
    now_fn: Callable[[], float] = time.time,
) -> tuple[str | None, str]:
    """Binary-search first-parent commits `(baseline_sha, tip_sha]` for the first failing commit.

    Explicitly confirms both that the isolated culprit returns `RunVerdict.FAIL` and
    its actual first parent returns `RunVerdict.PASS` or `RunVerdict.TEST_ABSENT`.
    Aborts cleanly if `deadline` is exceeded (including during git history/worktree
    operations) or if any midpoint is `RunVerdict.INCONCLUSIVE`.
    """
    try:
        commits = first_parent_commits(repo, baseline_sha, tip_sha, deadline=deadline, now_fn=now_fn)
    except (ValueError, TimeoutError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)

    if not commits:
        return None, f"no commits between baseline {baseline_sha[:9]} and tip {tip_sha[:9]}"

    tested: dict[str, RunVerdict] = {}

    def eval_sha(sha: str) -> tuple[RunVerdict, str]:
        if deadline is not None and now_fn() >= deadline:
            return RunVerdict.INCONCLUSIVE, "bisect wall-clock budget exceeded"
        verdict, detail = run_in_detached_worktree(
            repo,
            sha,
            predicate,
            worktree_root=worktree_root,
            deadline=deadline,
            now_fn=now_fn,
        )
        tested[sha] = verdict
        return verdict, detail

    lo = 0
    hi = len(commits) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        verdict, detail = eval_sha(commits[mid])
        if verdict == RunVerdict.INCONCLUSIVE:
            return None, f"inconclusive bisect at {commits[mid][:9]} ({detail})"
        if verdict in {RunVerdict.PASS, RunVerdict.TEST_ABSENT}:
            lo = mid + 1
        else:
            hi = mid

    culprit = commits[lo]
    if tested.get(culprit) != RunVerdict.FAIL:
        culprit_verdict, culprit_detail = eval_sha(culprit)
        if culprit_verdict != RunVerdict.FAIL:
            return (
                None,
                f"candidate {culprit[:9]} did not reproduce failure ({culprit_verdict.value}: {culprit_detail})",
            )

    try:
        parent = resolve_commit(repo, f"{culprit}^1", timeout=_budget_timeout(deadline, now_fn))
    except (TimeoutError, subprocess.TimeoutExpired):
        return None, "bisect wall-clock budget exceeded resolving candidate parent"
    if parent is None:
        return None, f"candidate {culprit[:9]} has no first parent to verify"

    if tested.get(parent) not in {RunVerdict.PASS, RunVerdict.TEST_ABSENT}:
        parent_verdict, parent_detail = eval_sha(parent)
        if parent_verdict == RunVerdict.INCONCLUSIVE:
            return None, f"inconclusive parent check at {parent[:9]} ({parent_detail})"
        if parent_verdict == RunVerdict.FAIL:
            return None, f"parent {parent[:9]} of candidate {culprit[:9]} also failed; failure is non-monotonic"
    else:
        parent_verdict = tested[parent]

    return culprit, f"isolated first failing commit {culprit[:9]} (parent {parent[:9]} {parent_verdict.value})"


def format_revert_message(
    culprit_sha: str,
    culprit_subject: str,
    *,
    checks_summary: str,
    run_url: str,
) -> str:
    """Format a signed revert commit message carrying valid MDK commit trailers."""
    short = culprit_sha[:9]
    body_lines = [
        f'Revert "{culprit_subject}"',
        "",
        f"This reverts commit {culprit_sha}.",
        "",
        f"Automated revert by the MDK Bisect Agent after isolating {short} as",
        "the first failing commit on Canary and confirming the exact failing",
        "check passes on the reverted tree.",
    ]
    if run_url:
        body_lines.extend(["", f"Canary run: {run_url}"])
    body_lines.extend(
        [
            "",
            f"Local-Checks: {checks_summary}",
            f"Local-Review: exempt (automated bisect revert of {short})",
            "Release-Impact: none",
            "",
        ]
    )
    return "\n".join(body_lines)


def attempt_clean_revert(
    repo: Path,
    culprit_sha: str,
    master_ref: str,
    predicate: WorktreePredicate,
    *,
    checks_summary: str,
    run_url: str = "",
    sign_commits: bool = True,
    dry_run: bool = True,
    open_revert_pr: Callable[[str, str, str], str] | None = None,
    find_existing_pr: Callable[[str], str | None] | None = None,
    refresh_master: Callable[[], bool] | None = None,
    worktree_root: Path | None = None,
    deadline: float | None = None,
    now_fn: Callable[[], float] = time.time,
) -> BisectOutcome:
    """Attempt a strictly revert-only recovery of `culprit_sha` onto `master_ref`.

    Uses a detached worktree so neither dry-run nor failed pushes ever create,
    reset, or delete local branches. Refreshes `master_ref` before the live-master
    recheck and confirms `master_ref` has not advanced before publishing so a stale
    revert is never published after a human fix lands. Rejects multi-parent merge
    culprits explicitly instead of reporting them as revert conflicts.
    """
    subject, author = commit_metadata(repo, culprit_sha)
    branch_name = f"revert/{culprit_sha[:9]}"
    parents = commit_parents(repo, culprit_sha)

    def _deferred(reason: str, *, clean_revert: bool = False, revert_verified: bool = False) -> BisectOutcome:
        return BisectOutcome(
            culprit_sha=culprit_sha,
            culprit_subject=subject,
            culprit_author_login=author,
            clean_revert=clean_revert,
            revert_verified=revert_verified,
            revert_branch=branch_name,
            pr_creation_failed=True,
            meltdown_triggered=False,
            reason=reason,
        )

    def _check_master_moved(checked_sha: str) -> str:
        """Return `unchanged`, `moved`, or `refresh_failed` after refreshing `master_ref`."""
        if refresh_master is None:
            return "unchanged"
        if not refresh_master():
            return "refresh_failed"
        latest = resolve_commit(repo, master_ref)
        if latest is None:
            return "refresh_failed"
        return "unchanged" if latest == checked_sha else "moved"

    def _budget_expired() -> bool:
        return deadline is not None and now_fn() >= deadline

    for _attempt in range(MAX_REVERT_MASTER_RETRIES):
        if _budget_expired():
            return _deferred(f"revert verification budget expired before checking {master_ref}; will retry")
        if refresh_master is not None and not refresh_master():
            return _deferred(f"failed to refresh {master_ref} before live-master recheck; will retry")

        master_sha = resolve_commit(repo, master_ref)
        if master_sha is None:
            return _deferred(f"could not resolve target ref {master_ref}; will retry")

        parent = worktree_root or Path(tempfile.gettempdir())
        parent.mkdir(parents=True, exist_ok=True)
        wt_dir = Path(tempfile.mkdtemp(prefix=f"mdk-revert-{culprit_sha[:9]}-", dir=parent))
        wt_dir.rmdir()

        try:
            try:
                add_timeout = _budget_timeout(deadline, now_fn)
                add = _git(
                    repo,
                    "worktree",
                    "add",
                    "--detach",
                    str(wt_dir),
                    master_sha,
                    check=False,
                    timeout=add_timeout,
                )
            except (TimeoutError, subprocess.TimeoutExpired):
                return _deferred(
                    f"timed out creating detached revert worktree at {master_sha[:9]}; will retry"
                )
            if add.returncode != 0:
                return _deferred(f"failed to create detached revert worktree at {master_sha[:9]}; will retry")

            # Re-verify current master still exhibits the failure before reverting or freezing
            # (including for multi-parent merge culprits in case a manual repair already landed).
            master_verdict, master_detail = predicate(wt_dir)
            if master_verdict in {RunVerdict.PASS, RunVerdict.TEST_ABSENT}:
                return BisectOutcome(
                    culprit_sha=culprit_sha,
                    culprit_subject=subject,
                    culprit_author_login=author,
                    revert_branch=branch_name,
                    already_healed=True,
                    meltdown_triggered=False,
                    reason=f"master {master_sha[:9]} already passes ({master_verdict.value}); revert skipped",
                )
            if master_verdict == RunVerdict.INCONCLUSIVE:
                if _budget_expired() or "budget exceeded" in master_detail:
                    return _deferred(
                        f"deferred live-master recheck at {master_sha[:9]} ({master_detail}); will retry"
                    )
                move_state = _check_master_moved(master_sha)
                if move_state == "refresh_failed":
                    return _deferred(f"failed to recheck {master_ref} after inconclusive live-master check; will retry")
                if move_state == "moved":
                    if _budget_expired():
                        return _deferred(
                            f"{master_ref} moved while live-master check was inconclusive and budget expired; will retry"
                        )
                    continue
                return _deferred(
                    f"inconclusive live-master recheck at {master_sha[:9]} ({master_detail}); will retry"
                )

            if len(parents) > 1:
                move_state = _check_master_moved(master_sha)
                if move_state == "refresh_failed":
                    return _deferred(f"failed to reconfirm {master_ref} before freezing merge culprit; will retry")
                if move_state == "moved":
                    if _budget_expired():
                        return _deferred(
                            f"{master_ref} moved before merge culprit {culprit_sha[:9]} could be rechecked; will retry"
                        )
                    continue
                return BisectOutcome(
                    culprit_sha=culprit_sha,
                    culprit_subject=subject,
                    culprit_author_login=author,
                    clean_revert=False,
                    revert_verified=False,
                    revert_branch=branch_name,
                    meltdown_triggered=True,
                    reason=(
                        f"merge commit culprit {culprit_sha[:9]} requires manual revert "
                        "(cannot safely auto-revert multi-parent merge)"
                    ),
                )

            try:
                revert = _git(
                    wt_dir,
                    "revert",
                    "--no-edit",
                    "--no-commit",
                    culprit_sha,
                    check=False,
                    timeout=_budget_timeout(deadline, now_fn),
                )
            except (TimeoutError, subprocess.TimeoutExpired):
                return _deferred(
                    f"timed out running `git revert {culprit_sha[:9]}` against {master_sha[:9]}; will retry"
                )
            if revert.returncode != 0:
                try:
                    _git(wt_dir, "revert", "--abort", check=False, timeout=GIT_CLEANUP_TIMEOUT_SECS)
                except (subprocess.TimeoutExpired, OSError):
                    pass
                move_state = _check_master_moved(master_sha)
                if move_state == "refresh_failed":
                    return _deferred(
                        f"failed to reconfirm {master_ref} after revert conflict on {culprit_sha[:9]}; will retry"
                    )
                if move_state == "moved":
                    if _budget_expired():
                        return _deferred(
                            f"{master_ref} moved during revert conflict on {culprit_sha[:9]} and budget expired; will retry"
                        )
                    continue
                return BisectOutcome(
                    culprit_sha=culprit_sha,
                    culprit_subject=subject,
                    culprit_author_login=author,
                    clean_revert=False,
                    revert_verified=False,
                    revert_branch=branch_name,
                    meltdown_triggered=True,
                    reason=f"tangled revert: `git revert {culprit_sha[:9]}` had conflicts against {master_sha[:9]}",
                )

            commit_msg = format_revert_message(
                culprit_sha,
                subject,
                checks_summary=checks_summary,
                run_url=run_url,
            )
            commit_args = ["commit", "-S" if sign_commits else "--no-gpg-sign", "-m", commit_msg]
            try:
                commit_res = _git(wt_dir, *commit_args, check=False, timeout=_budget_timeout(deadline, now_fn))
            except (TimeoutError, subprocess.TimeoutExpired):
                return _deferred(f"timed out committing signed revert of {culprit_sha[:9]}; will retry")
            if commit_res.returncode != 0:
                return BisectOutcome(
                    culprit_sha=culprit_sha,
                    culprit_subject=subject,
                    culprit_author_login=author,
                    clean_revert=False,
                    revert_verified=False,
                    revert_branch=branch_name,
                    meltdown_triggered=True,
                    reason=f"failed to commit signed revert of {culprit_sha[:9]} (git exit {commit_res.returncode})",
                )

            verdict, verify_detail = predicate(wt_dir)
            if verdict == RunVerdict.INCONCLUSIVE:
                if _budget_expired() or "budget exceeded" in verify_detail:
                    return _deferred(
                        f"revert verification budget expired for {culprit_sha[:9]} ({verify_detail}); will retry",
                        clean_revert=True,
                    )
                move_state = _check_master_moved(master_sha)
                if move_state == "refresh_failed":
                    return _deferred(
                        f"failed to reconfirm {master_ref} after inconclusive revert verification; will retry",
                        clean_revert=True,
                    )
                if move_state == "moved":
                    if _budget_expired():
                        return _deferred(
                            f"{master_ref} moved during inconclusive revert check and budget expired; will retry",
                            clean_revert=True,
                        )
                    continue
                return _deferred(
                    f"inconclusive revert verification for {culprit_sha[:9]} ({verify_detail}); will retry",
                    clean_revert=True,
                )
            if verdict not in {RunVerdict.PASS, RunVerdict.TEST_ABSENT}:
                move_state = _check_master_moved(master_sha)
                if move_state == "refresh_failed":
                    return _deferred(
                        f"failed to reconfirm {master_ref} after failed revert of {culprit_sha[:9]}; will retry",
                        clean_revert=True,
                    )
                if move_state == "moved":
                    if _budget_expired():
                        return _deferred(
                            f"{master_ref} moved during failed revert verification and budget expired; will retry",
                            clean_revert=True,
                        )
                    continue
                return BisectOutcome(
                    culprit_sha=culprit_sha,
                    culprit_subject=subject,
                    culprit_author_login=author,
                    clean_revert=True,
                    revert_verified=False,
                    revert_branch=branch_name,
                    meltdown_triggered=True,
                    reason=(
                        f"clean revert of {culprit_sha[:9]} did not restore green "
                        f"(likely multi-commit interaction; verdict={verdict.value})"
                    ),
                )

            # Confirm master has not advanced (e.g., gained a human fix) while verification ran.
            move_state = _check_master_moved(master_sha)
            if move_state == "refresh_failed":
                return _deferred(
                    f"failed to reconfirm {master_ref} before publishing revert; will retry",
                    clean_revert=True,
                    revert_verified=True,
                )
            if move_state == "moved":
                if _budget_expired():
                    return _deferred(
                        f"{master_ref} moved during revert verification and no budget remained to re-verify; will retry",
                        clean_revert=True,
                        revert_verified=False,
                    )
                # Master moved during verification: retry against the fresh tip instead of pushing stale revert.
                continue

            pr_url = ""
            if not dry_run:
                try:
                    push = _git(
                        wt_dir,
                        "push",
                        "--force-with-lease",
                        "origin",
                        f"HEAD:refs/heads/{branch_name}",
                        check=False,
                        timeout=GIT_REMOTE_TIMEOUT_SECS,
                    )
                except subprocess.TimeoutExpired:
                    return BisectOutcome(
                        culprit_sha=culprit_sha,
                        culprit_subject=subject,
                        culprit_author_login=author,
                        clean_revert=True,
                        revert_verified=True,
                        revert_branch=branch_name,
                        pr_creation_failed=True,
                        meltdown_triggered=False,
                        reason=f"timed out pushing revert branch {branch_name}; will retry",
                    )
                if push.returncode != 0:
                    return BisectOutcome(
                        culprit_sha=culprit_sha,
                        culprit_subject=subject,
                        culprit_author_login=author,
                        clean_revert=True,
                        revert_verified=True,
                        revert_branch=branch_name,
                        pr_creation_failed=True,
                        meltdown_triggered=False,
                        reason=f"failed to push revert branch {branch_name} (git exit {push.returncode})",
                    )
                if open_revert_pr is not None:
                    pr_url = open_revert_pr(branch_name, f'Revert "{subject}"', commit_msg)
                if not pr_url and find_existing_pr is not None:
                    pr_url = find_existing_pr(branch_name) or ""
                if not pr_url:
                    return BisectOutcome(
                        culprit_sha=culprit_sha,
                        culprit_subject=subject,
                        culprit_author_login=author,
                        clean_revert=True,
                        revert_verified=True,
                        revert_branch=branch_name,
                        pr_creation_failed=True,
                        meltdown_triggered=False,
                        reason=f"pushed {branch_name} but PR creation returned no URL; will retry",
                    )

            return BisectOutcome(
                culprit_sha=culprit_sha,
                culprit_subject=subject,
                culprit_author_login=author,
                clean_revert=True,
                revert_verified=True,
                revert_branch=branch_name,
                revert_pr_url=pr_url,
                meltdown_triggered=False,
                reason=f"{'dry-run: ' if dry_run else ''}clean revert of {culprit_sha[:9]} restored green",
            )
        finally:
            try:
                _git(repo, "worktree", "remove", "--force", str(wt_dir), check=False, timeout=GIT_CLEANUP_TIMEOUT_SECS)
            except (subprocess.TimeoutExpired, OSError):
                pass
            shutil.rmtree(wt_dir, ignore_errors=True)

    return BisectOutcome(
        culprit_sha=culprit_sha,
        culprit_subject=subject,
        culprit_author_login=author,
        revert_branch=branch_name,
        pr_creation_failed=True,
        meltdown_triggered=False,
        reason=f"{master_ref} moved repeatedly during revert verification; will retry on next poll",
    )
