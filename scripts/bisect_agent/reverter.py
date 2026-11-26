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


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        text=True,
    )


def resolve_commit(repo: Path, rev: str) -> str | None:
    """Resolve `rev` to a full 40-char commit SHA, or None if absent/invalid."""
    if not rev:
        return None
    res = _git(repo, "rev-parse", "--verify", f"{rev}^{{commit}}", check=False)
    return res.stdout.strip() if res.returncode == 0 else None


def is_ancestor_or_equal(repo: Path, older_sha: str, newer_sha: str) -> bool:
    """Return True when `older_sha` is equal to or an ancestor of `newer_sha`."""
    if not older_sha or not newer_sha:
        return False
    if older_sha == newer_sha:
        return True
    if resolve_commit(repo, older_sha) is None or resolve_commit(repo, newer_sha) is None:
        return False
    return _git(repo, "merge-base", "--is-ancestor", older_sha, newer_sha, check=False).returncode == 0


def cleanup_stale_worktrees(repo: Path, worktree_root: Path | None) -> None:
    """Prune stale git worktree metadata and leftover bisect/revert directories."""
    _git(repo, "worktree", "prune", check=False)
    if worktree_root is None or not worktree_root.is_dir():
        return
    for entry in worktree_root.iterdir():
        if entry.is_dir() and entry.name.startswith(("mdk-bisect-", "mdk-revert-")):
            _git(repo, "worktree", "remove", "--force", str(entry), check=False)
            shutil.rmtree(entry, ignore_errors=True)
    _git(repo, "worktree", "prune", check=False)


def first_parent_commits(repo: Path, baseline_sha: str, tip_sha: str) -> list[str]:
    """Return first-parent commits in `(baseline_sha, tip_sha]` oldest-first.

    Raises ValueError if `baseline_sha` or `tip_sha` is missing or not an ancestor.
    """
    if not baseline_sha or not tip_sha:
        raise ValueError("baseline_sha and tip_sha must both be non-empty")
    if resolve_commit(repo, baseline_sha) is None:
        raise ValueError(f"baseline commit {baseline_sha[:9]} is not present locally")
    if resolve_commit(repo, tip_sha) is None:
        raise ValueError(f"tip commit {tip_sha[:9]} is not present locally")
    anc = _git(repo, "merge-base", "--is-ancestor", baseline_sha, tip_sha, check=False)
    if anc.returncode != 0:
        raise ValueError(f"baseline {baseline_sha[:9]} is not an ancestor of {tip_sha[:9]}")
    out = _git(repo, "rev-list", "--first-parent", "--reverse", f"{baseline_sha}..{tip_sha}").stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


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
) -> tuple[RunVerdict, str]:
    """Check out `sha` in a clean detached worktree, run `predicate`, and remove it."""
    if resolve_commit(repo, sha) is None:
        return RunVerdict.INCONCLUSIVE, f"commit {sha[:9] if sha else '<empty>'} not found locally"
    parent = worktree_root or Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    wt_dir = Path(tempfile.mkdtemp(prefix=f"mdk-bisect-{sha[:9]}-", dir=parent))
    wt_dir.rmdir()
    try:
        add = _git(repo, "worktree", "add", "--detach", str(wt_dir), sha, check=False)
        if add.returncode != 0:
            return RunVerdict.INCONCLUSIVE, f"git worktree add failed for {sha[:9]}"
        return predicate(wt_dir)
    finally:
        _git(repo, "worktree", "remove", "--force", str(wt_dir), check=False)
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
    its parent returns `RunVerdict.PASS` or `RunVerdict.TEST_ABSENT`. Aborts cleanly
    if `deadline` is exceeded (so the caller can freeze and alert before systemd kills
    the oneshot unit) or if any midpoint is `RunVerdict.INCONCLUSIVE`.
    """
    try:
        commits = first_parent_commits(repo, baseline_sha, tip_sha)
    except (ValueError, subprocess.CalledProcessError) as exc:
        return None, str(exc)

    if not commits:
        return None, f"no commits between baseline {baseline_sha[:9]} and tip {tip_sha[:9]}"

    tested: dict[str, RunVerdict] = {}

    def eval_sha(sha: str) -> tuple[RunVerdict, str]:
        if deadline is not None and now_fn() >= deadline:
            return RunVerdict.INCONCLUSIVE, "bisect wall-clock budget exceeded"
        verdict, detail = run_in_detached_worktree(repo, sha, predicate, worktree_root=worktree_root)
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

    parent = baseline_sha if lo == 0 else commits[lo - 1]
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
    find_existing_pr: Callable[[str], str] | None = None,
    worktree_root: Path | None = None,
) -> BisectOutcome:
    """Attempt a strictly revert-only recovery of `culprit_sha` onto `master_ref`.

    Uses a detached worktree so neither dry-run nor failed pushes ever create,
    reset, or delete local branches. In live mode, pushes `HEAD:refs/heads/revert/<sha>`
    directly to `origin` only after verification passes.
    """
    subject, author = commit_metadata(repo, culprit_sha)
    branch_name = f"revert/{culprit_sha[:9]}"
    master_sha = resolve_commit(repo, master_ref)
    if master_sha is None:
        return BisectOutcome(
            culprit_sha=culprit_sha,
            culprit_subject=subject,
            culprit_author_login=author,
            revert_branch=branch_name,
            meltdown_triggered=True,
            reason=f"could not resolve target ref {master_ref}",
        )

    parent = worktree_root or Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    wt_dir = Path(tempfile.mkdtemp(prefix=f"mdk-revert-{culprit_sha[:9]}-", dir=parent))
    wt_dir.rmdir()

    try:
        add = _git(repo, "worktree", "add", "--detach", str(wt_dir), master_sha, check=False)
        if add.returncode != 0:
            return BisectOutcome(
                culprit_sha=culprit_sha,
                culprit_subject=subject,
                culprit_author_login=author,
                revert_branch=branch_name,
                meltdown_triggered=True,
                reason=f"failed to create detached revert worktree at {master_sha[:9]}",
            )

        # Re-verify current master still exhibits the failure before reverting.
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
            return BisectOutcome(
                culprit_sha=culprit_sha,
                culprit_subject=subject,
                culprit_author_login=author,
                revert_branch=branch_name,
                meltdown_triggered=True,
                reason=f"inconclusive live-master recheck at {master_sha[:9]} ({master_detail})",
            )

        revert = _git(wt_dir, "revert", "--no-edit", "--no-commit", culprit_sha, check=False)
        if revert.returncode != 0:
            _git(wt_dir, "revert", "--abort", check=False)
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
        commit_res = _git(wt_dir, *commit_args, check=False)
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

        verdict, _detail = predicate(wt_dir)
        if verdict not in {RunVerdict.PASS, RunVerdict.TEST_ABSENT}:
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

        pr_url = ""
        if not dry_run:
            push = _git(
                wt_dir,
                "push",
                "--force-with-lease",
                "origin",
                f"HEAD:refs/heads/{branch_name}",
                check=False,
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
                pr_url = find_existing_pr(branch_name)
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
        _git(repo, "worktree", "remove", "--force", str(wt_dir), check=False)
        shutil.rmtree(wt_dir, ignore_errors=True)
