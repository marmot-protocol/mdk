#!/usr/bin/env python3
"""Maintain one trusted comment explaining a PR's signature blockers."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


COMMENT_MARKER = "<!-- mdk-pr-signatures -->"


def api(path: str, *, method: str = "GET", body: dict | None = None,
        paginate: bool = False):
    command = ["gh", "api", path, "--method", method]
    if paginate:
        command += ["--paginate", "--slurp"]
    if body is not None:
        command += ["--input", "-"]
    result = subprocess.run(command, input=json.dumps(body) if body is not None else None,
                            text=True, capture_output=True, check=True, timeout=120)
    return json.loads(result.stdout)


def inspect_signatures(repo: str, number: int, expected_head: str) -> list[str]:
    path = f"repos/{repo}/pulls/{number}"
    before = api(path)
    if before["state"] != "open" or before["head"]["sha"] != expected_head:
        raise ValueError("PR is closed or its head changed; inspect the current run instead")
    # Unlike the PR-commits endpoint (capped at 250), a paginated comparison
    # returns the complete base..head range, including commits from fork PRs.
    base = before["base"]["sha"]
    pages = api(f"repos/{repo}/compare/{base}...{expected_head}?per_page=100", paginate=True)
    commits = [commit for page in pages for commit in page["commits"]]
    # Never approve a truncated list, an empty response, or a moving snapshot.
    after = api(path)
    commit_ids = {commit["sha"] for commit in commits}
    if (after["state"] != "open" or after["head"]["sha"] != expected_head
            or after["base"]["sha"] != before["base"]["sha"]
            or len(commits) != before["commits"] or len(commits) != after["commits"]
            or not commits or len(commit_ids) != len(commits) or expected_head not in commit_ids):
        raise ValueError("Could not verify the complete current PR commit list")
    return [commit["sha"] for commit in commits
            if commit["commit"].get("verification", {}).get("verified") is not True]


def update_comment(repo: str, number: int, head: str, unsigned: list[str]) -> None:
    pages = api(f"repos/{repo}/issues/{number}/comments?per_page=100", paginate=True)
    comment = next((item for page in pages for item in page
                    if item["user"]["login"] == "github-actions[bot]"
                    and item["body"].startswith(COMMENT_MARKER)), None)
    if not unsigned and comment is None:
        return
    if unsigned:
        commits = ", ".join(f"`{sha}`" for sha in unsigned[:20])
        if len(unsigned) > 20:
            commits += f", and {len(unsigned) - 20} more"
        body = (
            f"{COMMENT_MARKER}\n"
            "This PR remains open, but build and test jobs are paused until every PR commit "
            "has a signature GitHub verifies.\n\n"
            f"Commits needing a verified signature: {commits}.\n\n"
            "Please register your signing key with GitHub, then rewrite and sign the affected "
            "commits and push them to this PR branch. For a single-commit PR, use "
            "`git commit --amend --no-edit -S` followed by `git push --force-with-lease`. "
            "Adding a signed follow-up commit does not sign earlier commits.\n\n"
            "[GitHub signing guide](https://docs.github.com/en/authentication/"
            "managing-commit-signature-verification/signing-commits). "
            "Pushing signed replacements starts a new CI run; if you only register an existing "
            "signing key, re-run the failed workflows after GitHub shows the commits as Verified."
        )
    else:
        body = (f"{COMMENT_MARKER}\nAll PR commits now have verified signatures at `{head}`. "
                "The signature blocker is resolved; normal CI and merge requirements still apply.")
    # Do not let an older run overwrite the comment for a replacement head.
    current = api(f"repos/{repo}/pulls/{number}")
    if current["state"] != "open" or current["head"]["sha"] != head:
        raise ValueError("PR changed before the comment could be updated")
    if comment is None:
        api(f"repos/{repo}/issues/{number}/comments", method="POST", body={"body": body})
    elif comment["body"] != body:
        api(f"repos/{repo}/issues/comments/{comment['id']}", method="PATCH", body={"body": body})


def main() -> int:
    if os.environ["GITHUB_EVENT_NAME"] != "pull_request_target":
        raise ValueError("Only the trusted pull_request_target workflow may comment")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    repo = os.environ["GITHUB_REPOSITORY"]
    number = int(event["number"])
    head = event["pull_request"]["head"]["sha"]
    unsigned = inspect_signatures(repo, number, head)
    update_comment(repo, number, head, unsigned)
    if unsigned:
        print("Signature check blocked: every PR commit must be signed and Verified on GitHub.",
              file=sys.stderr)
        return 1
    print("All PR commits have GitHub-verified signatures.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f"Signature check could not complete: {error}", file=sys.stderr)
        sys.exit(1)
