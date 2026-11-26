"""Signed `tree-state` branch updates and White Noise (Marmot) alerting."""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime as dt
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any


def sanitize_single_line(text: str, *, max_len: int = 240) -> str:
    """Collapse whitespace/newlines and bound length for public state/commit summaries."""
    cleaned = " ".join(text.split())
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3].rstrip() + "..."


@dataclass(frozen=True)
class Roster:
    """Mapping from GitHub logins to White Noise (Marmot) targets."""

    github_to_group: dict[str, str] = field(default_factory=dict)
    engineering_group_id: str = ""
    wn_bin: str = "wn"
    alert_log_path: str = ""

    @classmethod
    def load(cls, path: Path | None) -> Roster:
        if path is None or not path.is_file():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            github_to_group=dict(raw.get("github_to_group", {})),
            engineering_group_id=str(raw.get("engineering_group_id", "")),
            wn_bin=str(raw.get("wn_bin", "wn")),
            alert_log_path=str(raw.get("alert_log_path", "")),
        )


class MarmotAlerter:
    """Deliver concise alerts via White Noise (`wn`) or record them in dry-run mode."""

    def __init__(self, roster: Roster, *, dry_run: bool = True) -> None:
        self.roster = roster
        self.dry_run = dry_run
        self.sent: list[dict[str, Any]] = []

    def notify_authors(self, logins: list[str], message: str) -> list[str]:
        """Alert each GitHub login mapped in the roster; fall back to engineering group."""
        delivered: list[str] = []
        for login in logins:
            group_id = self.roster.github_to_group.get(login)
            if group_id:
                self._send(target=f"direct:{login}", group_id=group_id, message=message)
                delivered.append(login)
        if not delivered and self.roster.engineering_group_id:
            self.notify_engineering_group(message)
        return delivered

    def notify_engineering_group(self, message: str) -> None:
        """Send an escalation or ops alert to the MDK engineering White Noise group."""
        self._send(
            target="engineering_group",
            group_id=self.roster.engineering_group_id,
            message=message,
        )

    def _send(self, *, target: str, group_id: str, message: str) -> None:
        record = {
            "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dry_run": self.dry_run,
            "target": target,
            "has_group": bool(group_id),
            "message": sanitize_single_line(message, max_len=400),
        }
        self.sent.append(record)
        if self.roster.alert_log_path:
            log_path = Path(self.roster.alert_log_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        if self.dry_run or not group_id:
            return
        wn_path = shutil.which(self.roster.wn_bin)
        if not wn_path:
            return
        # Best-effort delivery; notification failure must never abort tree-state updates.
        subprocess.run(
            [wn_path, "messages", "send", group_id, message],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )


class TreeStateController:
    """Read and update the signed orphan `origin/tree-state` branch (`state.json`)."""

    def __init__(
        self,
        repo: Path,
        *,
        dry_run: bool = True,
        sign_commits: bool = True,
    ) -> None:
        self.repo = repo
        self.dry_run = dry_run
        self.sign_commits = sign_commits

    def read_remote_status(self) -> str:
        """Return confirmed remote status: `green`, `red`, `absent`, or `error`.

        Explicitly distinguishes an unavailable remote/fetch failure (`error`) from a
        confirmed `red` state so `set_state("red")` never treats a read error as a
        completed freeze.
        """
        ls_res = subprocess.run(
            ["git", "-C", str(self.repo), "ls-remote", "--exit-code", "origin", "refs/heads/tree-state"],
            check=False,
            capture_output=True,
            text=True,
        )
        if ls_res.returncode == 2:
            return "absent"
        if ls_res.returncode != 0:
            return "error"

        fetch_res = subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "fetch",
                "--no-tags",
                "origin",
                "+refs/heads/tree-state:refs/remotes/origin/tree-state",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if fetch_res.returncode != 0:
            return "error"

        show = subprocess.run(
            ["git", "-C", str(self.repo), "show", "origin/tree-state:state.json"],
            check=False,
            capture_output=True,
            text=True,
        )
        if show.returncode != 0:
            return "error"
        try:
            doc = json.loads(show.stdout)
            state = doc.get("state")
            if state in {"green", "red"}:
                return str(state)
            return "error"
        except json.JSONDecodeError:
            return "error"

    def set_state(
        self,
        new_state: str,
        *,
        reason: str,
        run_url: str | None = None,
    ) -> bool:
        """Set `origin/tree-state` to `green` or `red`.

        Raises RuntimeError if `origin/tree-state` cannot be read or updated, so
        callers never silently mark a transition as completed when the push failed.
        """
        if new_state not in {"green", "red"}:
            raise ValueError(f"invalid tree state: {new_state}")
        clean_reason = sanitize_single_line(reason, max_len=240)
        public_url = run_url if isinstance(run_url, str) and run_url.startswith(("http://", "https://")) else None
        if self.dry_run:
            return True

        current = self.read_remote_status()
        if current == "error":
            raise RuntimeError("unable to read origin/tree-state before transition")
        if current == "absent":
            raise RuntimeError("origin/tree-state branch does not exist")
        if current == new_state:
            return False

        wt_dir = Path(tempfile.mkdtemp(prefix="mdk-tree-state-"))
        wt_dir.rmdir()
        try:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.repo),
                    "worktree",
                    "add",
                    "--detach",
                    str(wt_dir),
                    "origin/tree-state",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            payload = {
                "schema_version": 1,
                "state": new_state,
                "updated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "reason": clean_reason,
                "run_url": public_url,
            }
            (wt_dir / "state.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(wt_dir), "add", "state.json"], check=True)
            commit_cmd = ["git", "-C", str(wt_dir), "commit"]
            commit_cmd.append("-S" if self.sign_commits else "--no-gpg-sign")
            commit_cmd.extend(["-m", f"Set tree-state to {new_state}: {clean_reason}"])
            subprocess.run(commit_cmd, check=True, capture_output=True, text=True)
            subprocess.run(
                ["git", "-C", str(wt_dir), "push", "origin", "HEAD:refs/heads/tree-state"],
                check=True,
                capture_output=True,
                text=True,
            )
            return True
        finally:
            subprocess.run(
                ["git", "-C", str(self.repo), "worktree", "remove", "--force", str(wt_dir)],
                check=False,
                capture_output=True,
                text=True,
            )
            shutil.rmtree(wt_dir, ignore_errors=True)
