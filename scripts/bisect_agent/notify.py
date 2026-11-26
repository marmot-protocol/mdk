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


GIT_REMOTE_TIMEOUT_SECS = 60
GIT_LOCAL_TIMEOUT_SECS = 30
WN_SEND_TIMEOUT_SECS = 60


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
            if group_id and self._send(target=f"direct:{login}", group_id=group_id, message=message):
                delivered.append(login)
        if not delivered and self.roster.engineering_group_id:
            self.notify_engineering_group(message)
        return delivered

    def notify_engineering_group(self, message: str) -> bool:
        """Send an escalation or ops alert to the MDK engineering White Noise group.

        Returns True when the alert was accepted (or recorded in dry-run mode),
        False when delivery failed, timed out, or had no configured target/binary.
        """
        return self._send(
            target="engineering_group",
            group_id=self.roster.engineering_group_id,
            message=message,
        )

    def _send(self, *, target: str, group_id: str, message: str) -> bool:
        record = {
            "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dry_run": self.dry_run,
            "target": target,
            "has_group": bool(group_id),
            "message": sanitize_single_line(message, max_len=400),
            "accepted": False,
        }
        self.sent.append(record)
        # Alert log writes are best-effort and must never block delivery or escape to callers.
        if self.roster.alert_log_path:
            try:
                log_path = Path(self.roster.alert_log_path)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                with log_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record) + "\n")
            except OSError:
                pass
        if self.dry_run:
            record["accepted"] = True
            return True
        if not group_id:
            return False
        wn_path = shutil.which(self.roster.wn_bin)
        if not wn_path:
            return False
        # Best-effort delivery; notification failure must never abort tree-state updates,
        # while returning False lets escalation callers keep the alert pending for retry.
        try:
            proc = subprocess.run(
                [wn_path, "messages", "send", group_id, message],
                check=False,
                capture_output=True,
                text=True,
                timeout=WN_SEND_TIMEOUT_SECS,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        accepted = proc.returncode == 0
        record["accepted"] = accepted
        return accepted


class ManualFreezeError(RuntimeError):
    """Raised when an automated transition attempts to clear a manual tree-state freeze."""


def _is_full_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _has_valid_incidents(doc: dict[str, Any] | None) -> bool:
    """Return True when `doc` carries at least one valid durable `(source, tip_sha)` incident."""
    if not isinstance(doc, dict):
        return False
    raw = doc.get("incidents")
    if not isinstance(raw, dict):
        return False
    for key, item in raw.items():
        if not isinstance(item, dict):
            continue
        source = str(item.get("source") or key).strip()
        if source and _is_full_sha(item.get("tip_sha")):
            return True
    return False


def is_manual_freeze_document(doc: dict[str, Any] | None) -> bool:
    """Return True when `doc` represents a manual/external `red` freeze rather than an agent incident."""
    if not isinstance(doc, dict) or doc.get("state") != "red":
        return False
    if doc.get("manual") is True:
        return True
    return not _has_valid_incidents(doc)


class TreeStateController:
    """Read and update the signed orphan `origin/tree-state` branch (`state.json`)."""

    def __init__(
        self,
        repo: Path,
        *,
        dry_run: bool = True,
        sign_commits: bool = True,
        remote_timeout_secs: int = GIT_REMOTE_TIMEOUT_SECS,
        local_timeout_secs: int = GIT_LOCAL_TIMEOUT_SECS,
    ) -> None:
        self.repo = repo
        self.dry_run = dry_run
        self.sign_commits = sign_commits
        self.remote_timeout_secs = remote_timeout_secs
        self.local_timeout_secs = local_timeout_secs

    def read_remote_snapshot(self) -> tuple[str, dict[str, Any] | None, str]:
        """Return `(status, parsed_doc, rev_sha)` where `status` is `green`, `red`, `absent`, or `error`.

        `rev_sha` is the exact 40-char commit SHA of `refs/remotes/origin/tree-state` read,
        enabling compare-and-swap transitions bound to the checked revision.
        Explicitly distinguishes an unavailable remote/fetch/timeout failure (`error`) from a
        confirmed `red` state and rejects invalid JSON shapes so exceptions never escape.
        """
        try:
            ls_res = subprocess.run(
                ["git", "-C", str(self.repo), "ls-remote", "--exit-code", "origin", "refs/heads/tree-state"],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.remote_timeout_secs,
            )
        except (subprocess.TimeoutExpired, OSError):
            return "error", None, ""
        if ls_res.returncode == 2:
            return "absent", None, ""
        if ls_res.returncode != 0:
            return "error", None, ""

        try:
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
                timeout=self.remote_timeout_secs,
            )
        except (subprocess.TimeoutExpired, OSError):
            return "error", None, ""
        if fetch_res.returncode != 0:
            return "error", None, ""

        try:
            rev_res = subprocess.run(
                ["git", "-C", str(self.repo), "rev-parse", "--verify", "refs/remotes/origin/tree-state^{commit}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.local_timeout_secs,
            )
        except (subprocess.TimeoutExpired, OSError):
            return "error", None, ""
        if rev_res.returncode != 0:
            return "error", None, ""
        rev_sha = rev_res.stdout.strip()
        if not _is_full_sha(rev_sha):
            return "error", None, ""

        try:
            show = subprocess.run(
                ["git", "-C", str(self.repo), "show", f"{rev_sha}:state.json"],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.local_timeout_secs,
            )
        except (subprocess.TimeoutExpired, OSError):
            return "error", None, ""
        if show.returncode != 0:
            return "error", None, ""
        try:
            doc = json.loads(show.stdout)
        except json.JSONDecodeError:
            return "error", None, ""
        if not isinstance(doc, dict):
            return "error", None, ""
        state = doc.get("state")
        if not isinstance(state, str) or state not in {"green", "red"}:
            return "error", None, ""
        return state, doc, rev_sha

    def read_remote_document(self) -> tuple[str, dict[str, Any] | None]:
        """Return `(status, parsed_doc)` where `status` is `green`, `red`, `absent`, or `error`."""
        status, doc, _rev = self.read_remote_snapshot()
        return status, doc

    def read_remote_status(self) -> str:
        """Return confirmed remote status: `green`, `red`, `absent`, or `error`."""
        status, _doc, _rev = self.read_remote_snapshot()
        return status

    def set_state(
        self,
        new_state: str,
        *,
        reason: str,
        run_url: str | None = None,
        incidents: dict[str, dict[str, Any]] | None = None,
        expected_rev: str | None = None,
        allow_manual_override: bool = False,
    ) -> bool:
        """Set `origin/tree-state` to `green` or `red` with durable incident metadata.

        Binds the update to `expected_rev` (when provided) and the exact fetched
        `current_rev` via non-force push so concurrent updates never clobber each other.
        Preserves manual freezes in both directions unless `allow_manual_override=True`:
          - Refuses `green` transitions while remote holds a manual freeze (`ManualFreezeError`).
          - Refuses to overwrite a manual `red` freeze with agent incidents (returns `False`),
            preventing a subsequent automated green from clearing an operator freeze.
        """
        if new_state not in {"green", "red"}:
            raise ValueError(f"invalid tree state: {new_state}")
        clean_reason = sanitize_single_line(reason, max_len=240)
        public_url = run_url if isinstance(run_url, str) and run_url.startswith(("http://", "https://")) else None
        payload_incidents = dict(incidents) if new_state == "red" and incidents else {}
        if self.dry_run:
            return True

        current, current_doc, current_rev = self.read_remote_snapshot()
        if current == "error":
            raise RuntimeError("unable to read origin/tree-state before transition")
        if current == "absent":
            raise RuntimeError("origin/tree-state branch does not exist")
        if expected_rev is not None and current_rev != expected_rev:
            raise RuntimeError(
                f"origin/tree-state changed concurrently ({expected_rev[:9]} -> {current_rev[:9]})"
            )

        remote_is_manual = is_manual_freeze_document(current_doc)
        if remote_is_manual and not allow_manual_override:
            if new_state == "green":
                raise ManualFreezeError("refusing to clear manual origin/tree-state freeze automatically")
            # Keep an existing manual freeze intact rather than converting it into an
            # agent-clearable incident that the next automated green could clear.
            return False

        if current == new_state:
            existing_incidents = current_doc.get("incidents") if isinstance(current_doc, dict) else None
            if new_state == "green" or existing_incidents == payload_incidents:
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
                    current_rev,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=self.local_timeout_secs,
            )
            payload: dict[str, Any] = {
                "schema_version": 1,
                "state": new_state,
                "updated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "reason": clean_reason,
                "run_url": public_url,
                "incidents": payload_incidents,
            }
            (wt_dir / "state.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(wt_dir), "add", "state.json"],
                check=True,
                capture_output=True,
                text=True,
                timeout=self.local_timeout_secs,
            )
            commit_cmd = ["git", "-C", str(wt_dir), "commit"]
            commit_cmd.append("-S" if self.sign_commits else "--no-gpg-sign")
            commit_cmd.extend(["-m", f"Set tree-state to {new_state}: {clean_reason}"])
            subprocess.run(
                commit_cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.local_timeout_secs,
            )
            subprocess.run(
                ["git", "-C", str(wt_dir), "push", "origin", "HEAD:refs/heads/tree-state"],
                check=True,
                capture_output=True,
                text=True,
                timeout=self.remote_timeout_secs,
            )
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as exc:
            raise RuntimeError(f"failed to update origin/tree-state to {new_state}: {exc}") from exc
        finally:
            try:
                subprocess.run(
                    ["git", "-C", str(self.repo), "worktree", "remove", "--force", str(wt_dir)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=self.local_timeout_secs,
                )
            except (subprocess.TimeoutExpired, OSError):
                pass
            shutil.rmtree(wt_dir, ignore_errors=True)
