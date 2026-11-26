"""Data models and atomic state persistence for the MDK Bisect Agent."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
import os
from pathlib import Path
import tempfile
from typing import Any


class Bucket(str, Enum):
    """Classification buckets for Canary failures."""

    INFRA_ERROR = "infra_error"
    KNOWN_FLAKE = "known_flake"
    NEW_INTERMITTENT = "new_intermittent"
    DETERMINISTIC_REGRESSION = "deterministic_regression"
    UNREPRODUCIBLE = "unreproducible"


class RunVerdict(str, Enum):
    """Outcome of running a verification command on a checked-out commit."""

    PASS = "pass"
    FAIL = "fail"
    TEST_ABSENT = "test_absent"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class FailureSignal:
    """Normalized failure from bare-metal Canary or hosted Canary runs."""

    source: str  # "bare_metal_canary" | "hosted_canary"
    run_id: str
    run_url: str  # Public HTTP(S) URL when available; empty for local bare-metal runs.
    tip_sha: str
    baseline_sha: str
    failed_job: str
    failed_step: str = ""
    failed_test: str | None = None
    command: tuple[str, ...] = ()
    log_excerpt: str = ""
    conclusion: str = "failure"
    reproducible_locally: bool = True
    infra_hint: bool = False


@dataclass(frozen=True)
class ClassificationResult:
    """Result of classifying a single FailureSignal."""

    bucket: Bucket
    reason: str
    matched_issue: int | None = None


@dataclass(frozen=True)
class BisectOutcome:
    """Outcome of bisecting and attempting a revert-only recovery."""

    culprit_sha: str | None
    culprit_subject: str = ""
    culprit_author_login: str = ""
    clean_revert: bool = False
    revert_verified: bool = False
    revert_branch: str = ""
    revert_pr_url: str = ""
    meltdown_triggered: bool = False
    already_healed: bool = False
    duplicate_pr: bool = False
    pr_creation_failed: bool = False
    reason: str = ""


@dataclass
class IncidentRecord:
    """Active per-source Meltdown incident tracked for 30-minute escalation and recovery."""

    started_at: float
    reason: str
    run_url: str
    tip_sha: str
    source: str
    culprit_sha: str | None = None
    issue_number: int | None = None
    escalated_at: float | None = None


@dataclass
class AgentState:
    """Persistent controller state across poll intervals."""

    schema_version: int = 1
    seen_runs: list[str] = field(default_factory=list)
    retried_runs: list[str] = field(default_factory=list)
    consecutive_unreproducible_reds: dict[str, int] = field(default_factory=dict)
    consecutive_infra_failures: dict[str, int] = field(default_factory=dict)
    last_unreproducible_attempt: dict[str, str] = field(default_factory=dict)
    last_infra_attempt: dict[str, str] = field(default_factory=dict)
    consecutive_flake_blocks: dict[str, int] = field(default_factory=dict)
    intermittent_hits: dict[str, int] = field(default_factory=dict)
    open_revert_prs: dict[str, str] = field(default_factory=dict)
    open_revert_commands: dict[str, list[list[str]]] = field(default_factory=dict)
    tree_state: str = "green"
    active_incidents: dict[str, IncidentRecord] = field(default_factory=dict)

    def mark_seen(self, key: str, *, max_seen: int = 200) -> None:
        if key not in self.seen_runs:
            self.seen_runs.append(key)
        if len(self.seen_runs) > max_seen:
            self.seen_runs = self.seen_runs[-max_seen:]

    def mark_retried(self, base_run_id: str, *, max_retried: int = 200) -> None:
        if base_run_id not in self.retried_runs:
            self.retried_runs.append(base_run_id)
        if len(self.retried_runs) > max_retried:
            self.retried_runs = self.retried_runs[-max_retried:]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentState:
        raw_incidents = data.get("active_incidents", {})
        incidents: dict[str, IncidentRecord] = {}
        allowed = {
            "started_at",
            "reason",
            "run_url",
            "tip_sha",
            "source",
            "culprit_sha",
            "issue_number",
            "escalated_at",
        }
        if isinstance(raw_incidents, dict):
            for source, raw_inc in raw_incidents.items():
                if isinstance(raw_inc, dict):
                    filtered = {k: v for k, v in raw_inc.items() if k in allowed}
                    filtered.setdefault("source", str(source))
                    incidents[str(source)] = IncidentRecord(**filtered)

        return cls(
            schema_version=int(data.get("schema_version", 1)),
            seen_runs=list(data.get("seen_runs", [])),
            retried_runs=list(data.get("retried_runs", [])),
            consecutive_unreproducible_reds={
                str(k): int(v) for k, v in dict(data.get("consecutive_unreproducible_reds", {})).items()
            },
            consecutive_infra_failures={
                str(k): int(v) for k, v in dict(data.get("consecutive_infra_failures", {})).items()
            },
            last_unreproducible_attempt={
                str(k): str(v) for k, v in dict(data.get("last_unreproducible_attempt", {})).items()
            },
            last_infra_attempt={
                str(k): str(v) for k, v in dict(data.get("last_infra_attempt", {})).items()
            },
            consecutive_flake_blocks={
                str(k): int(v) for k, v in dict(data.get("consecutive_flake_blocks", {})).items()
            },
            intermittent_hits={
                str(k): int(v) for k, v in dict(data.get("intermittent_hits", {})).items()
            },
            open_revert_prs={
                str(k): str(v) for k, v in dict(data.get("open_revert_prs", {})).items()
            },
            open_revert_commands={
                str(k): [
                    [str(arg) for arg in cmd]
                    for cmd in cmds
                    if isinstance(cmd, list)
                ]
                for k, cmds in dict(data.get("open_revert_commands", {})).items()
                if isinstance(cmds, list)
            },
            tree_state=str(data.get("tree_state", "green")),
            active_incidents=incidents,
        )


def load_state(path: Path) -> AgentState:
    """Load persisted agent state, returning a clean default when absent."""
    if not path.is_file():
        return AgentState()
    raw = json.loads(path.read_text(encoding="utf-8"))
    return AgentState.from_dict(raw)


def save_state(path: Path, state: AgentState) -> None:
    """Atomically write private (0600) agent state JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".bisect-state-", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
