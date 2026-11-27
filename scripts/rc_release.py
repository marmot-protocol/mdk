#!/usr/bin/env python3
"""Plan, stage, publish, and expire SemVer Release Candidates (RCs) for MDK.

`.github/workflows/rc-releases.yml` drives every subcommand; see
`release.md#daily-release-candidates`. Pure functions at the top hold the SemVer
RC naming, compatibility, selection, and retention rules and are unit-tested in
`scripts/test_rc_release.py` and `scripts/test_ci_workflow_policy.py`.

Every RC is built strictly from the verified `canary` branch tip (never
unverified `master`), gated on `simulator-nightly` + `convergence-hardening` +
all three artifact tracks (`MarmotKit`, `Marmot C`, `wn-agent`), published
atomically as immutable pre-releases (`<track>-vX.Y.Z-rc.N`), and recorded with
its `signature_delta.json`, `impact_report.json`, and rolling integration notes
on the signed orphan `rc-meta` branch.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import classify_release_impact as impact_classifier  # noqa: E402

TRACKS = (
    ("marmotkit", "MarmotKit"),
    ("marmotc", "Marmot C"),
    ("wn-agent", "wn-agent"),
)
TRACK_PREFIXES = tuple(prefix for prefix, _ in TRACKS)
META_BRANCH = "rc-meta"
RC_LATEST_FILE = "rc/latest.json"
RC_DELTA_FILE = "rc/signature_delta.json"
RC_IMPACT_FILE = "rc/impact_report.json"
RC_NOTES_FILE = "rc/integration-notes.md"
RC_COUNTERS_FILE = "rc/counters.json"
RC_RELEASES_DIR = "rc/releases"
STABLE_LATEST_FILE = "stable/latest.json"
RETENTION_DAYS = 30
RC_WORKFLOW = "rc-releases.yml"
PROMOTE_WORKFLOW = "promote-release.yml"
LANE_JOB = "Wait for release lane"
LANE_STEP = "Wait for releases and snapshots to finish"
ACTIVE_STATUSES = ("queued", "in_progress", "waiting", "requested", "pending")

DEV_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)-dev$")
STABLE_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
RC_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)-rc\.([1-9]\d*)$")
RC_TAG = re.compile(
    r"^(?P<track>marmotkit|marmotc|wn-agent)-v(?P<version>\d+\.\d+\.\d+-rc\.[1-9]\d*)$"
)
STABLE_TRACK_TAG = re.compile(
    r"^(?P<track>marmotkit|marmotc|wn-agent)-v(?P<version>\d+\.\d+\.\d+)$"
)
# Legacy nightly pattern kept so retention continues expiring old dated nightlies cleanly.
LEGACY_NIGHTLY_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)-nightly\.(\d{8})(?:\.([1-9]\d{0,2}))?$")
LEGACY_NIGHTLY_TAG = re.compile(
    r"^(?P<track>marmotkit|marmotc|wn-agent)-v(?P<version>\d+\.\d+\.\d+-nightly\.\d{8}(?:\.[1-9]\d{0,2})?)$"
)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class ReleaseError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Pure rules
# ---------------------------------------------------------------------------


def dev_base_version(workspace_version: str) -> tuple[int, int, int] | None:
    """Return `(major, minor, patch)` for master's `X.Y.Z-dev`, or None otherwise."""
    match = DEV_VERSION.fullmatch(workspace_version)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def rc_matches_workspace_dev(rc_version: str, workspace_version: str) -> bool:
    """Return True if `rc_version` (`X.Y.Z-rc.N`) is valid for master's `W_MAJOR.W_MINOR.0-dev`.

    Allows either:
      - A minor RC on the active dev line (`0.20.0-rc.N` when workspace is `0.20.0-dev`), or
      - A patch RC on the preceding minor line (`0.19.1-rc.N` when workspace is `0.20.0-dev`).
    """
    rc_match = RC_VERSION.fullmatch(rc_version)
    dev_tuple = dev_base_version(workspace_version)
    if rc_match is None or dev_tuple is None:
        return False
    rc_major, rc_minor, rc_patch = int(rc_match.group(1)), int(rc_match.group(2)), int(rc_match.group(3))
    ws_major, ws_minor, ws_patch = dev_tuple
    if ws_patch != 0:
        return (rc_major, rc_minor, rc_patch) == (ws_major, ws_minor, ws_patch)
    if (rc_major, rc_minor, rc_patch) == (ws_major, ws_minor, 0):
        return True
    return rc_major == ws_major and rc_minor + 1 == ws_minor and rc_patch >= 1


def check_release_version(release_version: str, workspace_version: str) -> str:
    """Validate `release_version` (`X.Y.Z-rc.N` or `X.Y.Z`) against `workspace_version`.

    Returns `"rc"` for a compatible SemVer RC or `"stable"` for an exact Stable
    match; raises `ReleaseError` otherwise.
    """
    if RC_VERSION.fullmatch(release_version) is not None:
        if dev_base_version(workspace_version) is None:
            raise ReleaseError(
                f"RC {release_version} requires X.Y.Z-dev workspace version, got {workspace_version}"
            )
        if not rc_matches_workspace_dev(release_version, workspace_version):
            raise ReleaseError(
                f"RC {release_version} is incompatible with source workspace version {workspace_version}"
            )
        return "rc"
    if STABLE_VERSION.fullmatch(release_version) is not None:
        if release_version != workspace_version:
            raise ReleaseError(
                f"stable release version {release_version} does not match workspace version {workspace_version}"
            )
        return "stable"
    raise ReleaseError(f"release_version must be X.Y.Z-rc.N or X.Y.Z, got {release_version}")


def rc_base_version(version: str) -> str:
    match = RC_VERSION.fullmatch(version)
    if match is None:
        raise ReleaseError(f"not an RC version: {version}")
    return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"


def track_tags(version: str, *, allow_stable: bool = False) -> dict[str, str]:
    valid_rc = RC_VERSION.fullmatch(version) is not None
    valid_stable = allow_stable and STABLE_VERSION.fullmatch(version) is not None
    if not (valid_rc or valid_stable):
        raise ReleaseError(f"invalid release version: {version}")
    return {prefix: f"{prefix}-v{version}" for prefix in TRACK_PREFIXES}


def choose_rc_version(
    base: str,
    taken_tags: Iterable[str],
    *,
    min_counter: int = 0,
    historical_versions: Iterable[str] = (),
) -> str:
    """Return the next unused `<base>-rc.<N>` (`N >= 1`) across all tracks.

    A candidate counts as taken if any track tag exists or any persisted RC
    counter/history record on `rc-meta` already allocated it, because GitHub
    forbids reusing deleted immutable-release tag names after retention.
    """
    if STABLE_VERSION.fullmatch(base) is None:
        raise ReleaseError(f"base version must be X.Y.Z, got {base!r}")
    taken = set(taken_tags)
    max_seen = max(0, int(min_counter))
    for tag in taken:
        match = RC_TAG.fullmatch(tag)
        if not match:
            continue
        ver = match.group("version")
        rc_match = RC_VERSION.fullmatch(ver)
        if rc_match and f"{rc_match.group(1)}.{rc_match.group(2)}.{rc_match.group(3)}" == base:
            max_seen = max(max_seen, int(rc_match.group(4)))
    for ver in historical_versions:
        rc_match = RC_VERSION.fullmatch(ver)
        if rc_match and f"{rc_match.group(1)}.{rc_match.group(2)}.{rc_match.group(3)}" == base:
            max_seen = max(max_seen, int(rc_match.group(4)))
    for counter in range(max_seen + 1, max_seen + 10000):
        version = f"{base}-rc.{counter}"
        if not any(tag in taken for tag in track_tags(version).values()):
            return version
    raise ReleaseError(f"no free RC number left for {base}")


def select_canary_source(
    first_parent_master: list[str],
    canary_tip: str | None,
    previous_sha: str | None,
) -> str:
    """Select the exact verified `canary` commit on master's first-parent history.

    Never selects an unverified `master` commit and never rewinds behind `previous_sha`.
    """
    if not canary_tip:
        raise ReleaseError("origin/canary branch ref is missing; RC builds require a verified canary tip")
    if canary_tip not in first_parent_master:
        raise ReleaseError(
            f"origin/canary tip {canary_tip} is not on origin/master first-parent history"
        )
    if (
        previous_sha is not None
        and previous_sha in first_parent_master
        and first_parent_master.index(previous_sha) < first_parent_master.index(canary_tip)
    ):
        # Never move backwards past the previous published RC.
        return previous_sha
    return canary_tip


def legacy_nightly_tag_date(tag: str) -> dt.date | None:
    match = LEGACY_NIGHTLY_TAG.fullmatch(tag)
    if match is None:
        return None
    ver_match = LEGACY_NIGHTLY_VERSION.fullmatch(match.group("version"))
    if ver_match is None:
        return None
    try:
        return dt.datetime.strptime(ver_match.group(4), "%Y%m%d").date()
    except ValueError:
        return None


def parse_iso_date(timestamp: str | None) -> dt.date | None:
    if not timestamp:
        return None
    try:
        return dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def expired_prerelease_tags(
    tags: Iterable[str],
    releases_by_tag: dict[str, dict[str, Any]],
    today: dt.date,
    protected: Iterable[str],
    days: int = RETENTION_DAYS,
) -> list[str]:
    """Return expired RC and legacy nightly tags older than `days` before `today`.

    Formal releases (`vX.Y.Z`, `<track>-vX.Y.Z`), snapshots (`marmotkit-snapshot-*`),
    non-prereleases, and protected tags (current `rc/latest.json`) are never returned.
    """
    keep = set(protected)
    cutoff = today - dt.timedelta(days=days)
    expired: list[str] = []
    for tag in sorted(set(tags)):
        if tag in keep:
            continue
        nightly_date = legacy_nightly_tag_date(tag)
        if nightly_date is not None:
            if nightly_date < cutoff:
                expired.append(tag)
            continue
        if RC_TAG.fullmatch(tag) is not None:
            release = releases_by_tag.get(tag)
            if release is None:
                continue
            if not (release.get("prerelease") or release.get("draft")):
                continue
            created = parse_iso_date(release.get("published_at") or release.get("created_at"))
            if created is not None and created < cutoff:
                expired.append(tag)
    return expired


def latest_rc_document(
    version: str,
    source_sha: str,
    releases: dict[str, dict[str, Any]],
    repository: str,
    run_url: str,
    *,
    impact_report: dict[str, Any] | None = None,
    today: dt.date | None = None,
) -> dict[str, Any]:
    """Build `rc/latest.json` (and `rc/releases/<version>.json`) from published track releases."""
    tracks: dict[str, Any] = {}
    for prefix, tag in track_tags(version).items():
        release = releases[prefix]
        assets = []
        for asset in sorted(release["assets"], key=lambda item: item["name"]):
            digest = asset.get("digest") or ""
            if not digest.startswith("sha256:"):
                raise ReleaseError(f"{tag}: asset {asset['name']} has no SHA-256 digest")
            assets.append({
                "name": asset["name"],
                "url": f"https://github.com/{repository}/releases/download/{tag}/{asset['name']}",
                "sha256": digest.removeprefix("sha256:"),
                "size": asset["size"],
            })
        tracks[prefix] = {
            "tag": tag,
            "release_url": f"https://github.com/{repository}/releases/tag/{tag}",
            "assets": assets,
        }
    day = today or dt.datetime.now(dt.timezone.utc).date()
    doc: dict[str, Any] = {
        "schema": 2,
        "channel": "rc",
        "version": version,
        "base_version": rc_base_version(version),
        "source_sha": source_sha,
        "date": day.isoformat(),
        "workflow_run": run_url,
        "tracks": tracks,
        "signature_delta_path": RC_DELTA_FILE,
        "impact_report_path": RC_IMPACT_FILE,
        "integration_notes_path": RC_NOTES_FILE,
    }
    if impact_report is not None:
        doc["impact"] = impact_report.get("impact")
        doc["baseline_tag"] = impact_report.get("baseline_tag")
        doc["baseline_sha"] = impact_report.get("baseline_sha")
        doc["impact_triggers"] = impact_report.get("triggers", [])
    return doc


def busy_release_runs(runs_by_workflow: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Return active runs sharing macOS runner capacity with an RC: releases, promotions, snapshots."""
    busy = []
    for workflow, runs in runs_by_workflow.items():
        for run in runs:
            if run.get("status") not in ACTIVE_STATUSES:
                continue
            if workflow == "wn-agent-binaries.yml" and not (
                run.get("event") == "push" and str(run.get("head_branch", "")).startswith("wn-agent-v")
            ):
                continue
            busy.append(run)
    return busy


TRACK_JOB_PREFIXES = ("MarmotKit", "Marmot C", "wn-agent")


def rc_is_building(jobs: list[dict[str, Any]]) -> bool:
    """Whether an RC run has passed its lane wait and is actively building packaging tracks."""
    lane_passed = False
    for job in jobs:
        if job.get("name") != LANE_JOB:
            continue
        if job.get("conclusion") == "success":
            lane_passed = True
            break
        for step in job.get("steps") or []:
            if step.get("name") == LANE_STEP and step.get("conclusion") == "success":
                lane_passed = True
                break
        if lane_passed:
            break
    if not lane_passed:
        return False
    track_jobs = [
        job
        for job in jobs
        if any(str(job.get("name", "")).startswith(prefix) for prefix in TRACK_JOB_PREFIXES)
    ]
    if not track_jobs:
        # Lane just finished and downstream track jobs have not appeared in the API yet.
        return True
    return any(job.get("status") != "completed" for job in track_jobs)


# ---------------------------------------------------------------------------
# GitHub REST API
# ---------------------------------------------------------------------------


class GitHub:
    def __init__(self, repository: str, token: str, api_url: str = "https://api.github.com"):
        self.repository = repository
        self.token = token
        self.api_url = api_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        data: bytes | None = None,
        content_type: str = "application/json",
        url: str | None = None,
        allow_404: bool = False,
    ):
        target = url or f"{self.api_url}/{path.lstrip('/')}"
        payload = data if data is not None else (json.dumps(body).encode() if body is not None else None)
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "mdk-rc-release",
        }
        if payload is not None:
            headers["Content-Type"] = content_type
        for attempt in range(4):
            request = urllib.request.Request(target, data=payload, method=method, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=300) as response:
                    raw = response.read()
                    links = response.headers.get("Link", "")
                    return (json.loads(raw) if raw else None), links
            except urllib.error.HTTPError as error:
                if error.code == 404 and allow_404:
                    return None, ""
                if error.code in (500, 502, 503, 504) and attempt < 3:
                    time.sleep(5 * (attempt + 1))
                    continue
                detail = error.read().decode(errors="replace")[:500]
                raise ReleaseError(f"{method} {target} failed with HTTP {error.code}: {detail}") from None
            except urllib.error.URLError as error:
                if attempt < 3:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise ReleaseError(f"{method} {target} failed: {error.reason}") from None
        raise AssertionError("unreachable")

    def get(self, path: str, *, allow_404: bool = False):
        return self.request("GET", path, allow_404=allow_404)[0]

    def paginate(self, path: str, key: str | None = None) -> list:
        separator = "&" if "?" in path else "?"
        url: str | None = f"{self.api_url}/{path.lstrip('/')}{separator}per_page=100"
        items: list = []
        while url:
            page, links = self.request("GET", "", url=url)
            items.extend(page[key] if key else page)
            url = None
            for part in links.split(","):
                if 'rel="next"' in part:
                    url = part[part.index("<") + 1 : part.index(">")]
        return items

    def repo(self, suffix: str) -> str:
        return f"repos/{self.repository}/{suffix.lstrip('/')}"

    def releases(self) -> list[dict[str, Any]]:
        return self.paginate(self.repo("releases"))

    def release_for_tag(self, tag: str) -> dict[str, Any] | None:
        matches = [release for release in self.releases() if release["tag_name"] == tag]
        if len(matches) > 1:
            raise ReleaseError(f"{tag}: {len(matches)} releases share this tag")
        return matches[0] if matches else None

    def tag_names(self, prefix: str) -> list[str]:
        refs = self.paginate(self.repo(f"git/matching-refs/tags/{urllib.parse.quote(prefix)}"))
        return [ref["ref"].removeprefix("refs/tags/") for ref in refs]

    def tag_commit(self, tag: str) -> str | None:
        ref = self.get(self.repo(f"git/ref/tags/{urllib.parse.quote(tag)}"), allow_404=True)
        if ref is None:
            return None
        obj = ref["object"]
        while obj["type"] == "tag":
            obj = self.get(self.repo(f"git/tags/{obj['sha']}"))["object"]
        return obj["sha"]

    def read_meta_file(self, path: str, *, branch: str = META_BRANCH) -> str | None:
        content = self.get(
            self.repo(f"contents/{urllib.parse.quote(path)}?ref={urllib.parse.quote(branch)}"),
            allow_404=True,
        )
        if content is None:
            return None
        return base64.b64decode(content["content"]).decode("utf-8")

    def read_meta_json(self, path: str, *, branch: str = META_BRANCH) -> dict[str, Any] | None:
        text = self.read_meta_file(path, branch=branch)
        return json.loads(text) if text is not None else None

    def read_latest_rc(self) -> dict[str, Any] | None:
        return self.read_meta_json(RC_LATEST_FILE)

    def read_rc_counters(self) -> dict[str, int]:
        doc = self.read_meta_json(RC_COUNTERS_FILE)
        if not isinstance(doc, dict):
            return {}
        raw = doc.get("highest_rc")
        if not isinstance(raw, dict):
            return {}
        return {str(k): int(v) for k, v in raw.items() if isinstance(v, int)}

    def list_historical_rc_versions(self) -> list[str]:
        listing = self.get(
            self.repo(f"contents/{RC_RELEASES_DIR}?ref={urllib.parse.quote(META_BRANCH)}"),
            allow_404=True,
        )
        if not isinstance(listing, list):
            return []
        return [
            str(item["name"]).removesuffix(".json")
            for item in listing
            if isinstance(item, dict) and str(item.get("name", "")).endswith(".json")
        ]

    def active_runs(self, workflow: str) -> list[dict[str, Any]]:
        runs = []
        for status in ACTIVE_STATUSES:
            page = self.get(
                self.repo(f"actions/workflows/{workflow}/runs?status={status}&per_page=100"),
                allow_404=True,
            )
            if page:
                runs.extend(page["workflow_runs"])
        return runs


# ---------------------------------------------------------------------------
# Helpers & Meta Branch Commits
# ---------------------------------------------------------------------------


def meta_github_from_env(gh: GitHub) -> GitHub:
    """The client that writes `rc-meta`: `META_GH_TOKEN` when set, else `gh`."""
    token = os.environ.get("META_GH_TOKEN")
    return GitHub(gh.repository, token, gh.api_url) if token else gh


def github_from_env() -> GitHub:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repository:
        raise ReleaseError("GH_TOKEN (or GITHUB_TOKEN) and GITHUB_REPOSITORY are required")
    return GitHub(repository, token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))


def write_outputs(values: dict[str, str]) -> None:
    lines = "".join(f"{key}={value}\n" for key, value in values.items())
    sys.stdout.write(lines)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(lines)


def write_summary(text: str) -> None:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text.rstrip("\n") + "\n")


def notice(message: str) -> None:
    print(f"::notice::{message}")


def run_url() -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"


def today_utc(value: str | None) -> dt.date:
    if value:
        return dt.date.fromisoformat(value)
    return dt.datetime.now(dt.timezone.utc).date()


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def workspace_version_at(sha: str) -> str:
    manifest = tomllib.loads(git("show", f"{sha}:Cargo.toml"))
    return manifest["workspace"]["package"]["version"]


def ref_commit(ref: str | None) -> str | None:
    if not ref:
        return None
    probe = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        return None
    return probe.stdout.strip() or None


def write_meta_files(
    gh: GitHub,
    files: dict[str, str],
    message: str,
    *,
    branch: str = META_BRANCH,
) -> str:
    """Update `files` on orphan branch `branch` via GitHub API so the commit is signed."""
    head = gh.get(gh.repo(f"git/ref/heads/{branch}"), allow_404=True)
    parents = [head["object"]["sha"]] if head else []
    base_tree = None
    if head:
        head_commit = gh.get(gh.repo(f"git/commits/{head['object']['sha']}"))
        base_tree = head_commit["tree"]["sha"]

    tree_entries = []
    for path, content in sorted(files.items()):
        blob, _ = gh.request("POST", gh.repo("git/blobs"), {"content": content, "encoding": "utf-8"})
        tree_entries.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})

    tree_body: dict[str, Any] = {"tree": tree_entries}
    if base_tree:
        tree_body["base_tree"] = base_tree
    tree, _ = gh.request("POST", gh.repo("git/trees"), tree_body)

    # Omit author/committer so GitHub signs the commit automatically.
    commit, _ = gh.request("POST", gh.repo("git/commits"), {
        "message": message,
        "tree": tree["sha"],
        "parents": parents,
    })
    verification = commit.get("verification") or {}
    if verification.get("verified") is not True:
        raise ReleaseError(
            f"{branch} commit {commit['sha']} is not verified ({verification.get('reason')}); "
            f"{branch} was not updated"
        )
    if head:
        gh.request("PATCH", gh.repo(f"git/refs/heads/{branch}"), {"sha": commit["sha"], "force": False})
    else:
        gh.request("POST", gh.repo("git/refs"), {"ref": f"refs/heads/{branch}", "sha": commit["sha"]})
    return commit["sha"]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def command_plan(args: argparse.Namespace) -> int:
    gh = github_from_env()
    day = today_utc(args.today)
    root = Path(args.root).resolve()
    all_master = git("-C", str(root), "rev-list", "--first-parent", args.master_ref).split()
    canary_tip = ref_commit(args.canary_ref)
    latest = gh.read_latest_rc()
    previous_sha = latest["source_sha"] if latest else None
    previous_version = latest["version"] if latest else "none"

    source_sha = select_canary_source(all_master, canary_tip, previous_sha)
    workspace_version = tomllib.loads(git("-C", str(root), "show", f"{source_sha}:Cargo.toml"))["workspace"][
        "package"
    ]["version"]

    outputs = {
        "skip": "false",
        "skip_reason": "",
        "source_sha": source_sha,
        "previous_sha": previous_sha or "",
        "date": day.isoformat(),
        "baseline_tag": "",
        "impact": "",
        "base_version": "",
        "version": "",
        "marmotkit_tag": "",
        "marmotc_tag": "",
        "wn_agent_tag": "",
    }

    report: dict[str, Any] | None = None
    delta: dict[str, Any] | None = None
    notes_md = ""

    if dev_base_version(workspace_version) is None:
        outputs.update(
            skip="true",
            skip_reason=f"source workspace version {workspace_version} is not an X.Y.Z-dev version",
        )
    else:
        report, delta = impact_classifier.classify_range(
            root,
            baseline_ref=args.baseline_ref,
            target_ref=source_sha,
            override_impact=args.override_impact,
        )
        base_version = report["target_base_version"]
        outputs["baseline_tag"] = report["baseline_tag"]
        outputs["impact"] = report["impact"]
        outputs["base_version"] = base_version

        if source_sha == previous_sha and not args.force:
            outputs.update(
                skip="true",
                skip_reason=f"origin/canary tip is unchanged since {previous_version}",
            )
        else:
            taken = [tag for prefix in TRACK_PREFIXES for tag in gh.tag_names(f"{prefix}-v{base_version}-rc.")]
            counters = gh.read_rc_counters()
            historical_versions = gh.list_historical_rc_versions()
            version = choose_rc_version(
                base_version,
                taken,
                min_counter=counters.get(base_version, 0),
                historical_versions=historical_versions,
            )
            if not rc_matches_workspace_dev(version, workspace_version):
                raise ReleaseError(
                    f"planned RC {version} is incompatible with source workspace version {workspace_version}"
                )
            tags = track_tags(version)
            outputs.update(
                version=version,
                marmotkit_tag=tags["marmotkit"],
                marmotc_tag=tags["marmotc"],
                wn_agent_tag=tags["wn-agent"],
            )
            notes_md = impact_classifier.render_integration_notes(report, delta, version_label=version)

    if args.artifacts_dir and report is not None and delta is not None:
        out_dir = Path(args.artifacts_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "impact_report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (out_dir / "signature_delta.json").write_text(
            json.dumps(delta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (out_dir / "signature_delta.md").write_text(
            impact_classifier.render_signature_delta_markdown(delta), encoding="utf-8"
        )
        (out_dir / "integration-notes.md").write_text(
            notes_md or impact_classifier.render_integration_notes(report, delta), encoding="utf-8"
        )

    write_outputs(outputs)
    triggers_md = (
        "\n".join(f"  - {t}" for t in (report or {}).get("triggers", []))
        or "  - none"
    )
    write_summary("\n".join([
        "## Daily SemVer RC plan",
        "",
        f"- Verified `origin/canary` SHA: `{source_sha}`",
        f"- Previous RC: `{previous_version}` from `{previous_sha or 'none'}`",
        f"- Baseline stable tag: `{outputs['baseline_tag'] or 'n/a'}`",
        f"- Source workspace version: `{workspace_version}`",
        f"- Classified impact: `{outputs['impact'] or 'n/a'}` -> target `{outputs['version'] or 'n/a'}`",
        f"- Triggers:\n{triggers_md}",
        f"- Tags: `{outputs['marmotkit_tag']}`, `{outputs['marmotc_tag']}`, `{outputs['wn_agent_tag']}`",
        f"- Decision: {'skip — ' + outputs['skip_reason'] if outputs['skip'] == 'true' else 'build'}",
    ]))
    if outputs["skip"] == "true":
        notice(f"Skipping today's RC: {outputs['skip_reason']}")
    return 0


def building_rcs(gh: GitHub) -> list[dict[str, Any]]:
    return [
        run
        for run in gh.active_runs(RC_WORKFLOW)
        if rc_is_building(gh.paginate(gh.repo(f"actions/runs/{run['id']}/jobs"), key="jobs"))
    ]


def command_wait_lane(args: argparse.Namespace) -> int:
    gh = github_from_env()
    own_run = os.environ.get("GITHUB_RUN_ID", "")
    deadline = time.monotonic() + args.timeout_minutes * 60
    wait_for_rc = args.rc
    while True:
        if wait_for_rc:
            busy = building_rcs(gh)
        else:
            busy = busy_release_runs({
                workflow: gh.active_runs(workflow)
                for workflow in ("bindings.yaml", "c-bindings.yml", "wn-agent-binaries.yml", PROMOTE_WORKFLOW)
            })
        busy = [run for run in busy if str(run.get("id")) != own_run]
        if not busy:
            write_outputs({"lane_free": "true"})
            return 0
        urls = ", ".join(run["html_url"] for run in busy)
        if time.monotonic() >= deadline:
            print(f"::warning::release lane still busy after {args.timeout_minutes} minutes: {urls}")
            write_outputs({"lane_free": "false"})
            write_summary(f"Release lane still busy after {args.timeout_minutes} minutes: {urls}")
            return 1 if args.fail_on_timeout else 0
        print(f"waiting for {len(busy)} active run(s): {urls}", flush=True)
        time.sleep(args.interval_seconds)


def command_stage_draft(args: argparse.Namespace) -> int:
    """Create a draft RC (or promoted stable) release, upload and verify its assets; never publish."""
    gh = github_from_env()
    tag = args.tag
    is_rc = RC_TAG.fullmatch(tag) is not None
    is_stable = args.stable and STABLE_TRACK_TAG.fullmatch(tag) is not None
    if not (is_rc or is_stable):
        raise ReleaseError(f"{tag} is not a valid {'stable' if args.stable else 'RC'} track tag")
    if not FULL_SHA.fullmatch(args.target):
        raise ReleaseError("--target must be a full 40-character commit SHA")
    assets = [Path(path) for path in args.assets]
    names = [asset.name for asset in assets]
    if not assets or len(set(names)) != len(names):
        raise ReleaseError(f"{tag}: assets must be non-empty and uniquely named")

    existing = gh.release_for_tag(tag)
    if existing is not None:
        if not existing["draft"]:
            raise ReleaseError(f"{tag}: a published release already exists; release assets are immutable")
        print(f"removing incomplete draft {tag} before retry")
        gh.request("DELETE", gh.repo(f"releases/{existing['id']}"))
    if gh.tag_commit(tag) is not None:
        raise ReleaseError(f"{tag}: tag already exists; release tags are never moved or reused")

    release, _ = gh.request("POST", gh.repo("releases"), {
        "tag_name": tag,
        "target_commitish": args.target,
        "name": args.title,
        "body": Path(args.notes_file).read_text(encoding="utf-8"),
        "draft": True,
        "prerelease": (not is_stable) or bool(args.prerelease),
        "make_latest": "false",
    })
    upload_base = release["upload_url"].split("{", 1)[0]
    for asset in assets:
        query = urllib.parse.urlencode({"name": asset.name})
        gh.request(
            "POST",
            "",
            data=asset.read_bytes(),
            content_type="application/octet-stream",
            url=f"{upload_base}?{query}",
        )

    uploaded = {item["name"]: item for item in gh.get(gh.repo(f"releases/{release['id']}"))["assets"]}
    if sorted(uploaded) != sorted(names):
        raise ReleaseError(f"{tag}: uploaded asset names do not match the local artifacts")
    for asset in assets:
        digest = "sha256:" + hashlib.sha256(asset.read_bytes()).hexdigest()
        item = uploaded[asset.name]
        if item["size"] != asset.stat().st_size or item.get("digest") != digest:
            raise ReleaseError(f"{tag}: uploaded asset verification failed for {asset.name}")
    print(f"staged draft {tag} with {len(assets)} verified assets")
    return 0


def check_staged_release(
    gh: GitHub,
    release: dict[str, Any] | None,
    tag: str,
    title: str,
    source_sha: str,
    *,
    expect_prerelease: bool = True,
) -> None:
    if release is None:
        raise ReleaseError(f"{tag}: no staged draft found")
    if release["name"] != title or bool(release["prerelease"]) != expect_prerelease or not release["assets"]:
        raise ReleaseError(f"{tag}: staged release has unexpected title, pre-release flag or assets")
    if release["draft"]:
        if release["target_commitish"] != source_sha:
            raise ReleaseError(f"{tag}: draft targets {release['target_commitish']}, expected {source_sha}")
    elif gh.tag_commit(tag) != source_sha:
        raise ReleaseError(f"{tag}: already published from a different commit")


def publish_release(
    gh: GitHub,
    release: dict[str, Any],
    tag: str,
    source_sha: str,
    *,
    prerelease: bool = True,
    make_latest: str = "false",
) -> dict[str, Any]:
    if release["draft"]:
        gh.request("PATCH", gh.repo(f"releases/{release['id']}"), {
            "draft": False,
            "prerelease": prerelease,
            "make_latest": make_latest,
        })
    for _ in range(10):
        release = gh.get(gh.repo(f"releases/{release['id']}"))
        if not release["draft"] and release.get("immutable") is True:
            break
        time.sleep(3)
    else:
        raise ReleaseError(f"{tag}: published release did not become immutable")
    commit = gh.tag_commit(tag)
    if commit != source_sha:
        raise ReleaseError(f"{tag}: tag points at {commit}, expected {source_sha}")
    return release


def publish_rc(
    gh: GitHub,
    version: str,
    source_sha: str,
    workflow_run: str,
    *,
    impact_report: dict[str, Any] | None = None,
    signature_delta: dict[str, Any] | None = None,
    integration_notes: str | None = None,
    today: dt.date | None = None,
    meta_gh: GitHub | None = None,
) -> str | None:
    """Publish all three staged RC tracks atomically, then update `rc-meta`.

    `gh` (the release token) publishes the tracks; `meta_gh` (default `gh`) reads and writes
    `rc-meta`, so its commits stay GitHub-signed by the workflow token.
    """
    meta_gh = meta_gh or gh
    tags = track_tags(version)
    titles = dict(TRACKS)
    staged = {prefix: gh.release_for_tag(tag) for prefix, tag in tags.items()}
    for prefix, tag in tags.items():
        check_staged_release(
            gh,
            staged[prefix],
            tag,
            f"v{version} - {titles[prefix]}",
            source_sha,
            expect_prerelease=True,
        )

    published: list[str] = []
    try:
        releases = {}
        for prefix, tag in tags.items():
            releases[prefix] = publish_release(
                gh, staged[prefix], tag, source_sha, prerelease=True, make_latest="false"
            )
            published.append(tag)
        document = latest_rc_document(
            version,
            source_sha,
            releases,
            gh.repository,
            workflow_run,
            impact_report=impact_report,
            today=today,
        )
        if meta_gh.read_latest_rc() == document:
            return None
        base = rc_base_version(version)
        rc_num = int(RC_VERSION.fullmatch(version).group(4))
        counters = meta_gh.read_rc_counters()
        counters[base] = max(counters.get(base, 0), rc_num)
        counters_doc = {"schema": 1, "highest_rc": counters}
        files: dict[str, str] = {
            RC_LATEST_FILE: json.dumps(document, indent=2, sort_keys=True) + "\n",
            RC_COUNTERS_FILE: json.dumps(counters_doc, indent=2, sort_keys=True) + "\n",
            f"{RC_RELEASES_DIR}/{version}.json": json.dumps(document, indent=2, sort_keys=True) + "\n",
        }
        if signature_delta is not None:
            files[RC_DELTA_FILE] = json.dumps(signature_delta, indent=2, sort_keys=True) + "\n"
        if impact_report is not None:
            files[RC_IMPACT_FILE] = json.dumps(impact_report, indent=2, sort_keys=True) + "\n"
        if integration_notes is not None:
            files[RC_NOTES_FILE] = integration_notes.rstrip() + "\n"
        return write_meta_files(meta_gh, files, f"RC {version} from {source_sha}")
    except ReleaseError as error:
        raise ReleaseError(
            f"{error}. Published so far: {', '.join(published) or 'none'}; {RC_LATEST_FILE} still names "
            "the previous RC. Re-run this job: it resumes from the tracks already published."
        ) from None


def _read_required_companion(path_arg: str | None, flag: str) -> str | None:
    if not path_arg:
        return None
    path = Path(path_arg)
    if not path.is_file():
        raise ReleaseError(f"{flag} file is missing: {path}")
    return path.read_text(encoding="utf-8")


def command_publish(args: argparse.Namespace) -> int:
    gh = github_from_env()
    if not FULL_SHA.fullmatch(args.source_sha):
        raise ReleaseError("--source-sha must be a full 40-character commit SHA")
    impact_raw = _read_required_companion(args.impact_report, "--impact-report")
    delta_raw = _read_required_companion(args.signature_delta, "--signature-delta")
    integration_notes = _read_required_companion(args.integration_notes, "--integration-notes")
    impact_report = json.loads(impact_raw) if impact_raw is not None else None
    signature_delta = json.loads(delta_raw) if delta_raw is not None else None
    commit = publish_rc(
        gh,
        args.version,
        args.source_sha,
        run_url(),
        impact_report=impact_report,
        signature_delta=signature_delta,
        integration_notes=integration_notes,
        meta_gh=meta_github_from_env(gh),
    )
    write_summary("\n".join([
        f"## SemVer RC published (`{args.version}`)",
        "",
        *(
            f"- [`{tag}`](https://github.com/{gh.repository}/releases/tag/{tag})"
            for tag in track_tags(args.version).values()
        ),
        f"- `{RC_LATEST_FILE}` on `{META_BRANCH}`: "
        + (f"verified commit `{commit}`" if commit else "already up to date"),
    ]))
    return 0


def cleanup_unpublished_drafts(gh: GitHub, version: str) -> list[str]:
    """Drop unpublished draft pre-releases ONLY if zero tracks for `version` are published.

    If any track was already published (immutable partial publish), preserve the
    remaining drafts so re-running the failed `publish` job can resume and finish
    the cohort atomically.
    """
    if not version or RC_VERSION.fullmatch(version) is None:
        return []
    tags = list(track_tags(version).values())
    existing_by_tag = {tag: gh.release_for_tag(tag) for tag in tags}
    for tag in tags:
        rel = existing_by_tag[tag]
        if (rel is not None and not rel["draft"]) or gh.tag_commit(tag) is not None:
            print(
                f"preserving remaining drafts for {version}: {tag} is already published "
                "(re-run publish job to resume)"
            )
            return []
    deleted: list[str] = []
    for tag in tags:
        rel = existing_by_tag[tag]
        if rel is not None and rel["draft"]:
            print(f"dropping unpublished RC draft {tag}")
            gh.request("DELETE", gh.repo(f"releases/{rel['id']}"))
            deleted.append(tag)
    return deleted


def command_cleanup_drafts(args: argparse.Namespace) -> int:
    """Drop unpublished draft pre-releases for a failed RC run so retries start clean."""
    gh = github_from_env()
    cleanup_unpublished_drafts(gh, args.version)
    return 0


def command_retention(args: argparse.Namespace) -> int:
    gh = github_from_env()
    today = today_utc(args.today)
    latest = gh.read_latest_rc()
    protected = [track["tag"] for track in latest["tracks"].values()] if latest else []
    releases = {release["tag_name"]: release for release in gh.releases()}
    tags = set(releases) | {tag for prefix in TRACK_PREFIXES for tag in gh.tag_names(f"{prefix}-v")}
    expired = expired_prerelease_tags(tags, releases, today, protected, args.days)

    lines = [f"## RC / legacy nightly retention ({args.days} days, {'dry run' if args.dry_run else 'deleting'})", ""]
    for tag in expired:
        release = releases.get(tag)
        if release is not None and not (release["prerelease"] or release["draft"]):
            raise ReleaseError(f"{tag}: refusing to delete a release that is not a pre-release")
        lines.append(f"- {tag}" + ("" if release else " (tag only)"))
        if args.dry_run:
            continue
        if release is not None:
            gh.request("DELETE", gh.repo(f"releases/{release['id']}"))
        if gh.tag_commit(tag) is not None:
            gh.request("DELETE", gh.repo(f"git/refs/tags/{urllib.parse.quote(tag)}"))
    if not expired:
        lines.append("- nothing to delete")
    write_summary("\n".join(lines))
    print("\n".join(lines))
    return 0


def command_check_version(args: argparse.Namespace) -> int:
    """Validate `release_version` against `workspace_version` and print `rc` or `stable`."""
    kind = check_release_version(args.release_version, args.workspace_version)
    print(kind)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check-version", help="validate RC or Stable release_version against workspace Cargo.toml")
    check.add_argument("--release-version", required=True)
    check.add_argument("--workspace-version", required=True)
    check.set_defaults(func=command_check_version)

    plan = commands.add_parser("plan", help="select verified canary SHA, classify impact, and pick next RC version")
    plan.add_argument("--root", default=".", help="repository root")
    plan.add_argument("--master-ref", default="origin/master")
    plan.add_argument("--canary-ref", default="origin/canary")
    plan.add_argument("--baseline-ref", default=None)
    plan.add_argument("--override-impact", choices=("patch", "minor"), default=None)
    plan.add_argument("--artifacts-dir", default=None, help="directory to write impact_report/signature_delta/notes")
    plan.add_argument("--force", action="store_true")
    plan.add_argument("--today", help="override UTC date (YYYY-MM-DD) for testing")
    plan.set_defaults(func=command_plan)

    wait = commands.add_parser("wait-lane", help="coordinate shared macOS release runners")
    wait.add_argument("--rc", action="store_true", help="wait for a building RC instead")
    wait.add_argument("--timeout-minutes", type=int, default=180)
    wait.add_argument("--interval-seconds", type=int, default=60)
    wait.add_argument("--fail-on-timeout", action="store_true")
    wait.set_defaults(func=command_wait_lane)

    stage = commands.add_parser("stage-draft", help="upload one track's verified assets to a draft release")
    stage.add_argument("--tag", required=True)
    stage.add_argument("--title", required=True)
    stage.add_argument("--target", required=True)
    stage.add_argument("--notes-file", required=True)
    stage.add_argument("--stable", action="store_true", help="allow stable X.Y.Z track tag for promotion")
    stage.add_argument("--prerelease", action="store_true", help="mark staged release as prerelease (e.g. wn-agent)")
    stage.add_argument("assets", nargs="+")
    stage.set_defaults(func=command_stage_draft)

    publish = commands.add_parser("publish", help="publish the three staged RC drafts and update rc-meta")
    publish.add_argument("--version", required=True)
    publish.add_argument("--source-sha", required=True)
    publish.add_argument("--impact-report", default=None)
    publish.add_argument("--signature-delta", default=None)
    publish.add_argument("--integration-notes", default=None)
    publish.set_defaults(func=command_publish)

    cleanup = commands.add_parser("cleanup-drafts", help="drop unpublished draft pre-releases for a failed RC")
    cleanup.add_argument("--version", required=True)
    cleanup.set_defaults(func=command_cleanup_drafts)

    retention = commands.add_parser("retention", help="delete expired RC and legacy nightly pre-releases")
    retention.add_argument("--days", type=int, default=RETENTION_DAYS)
    retention.add_argument("--today", help="override UTC date (YYYY-MM-DD) for testing")
    retention.add_argument("--dry-run", action="store_true")
    retention.set_defaults(func=command_retention)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ReleaseError, impact_classifier.ClassificationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
