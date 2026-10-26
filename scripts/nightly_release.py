#!/usr/bin/env python3
"""Plan, stage, publish and expire the dated MarmotKit, Marmot C and WN Agent nightlies.

`.github/workflows/nightly-releases.yml` drives every subcommand; see release.md#nightly-builds. The
pure functions at the top hold the naming, selection and retention rules and are unit-tested in
scripts/test_ci_workflow_policy.py. The commands below them talk to the GitHub REST API with the
workflow token and never touch formal (`<track>-vX.Y.Z`) or snapshot (`marmotkit-snapshot-<sha>`)
releases.
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
from typing import Callable, Iterable

TRACKS = (
    ("marmotkit", "MarmotKit"),
    ("marmotc", "Marmot C"),
    ("wn-agent", "wn-agent"),
)
TRACK_PREFIXES = tuple(prefix for prefix, _ in TRACKS)
META_BRANCH = "nightly-meta"
META_FILE = "latest.json"
RETENTION_DAYS = 30
CI_WORKFLOW = "ci.yml"
REQUIRED_CI_JOB = "Required CI"
NIGHTLY_WORKFLOW = "nightly-releases.yml"
# The nightly job that waits for releases and snapshots to leave the macOS lane.
LANE_JOB = "Wait for release lane"
LANE_STEP = "Wait for releases and snapshots to finish"
ACTIVE_STATUSES = ("queued", "in_progress", "waiting", "requested", "pending")

DEV_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)-dev")
NIGHTLY_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)-nightly\.(\d{8})(?:\.([1-9]\d{0,2}))?")
NIGHTLY_TAG = re.compile(
    r"(?P<track>marmotkit|marmotc|wn-agent)-v(?P<version>" + NIGHTLY_VERSION.pattern + ")"
)
FULL_SHA = re.compile(r"[0-9a-f]{40}")


class NightlyError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Pure rules
# ---------------------------------------------------------------------------


def nightly_base_version(workspace_version: str) -> str | None:
    """Return `X.Y.Z` for master's `X.Y.Z-dev`, or None when the source is not a dev version."""
    match = DEV_VERSION.fullmatch(workspace_version)
    return ".".join(match.groups()) if match else None


def nightly_date(version: str) -> dt.date:
    match = NIGHTLY_VERSION.fullmatch(version)
    if match is None:
        raise NightlyError(f"not a nightly version: {version}")
    return dt.datetime.strptime(match.group(4), "%Y%m%d").date()


def nightly_tag_date(tag: str) -> dt.date | None:
    """Return the build date of a nightly tag, or None for every other tag (formal, snapshot, rc)."""
    match = NIGHTLY_TAG.fullmatch(tag)
    if match is None:
        return None
    try:
        return nightly_date(match.group("version"))
    except ValueError:
        return None


def nightly_tags(version: str) -> dict[str, str]:
    if NIGHTLY_VERSION.fullmatch(version) is None:
        raise NightlyError(f"not a nightly version: {version}")
    return {prefix: f"{prefix}-v{version}" for prefix in TRACK_PREFIXES}


def choose_nightly_version(base: str, day: dt.date, taken_tags: Iterable[str]) -> str:
    """Name the nightly `<base>-nightly.<YYYYMMDD>`, adding `.N` when that day's name is used.

    Semver orders `nightly.20261020` < `nightly.20261020.1` < `nightly.20261021`, so a second
    build on one day still sorts after the first. A name counts as used when any track's tag
    exists, because deleted immutable-release tags can never be reused.
    """
    taken = set(taken_tags)
    stem = f"{base}-nightly.{day:%Y%m%d}"
    for counter in range(0, 1000):
        version = stem if counter == 0 else f"{stem}.{counter}"
        if not any(tag in taken for tag in nightly_tags(version).values()):
            return version
    raise NightlyError(f"no free nightly name left for {stem}")


def select_source(
    first_parent_shas: list[str],
    previous_sha: str | None,
    required_ci_passed: Callable[[str], bool],
) -> str | None:
    """Return the newest master commit whose merge-queue Required CI passed.

    Walking stops at the previous nightly's source, which already passed, so selection never moves
    backwards and an unchanged master resolves to the previous SHA.
    """
    for sha in first_parent_shas:
        if sha == previous_sha:
            return sha
        if required_ci_passed(sha):
            return sha
    return None


def expired_nightly_tags(
    tags: Iterable[str], today: dt.date, protected: Iterable[str], days: int = RETENTION_DAYS
) -> list[str]:
    """Return nightly tags whose build date is more than `days` before `today`."""
    keep = set(protected)
    cutoff = today - dt.timedelta(days=days)
    expired = []
    for tag in sorted(set(tags)):
        built = nightly_tag_date(tag)
        if built is not None and built < cutoff and tag not in keep:
            expired.append(tag)
    return expired


def latest_document(
    version: str,
    source_sha: str,
    releases: dict[str, dict],
    repository: str,
    run_url: str,
) -> dict:
    """Build latest.json from the three published releases."""
    tracks = {}
    for prefix, tag in nightly_tags(version).items():
        release = releases[prefix]
        assets = []
        for asset in sorted(release["assets"], key=lambda item: item["name"]):
            digest = asset.get("digest") or ""
            if not digest.startswith("sha256:"):
                raise NightlyError(f"{tag}: asset {asset['name']} has no SHA-256 digest")
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
    return {
        "schema": 1,
        "version": version,
        "source_sha": source_sha,
        "date": nightly_date(version).isoformat(),
        "workflow_run": run_url,
        "tracks": tracks,
    }


def busy_release_runs(runs_by_workflow: dict[str, list[dict]]) -> list[dict]:
    """Return active runs that share macOS capacity with a nightly: releases and snapshots.

    WN Agent also builds on every master push; only its tag-pushed release runs count.
    """
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
        body: dict | None = None,
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
            "User-Agent": "mdk-nightly-release",
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
                raise NightlyError(f"{method} {target} failed with HTTP {error.code}: {detail}") from None
            except urllib.error.URLError as error:
                if attempt < 3:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise NightlyError(f"{method} {target} failed: {error.reason}") from None
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
                    url = part[part.index("<") + 1:part.index(">")]
        return items

    def repo(self, suffix: str) -> str:
        return f"repos/{self.repository}/{suffix.lstrip('/')}"

    # Releases and tags -----------------------------------------------------

    def releases(self) -> list[dict]:
        return self.paginate(self.repo("releases"))

    def release_for_tag(self, tag: str) -> dict | None:
        # GET releases/tags/<tag> hides drafts, so list everything.
        matches = [release for release in self.releases() if release["tag_name"] == tag]
        if len(matches) > 1:
            raise NightlyError(f"{tag}: {len(matches)} releases share this tag")
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

    # Nightly metadata ------------------------------------------------------

    def read_latest(self) -> dict | None:
        content = self.get(
            self.repo(f"contents/{META_FILE}?ref={META_BRANCH}"), allow_404=True
        )
        if content is None:
            return None
        return json.loads(base64.b64decode(content["content"]))

    # CI evidence -----------------------------------------------------------

    def required_ci_passed(self, sha: str) -> bool:
        runs = self.get(self.repo(
            f"actions/workflows/{CI_WORKFLOW}/runs?event=merge_group&head_sha={sha}&status=success&per_page=20"
        ))["workflow_runs"]
        for run in runs:
            if run["head_sha"] != sha or run["conclusion"] != "success":
                continue
            jobs = self.paginate(self.repo(f"actions/runs/{run['id']}/jobs"), key="jobs")
            if any(job["name"] == REQUIRED_CI_JOB and job["conclusion"] == "success" for job in jobs):
                return True
        return False

    def active_runs(self, workflow: str) -> list[dict]:
        runs = []
        for status in ACTIVE_STATUSES:
            page = self.get(self.repo(f"actions/workflows/{workflow}/runs?status={status}&per_page=100"),
                            allow_404=True)
            if page:
                runs.extend(page["workflow_runs"])
        return runs


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def github_from_env() -> GitHub:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repository:
        raise NightlyError("GH_TOKEN (or GITHUB_TOKEN) and GITHUB_REPOSITORY are required")
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


def command_plan(args: argparse.Namespace) -> int:
    gh = github_from_env()
    day = today_utc(args.today)
    shas = git("rev-list", "--first-parent", f"--max-count={args.depth}", args.master_ref).split()
    latest = gh.read_latest()
    previous_sha = latest["source_sha"] if latest else None
    previous_version = latest["version"] if latest else "none"

    source_sha = select_source(shas, previous_sha, gh.required_ci_passed)
    if source_sha is None:
        raise NightlyError(
            f"none of the newest {len(shas)} master commits has a successful merge-queue Required CI run"
        )

    outputs = {
        "skip": "false",
        "skip_reason": "",
        "source_sha": source_sha,
        "previous_sha": previous_sha or "",
        "date": day.isoformat(),
        "version": "",
        "marmotkit_tag": "",
        "marmotc_tag": "",
        "wn_agent_tag": "",
    }
    workspace_version = workspace_version_at(source_sha)
    base = nightly_base_version(workspace_version)
    if source_sha == previous_sha and not args.force:
        outputs.update(skip="true", skip_reason=f"master's newest green commit is unchanged since {previous_version}")
    elif base is None:
        outputs.update(skip="true", skip_reason=f"source workspace version {workspace_version} is not an X.Y.Z-dev version")
    if base is not None:
        taken = [tag for prefix in TRACK_PREFIXES for tag in gh.tag_names(f"{prefix}-v{base}-nightly.")]
        version = choose_nightly_version(base, day, taken)
        tags = nightly_tags(version)
        outputs.update(
            version=version,
            marmotkit_tag=tags["marmotkit"],
            marmotc_tag=tags["marmotc"],
            wn_agent_tag=tags["wn-agent"],
        )

    write_outputs(outputs)
    walked = shas.index(source_sha) + 1 if source_sha in shas else len(shas)
    write_summary("\n".join([
        "## Nightly plan",
        "",
        f"- Master head: `{shas[0] if shas else 'unknown'}`",
        f"- Newest commit with merge-queue Required CI: `{source_sha}` ({walked} commit(s) walked)",
        f"- Previous nightly: `{previous_version}` from `{previous_sha or 'none'}`",
        f"- Source workspace version: `{workspace_version}`",
        f"- Nightly version: `{outputs['version'] or 'n/a'}` (date {day.isoformat()})",
        f"- Tags: `{outputs['marmotkit_tag']}`, `{outputs['marmotc_tag']}`, `{outputs['wn_agent_tag']}`",
        f"- Decision: {'skip — ' + outputs['skip_reason'] if outputs['skip'] == 'true' else 'build'}",
    ]))
    if outputs["skip"] == "true":
        notice(f"Skipping tonight's nightly: {outputs['skip_reason']}")
    return 0


def nightly_is_building(jobs: list[dict]) -> bool:
    """Whether a nightly run has finished waiting for the lane, so it is about to build or building.

    The wait step's own result is checked as well as the job's, which narrows the moment when a
    release or snapshot could start between the nightly's last check and its job completing.
    """
    for job in jobs:
        if job.get("name") != LANE_JOB:
            continue
        if job.get("conclusion") == "success":
            return True
        for step in job.get("steps") or []:
            if step.get("name") == LANE_STEP and step.get("conclusion") == "success":
                return True
    return False


def building_nightlies(gh: GitHub) -> list[dict]:
    """Return active nightly runs that are past their lane wait.

    A nightly still waiting for the lane yields to releases and snapshots; waiting on it as well
    would deadlock both sides until one timed out.
    """
    return [
        run for run in gh.active_runs(NIGHTLY_WORKFLOW)
        if nightly_is_building(gh.paginate(gh.repo(f"actions/runs/{run['id']}/jobs"), key="jobs"))
    ]


def command_wait_lane(args: argparse.Namespace) -> int:
    """Wait while releases or snapshots (or, with --nightly, a building nightly) hold macOS capacity."""
    gh = github_from_env()
    own_run = os.environ.get("GITHUB_RUN_ID", "")
    deadline = time.monotonic() + args.timeout_minutes * 60
    while True:
        if args.nightly:
            busy = building_nightlies(gh)
        else:
            busy = busy_release_runs({
                workflow: gh.active_runs(workflow)
                for workflow in ("bindings.yaml", "c-bindings.yml", "wn-agent-binaries.yml")
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
    """Create a draft nightly pre-release and upload and verify its assets; never publish it."""
    gh = github_from_env()
    tag = args.tag
    if nightly_tag_date(tag) is None:
        raise NightlyError(f"{tag} is not a nightly tag")
    if not FULL_SHA.fullmatch(args.target):
        raise NightlyError("--target must be a full 40-character commit SHA")
    assets = [Path(path) for path in args.assets]
    names = [asset.name for asset in assets]
    if not assets or len(set(names)) != len(names):
        raise NightlyError(f"{tag}: assets must be non-empty and uniquely named")

    existing = gh.release_for_tag(tag)
    if existing is not None:
        if not existing["draft"]:
            raise NightlyError(f"{tag}: a published release already exists; nightly assets are immutable")
        print(f"removing incomplete draft {tag} before retry")
        gh.request("DELETE", gh.repo(f"releases/{existing['id']}"))
    if gh.tag_commit(tag) is not None:
        raise NightlyError(f"{tag}: tag already exists; nightly tags are never moved or reused")

    release, _ = gh.request("POST", gh.repo("releases"), {
        "tag_name": tag,
        "target_commitish": args.target,
        "name": args.title,
        "body": Path(args.notes_file).read_text(encoding="utf-8"),
        "draft": True,
        "prerelease": True,
        "make_latest": "false",
    })
    upload_base = release["upload_url"].split("{", 1)[0]
    for asset in assets:
        query = urllib.parse.urlencode({"name": asset.name})
        gh.request("POST", "", data=asset.read_bytes(), content_type="application/octet-stream",
                   url=f"{upload_base}?{query}")

    uploaded = {item["name"]: item for item in gh.get(gh.repo(f"releases/{release['id']}"))["assets"]}
    if sorted(uploaded) != sorted(names):
        raise NightlyError(f"{tag}: uploaded asset names do not match the local artifacts")
    for asset in assets:
        digest = "sha256:" + hashlib.sha256(asset.read_bytes()).hexdigest()
        item = uploaded[asset.name]
        if item["size"] != asset.stat().st_size or item.get("digest") != digest:
            raise NightlyError(f"{tag}: uploaded asset verification failed for {asset.name}")
    print(f"staged draft {tag} with {len(assets)} verified assets")
    return 0


def check_staged_release(gh: GitHub, release: dict | None, tag: str, title: str, source_sha: str) -> None:
    """Raise unless `release` is this nightly's verified draft, or its already-published self on a re-run."""
    if release is None:
        raise NightlyError(f"{tag}: no staged draft found")
    if release["name"] != title or not release["prerelease"] or not release["assets"]:
        raise NightlyError(f"{tag}: staged release has unexpected title, pre-release flag or assets")
    if release["draft"]:
        if release["target_commitish"] != source_sha:
            raise NightlyError(f"{tag}: draft targets {release['target_commitish']}, expected {source_sha}")
    elif gh.tag_commit(tag) != source_sha:
        raise NightlyError(f"{tag}: already published from a different commit")


def publish_release(gh: GitHub, release: dict, tag: str, source_sha: str) -> dict:
    if release["draft"]:
        gh.request("PATCH", gh.repo(f"releases/{release['id']}"),
                   {"draft": False, "prerelease": True, "make_latest": "false"})
    for _ in range(10):
        release = gh.get(gh.repo(f"releases/{release['id']}"))
        if not release["draft"] and release.get("immutable") is True:
            break
        time.sleep(3)
    else:
        raise NightlyError(f"{tag}: published release did not become immutable")
    commit = gh.tag_commit(tag)
    if commit != source_sha:
        raise NightlyError(f"{tag}: tag points at {commit}, expected {source_sha}")
    return release


def write_meta_commit(gh: GitHub, document: dict) -> str:
    """Commit latest.json as the only file on nightly-meta; require GitHub's verified signature."""
    content = json.dumps(document, indent=2, sort_keys=True) + "\n"
    head = gh.get(gh.repo(f"git/ref/heads/{META_BRANCH}"), allow_404=True)
    parents = [head["object"]["sha"]] if head else []
    blob, _ = gh.request("POST", gh.repo("git/blobs"), {"content": content, "encoding": "utf-8"})
    tree, _ = gh.request("POST", gh.repo("git/trees"), {"tree": [
        {"path": META_FILE, "mode": "100644", "type": "blob", "sha": blob["sha"]},
    ]})
    # No author or committer: GitHub then signs the bot's commit itself.
    commit, _ = gh.request("POST", gh.repo("git/commits"), {
        "message": f"Nightly {document['version']} from {document['source_sha']}",
        "tree": tree["sha"],
        "parents": parents,
    })
    verification = commit.get("verification") or {}
    if verification.get("verified") is not True:
        raise NightlyError(
            f"latest.json commit {commit['sha']} is not verified ({verification.get('reason')}); "
            f"{META_BRANCH} was not updated"
        )
    if head:
        gh.request("PATCH", gh.repo(f"git/refs/heads/{META_BRANCH}"), {"sha": commit["sha"], "force": False})
    else:
        gh.request("POST", gh.repo("git/refs"), {"ref": f"refs/heads/{META_BRANCH}", "sha": commit["sha"]})
    return commit["sha"]


def publish_nightly(gh: GitHub, version: str, source_sha: str, workflow_run: str) -> str | None:
    """Publish the three staged tracks, then point latest.json at them.

    Every track is checked before any is published, so a missing or wrong track publishes nothing.
    Publication itself cannot be undone (immutable releases), so it is resumable instead: a re-run
    accepts tracks that are already published from this source and finishes the rest. latest.json
    moves only after all three are public, so its readers never see a partial nightly.
    """
    tags = nightly_tags(version)
    titles = dict(TRACKS)
    staged = {prefix: gh.release_for_tag(tag) for prefix, tag in tags.items()}
    for prefix, tag in tags.items():
        check_staged_release(gh, staged[prefix], tag, f"v{version} - {titles[prefix]}", source_sha)

    published: list[str] = []
    try:
        releases = {}
        for prefix, tag in tags.items():
            releases[prefix] = publish_release(gh, staged[prefix], tag, source_sha)
            published.append(tag)
        document = latest_document(version, source_sha, releases, gh.repository, workflow_run)
        if gh.read_latest() == document:
            return None
        return write_meta_commit(gh, document)
    except NightlyError as error:
        raise NightlyError(
            f"{error}. Published so far: {', '.join(published) or 'none'}; latest.json still names the "
            "previous nightly. Re-run this job: it resumes from the tracks already published."
        ) from None


def command_publish(args: argparse.Namespace) -> int:
    gh = github_from_env()
    if not FULL_SHA.fullmatch(args.source_sha):
        raise NightlyError("--source-sha must be a full 40-character commit SHA")
    commit = publish_nightly(gh, args.version, args.source_sha, run_url())
    write_summary("\n".join([
        "## Nightly published",
        "",
        *(f"- [`{tag}`](https://github.com/{gh.repository}/releases/tag/{tag})"
          for tag in nightly_tags(args.version).values()),
        f"- `{META_FILE}` on `{META_BRANCH}`: "
        + (f"verified commit `{commit}`" if commit else "already up to date"),
    ]))
    return 0


def command_retention(args: argparse.Namespace) -> int:
    gh = github_from_env()
    today = today_utc(args.today)
    latest = gh.read_latest()
    protected = [track["tag"] for track in latest["tracks"].values()] if latest else []
    releases = {release["tag_name"]: release for release in gh.releases()}
    tags = set(releases) | {tag for prefix in TRACK_PREFIXES for tag in gh.tag_names(f"{prefix}-v")}
    expired = expired_nightly_tags(tags, today, protected, args.days)

    lines = [f"## Nightly retention ({args.days} days, {'dry run' if args.dry_run else 'deleting'})", ""]
    for tag in expired:
        release = releases.get(tag)
        # Re-check the shape of each release right before deleting it.
        if release is not None and not (release["prerelease"] or release["draft"]):
            raise NightlyError(f"{tag}: refusing to delete a release that is not a pre-release")
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="select the source commit and nightly version")
    plan.add_argument("--master-ref", default="origin/master")
    plan.add_argument("--depth", type=int, default=50)
    plan.add_argument("--force", action="store_true", help="plan a build even if the source is unchanged")
    plan.add_argument("--today", help="override the UTC date (YYYY-MM-DD) for testing")
    plan.set_defaults(func=command_plan)

    wait = commands.add_parser("wait-lane", help="wait for releases and snapshots to leave the macOS lane")
    wait.add_argument("--nightly", action="store_true", help="wait for a running nightly instead")
    wait.add_argument("--timeout-minutes", type=int, default=180)
    wait.add_argument("--interval-seconds", type=int, default=60)
    wait.add_argument("--fail-on-timeout", action="store_true")
    wait.set_defaults(func=command_wait_lane)

    stage = commands.add_parser("stage-draft", help="upload one track's assets to a draft pre-release")
    stage.add_argument("--tag", required=True)
    stage.add_argument("--title", required=True)
    stage.add_argument("--target", required=True)
    stage.add_argument("--notes-file", required=True)
    stage.add_argument("assets", nargs="+")
    stage.set_defaults(func=command_stage_draft)

    publish = commands.add_parser("publish", help="publish the staged drafts and update latest.json")
    publish.add_argument("--version", required=True)
    publish.add_argument("--source-sha", required=True)
    publish.set_defaults(func=command_publish)

    retention = commands.add_parser("retention", help="delete nightly releases and tags past retention")
    retention.add_argument("--days", type=int, default=RETENTION_DAYS)
    retention.add_argument("--today", help="override the UTC date (YYYY-MM-DD) for testing")
    retention.add_argument("--dry-run", action="store_true")
    retention.set_defaults(func=command_retention)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except NightlyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
