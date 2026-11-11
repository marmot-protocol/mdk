#!/usr/bin/env python3
"""Rank flaky tests from the JUnit reports that merge-queue CI runs upload.

Every test job wraps nextest in scripts/ci_runner.py, which writes a JUnit
report into the job's `ci-runner-<job>-<index>-<attempt>` artifact. GitHub
keeps those artifacts for seven days. This script lists recent `ci.yml`
merge-group runs, downloads only the test jobs' artifacts, and keeps a compact
per-run summary in a local cache, so a rerun fetches only runs it has not seen.
Cached summaries outlive the artifacts, so a longer window works from the cache.

It stops fetching before the GitHub API budget runs out and reports the
leaderboard from what it has, with a note saying the data is partial.

Only test names, panic locations and the panic message line leave a report.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import gzip
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

CACHE_VERSION = 1
DEFAULT_REPO = "marmot-protocol/mdk"
DEFAULT_JOBS = ("rust-test", "cli-e2e", "relay-runtime", "relay-e2e", "conformance", "conformance-extras")
# A testcase with one of these failed every attempt; nextest adds a
# rerunFailure for each retry after the first failure.
HARD_FAILURES = {"failure", "error"}
RETRY_FAILURES = {"rerunFailure", "rerunError"}
FLAKY_FAILURES = {"flakyFailure", "flakyError"}
PANIC = re.compile(r"panicked at (\S+?:\d+:\d+):?\s*$")
RATE_LIMITED = re.compile(r"rate limit|HTTP 429|abuse detection", re.IGNORECASE)
SERVER_ERROR = re.compile(r"HTTP 5\d\d")
RETRY_DELAYS = (2.0, 10.0)
MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_MESSAGE_CHARS = 240
MAX_SAMPLES = 5


class MalformedReport(ValueError):
    """A JUnit report that is not the XML nextest writes."""


class RateLimited(RuntimeError):
    """The API budget for this invocation is spent."""


class GhError(RuntimeError):
    """A `gh` call failed for a reason other than the rate limit."""


@dataclass
class Outcome:
    classname: str
    name: str
    flaky: int = 0
    failed: int = 0
    samples: list[list[str]] = field(default_factory=list)

    def add_sample(self, sample: list[str]) -> None:
        if sample not in self.samples and len(self.samples) < MAX_SAMPLES:
            self.samples.append(sample)


def failure_sample(element: ET.Element) -> list[str]:
    """Return [location, message line] for one failed attempt.

    A panic yields its location and the first line after it. Anything else
    (a timeout, a signal) yields only nextest's failure type, never output.
    """
    lines = (element.text or element.get("message") or "").splitlines()
    for index, line in enumerate(lines):
        match = PANIC.search(line)
        if match is None:
            continue
        message = next((rest.strip() for rest in lines[index + 1:]
                        if rest.strip() and not rest.startswith("note: run with `RUST_BACKTRACE")), "")
        return [match.group(1), message[:MAX_MESSAGE_CHARS]]
    return ["", (element.get("type") or "test failure")[:MAX_MESSAGE_CHARS]]


def parse_report(data: bytes) -> tuple[list[str], dict[str, Outcome]]:
    """Parse one nextest JUnit report into (test ids seen, failed-attempt outcomes)."""
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise MalformedReport("JUnit reports carry no DTD")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise MalformedReport(str(error)) from error
    if root.tag not in {"testsuites", "testsuite"}:
        raise MalformedReport(f"unexpected root element {root.tag!r}")
    seen: list[str] = []
    outcomes: dict[str, Outcome] = {}
    for case in root.iter("testcase"):
        name = case.get("name")
        if not name:
            raise MalformedReport("testcase without a name")
        classname = case.get("classname")
        test = f"{classname}::{name}" if classname else name
        seen.append(test)
        attempts = [child for child in case
                    if child.tag in HARD_FAILURES | RETRY_FAILURES | FLAKY_FAILURES]
        if not attempts:
            continue
        outcome = outcomes.setdefault(test, Outcome(classname or "", name))
        hard = any(child.tag in HARD_FAILURES for child in attempts)
        for child in attempts:
            if hard:
                outcome.failed += 1
            else:
                outcome.flaky += 1
            outcome.add_sample(failure_sample(child))
    return seen, outcomes


class Budget:
    """The API calls this invocation may still make, shared across workers."""

    def __init__(self, calls: int) -> None:
        self._calls = max(calls, 0)
        self._lock = threading.Lock()
        self.exhausted = False

    def take(self, calls: int = 1) -> None:
        with self._lock:
            if self.exhausted or self._calls < calls:
                self.exhausted = True
                raise RateLimited
            self._calls -= calls

    def refund(self, calls: int) -> None:
        with self._lock:
            self._calls += calls

    def spend_all(self) -> None:
        with self._lock:
            self._calls = 0
            self.exhausted = True


class GitHub:
    """The few GitHub API calls this report needs, made through `gh`."""

    def __init__(self, repo: str, gh: str = "gh") -> None:
        self.repo = repo
        self.gh = gh
        self.budget = Budget(0)

    def _call(self, path: str, params: dict[str, str] | None = None, *, charged: bool = True) -> bytes:
        if charged:
            self.budget.take()
        command = [self.gh, "api", "-X", "GET", path]
        for key, value in (params or {}).items():
            command += ["-f", f"{key}={value}"]
        for delay in (*RETRY_DELAYS, None):
            try:
                result = subprocess.run(command, capture_output=True, timeout=600, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise GhError(f"gh api {path}: {error}") from error
            if result.returncode == 0:
                return result.stdout
            message = result.stderr.decode("utf-8", "replace").strip().splitlines()
            message = message[-1] if message else f"exit {result.returncode}"
            if RATE_LIMITED.search(message):
                self.budget.spend_all()
                raise RateLimited
            # GitHub answers some artifact downloads with a transient 5xx.
            if delay is None or not SERVER_ERROR.search(message):
                raise GhError(f"gh api {path}: {message}")
            time.sleep(delay)
        raise AssertionError("unreachable")

    def _json(self, path: str, params: dict[str, str] | None = None, *, charged: bool = True):
        try:
            return json.loads(self._call(path, params, charged=charged))
        except json.JSONDecodeError as error:
            raise GhError(f"gh api {path}: invalid JSON") from error

    def core_remaining(self) -> int:
        # GET /rate_limit does not count against the limit.
        return int(self._json("rate_limit", charged=False)["resources"]["core"]["remaining"])

    def runs(self, workflow: str, event: str, since: dt.datetime) -> list[dict]:
        runs: list[dict] = []
        for page in range(1, 11):
            body = self._json(f"repos/{self.repo}/actions/workflows/{workflow}/runs", {
                "event": event, "created": f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
                "per_page": "100", "page": str(page)})
            batch = body.get("workflow_runs", [])
            runs += batch
            if len(batch) < 100:
                break
        return runs

    def artifacts(self, run_id: int) -> list[dict]:
        artifacts: list[dict] = []
        for page in range(1, 11):
            body = self._json(f"repos/{self.repo}/actions/runs/{run_id}/artifacts",
                              {"per_page": "100", "page": str(page)})
            batch = body.get("artifacts", [])
            artifacts += batch
            if len(batch) < 100:
                break
        return artifacts

    def artifact_zip(self, artifact_id: int, *, charged: bool = True) -> bytes:
        return self._call(f"repos/{self.repo}/actions/artifacts/{artifact_id}/zip", charged=charged)


def empty_summary(run: dict) -> dict:
    return {"version": CACHE_VERSION, "run_id": run["id"], "run_attempt": run.get("run_attempt", 1),
            "created_at": run["created_at"], "conclusion": run.get("conclusion"),
            "reports": 0, "malformed": 0, "tests": [], "outcomes": {}}


def add_report(summary: dict, data: bytes) -> None:
    try:
        seen, outcomes = parse_report(data)
    except MalformedReport:
        summary["malformed"] += 1
        return
    summary["reports"] += 1
    tests = set(summary["tests"])
    tests.update(seen)
    summary["tests"] = sorted(tests)
    for test, outcome in outcomes.items():
        merged = summary["outcomes"].setdefault(test, {
            "classname": outcome.classname, "name": outcome.name, "flaky": 0, "failed": 0, "samples": []})
        merged["flaky"] += outcome.flaky
        merged["failed"] += outcome.failed
        for sample in outcome.samples:
            if sample not in merged["samples"] and len(merged["samples"]) < MAX_SAMPLES:
                merged["samples"].append(sample)


def add_artifact(summary: dict, archive: bytes) -> None:
    """Read the JUnit reports straight out of one artifact zip, never to disk."""
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            for member in bundle.infolist():
                if member.is_dir() or not member.filename.endswith(".xml"):
                    continue
                if member.file_size > MAX_REPORT_BYTES:
                    summary["malformed"] += 1
                    continue
                add_report(summary, bundle.read(member))
    except zipfile.BadZipFile:
        summary["malformed"] += 1


class Cache:
    """One gzip JSON summary per completed run."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def path(self, run_id: int) -> Path:
        return self.root / f"run-{int(run_id)}.json.gz"

    def load(self, run_id: int) -> dict | None:
        try:
            with gzip.open(self.path(run_id), "rt", encoding="utf-8") as handle:
                summary = json.load(handle)
        except (OSError, ValueError, EOFError):
            return None
        return summary if summary.get("version") == CACHE_VERSION else None

    def store(self, summary: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(dir=self.root, prefix=".run-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as raw, gzip.open(raw, "wt", encoding="utf-8") as handle:
                json.dump(summary, handle, separators=(",", ":"))
            os.replace(temp, self.path(summary["run_id"]))
        except BaseException:
            Path(temp).unlink(missing_ok=True)
            raise

    def all(self) -> list[dict]:
        summaries = []
        for path in sorted(self.root.glob("run-*.json.gz")):
            summary = self.load(int(path.name.removeprefix("run-").removesuffix(".json.gz")))
            if summary is not None:
                summaries.append(summary)
        return summaries

    def prune(self, since: dt.datetime) -> int:
        removed = 0
        for summary in self.all():
            if parse_time(summary["created_at"]) < since:
                self.path(summary["run_id"]).unlink(missing_ok=True)
                removed += 1
        return removed


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def fetch_run(github: GitHub, run: dict, artifact_name: re.Pattern[str]) -> dict:
    selected = [artifact for artifact in github.artifacts(run["id"])
                if artifact_name.fullmatch(artifact.get("name", "")) and not artifact.get("expired")]
    # Claim the whole run's downloads up front, so a spent budget never leaves
    # a run half-fetched after paying for some of it.
    github.budget.take(len(selected))
    summary = empty_summary(run)
    for index, artifact in enumerate(selected):
        try:
            add_artifact(summary, github.artifact_zip(artifact["id"], charged=False))
        except BaseException:
            github.budget.refund(len(selected) - index - 1)
            raise
    return summary


@dataclass
class Collection:
    summaries: list[dict]
    listed: int = 0
    fetched: int = 0
    unfetched: int = 0
    in_progress: int = 0
    listing_failed: bool = False
    notes: list[str] = field(default_factory=list)


def collect(args: argparse.Namespace, since: dt.datetime, github: GitHub | None) -> Collection:
    cache = Cache(args.cache_dir)
    if args.prune:
        cache.prune(since)
    collection = Collection([])
    if github is not None:
        try:
            remaining = github.core_remaining()
            github.budget = Budget(remaining - args.reserve)
            runs = github.runs(args.workflow, args.event, since)
        except RateLimited:
            collection.notes.append("The GitHub API budget was spent before runs could be listed; "
                                    "this report uses cached runs only.")
            runs = []
        except GhError as error:
            print(f"flake_report: {error}", file=sys.stderr)
            collection.notes.append("Listing runs failed; this report uses cached runs only.")
            collection.listing_failed = True
            runs = []
        collection.listed = len(runs)
        artifact_name = re.compile(
            r"ci-runner-(?:" + "|".join(re.escape(job) for job in args.jobs) + r")-\d+-\d+")
        pending = []
        for run in runs:
            if run.get("status") != "completed":
                collection.in_progress += 1
                continue
            cached = cache.load(run["id"])
            if cached is None or cached.get("run_attempt", 1) < run.get("run_attempt", 1):
                pending.append(run)
        pending.sort(key=lambda run: run["created_at"], reverse=True)
        failed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futures = {pool.submit(fetch_run, github, run, artifact_name): run for run in pending}
            for future in concurrent.futures.as_completed(futures):
                try:
                    summary = future.result()
                except RateLimited:
                    collection.unfetched += 1
                    continue
                except GhError as error:
                    print(f"flake_report: {error}", file=sys.stderr)
                    failed += 1
                    continue
                cache.store(summary)
                collection.fetched += 1
        if collection.unfetched:
            collection.notes.append(
                f"Partial data: the GitHub API budget ran out before {collection.unfetched} of "
                f"{len(pending)} new runs were fetched. Run again after the limit resets; "
                "the cache keeps what was fetched.")
        if failed:
            collection.notes.append(f"{failed} runs could not be fetched and are left out; "
                                    "a rerun tries them again.")
    collection.summaries = [summary for summary in cache.all()
                            if parse_time(summary["created_at"]) >= since]
    return collection


def leaderboard(summaries: list[dict]) -> list[dict]:
    rows: dict[str, dict] = {}
    for summary in summaries:
        for test, outcome in summary["outcomes"].items():
            classname = outcome["classname"]
            row = rows.setdefault(test, {
                "test": outcome["name"], "package": classname.partition("::")[0],
                "binary_id": classname, "flaky_attempts": 0, "failed_attempts": 0, "runs_seen": 0,
                "failing_runs": [], "first_seen": created_date(summary), "last_seen": created_date(summary),
                "samples": []})
            row["flaky_attempts"] += outcome["flaky"]
            row["failed_attempts"] += outcome["failed"]
            row["failing_runs"].append(summary["run_id"])
            row["first_seen"] = min(row["first_seen"], created_date(summary))
            row["last_seen"] = max(row["last_seen"], created_date(summary))
            for location, message in outcome["samples"]:
                sample = {"location": location, "message": message}
                if sample not in row["samples"] and len(row["samples"]) < MAX_SAMPLES:
                    row["samples"].append(sample)
    for summary in summaries:
        for test in rows.keys() & set(summary["tests"]):
            rows[test]["runs_seen"] += 1
    for row in rows.values():
        row["failing_runs"] = sorted(set(row["failing_runs"]))
        # nextest names a unit-test binary after its package and an
        # integration binary `<package>::<target>`, as the JUnit classname does.
        row["stress"] = (f"just flake-stress {row['package']} "
                         f"'binary_id({row['binary_id']}) & test(={row['test']})'")
    return sorted(rows.values(), key=lambda row: (
        -(row["flaky_attempts"] + row["failed_attempts"]), -row["failed_attempts"],
        row["binary_id"], row["test"]))


def created_date(summary: dict) -> str:
    return parse_time(summary["created_at"]).strftime("%Y-%m-%d")


def code(text: str) -> str:
    """A Markdown code span, widened when the text holds a backtick."""
    return f"`` {text} ``" if "`" in text else f"`{text}`"


def render_markdown(report: dict, top: int, samples: int) -> str:
    rows = report["tests"]
    runs = report["runs"]
    flaky = sum(row["flaky_attempts"] for row in rows)
    failed = sum(row["failed_attempts"] for row in rows)
    lines = [
        "# Flaky test leaderboard",
        "",
        f"Generated {report['generated_at']} from {runs['with_reports']} merge-queue "
        f"`{report['workflow']}` runs with test reports, created since {report['since']}. "
        f"{len(rows)} tests failed at least one attempt: {flaky} failed attempts of tests that then "
        f"passed on retry (flaky), and {failed} of tests that failed every attempt (failed).",
        "",
        "Counts are failed attempts. The relay-runtime job runs with `--retries 0`, so its flakes count as failed. "
        "Runs seen counts the runs whose reports include the test.",
    ]
    if runs["malformed_reports"]:
        lines += ["", f"{runs['malformed_reports']} report files could not be parsed and are left out."]
    for note in report["notes"]:
        lines += ["", f"> **Note:** {note}"]
    if not rows:
        lines += ["", "No test failed an attempt in this window."]
        return "\n".join(lines) + "\n"
    lines += ["", "| # | Test | Package (binary) | Flaky | Failed | Runs seen | First seen | Last seen |",
              "| ---: | --- | --- | ---: | ---: | ---: | --- | --- |"]
    for rank, row in enumerate(rows[:top], 1):
        lines.append(f"| {rank} | {code(row['test'])} | {code(row['binary_id'])} | {row['flaky_attempts']} | "
                     f"{row['failed_attempts']} | {row['runs_seen']} | {row['first_seen']} | {row['last_seen']} |")
    if len(rows) > top:
        more = len(rows) - top
        lines += ["", f"{more} more {'test' if more == 1 else 'tests'} failed at least one attempt."]
    if samples:
        lines += ["", "## Failure samples"]
        for rank, row in enumerate(rows[:samples], 1):
            lines += ["", f"{rank}. {code(row['test'])}", "", f"   {code(row['stress'])}", ""]
            for sample in row["samples"]:
                where = code(sample["location"]) + ": " if sample["location"] else ""
                lines.append(f"   - {where}{code(sample['message'])}" if sample["message"] else f"   - {where}")
    return "\n".join(lines) + "\n"


def fit_markdown(report: dict, top: int, samples: int, max_chars: int) -> str:
    """Drop sample sections, then table rows, until the Markdown fits."""
    while True:
        text = render_markdown(report, top, samples)
        if len(text) <= max_chars or (top <= 1 and samples == 0):
            return text
        if samples:
            samples -= 1
        else:
            top -= 1


def build_report(args: argparse.Namespace, since: dt.datetime, collection: Collection) -> dict:
    summaries = collection.summaries
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "repo": args.repo, "workflow": args.workflow, "event": args.event,
        "since": since.strftime("%Y-%m-%d %H:%M UTC"),
        "runs": {"cached": len(summaries), "with_reports": sum(1 for s in summaries if s["reports"]),
                 "listed": collection.listed, "fetched": collection.fetched,
                 "unfetched": collection.unfetched, "in_progress": collection.in_progress,
                 "malformed_reports": sum(s["malformed"] for s in summaries)},
        "partial": bool(collection.unfetched),
        "notes": collection.notes,
        "tests": leaderboard(summaries),
    }


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "mdk-flake-report"


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--workflow", default="ci.yml")
    parser.add_argument("--event", default="merge_group")
    parser.add_argument("--days", type=float, default=7.0,
                        help="window of runs to report; CI keeps the artifacts for 7 days (default: 7)")
    parser.add_argument("--jobs", type=lambda value: [job for job in value.split(",") if job],
                        default=list(DEFAULT_JOBS), help="comma-separated CI job ids whose reports count")
    parser.add_argument("--cache-dir", type=Path, default=default_cache_dir())
    parser.add_argument("--offline", action="store_true", help="report from the cache without calling GitHub")
    parser.add_argument("--prune", action="store_true", help="drop cached runs older than the window")
    parser.add_argument("--parallel", type=int, default=8, help="runs fetched at once (default: 8)")
    parser.add_argument("--reserve", type=int, default=100,
                        help="API calls to leave unspent from the hourly limit (default: 100)")
    parser.add_argument("--top", type=int, default=50, help="table rows (default: 50)")
    parser.add_argument("--samples", type=int, default=20, help="tests with failure samples (default: 20)")
    parser.add_argument("--max-chars", type=int, default=0,
                        help="shrink the Markdown to fit this many characters (an issue body takes 65536)")
    parser.add_argument("--output", type=Path, help="write the Markdown here instead of stdout")
    parser.add_argument("--json", type=Path, help="also write the full leaderboard as JSON")
    args = parser.parse_args(argv)
    if args.parallel < 1 or args.days <= 0 or args.top < 1 or args.samples < 0 or not args.jobs:
        parser.error("--parallel, --days and --top must be positive, --samples not negative, --jobs not empty")
    return args


def main(argv: list[str] | None = None, github: GitHub | None = None) -> int:
    args = parse_args(argv)
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=args.days)
    if github is None and not args.offline:
        github = GitHub(args.repo)
    collection = collect(args, since, None if args.offline else github)
    report = build_report(args, since, collection)
    if collection.listing_failed and not collection.summaries:
        print("flake_report: listing runs failed and the cache has none; is gh authenticated?", file=sys.stderr)
        return 1
    markdown = (fit_markdown(report, args.top, args.samples, args.max_chars) if args.max_chars
                else render_markdown(report, args.top, args.samples))
    if args.output:
        args.output.write_text(markdown, encoding="utf-8")
    else:
        sys.stdout.write(markdown)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["partial"]:
        print("flake_report: partial data; see the note in the report", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
