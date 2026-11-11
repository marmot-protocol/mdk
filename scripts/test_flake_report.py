#!/usr/bin/env python3
"""Regression tests for the merge-queue flaky-test leaderboard."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import tempfile
import textwrap
import unittest
import unittest.mock
import zipfile
from pathlib import Path

import flake_report
from flake_report import Budget, GhError, MalformedReport, RateLimited, parse_report


PANIC = (
    "thread &apos;{name}&apos; (4097) panicked at {location}:\n"
    "{message}\n"
    "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace"
)


def report(*cases: str, classname: str = "wn-cli::cli") -> bytes:
    body = "\n".join(
        f'<testcase name="{name}" classname="{classname}" time="1.0">{children}</testcase>'
        for name, children in (case.split("|", 1) if "|" in case else (case, "") for case in cases)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuites name="nextest-run"><testsuite name="{classname}">{body}</testsuite></testsuites>'
    ).encode()


def attempt(tag: str, name: str, location: str, message: str) -> str:
    text = PANIC.format(name=name, location=location, message=message)
    return f'<{tag} message="panicked at {location}" type="test failure with exit code 101">{text}</{tag}>'


PASS = "passes"
FLAKY = "flaky|" + attempt("flakyFailure", "flaky", "crates/cli/tests/cli.rs:12:5", "assertion `left == right` failed")
FAILED = "broken|" + attempt("failure", "broken", "crates/cli/tests/cli.rs:40:9", "receiver must see it: Elapsed(())") + \
    attempt("rerunFailure", "broken", "crates/cli/tests/cli.rs:40:9", "receiver must see it: Elapsed(())")
TIMEOUT = 'hangs|<failure type="test timeout">secret output that must not be reported</failure>'


class ParseReportTests(unittest.TestCase):
    def test_a_passing_test_is_seen_without_an_outcome(self):
        seen, outcomes = parse_report(report(PASS))
        self.assertEqual(seen, ["wn-cli::cli::passes"])
        self.assertEqual(outcomes, {})

    def test_a_retry_that_passes_counts_as_flaky(self):
        _, outcomes = parse_report(report(FLAKY))
        outcome = outcomes["wn-cli::cli::flaky"]
        self.assertEqual((outcome.flaky, outcome.failed), (1, 0))
        self.assertEqual(outcome.samples, [["crates/cli/tests/cli.rs:12:5", "assertion `left == right` failed"]])

    def test_every_attempt_of_a_test_that_never_passes_counts_as_failed(self):
        _, outcomes = parse_report(report(FAILED))
        outcome = outcomes["wn-cli::cli::broken"]
        self.assertEqual((outcome.flaky, outcome.failed), (0, 2))
        # The two attempts share one panic, so one sample remains.
        self.assertEqual(outcome.samples, [["crates/cli/tests/cli.rs:40:9", "receiver must see it: Elapsed(())"]])

    def test_a_failure_without_a_panic_reports_only_its_type(self):
        _, outcomes = parse_report(report(TIMEOUT))
        self.assertEqual(outcomes["wn-cli::cli::hangs"].samples, [["", "test timeout"]])

    def test_malformed_reports_are_rejected(self):
        for data in [b"<testsuites><testcase name='x'>", b"<html/>",
                     b'<!DOCTYPE x [<!ENTITY a "a">]><testsuites/>',
                     b"<testsuites><testsuite><testcase/></testsuite></testsuites>"]:
            with self.subTest(data=data), self.assertRaises(MalformedReport):
                parse_report(data)


def artifact_zip(*reports: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for index, data in enumerate(reports):
            bundle.writestr(f"rust-test-{index}.xml", data)
        bundle.writestr("rust-test-0.log", b"not a report")
    return buffer.getvalue()


class FakeGitHub:
    """Serves runs and artifacts, charging the budget the way `gh api` calls do."""

    def __init__(self, runs, artifacts, remaining=1000):
        self.runs_listed = runs
        self.artifacts_by_run = artifacts
        self.remaining = remaining
        self.budget = Budget(0)
        self.downloads = []

    def core_remaining(self):
        return self.remaining

    def runs(self, workflow, event, since):
        self.budget.take()
        return self.runs_listed

    def artifacts(self, run_id):
        self.budget.take()
        return [{"id": artifact_id, "name": name, "expired": False}
                for artifact_id, name, _ in self.artifacts_by_run[run_id]]

    def artifact_zip(self, artifact_id, *, charged=True):
        if charged:
            self.budget.take()
        self.downloads.append(artifact_id)
        for artifacts in self.artifacts_by_run.values():
            for known, _, data in artifacts:
                if known == artifact_id:
                    if isinstance(data, Exception):
                        raise data
                    return data
        raise AssertionError(artifact_id)


def run(run_id, hours_ago, status="completed", attempt=1):
    created = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours_ago)
    return {"id": run_id, "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"), "status": status,
            "conclusion": "success", "run_attempt": attempt}


class GhCallTests(unittest.TestCase):
    """The real `gh` wrapper, driven by a stand-in `gh` executable."""

    def gh(self, *stderr_lines: str) -> flake_report.GitHub:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        script = Path(tmp.name) / "gh"
        count = Path(tmp.name) / "count"
        # Fails with each given stderr line in turn, then prints "ok".
        failures = " ".join(f"'{line}'" for line in stderr_lines)
        script.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            failures=({failures})
            n=$(cat "{count}" 2>/dev/null || echo 0)
            echo $((n + 1)) > "{count}"
            if (( n < ${{#failures[@]}} )); then echo "${{failures[$n]}}" >&2; exit 1; fi
            printf ok
        """))
        script.chmod(0o755)
        github = flake_report.GitHub("o/r", gh=str(script))
        github.budget = Budget(10)
        self.calls = lambda: int(count.read_text())
        return github

    def test_a_transient_server_error_is_retried(self):
        github = self.gh("gh: Server Error (HTTP 502)")
        with unittest.mock.patch.object(flake_report, "RETRY_DELAYS", (0, 0)):
            self.assertEqual(github.artifact_zip(1), b"ok")
        self.assertEqual(self.calls(), 2)

    def test_a_rate_limit_spends_the_budget(self):
        github = self.gh("gh: API rate limit exceeded for user ID 1. (HTTP 403)")
        with self.assertRaises(RateLimited):
            github.artifact_zip(1)
        with self.assertRaises(RateLimited):
            github.artifacts(2)
        self.assertEqual(self.calls(), 1)

    def test_other_errors_are_not_retried(self):
        github = self.gh("gh: Not Found (HTTP 404)")
        with self.assertRaisesRegex(GhError, "HTTP 404"):
            github.artifact_zip(1)
        self.assertEqual(self.calls(), 1)


class LeaderboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = Path(self.tmp.name) / "cache"

    def main(self, github, *extra):
        out = Path(self.tmp.name) / "out.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = flake_report.main(["--cache-dir", str(self.cache), "--json", str(out), *extra], github)
        return code, stdout.getvalue(), json.loads(out.read_text()) if out.exists() else None

    def test_ranks_tests_across_runs_and_reuses_the_cache(self):
        github = FakeGitHub(
            [run(1, 2), run(2, 1), run(3, 0.1, status="in_progress")],
            {1: [(11, "ci-runner-cli-e2e-0-1", artifact_zip(report(PASS, FLAKY, FAILED))),
                 (12, "ci-runner-rust-test-build-0-1", b"never downloaded")],
             2: [(21, "ci-runner-cli-e2e-1-1", artifact_zip(report(PASS, FLAKY), b"<broken"))]})
        code, markdown, data = self.main(github)
        self.assertEqual(code, 0)
        self.assertEqual(sorted(github.downloads), [11, 21])
        # Equal totals rank the test that never passed first.
        broken, flaky = data["tests"]
        self.assertEqual((broken["test"], broken["failed_attempts"], broken["runs_seen"]), ("broken", 2, 1))
        self.assertEqual((flaky["test"], flaky["flaky_attempts"], flaky["runs_seen"]), ("flaky", 2, 2))
        self.assertEqual(flaky["stress"], "just flake-stress wn-cli 'binary_id(wn-cli::cli) & test(=flaky)'")
        self.assertEqual(data["runs"]["malformed_reports"], 1)
        self.assertEqual(data["runs"]["in_progress"], 1)
        self.assertIn("| 2 | `flaky` | `wn-cli::cli` | 2 | 0 | 2 |", markdown)
        self.assertIn("`` assertion `left == right` failed ``", markdown)

        github.downloads.clear()
        code, _, again = self.main(github)
        self.assertEqual(github.downloads, [])
        self.assertEqual(again["tests"], data["tests"])

    def test_a_spent_budget_reports_partial_data_without_half_fetched_runs(self):
        artifacts = [(n, f"ci-runner-rust-test-{n}-1", artifact_zip(report(FLAKY))) for n in range(3)]
        # Listing runs and one run's artifacts fits; that run's three downloads do not.
        github = FakeGitHub([run(1, 1)], {1: artifacts}, remaining=104)
        code, markdown, data = self.main(github)
        self.assertEqual(code, 0)
        self.assertTrue(data["partial"])
        self.assertEqual(github.downloads, [])
        self.assertIn("Partial data", markdown)
        self.assertEqual(list(self.cache.glob("run-*")), [])

    def test_rate_limit_errors_from_gh_stop_fetching(self):
        github = FakeGitHub([run(1, 1)], {1: [(1, "ci-runner-cli-e2e-0-1", RateLimited())]})
        _, _, data = self.main(github)
        self.assertTrue(data["partial"])

    def test_a_failed_download_leaves_the_run_for_the_next_invocation(self):
        github = FakeGitHub([run(1, 1)], {1: [(1, "ci-runner-cli-e2e-0-1", GhError("HTTP 500"))]})
        _, markdown, _ = self.main(github)
        self.assertIn("could not be fetched", markdown)
        self.assertEqual(list(self.cache.glob("run-*")), [])

    def test_a_rerun_attempt_is_fetched_again(self):
        first = FakeGitHub([run(1, 1)], {1: [(1, "ci-runner-cli-e2e-0-1", artifact_zip(report(PASS)))]})
        self.main(first)
        second = FakeGitHub([run(1, 1, attempt=2)],
                            {1: [(1, "ci-runner-cli-e2e-0-1", artifact_zip(report(PASS))),
                                 (2, "ci-runner-cli-e2e-0-2", artifact_zip(report(FLAKY)))]})
        _, _, data = self.main(second)
        self.assertEqual(sorted(second.downloads), [1, 2])
        self.assertEqual(data["tests"][0]["test"], "flaky")

    def test_offline_reports_only_cached_runs_inside_the_window(self):
        cache = flake_report.Cache(self.cache)
        for run_id, hours_ago, case in [(1, 1, FLAKY), (2, 24 * 10, FAILED)]:
            summary = flake_report.empty_summary(run(run_id, hours_ago))
            flake_report.add_report(summary, report(case))
            cache.store(summary)
        _, _, data = self.main(None, "--offline", "--prune")
        self.assertEqual([row["test"] for row in data["tests"]], ["flaky"])
        self.assertEqual([path.name for path in self.cache.glob("run-*")], ["run-1.json.gz"])

    def test_markdown_shrinks_to_fit_an_issue_body(self):
        report_data = {"generated_at": "now", "workflow": "ci.yml", "since": "then", "notes": [],
                       "runs": {"with_reports": 1, "malformed_reports": 0},
                       "tests": [{"test": f"t{n}", "binary_id": "p", "flaky_attempts": 1, "failed_attempts": 0,
                                  "runs_seen": 1, "first_seen": "d", "last_seen": "d", "stress": "s",
                                  "samples": [{"location": "l", "message": "m" * 200}]} for n in range(50)]}
        full = flake_report.render_markdown(report_data, 50, 50)
        fitted = flake_report.fit_markdown(report_data, 50, 50, len(full) // 2)
        self.assertLessEqual(len(fitted), len(full) // 2)
        self.assertIn("| 50 | `t49` |", fitted)


if __name__ == "__main__":
    unittest.main()
