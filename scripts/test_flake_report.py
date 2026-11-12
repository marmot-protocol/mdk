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
from flake_report import GhError, MalformedReport, RateLimited, parse_report


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
        self.assertEqual(seen, ["wn-cli::cli\tpasses"])
        self.assertEqual(outcomes, {})

    def test_a_retry_that_passes_counts_as_flaky(self):
        _, outcomes = parse_report(report(FLAKY))
        outcome = outcomes["wn-cli::cli\tflaky"]
        self.assertEqual((outcome.flaky, outcome.failed), (1, 0))
        self.assertEqual(outcome.samples, [["crates/cli/tests/cli.rs:12:5", "assertion `left == right` failed"]])

    def test_every_attempt_of_a_test_that_never_passes_counts_as_failed(self):
        _, outcomes = parse_report(report(FAILED))
        outcome = outcomes["wn-cli::cli\tbroken"]
        self.assertEqual((outcome.flaky, outcome.failed), (0, 2))
        # The two attempts share one panic, so one sample remains.
        self.assertEqual(outcome.samples, [["crates/cli/tests/cli.rs:40:9", "receiver must see it: Elapsed(())"]])

    def test_only_the_line_after_the_panic_is_reported(self):
        # An empty panic message must not pull in whatever the test printed next.
        case = 'quiet|<failure type="test failure">thread &apos;quiet&apos; panicked at src/lib.rs:3:5:\n\n' \
            'note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n' \
            'PRIVATE LOG LINE</failure>'
        _, outcomes = parse_report(report(case))
        self.assertEqual(outcomes["wn-cli::cli\tquiet"].samples, [["src/lib.rs:3:5", ""]])

    def test_a_failure_without_a_panic_reports_only_its_type(self):
        _, outcomes = parse_report(report(TIMEOUT))
        self.assertEqual(outcomes["wn-cli::cli\thangs"].samples, [["", "test timeout"]])

    def test_a_unit_test_and_an_integration_test_with_one_joined_path_stay_apart(self):
        seen, _ = parse_report(report("relay_runtime::isolates", classname="marmot-app"))
        other, _ = parse_report(report("isolates", classname="marmot-app::relay_runtime"))
        self.assertNotEqual(seen, other)

    def test_a_test_interrupted_by_job_cancellation_is_not_a_failure(self):
        cancelled = 'slow|<failure message="process aborted with signal 15 (SIGTERM)" type="test abort"/>'
        aborted = 'crash|<failure message="process aborted with signal 6 (SIGABRT)" type="test abort"/>'
        _, outcomes = parse_report(report(cancelled, aborted))
        self.assertEqual(list(outcomes), ["wn-cli::cli\tcrash"])

    def test_a_failure_whose_retry_was_cancelled_counts_as_failed(self):
        retry = attempt("rerunFailure", "slow", "src/lib.rs:3:5", "boom")
        case = f'slow|<failure message="process aborted with signal 15 (SIGTERM)" type="test abort"/>{retry}'
        _, outcomes = parse_report(report(case))
        outcome = outcomes["wn-cli::cli\tslow"]
        self.assertEqual((outcome.flaky, outcome.failed), (0, 1))

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
    """Serves runs and artifacts, spending the rate limit the way `gh api` calls do."""

    def __init__(self, runs, artifacts, remaining=1000):
        self.runs_listed = runs
        self.artifacts_by_run = artifacts
        self.remaining = remaining
        self.downloads = []

    def spend(self):
        if self.remaining <= 0:
            raise RateLimited
        self.remaining -= 1

    def core_remaining(self):
        return self.remaining

    def runs(self, workflow, event, since):
        self.spend()
        if isinstance(self.runs_listed, Exception):
            raise self.runs_listed
        return self.runs_listed, None

    def artifacts(self, run_id):
        self.spend()
        return [{"id": artifact_id, "name": name, "expired": data is None}
                for artifact_id, name, data in self.artifacts_by_run[run_id]]

    def artifact_zip(self, artifact_id):
        self.spend()
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
        self.calls = lambda: int(count.read_text())
        return github

    def test_a_transient_server_error_is_retried(self):
        github = self.gh("gh: Server Error (HTTP 502)")
        with unittest.mock.patch.object(flake_report, "RETRY_DELAYS", (0, 0)):
            self.assertEqual(github.artifact_zip(1), b"ok")
        self.assertEqual(self.calls(), 2)

    def test_a_rate_limit_is_not_retried(self):
        github = self.gh("gh: API rate limit exceeded for user ID 1. (HTTP 403)")
        with self.assertRaises(RateLimited):
            github.artifact_zip(1)
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
        self.assertEqual(flaky["stress"], "just flake-stress wn-cli 'binary_id(wn-cli::cli) & test(=flaky)' "
                                          "40 --features test-policy-overrides")
        self.assertEqual(data["runs"]["malformed_reports"], 1)
        self.assertEqual(data["runs"]["in_progress"], 1)
        self.assertIn("| 2 | `flaky` | `wn-cli::cli` | 2 | 0 | 2 |", markdown)
        self.assertIn("`` assertion `left == right` failed ``", markdown)

        github.downloads.clear()
        code, _, again = self.main(github)
        self.assertEqual(github.downloads, [])
        self.assertEqual(again["tests"], data["tests"])

    def test_fetching_stops_when_the_rate_limit_reaches_the_reserve(self):
        runs = [run(n, n) for n in range(1, 4)]
        artifacts = {n: [(n, f"ci-runner-rust-test-{n}-1", artifact_zip(report(FLAKY)))] for n in range(1, 4)}
        # Listing and the newest run (one artifact list, one download) leave 101; the next leaves 99.
        github = FakeGitHub(runs, artifacts, remaining=104)
        _, markdown, data = self.main(github, "--parallel", "1", "--reserve", "100")
        self.assertEqual(github.downloads, [1, 2])
        self.assertTrue(data["partial"])
        self.assertIn("before 1 of 3 new runs were fetched", markdown)

    def test_a_run_cut_off_by_the_rate_limit_is_fetched_again_next_time(self):
        artifacts = {1: [(n, f"ci-runner-rust-test-{n}-1", artifact_zip(report(FLAKY))) for n in range(3)]}
        # GitHub refuses the run's second download.
        _, _, data = self.main(FakeGitHub([run(1, 1)], artifacts, remaining=3), "--reserve", "0")
        self.assertTrue(data["partial"])
        self.assertEqual(list(self.cache.rglob("run-*")), [])
        github = FakeGitHub([run(1, 1)], artifacts)
        _, _, data = self.main(github)
        self.assertEqual(github.downloads, [0, 1, 2])
        self.assertEqual(data["tests"][0]["flaky_attempts"], 3)

    def test_a_rate_limit_after_the_first_page_keeps_the_listed_runs(self):
        github = flake_report.GitHub("o/r")
        page = {"workflow_runs": [{"id": n} for n in range(100)], "total_count": 150}
        responses = [json.dumps(page).encode(), RateLimited()]
        with unittest.mock.patch.object(github, "_call", side_effect=responses):
            runs, cut = github.runs("ci.yml", "merge_group", dt.datetime.now(dt.timezone.utc))
        self.assertEqual((len(runs), cut), (100, "the API rate limit was reached"))

    def test_a_failed_listing_publishes_nothing_even_with_a_cache(self):
        self.main(FakeGitHub([run(1, 1)], {1: [(1, "ci-runner-cli-e2e-0-1", artifact_zip(report(FLAKY)))]}))
        code, markdown, _ = self.main(FakeGitHub(GhError("HTTP 401"), {}))
        self.assertEqual((code, markdown), (1, ""))

    def test_a_rate_limit_under_the_reserve_before_listing_is_partial(self):
        _, markdown, data = self.main(FakeGitHub([run(1, 1)], {}, remaining=99), "--reserve", "100")
        self.assertTrue(data["partial"])
        self.assertIn("before runs could be listed", markdown)

    def test_a_failed_download_leaves_the_run_for_the_next_invocation(self):
        github = FakeGitHub([run(1, 1)], {1: [(1, "ci-runner-cli-e2e-0-1", GhError("HTTP 500"))]})
        _, markdown, data = self.main(github)
        self.assertIn("could not be fetched", markdown)
        self.assertTrue(data["partial"])
        self.assertEqual(list(self.cache.rglob("run-*")), [])

    def test_expired_reports_mark_the_report_partial_on_every_rerun(self):
        github = FakeGitHub([run(1, 1)], {1: [(1, "ci-runner-cli-e2e-0-1", None),
                                              (2, "ci-runner-cli-e2e-1-1", artifact_zip(report(PASS)))]})
        for _ in range(2):
            _, markdown, data = self.main(github)
            self.assertTrue(data["partial"])
            self.assertIn("1 test reports in 1 runs had expired", markdown)
        self.assertEqual(github.downloads, [2])

    def test_a_rerun_attempt_is_fetched_again(self):
        first = FakeGitHub([run(1, 1)], {1: [(1, "ci-runner-cli-e2e-0-1", artifact_zip(report(PASS)))]})
        self.main(first)
        second = FakeGitHub([run(1, 1, attempt=2)],
                            {1: [(1, "ci-runner-cli-e2e-0-1", artifact_zip(report(PASS))),
                                 (2, "ci-runner-cli-e2e-0-2", artifact_zip(report(FLAKY)))]})
        _, _, data = self.main(second)
        self.assertEqual(sorted(second.downloads), [1, 2])
        self.assertEqual(data["tests"][0]["test"], "flaky")

    def test_a_rerun_attempt_that_fails_to_fetch_is_left_out(self):
        self.main(FakeGitHub([run(1, 1)], {1: [(1, "ci-runner-cli-e2e-0-1", artifact_zip(report(FLAKY)))]}))
        second = FakeGitHub([run(1, 1, attempt=2)], {1: [(2, "ci-runner-cli-e2e-0-2", GhError("HTTP 500"))]})
        _, markdown, data = self.main(second)
        self.assertEqual((data["tests"], data["runs"]["cached"]), ([], 0))
        self.assertIn("could not be fetched and are left out", markdown)

    def test_a_rerun_attempt_in_progress_leaves_out_the_cached_attempt(self):
        self.main(FakeGitHub([run(1, 1)], {1: [(1, "ci-runner-cli-e2e-0-1", artifact_zip(report(FLAKY)))]}))
        second = FakeGitHub([run(1, 1, status="in_progress", attempt=2)], {})
        _, _, data = self.main(second)
        self.assertEqual((data["tests"], data["runs"]["cached"], data["runs"]["in_progress"]), ([], 0, 1))
        self.assertEqual(second.downloads, [])

    def test_another_job_selection_does_not_reuse_cached_summaries(self):
        artifacts = {1: [(1, "ci-runner-cli-e2e-0-1", artifact_zip(report(FLAKY))),
                         (2, "ci-runner-relay-runtime-0-1", artifact_zip(report(PASS)))]}
        github = FakeGitHub([run(1, 1)], artifacts)
        _, _, data = self.main(github)
        self.assertEqual(sorted(github.downloads), [1, 2])
        self.assertEqual([row["test"] for row in data["tests"]], ["flaky"])
        github = FakeGitHub([run(1, 1)], artifacts)
        _, _, data = self.main(github, "--jobs", "relay-runtime")
        self.assertEqual(github.downloads, [2])
        self.assertEqual(data["tests"], [])

    def test_offline_reports_only_cached_runs_inside_the_window(self):
        cache = flake_report.Cache(flake_report.cache_root(flake_report.parse_args(["--cache-dir", str(self.cache)])))
        for run_id, hours_ago, case in [(1, 1, FLAKY), (2, 24 * 10, FAILED)]:
            summary = flake_report.empty_summary(run(run_id, hours_ago))
            flake_report.add_report(summary, report(case))
            cache.store(summary)
        _, _, data = self.main(None, "--offline", "--prune")
        self.assertEqual([row["test"] for row in data["tests"]], ["flaky"])
        self.assertEqual([path.name for path in self.cache.rglob("run-*")], ["run-1.json.gz"])

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
