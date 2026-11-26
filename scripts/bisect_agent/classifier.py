"""Exact failed-command extraction and failure classification."""

from __future__ import annotations

import re
from typing import Callable, Iterable

from .models import Bucket, ClassificationResult, FailureSignal, RunVerdict

# Features CI compiles these packages' tests with (mirrors scripts/flake_report.py).
STRESS_FEATURES: dict[str, str] = {
    "cgka-engine": "test-policy-overrides,test-crash-hooks",
    "marmot-app": "test-policy-overrides",
    "marmot-session": "test-policy-overrides",
    "wn-cli": "test-policy-overrides",
}

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# `gh run view --log` prefixes each line with `<job>\t<step>\t` and GitHub Actions
# adds an optional BOM + RFC3339 UTC timestamp (`2026-11-26T12:00:00.1234567Z `).
GH_LOG_PREFIX_RE = re.compile(r"^[^\t\n]*\t[^\t\n]*\t")
GHA_TIMESTAMP_RE = re.compile(r"^\ufeff?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\s*")

INFRA_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"No space left on device", re.IGNORECASE),
    re.compile(r"The runner has received a shutdown signal", re.IGNORECASE),
    re.compile(r"lost communication with the server", re.IGNORECASE),
    re.compile(r"CI infrastructure error", re.IGNORECASE),
    re.compile(r"HTTP 5\d\d|502 Bad Gateway|503 Service Unavailable|504 Gateway", re.IGNORECASE),
    re.compile(r"CRYPT_E_REVOCATION_OFFLINE|TLS handshake|Connection reset by peer", re.IGNORECASE),
    re.compile(r"Unable to connect to the remote server|Could not resolve host", re.IGNORECASE),
    re.compile(r"process aborted with signal 15 \(SIGTERM\)", re.IGNORECASE),
    re.compile(r"command timed out after \d+s", re.IGNORECASE),
)

# Nextest failure line (supports optional stress `[1/10]`, retry `TRY 2`, and progress `( 988/1564)`):
#   FAIL [  12.345s] cgka-engine::crash_recovery_sqlite some::test_name
#   TRY 2 FAIL [   1.432s] ( 988/1564) marmot-session::runtime some::test_name
NEXTEST_FAIL_RE = re.compile(
    r"^\s*(?:\[\d+/\d+\]\s+)?(?:TRY\s+\d+\s+)?FAIL\s+\[[^\]]+\]\s+(?:\(\s*\d+/\d+\)\s+)?([A-Za-z0-9_-]+)(?:::([A-Za-z0-9_/-]+))?\s+(\S+)\s*$",
    re.MULTILINE,
)

NEXTEST_PASS_RE = re.compile(
    r"^\s*(?:\[\d+/\d+\]\s+)?(?:TRY\s+\d+\s+)?PASS\s+\[[^\]]+\]\s+(?:\(\s*\d+/\d+\)\s+)?([A-Za-z0-9_-]+)(?:::([A-Za-z0-9_/-]+))?\s+(\S+)\s*$",
    re.MULTILINE,
)

NEXTEST_NO_TESTS_RE = re.compile(
    r"(?:\b0 tests run\b|error: no tests to run)",
    re.IGNORECASE,
)

# Hosted job names that require macOS or Windows and cannot be reproduced on Linux mdk-ci-1.
NON_LINUX_JOB_MARKERS: tuple[str, ...] = (
    "iOS keychain",
    "MarmotKit native host",
    "Windows filesystem",
    "Build Apple candidate",
    "Package iOS",
    "Package macOS",
    "macos",
    "ios-account-clippy",
    "marmotkit-native-host",
    "windows-filesystem",
)

# Bare-metal step -> exact reproducible command.
# Matches `/srv/mdk/bin/mdk-canary.sh` failed_step names.
BARE_METAL_STEP_COMMANDS: dict[str, tuple[str, ...]] = {
    "fast-ci": ("just", "fast-ci"),
    "cargo-audit": ("cargo", "--locked", "audit"),
    "wasm-check": ("just", "wasm-check"),
    "android-check": ("just", "android-check"),
    "simulator-smoke": ("just", "simulator-smoke"),
}

# Single-purpose hosted CI job name -> exact reproducible Linux command.
# Multi-step jobs like `Rust format` are mapped per failed step in HOSTED_STEP_COMMANDS
# so a static-gate failure is never silently replayed as `just fmt-check`.
HOSTED_JOB_COMMANDS: dict[str, tuple[str, ...]] = {
    "Rust audit": ("cargo", "--locked", "audit"),
    "Rust WASM check": ("just", "wasm-check"),
    "Rust Android check": ("just", "android-check"),
    "Rust check and clippy": ("just", "clippy"),
    "C bindings smoke": ("just", "c-smoke"),
    "Convergence policy pin (release assertions)": ("just", "test-convergence-policy-pin"),
    "Tamarin proofs": ("just", "tamarin"),
}

# Exact failed step name inside multi-step hosted jobs (e.g. `Rust format`) -> command.
HOSTED_STEP_COMMANDS: dict[str, tuple[str, ...]] = {
    "Check formatting": ("just", "fmt-check"),
    "Naming gate (retired legacy tokens)": ("just", "naming-gate"),
    "Tracing and direct-output source audit": ("just", "tracing-audit"),
    "C binding command-surface parity gate": ("just", "c-parity-gate"),
    "Complete binding documentation inventory": ("just", "binding-docs-gate"),
    "Changelog fragments": ("just", "changelog-gate"),
    "PR commit trailers contract": ("just", "pr-trailers-contract"),
    "Bisect agent contract": ("just", "bisect-agent-contract"),
    "Binding build phase contracts": ("just", "binding-build-gate"),
    "Install example SHA-256 gate": ("just", "install-example-sha256-gate"),
    "Campaign image toolchain gate": ("just", "campaign-toolchain-gate"),
    "Apple privacy packaging gate": ("just", "apple-privacy-gate"),
    "MarmotKit release-profile gate": ("just", "release-profile-gate"),
    "Agent install documentation gate": ("just", "agent-install-docs-gate"),
    "Public app campaign contract": ("just", "app-stack-campaign-contract"),
    "CI policy and path-classifier gates": (
        "just",
        "convergence-ledger-gate",
        "cargo-audit-policy-gate",
        "ci-path-classifier-gate",
        "flake-report-contract",
    ),
    "Test timing ratchet": ("just", "test-timing-ratchet"),
}


def normalize_log_text(log_text: str) -> str:
    """Strip ANSI escape codes, `gh run view --log` job/step prefixes, and GHA timestamps."""
    lines: list[str] = []
    for raw_line in log_text.splitlines():
        line = ANSI_ESCAPE_RE.sub("", raw_line)
        line = GH_LOG_PREFIX_RE.sub("", line)
        line = GHA_TIMESTAMP_RE.sub("", line)
        lines.append(line)
    return "\n".join(lines)


def is_infra_failure(log_excerpt: str, conclusion: str = "failure") -> bool:
    """Return True when logs or conclusion point to runner/network/infra failure.

    Never classifies output containing an actual nextest `FAIL` line as an infra error
    (network/relay tests legitimately print strings like `Connection reset by peer` or
    `HTTP 502` when asserting error handling).
    """
    cleaned = normalize_log_text(log_excerpt)
    if NEXTEST_FAIL_RE.search(cleaned):
        return False
    if conclusion in {"timed_out", "cancelled", "startup_failure"}:
        return True
    return any(pattern.search(cleaned) for pattern in INFRA_PATTERNS)


def is_non_linux_job(job_name: str) -> bool:
    """Return True for macOS/iOS/Windows jobs that Linux mdk-ci-1 cannot run locally."""
    lower = job_name.lower()
    return any(marker.lower() in lower for marker in NON_LINUX_JOB_MARKERS)


def is_nextest_command(command: tuple[str, ...]) -> bool:
    """Return True when `command` invokes `cargo nextest run`."""
    return len(command) >= 3 and command[0] == "cargo" and command[1] == "nextest" and command[2] == "run"


def nextest_command_for_test(
    package: str,
    binary: str | None,
    test_name: str,
    *,
    stress_count: int = 1,
) -> tuple[str, ...]:
    """Build the narrowest reproducible `cargo nextest run` command for one failing test.

    Uses nextest's exact `binary_id(=...)` filterset so lib tests, integration tests,
    and binary-crate tests (`bin/...`) are all targeted unambiguously, with
    `--no-tests=fail` so a renamed/absent test is never misread as a pass.
    """
    cmd: list[str] = ["cargo", "nextest", "run", "--locked", "-p", package]
    features = STRESS_FEATURES.get(package)
    if features:
        cmd.extend(["--features", features])
    binary_id = f"{package}::{binary}" if binary else package
    filter_expr = f"binary_id(={binary_id}) & test(={test_name})"
    cmd.extend(["-E", filter_expr, "--no-tests=fail", "--retries", "0", "--no-fail-fast"])
    if stress_count > 1:
        cmd.extend(["--stress-count", str(stress_count)])
    return tuple(cmd)


def parse_first_nextest_failure(log_text: str) -> tuple[str, str | None, str] | None:
    """Return `(package, binary_or_none, test_name)` for the first test whose final outcome is FAIL.

    Ignores tests that failed on an earlier retry (`TRY 1 FAIL`) and subsequently passed
    (`TRY 2 PASS`) in the same run.
    """
    cleaned = normalize_log_text(log_text)
    outcomes: dict[tuple[str, str | None, str], str] = {}
    for line in cleaned.splitlines():
        fail_m = NEXTEST_FAIL_RE.match(line)
        if fail_m:
            outcomes[(fail_m.group(1), fail_m.group(2), fail_m.group(3))] = "fail"
            continue
        pass_m = NEXTEST_PASS_RE.match(line)
        if pass_m:
            outcomes[(pass_m.group(1), pass_m.group(2), pass_m.group(3))] = "pass"
    for key, status in outcomes.items():
        if status == "fail":
            return key
    return None


def evaluate_command_result(
    returncode: int,
    output: str,
    command: tuple[str, ...],
) -> tuple[RunVerdict, str]:
    """Classify raw command exit status + output into a structured RunVerdict.

    Returns `(verdict, concise_privacy_safe_summary)`. Never echoes raw stdout/stderr.
    """
    cleaned = normalize_log_text(output)

    if is_nextest_command(command):
        if NEXTEST_NO_TESTS_RE.search(cleaned) or returncode == 4:
            return RunVerdict.TEST_ABSENT, "target test absent on this commit (0 tests matched)"
        if returncode == 0:
            if NEXTEST_PASS_RE.search(cleaned):
                return RunVerdict.PASS, "target test passed"
            return RunVerdict.INCONCLUSIVE, "nextest exited 0 without recording a target PASS line"
        # Check for an actual test FAIL line BEFORE infra patterns so relay/network test
        # output mentioning TLS/HTTP/connection resets is never misread as infra.
        if NEXTEST_FAIL_RE.search(cleaned):
            return RunVerdict.FAIL, "target test failed"
        if is_infra_failure(cleaned):
            return RunVerdict.INCONCLUSIVE, f"infrastructure or timeout error (exit {returncode})"
        return RunVerdict.INCONCLUSIVE, f"nextest failed before executing target test (exit {returncode})"

    if is_infra_failure(cleaned):
        return RunVerdict.INCONCLUSIVE, f"infrastructure or timeout error (exit {returncode})"
    if returncode == 0:
        return RunVerdict.PASS, "command passed"
    return RunVerdict.FAIL, f"command exited with status {returncode}"


def extract_bare_metal_signal(
    status_doc: dict,
    log_text: str,
    *,
    run_url: str = "",
) -> FailureSignal:
    """Convert a red `/srv/mdk/state/canary-status.json` snapshot into a FailureSignal.

    Expected status schema from `/srv/mdk/bin/mdk-canary.sh`:
      {state, sha, canary_sha|previous_canary, failed_step, updated_at, duration_sec, consecutive_failures, log}

    Never places local host file paths into `run_url` (public surfaces only receive
    HTTP(S) URLs or empty string).
    """
    step = str(status_doc.get("failed_step") or "")
    tip_sha = str(status_doc.get("sha") or "")
    baseline_sha = str(status_doc.get("canary_sha") or status_doc.get("previous_canary") or "")
    excerpt = "\n".join(normalize_log_text(log_text).splitlines()[-80:])
    failed_test: str | None = None
    command = BARE_METAL_STEP_COMMANDS.get(step, ())

    parsed = parse_first_nextest_failure(log_text)
    if parsed and step in {"workspace-nextest", "simulator-smoke"}:
        pkg, binary, test_name = parsed
        failed_test = f"{pkg}::{binary}::{test_name}" if binary else f"{pkg}::{test_name}"
        command = nextest_command_for_test(pkg, binary, test_name)

    public_url = run_url if run_url.startswith(("http://", "https://")) else ""
    return FailureSignal(
        source="bare_metal_canary",
        run_id=f"bare-metal:{tip_sha[:12]}:{status_doc.get('updated_at', '')}",
        run_url=public_url,
        tip_sha=tip_sha,
        baseline_sha=baseline_sha,
        failed_job=f"mdk-canary:{step or 'unknown'}",
        failed_step=step,
        failed_test=failed_test,
        command=command,
        log_excerpt=excerpt,
        conclusion="failure",
        reproducible_locally=bool(command),
        infra_hint=is_infra_failure(excerpt),
    )


def extract_hosted_signal(
    *,
    source: str,
    run_id: str,
    run_url: str,
    tip_sha: str,
    baseline_sha: str,
    failed_job: str,
    log_text: str,
    failed_step: str = "",
    conclusion: str = "failure",
) -> FailureSignal:
    """Convert a failed hosted Canary workflow job into a FailureSignal."""
    cleaned = normalize_log_text(log_text)
    excerpt = "\n".join(cleaned.splitlines()[-80:])
    non_linux = is_non_linux_job(failed_job)
    failed_test: str | None = None
    command: tuple[str, ...] = ()

    if not non_linux:
        parsed = parse_first_nextest_failure(cleaned)
        if parsed:
            pkg, binary, test_name = parsed
            failed_test = f"{pkg}::{binary}::{test_name}" if binary else f"{pkg}::{test_name}"
            command = nextest_command_for_test(pkg, binary, test_name)
        elif failed_step and failed_step in HOSTED_STEP_COMMANDS:
            command = HOSTED_STEP_COMMANDS[failed_step]
        else:
            for prefix, mapped in HOSTED_JOB_COMMANDS.items():
                if failed_job == prefix or failed_job.endswith(f"/ {prefix}"):
                    command = mapped
                    break

    return FailureSignal(
        source=source,
        run_id=str(run_id),
        run_url=run_url,
        tip_sha=tip_sha,
        baseline_sha=baseline_sha,
        failed_job=failed_job,
        failed_step=failed_step,
        failed_test=failed_test,
        command=command,
        log_excerpt=excerpt,
        conclusion=conclusion,
        reproducible_locally=(not non_linux and bool(command)),
        infra_hint=is_infra_failure(excerpt, conclusion),
    )


def match_known_flake_issue(
    failed_test: str | None,
    open_issues: Iterable[dict],
) -> int | None:
    """Match a failing test name against open `Flaky:` issues."""
    if not failed_test:
        return None
    short_name = failed_test.split("::")[-1]
    for issue in open_issues:
        title = str(issue.get("title") or "")
        body = str(issue.get("body") or "")
        is_flake_issue = title.lower().startswith("flaky:") or title == "Flaky test leaderboard"
        if not is_flake_issue:
            continue
        if failed_test in title or failed_test in body or short_name in title:
            number = issue.get("number")
            if isinstance(number, int):
                return number
    return None


def match_issue_by_title(title: str, open_issues: Iterable[dict]) -> int | None:
    """Return the issue number for an open issue with an exact matching title, if any."""
    target = title.strip().lower()
    for issue in open_issues:
        if str(issue.get("title") or "").strip().lower() == target:
            number = issue.get("number")
            if isinstance(number, int):
                return number
    return None


def stress_command(command: tuple[str, ...], stress_count: int) -> tuple[str, ...]:
    """Return a stress-enabled command when `command` is a `cargo nextest run` invocation."""
    if stress_count <= 1 or not is_nextest_command(command):
        return command
    filtered = list(command)
    if "--stress-count" in filtered:
        idx = filtered.index("--stress-count")
        filtered[idx + 1] = str(stress_count)
    else:
        filtered.extend(["--stress-count", str(stress_count)])
    return tuple(filtered)


# Callback type: run_on_sha(sha, command) -> (verdict: RunVerdict, detail: str)
RunCommandOnSha = Callable[[str, tuple[str, ...]], tuple[RunVerdict, str]]


def classify_failure(
    signal: FailureSignal,
    *,
    run_on_sha: RunCommandOnSha,
    open_flake_issues: Iterable[dict] = (),
    stress_count: int = 10,
) -> ClassificationResult:
    """Classify a FailureSignal into one of the MDK Canary buckets.

    Only regressions that reproduce on `tip` and do not fail on a distinct `baseline`
    enter `DETERMINISTIC_REGRESSION` for automated bisect/revert. Signals without a
    distinct baseline stay in `UNREPRODUCIBLE` so a single missing-baseline run never
    immediately freezes `master`. Intermittent failures (including stress-only hits)
    stay in `NEW_INTERMITTENT` or `KNOWN_FLAKE` and never trigger automated reverts.
    """
    # Bucket 1: Runner/network/disk infrastructure error.
    if signal.infra_hint or is_infra_failure(signal.log_excerpt, signal.conclusion):
        return ClassificationResult(
            bucket=Bucket.INFRA_ERROR,
            reason=f"infrastructure failure detected in {signal.failed_job} ({signal.conclusion})",
        )

    # Bucket 2a: Known flake matching an open `Flaky:` issue.
    matched_issue = match_known_flake_issue(signal.failed_test, open_flake_issues)
    if matched_issue is not None:
        return ClassificationResult(
            bucket=Bucket.KNOWN_FLAKE,
            reason=f"matches open flake issue #{matched_issue} for {signal.failed_test}",
            matched_issue=matched_issue,
        )

    # Platform-specific or unparsed failure with no local reproduction command.
    if not signal.reproducible_locally or not signal.command:
        step_note = f" (step `{signal.failed_step}`)" if signal.failed_step else ""
        if is_non_linux_job(signal.failed_job):
            reason = f"non-Linux job `{signal.failed_job}`{step_note} is not locally reproducible on this host"
        else:
            reason = f"no reproducible command extracted for `{signal.failed_job}`{step_note}"
        return ClassificationResult(
            bucket=Bucket.UNREPRODUCIBLE,
            reason=reason,
        )

    # Single-shot reproduction on tip.
    tip_verdict, tip_detail = run_on_sha(signal.tip_sha, signal.command)
    if tip_verdict in {RunVerdict.INCONCLUSIVE, RunVerdict.TEST_ABSENT}:
        return ClassificationResult(
            bucket=Bucket.INFRA_ERROR,
            reason=f"inconclusive reproduction on {signal.tip_sha[:9]} ({tip_detail})",
        )

    if tip_verdict == RunVerdict.FAIL:
        if not signal.baseline_sha or signal.baseline_sha == signal.tip_sha:
            return ClassificationResult(
                bucket=Bucket.UNREPRODUCIBLE,
                reason=f"reproduced on {signal.tip_sha[:9]} but no distinct green baseline is available to bisect",
            )
        base_verdict, base_detail = run_on_sha(signal.baseline_sha, signal.command)
        if base_verdict == RunVerdict.FAIL:
            return ClassificationResult(
                bucket=Bucket.INFRA_ERROR,
                reason=(
                    f"baseline break: {signal.failed_job} fails on both tip "
                    f"{signal.tip_sha[:9]} and baseline {signal.baseline_sha[:9]} "
                    "(likely advisory/toolchain/environment change)"
                ),
            )
        if base_verdict == RunVerdict.INCONCLUSIVE:
            return ClassificationResult(
                bucket=Bucket.INFRA_ERROR,
                reason=f"inconclusive baseline check on {signal.baseline_sha[:9]} ({base_detail})",
            )
        return ClassificationResult(
            bucket=Bucket.DETERMINISTIC_REGRESSION,
            reason=(
                f"reproduced on {signal.tip_sha[:9]} and did not fail on "
                f"baseline {signal.baseline_sha[:9]} ({base_verdict.value})"
            ),
        )

    # Passed single retry. Only run differential stress on targeted `cargo nextest run` commands
    # (never loop heavy workspace commands like `just fast-ci`).
    if not is_nextest_command(signal.command) or stress_count <= 1:
        return ClassificationResult(
            bucket=Bucket.NEW_INTERMITTENT,
            reason=f"passed single retry on {signal.tip_sha[:9]} (non-nextest command; stress skipped)",
        )

    tip_failed, tip_inconclusive = _run_nextest_stress(run_on_sha, signal.tip_sha, signal.command, stress_count)
    if tip_inconclusive:
        return ClassificationResult(
            bucket=Bucket.INFRA_ERROR,
            reason=f"inconclusive stress check on tip {signal.tip_sha[:9]}",
        )

    base_failed = False
    if signal.baseline_sha and signal.baseline_sha != signal.tip_sha:
        base_failed, base_inconclusive = _run_nextest_stress(
            run_on_sha, signal.baseline_sha, signal.command, stress_count
        )
        if base_inconclusive:
            return ClassificationResult(
                bucket=Bucket.INFRA_ERROR,
                reason=f"inconclusive stress check on baseline {signal.baseline_sha[:9]}",
            )

    if tip_failed and base_failed:
        return ClassificationResult(
            bucket=Bucket.KNOWN_FLAKE,
            reason=(
                f"reproduced intermittently under {stress_count}x stress on both tip "
                f"{signal.tip_sha[:9]} and baseline {signal.baseline_sha[:9]}"
            ),
        )

    if tip_failed:
        return ClassificationResult(
            bucket=Bucket.NEW_INTERMITTENT,
            reason=(
                f"intermittent failure under {stress_count}x stress on tip {signal.tip_sha[:9]} "
                f"(passed baseline {signal.baseline_sha[:9]}; manual triage required, never auto-reverted)"
            ),
        )

    return ClassificationResult(
        bucket=Bucket.NEW_INTERMITTENT,
        reason=(
            f"passed single retry and {stress_count}x stress on both tip "
            f"{signal.tip_sha[:9]} and baseline {signal.baseline_sha[:9]}"
        ),
    )


def _run_nextest_stress(
    run_on_sha: RunCommandOnSha,
    sha: str,
    command: tuple[str, ...],
    stress_count: int,
) -> tuple[bool, bool]:
    """Run a `cargo nextest run` command with `--stress-count`; return `(failed, inconclusive)`."""
    scmd = stress_command(command, stress_count)
    verdict, _detail = run_on_sha(sha, scmd)
    if verdict == RunVerdict.INCONCLUSIVE:
        return False, True
    return (verdict == RunVerdict.FAIL), False
