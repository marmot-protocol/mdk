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

# Nextest terminal failure statuses (matches pinned cargo-nextest 0.9.132
# `status_str` / `short_status_str`, optional retry `TRY <n>`, duration `[...s]`,
# optional post-duration stress counter `[1/10]` or `[1]`, and optional progress
# `( 988/1564)` or `(─────────)`):
#   FAIL [  12.345s] cgka-engine::crash_recovery_sqlite some::test_name
#   TRY 2 FAIL [   1.432s] ( 988/1564) marmot-session::runtime some::test_name
#   TRY 1 TMT [ 240.004s] (─────────) wn-cli::cli hangs_forever
#   SIGSEGV [   0.012s] [1/10] (1/1) marmot-c::ffi segfault_case
#   TRY 1 XFAIL [   0.001s] (─────────) cgka-engine::a exec_failed
NEXTEST_FAIL_RE = re.compile(
    r"^\s*(?:\[\s*\d+(?:/\d+)?\s*\]\s+)?(?:TRY\s+\d+\s+)?"
    r"(?:FAIL|XFAIL|TIMEOUT|TMT|ABORT|ABRT|LEAK-FAIL|LKFL|EXECFAIL|SIG[A-Z0-9]+)"
    r"\s+\[[^\]]+\]\s+(?:\[\s*\d+(?:/\d+)?\s*\]\s+)?(?:\([^)]+\)\s+)?"
    r"([A-Za-z0-9_-]+)(?:::([A-Za-z0-9_/-]+))?\s+(\S+)\s*$",
    re.MULTILINE,
)

NEXTEST_PASS_RE = re.compile(
    r"^\s*(?:\[\s*\d+(?:/\d+)?\s*\]\s+)?(?:(?:TRY\s+\d+\s+)?(?:PASS|LEAK)|FLAKY\s+\d+/\d+)"
    r"\s+\[[^\]]+\]\s+(?:\[\s*\d+(?:/\d+)?\s*\]\s+)?(?:\([^)]+\)\s+)?"
    r"([A-Za-z0-9_-]+)(?:::([A-Za-z0-9_/-]+))?\s+(\S+)\s*$",
    re.MULTILINE,
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

# Exact failed step name inside hosted Linux jobs -> faithful local replay command.
# Steps requiring CI-only fixtures or dynamically installed tools not provisioned on
# bare-metal Linux (e.g. `Header diff gate` needing pinned cbindgen, `Run Tamarin proofs`
# and `Verify pairing authentication and model controls` needing Tamarin/Maude,
# `Run real relay CLI E2E` needing Docker relays + `MDK_E2E_REQUIRE_RELAYS=1`,
# `Verify TLA liveness and counterexample` needing Java/TLC, and `Test consent and both
# diagnostic exporters` needing `uv`) are intentionally omitted so they classify as
# `UNREPRODUCIBLE` rather than replaying the wrong command or skipping silently.
HOSTED_STEP_COMMANDS: dict[str, tuple[str, ...]] = {
    # Rust format
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
    # Rust audit
    "Audit Rust dependencies": ("cargo", "--locked", "audit"),
    # Terminal harness installer tests
    "Test Claude Code, Codex, Pi, OpenCode, and Goose installers": (
        "bash",
        "-euo",
        "pipefail",
        "-c",
        "integrations/terminal-harness/tests/test_installer.sh claude"
        " && integrations/terminal-harness/tests/test_installer.sh codex"
        " && integrations/terminal-harness/tests/test_installer.sh pi"
        " && integrations/terminal-harness/tests/test_installer.sh opencode"
        " && integrations/terminal-harness/tests/test_installer.sh goose",
    ),
    "Test the connector-only wn-agent installer": (
        "integrations/terminal-harness/tests/test_connector_only_installer.sh",
    ),
    # Rust WASM / Android / Clippy / Convergence policy pin
    "Build browser WASM libraries": ("just", "wasm-check"),
    "Check marmot-uniffi for Android arm64-v8a": ("just", "android-check"),
    "Run clippy": (
        "env",
        "RUSTFLAGS=-D warnings",
        "cargo",
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ),
    "Run clippy with all features": (
        "env",
        "RUSTFLAGS=-D warnings",
        "cargo",
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--locked",
        "--",
        "-D",
        "warnings",
    ),
    "Run default-build convergence policy pin tests": ("just", "test-convergence-policy-pin"),
    # C bindings smoke (Header diff gate intentionally unmapped: needs pinned cbindgen)
    "Alloc-audit tests": ("cargo", "test", "-p", "marmot-c", "--features", "alloc-audit", "--locked"),
    "Compile and run debug C smoke test (gcc)": ("./crates/marmot-c/c-smoke.sh", "--debug", "gcc"),
    # Doctests and diagnostic exporters (self-contained Linux steps only)
    "Test native Markdown parser": ("odin", "test", "crates/marmot-markdown/odin"),
    "Run doctests": ("cargo", "test", "--workspace", "--exclude", "cgka-conformance-simulator", "--doc", "--locked"),
    # Build CLI tests (must run WITHOUT test-policy-overrides!)
    "Device linking at production timing": (
        "cargo",
        "nextest",
        "run",
        "-p",
        "wn-cli",
        "--lib",
        "--test",
        "cli",
        "--locked",
        "--profile",
        "ci",
        "--retries",
        "0",
        "-E",
        "test(=devices_link_across_daemon_commands_at_production_timing) | test(=commands::devices::tests::plain_prompt_details_keep_capability_names_and_sanitize_device_labels)",
        "--no-tests=fail",
    ),
    # Convergence gates and simulator doctests (TLA+ step intentionally unmapped: needs Java/TLC)
    "Validate convergence execution-lane policy": ("just", "convergence-lane-policy"),
    "Validate convergence failure-corpus lifecycle": (
        "cargo",
        "nextest",
        "run",
        "-p",
        "convergence-campaign-runner",
        "--test",
        "failure_corpus",
        "--locked",
    ),
    "Run focused convergence regressions": ("just", "focused-convergence-regressions"),
    "Run simulator doctests": ("cargo", "test", "-p", "cgka-conformance-simulator", "--doc", "--locked"),
    # Tamarin proofs (pure-Python verifier tests only; Tamarin/Maude proof steps omitted)
    "Check Tamarin prover runner tests": (
        "python3",
        "-B",
        "-m",
        "unittest",
        "discover",
        "-s",
        "formal/tamarin",
        "-p",
        "test_*.py",
    ),
    "Check pairing verifier timeout handling": (
        "python3",
        "-B",
        "-m",
        "unittest",
        "discover",
        "-s",
        "formal/pairing",
        "-p",
        "test_*.py",
    ),
}

# Allowlist of hosted nextest jobs whose individual failing tests can be replayed
# faithfully on Linux with `nextest_command_for_test` (without external Docker relays
# or non-standard feature flags), preserving the originating nextest profile and
# concurrency settings from `.github/workflows/ci.yml`.
# `Relay CLI E2E` is deliberately NOT in this allowlist.
# Entries: `(job_prefix, step_name_to_(profile, test_threads))`
NEXTEST_REPLAYABLE_HOSTED_JOBS: tuple[tuple[str, dict[str, tuple[str, int | None]]], ...] = (
    (
        "Rust tests (",
        {
            "": ("ci", None),
            "Run workspace tests": ("ci", None),
            "Run archived workspace tests": ("ci", None),
        },
    ),
    (
        "CLI e2e (mock relay, ",
        {
            "": ("ci", None),
            "Run CLI end-to-end tests": ("ci", None),
        },
    ),
    (
        "Relay runtime tests (",
        {
            "": ("ci", 1),
            "Run relay runtime tests serially": ("ci", 1),
            "Run held peer-index upgrade lookup": ("default", None),
        },
    ),
    (
        "Simulator and vectors (",
        {
            "": ("default", None),
            "Run archived simulator tests": ("default", None),
        },
    ),
)


def nextest_replay_profile_for_hosted_job(failed_job: str, failed_step: str = "") -> tuple[str, int | None] | None:
    """Return `(profile, test_threads)` when a hosted job+step can be replayed faithfully via nextest."""
    leaf = failed_job.rsplit("/ ", 1)[-1].strip()
    for prefix, step_profiles in NEXTEST_REPLAYABLE_HOSTED_JOBS:
        if leaf.startswith(prefix):
            return step_profiles.get(failed_step)
    return None


def is_nextest_replayable_hosted_job(failed_job: str, failed_step: str = "") -> bool:
    """Return True only when a hosted job+step can be replayed faithfully via single-test nextest."""
    return nextest_replay_profile_for_hosted_job(failed_job, failed_step) is not None


def normalize_log_text(log_text: str) -> str:
    """Strip ANSI escape codes, `gh run view --log` job/step prefixes, and GHA timestamps."""
    lines: list[str] = []
    for raw_line in log_text.splitlines():
        line = ANSI_ESCAPE_RE.sub("", raw_line)
        line = GH_LOG_PREFIX_RE.sub("", line)
        line = GHA_TIMESTAMP_RE.sub("", line)
        lines.append(line)
    return "\n".join(lines)


def log_tail(cleaned: str) -> str:
    """Return the last lines of a normalized log, where a job's terminal failure is printed.

    Infra patterns are matched only here: earlier output includes passing tests that print
    infra-like text on purpose (fast-ci's CI-runner tests simulate a full disk).
    """
    return "\n".join(cleaned.splitlines()[-80:])


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
    profile: str | None = None,
    test_threads: int | None = None,
    stress_count: int = 1,
) -> tuple[str, ...]:
    """Build the narrowest reproducible `cargo nextest run` command for one failing test.

    Uses nextest's exact `binary_id(=...)` filterset so lib tests, integration tests,
    and binary-crate tests (`bin/...`) are all targeted unambiguously, preserves the
    originating nextest `--profile` (e.g. `ci` for `wn-cli::cli` timeout backstops)
    and `--test-threads`, and pins `--retries 0 --no-tests=fail` so a renamed/absent
    test is never misread as a pass.
    """
    cmd: list[str] = ["cargo", "nextest", "run", "--locked", "-p", package]
    features = STRESS_FEATURES.get(package)
    if features:
        cmd.extend(["--features", features])
    if profile:
        cmd.extend(["--profile", profile])
    if test_threads is not None:
        cmd.extend(["--test-threads", str(test_threads)])
    binary_id = f"{package}::{binary}" if binary else package
    filter_expr = f"binary_id(={binary_id}) & test(={test_name})"
    cmd.extend(["-E", filter_expr, "--no-tests=fail", "--retries", "0", "--no-fail-fast"])
    if stress_count > 1:
        cmd.extend(["--stress-count", str(stress_count)])
    return tuple(cmd)


def parse_nextest_failures(log_text: str) -> list[tuple[str, str | None, str]]:
    """Return all `(package, binary_or_none, test_name)` records whose final outcome is failure.

    Preserves order of first appearance and ignores tests that failed on an earlier retry
    (`TRY 1 FAIL` / `TRY 1 TMT`) and subsequently passed (`TRY 2 PASS` / `FLAKY 2/2`).
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
    return [key for key, status in outcomes.items() if status == "fail"]


def parse_first_nextest_failure(log_text: str) -> tuple[str, str | None, str] | None:
    """Return `(package, binary_or_none, test_name)` for the first test whose final outcome is failure."""
    failures = parse_nextest_failures(log_text)
    return failures[0] if failures else None


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
        # Nextest's designated NO_TESTS_RUN exit code is 4 (`--no-tests=fail`).
        # Never classify exit 100 (or any other failure code) as TEST_ABSENT based
        # on output text alone, since a failing test can print "no tests to run".
        if returncode == 4:
            return RunVerdict.TEST_ABSENT, "target test absent on this commit (nextest exit 4)"
        if returncode == 0:
            if NEXTEST_PASS_RE.search(cleaned):
                return RunVerdict.PASS, "target test passed"
            return RunVerdict.INCONCLUSIVE, "nextest exited 0 without recording a target PASS line"
        # Check for an actual test failure/timeout/abort line BEFORE infra patterns so
        # relay/network test output mentioning TLS/HTTP/connection resets is never misread.
        if NEXTEST_FAIL_RE.search(cleaned):
            return RunVerdict.FAIL, "target test failed"
        if is_infra_failure(log_tail(cleaned)):
            return RunVerdict.INCONCLUSIVE, f"infrastructure or timeout error (exit {returncode})"
        return RunVerdict.INCONCLUSIVE, f"nextest failed before executing target test (exit {returncode})"

    if is_infra_failure(log_tail(cleaned)):
        return RunVerdict.INCONCLUSIVE, f"infrastructure or timeout error (exit {returncode})"
    if returncode == 0:
        return RunVerdict.PASS, "command passed"
    return RunVerdict.FAIL, f"command exited with status {returncode}"


def extract_bare_metal_signals(
    status_doc: dict,
    log_text: str,
    *,
    run_url: str = "",
) -> list[FailureSignal]:
    """Convert a red `/srv/mdk/state/canary-status.json` snapshot into one FailureSignal per terminal failure.

    Expected status schema from `/srv/mdk/bin/mdk-canary.sh`:
      {state, sha, canary_sha|previous_canary, failed_step, updated_at, duration_sec, consecutive_failures, log}

    Emits one signal for each terminal failing nextest test so a known flake can never hide
    a deterministic regression in the same run. Never places local host file paths into `run_url`.
    """
    step = str(status_doc.get("failed_step") or "")
    tip_sha = str(status_doc.get("sha") or "")
    baseline_sha = str(status_doc.get("canary_sha") or status_doc.get("previous_canary") or "")
    cleaned = normalize_log_text(log_text)
    excerpt = log_tail(cleaned)
    public_url = run_url if run_url.startswith(("http://", "https://")) else ""
    base_run_id = f"bare-metal:{tip_sha[:12]}:{status_doc.get('updated_at', '')}"

    parsed_failures = parse_nextest_failures(cleaned)
    if parsed_failures and step in {"workspace-nextest", "simulator-smoke"}:
        profile = "ci" if step == "workspace-nextest" else "default"
        signals: list[FailureSignal] = []
        for pkg, binary, test_name in parsed_failures:
            failed_test = f"{pkg}::{binary}::{test_name}" if binary else f"{pkg}::{test_name}"
            cmd = nextest_command_for_test(pkg, binary, test_name, profile=profile)
            sig_run_id = f"{base_run_id}:test:{failed_test}" if len(parsed_failures) > 1 else base_run_id
            signals.append(
                FailureSignal(
                    source="bare_metal_canary",
                    run_id=sig_run_id,
                    run_url=public_url,
                    tip_sha=tip_sha,
                    baseline_sha=baseline_sha,
                    failed_job=f"mdk-canary:{step or 'unknown'}",
                    failed_step=step,
                    failed_test=failed_test,
                    command=cmd,
                    log_excerpt=excerpt,
                    conclusion="failure",
                    reproducible_locally=True,
                    infra_hint=False,
                )
            )
        return signals

    command = BARE_METAL_STEP_COMMANDS.get(step, ())
    return [
        FailureSignal(
            source="bare_metal_canary",
            run_id=base_run_id,
            run_url=public_url,
            tip_sha=tip_sha,
            baseline_sha=baseline_sha,
            failed_job=f"mdk-canary:{step or 'unknown'}",
            failed_step=step,
            failed_test=None,
            command=command,
            log_excerpt=excerpt,
            conclusion="failure",
            reproducible_locally=bool(command),
            infra_hint=is_infra_failure(excerpt),
        )
    ]


def extract_bare_metal_signal(
    status_doc: dict,
    log_text: str,
    *,
    run_url: str = "",
) -> FailureSignal:
    """Convert a red bare-metal snapshot into its first FailureSignal."""
    return extract_bare_metal_signals(status_doc, log_text, run_url=run_url)[0]


def extract_hosted_signals(
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
) -> list[FailureSignal]:
    """Convert a failed hosted Canary workflow job into one FailureSignal per terminal failure.

    Parses all terminal nextest failures from the full fetched log before slicing `log_excerpt`
    so a known flake in a shard never masks a deterministic regression in the same shard, and
    only emits local replay commands for exact steps in `HOSTED_STEP_COMMANDS` or allowlisted
    nextest jobs with their originating `--profile` / `--test-threads`.
    """
    cleaned = normalize_log_text(log_text)
    excerpt = log_tail(cleaned)
    non_linux = is_non_linux_job(failed_job)
    parsed_failures = parse_nextest_failures(cleaned)
    base_run_id = str(run_id)

    if not non_linux and failed_step and failed_step in HOSTED_STEP_COMMANDS:
        command = HOSTED_STEP_COMMANDS[failed_step]
        first_test: str | None = None
        if parsed_failures:
            pkg, binary, test_name = parsed_failures[0]
            first_test = f"{pkg}::{binary}::{test_name}" if binary else f"{pkg}::{test_name}"
        return [
            FailureSignal(
                source=source,
                run_id=base_run_id,
                run_url=run_url,
                tip_sha=tip_sha,
                baseline_sha=baseline_sha,
                failed_job=failed_job,
                failed_step=failed_step,
                failed_test=first_test,
                command=command,
                log_excerpt=excerpt,
                conclusion=conclusion,
                reproducible_locally=True,
                infra_hint=False if parsed_failures else is_infra_failure(excerpt, conclusion),
            )
        ]

    if parsed_failures:
        replay_profile = None if non_linux else nextest_replay_profile_for_hosted_job(failed_job, failed_step)
        signals: list[FailureSignal] = []
        for pkg, binary, test_name in parsed_failures:
            failed_test = f"{pkg}::{binary}::{test_name}" if binary else f"{pkg}::{test_name}"
            cmd: tuple[str, ...] = ()
            if replay_profile is not None:
                profile, test_threads = replay_profile
                cmd = nextest_command_for_test(
                    pkg,
                    binary,
                    test_name,
                    profile=profile,
                    test_threads=test_threads,
                )
            sig_run_id = f"{base_run_id}:test:{failed_test}" if len(parsed_failures) > 1 else base_run_id
            signals.append(
                FailureSignal(
                    source=source,
                    run_id=sig_run_id,
                    run_url=run_url,
                    tip_sha=tip_sha,
                    baseline_sha=baseline_sha,
                    failed_job=failed_job,
                    failed_step=failed_step,
                    failed_test=failed_test,
                    command=cmd,
                    log_excerpt=excerpt,
                    conclusion=conclusion,
                    reproducible_locally=(not non_linux and bool(cmd)),
                    infra_hint=False,
                )
            )
        return signals

    return [
        FailureSignal(
            source=source,
            run_id=base_run_id,
            run_url=run_url,
            tip_sha=tip_sha,
            baseline_sha=baseline_sha,
            failed_job=failed_job,
            failed_step=failed_step,
            failed_test=None,
            command=(),
            log_excerpt=excerpt,
            conclusion=conclusion,
            reproducible_locally=False,
            infra_hint=is_infra_failure(excerpt, conclusion),
        )
    ]


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
    """Convert a failed hosted Canary workflow job into its first FailureSignal."""
    return extract_hosted_signals(
        source=source,
        run_id=run_id,
        run_url=run_url,
        tip_sha=tip_sha,
        baseline_sha=baseline_sha,
        failed_job=failed_job,
        log_text=log_text,
        failed_step=failed_step,
        conclusion=conclusion,
    )[0]


def _contains_exact_test_token(text: str, token: str) -> bool:
    """Return True when `token` appears in `text` as a complete test identifier."""
    if not token:
        return False
    pattern = re.compile(rf"(?<![A-Za-z0-9_:/-]){re.escape(token)}(?![A-Za-z0-9_:/-])")
    return pattern.search(text) is not None


def _legacy_flaky_title_subject(title: str) -> str:
    """Return the stripped test subject from a `Flaky: <subject>` title, or empty string."""
    if not title.lower().startswith("flaky:"):
        return ""
    subject = title.split(":", 1)[1].strip()
    if len(subject) >= 2 and subject[0] == "`" and subject[-1] == "`":
        subject = subject[1:-1].strip()
    return subject


def match_known_flake_issue(
    failed_test: str | None,
    open_issues: Iterable[dict],
) -> int | None:
    """Match a failing test identity against open `Flaky:` issues without substring false positives.

    Pass 1 matches a complete test identifier (boundary-delimited) in `title` or `body`
    (supporting both `pkg::bin::test` and nextest/JUnit `pkg::bin test` forms).
    Pass 2 falls back to legacy `Flaky: <short_name>` titles ONLY when the stripped title
    subject equals the exact short name unambiguously (a single matching legacy issue).
    """
    if not failed_test:
        return None
    issues = list(open_issues)
    # Candidate complete test identifiers (e.g. `pkg::bin::test`, and `pkg::bin test`
    # used by nextest JUnit reports).
    full_tokens = [failed_test]
    if "::" in failed_test:
        prefix, leaf = failed_test.rsplit("::", 1)
        full_tokens.append(f"{prefix} {leaf}")
    else:
        leaf = failed_test

    legacy_matches: list[int] = []
    for issue in issues:
        number = issue.get("number")
        if not isinstance(number, int):
            continue
        title = str(issue.get("title") or "")
        body = str(issue.get("body") or "")
        is_flake_issue = title.lower().startswith("flaky:")
        if not is_flake_issue:
            continue
        if any(_contains_exact_test_token(title, tok) or _contains_exact_test_token(body, tok) for tok in full_tokens):
            return number
        subject = _legacy_flaky_title_subject(title)
        if subject and "::" not in subject and " " not in subject and subject == leaf:
            legacy_matches.append(number)

    if len(legacy_matches) == 1:
        return legacy_matches[0]
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

    For locally reproducible signals, always runs `tip` (and `baseline` on `tip`
    failure) reproduction before consulting individual `Flaky:` issues so a
    deterministic regression is never suppressed. Individual `Flaky:` issues (never
    `"Flaky test leaderboard"`) are consulted:
      - on the locally-unreproducible fallback (non-Linux / Relay-E2E) so human-tracked
        non-Linux flakes do not escalate into false Meltdowns;
      - when `tip` passes single retry (intermittent), skipping stress runs;
      - on a second `tip` replay before returning `UNREPRODUCIBLE` when no distinct
        green baseline is available, so intermittent tracked flakes without a baseline
        stay `KNOWN_FLAKE` instead of triggering false Meltdowns;
      - when both `tip` and `baseline` fail; and
      - in palindrome confirmation order (`tip -> baseline -> baseline -> tip`, or
        `tip -> baseline(TEST_ABSENT) -> tip` for newly added tests), defeating both
        alternating and early-fail/later-pass burst streams before returning
        `DETERMINISTIC_REGRESSION`.
    """
    # Bucket 1: Runner/network/disk infrastructure error.
    # Never let diagnostic tail strings override a concrete parsed nextest test failure.
    if signal.infra_hint or (not signal.failed_test and is_infra_failure(signal.log_excerpt, signal.conclusion)):
        return ClassificationResult(
            bucket=Bucket.INFRA_ERROR,
            reason=f"infrastructure failure detected in {signal.failed_job} ({signal.conclusion})",
        )

    matched_issue = match_known_flake_issue(signal.failed_test, open_flake_issues)

    # Platform-specific or unparsed failure with no local reproduction command.
    if not signal.reproducible_locally or not signal.command:
        if matched_issue is not None:
            return ClassificationResult(
                bucket=Bucket.KNOWN_FLAKE,
                reason=(
                    f"non-locally-reproducible failure in `{signal.failed_job}` matches "
                    f"open flake issue #{matched_issue} for {signal.failed_test}"
                ),
                matched_issue=matched_issue,
            )
        step_note = f" (step `{signal.failed_step}`)" if signal.failed_step else ""
        if is_non_linux_job(signal.failed_job):
            reason = f"non-Linux job `{signal.failed_job}`{step_note} is not locally reproducible on this host"
        else:
            reason = f"no reproducible command extracted for `{signal.failed_job}`{step_note}"
        return ClassificationResult(
            bucket=Bucket.UNREPRODUCIBLE,
            reason=reason,
        )

    # Single-shot reproduction on tip BEFORE consulting open `Flaky:` issues.
    tip_verdict, tip_detail = run_on_sha(signal.tip_sha, signal.command)
    if tip_verdict in {RunVerdict.INCONCLUSIVE, RunVerdict.TEST_ABSENT}:
        return ClassificationResult(
            bucket=Bucket.INFRA_ERROR,
            reason=f"inconclusive reproduction on {signal.tip_sha[:9]} ({tip_detail})",
        )

    if tip_verdict == RunVerdict.FAIL:
        def _confirm_tracked_tip() -> ClassificationResult | None:
            tip_confirm, tip_confirm_detail = run_on_sha(signal.tip_sha, signal.command)
            if tip_confirm in {RunVerdict.INCONCLUSIVE, RunVerdict.TEST_ABSENT}:
                return ClassificationResult(
                    bucket=Bucket.INFRA_ERROR,
                    reason=f"inconclusive confirmation on {signal.tip_sha[:9]} ({tip_confirm_detail})",
                )
            if tip_confirm == RunVerdict.PASS:
                return ClassificationResult(
                    bucket=Bucket.KNOWN_FLAKE,
                    reason=(
                        f"mixed tip outcomes on {signal.tip_sha[:9]} (failed then passed); "
                        f"matches open flake issue #{matched_issue} for {signal.failed_test}"
                    ),
                    matched_issue=matched_issue,
                )
            return None

        if not signal.baseline_sha or signal.baseline_sha == signal.tip_sha:
            if matched_issue is not None:
                # Confirm repeatability on `tip` before returning UNREPRODUCIBLE so a
                # tracked flake without a distinct green baseline stays KNOWN_FLAKE.
                tip_check = _confirm_tracked_tip()
                if tip_check is not None:
                    return tip_check
            return ClassificationResult(
                bucket=Bucket.UNREPRODUCIBLE,
                reason=f"reproduced on {signal.tip_sha[:9]} but no distinct green baseline is available to bisect",
                matched_issue=matched_issue,
            )

        base_verdict, base_detail = run_on_sha(signal.baseline_sha, signal.command)
        if base_verdict == RunVerdict.FAIL:
            if matched_issue is not None:
                return ClassificationResult(
                    bucket=Bucket.KNOWN_FLAKE,
                    reason=(
                        f"fails on both tip {signal.tip_sha[:9]} and baseline "
                        f"{signal.baseline_sha[:9]}; matches open flake issue "
                        f"#{matched_issue} for {signal.failed_test}"
                    ),
                    matched_issue=matched_issue,
                )
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
        if matched_issue is not None:
            # Confirm in palindrome order (`tip -> baseline -> baseline -> tip`) so
            # neither alternating (`[F, P, F, P]`) nor early-fail/later-pass burst
            # streams (`[F, F, P, P]`, `[F, P, P, P]`) align with tip/baseline.
            if base_verdict == RunVerdict.PASS:
                base_confirm, base_confirm_detail = run_on_sha(signal.baseline_sha, signal.command)
                if base_confirm in {RunVerdict.INCONCLUSIVE, RunVerdict.TEST_ABSENT}:
                    return ClassificationResult(
                        bucket=Bucket.INFRA_ERROR,
                        reason=f"inconclusive baseline confirmation on {signal.baseline_sha[:9]} ({base_confirm_detail})",
                    )
                if base_confirm == RunVerdict.FAIL:
                    return ClassificationResult(
                        bucket=Bucket.KNOWN_FLAKE,
                        reason=(
                            f"reproduced on tip {signal.tip_sha[:9]} and failed baseline confirmation "
                            f"on {signal.baseline_sha[:9]}; matches open flake issue #{matched_issue} "
                            f"for {signal.failed_test}"
                        ),
                        matched_issue=matched_issue,
                    )
            tip_check = _confirm_tracked_tip()
            if tip_check is not None:
                return tip_check
        return ClassificationResult(
            bucket=Bucket.DETERMINISTIC_REGRESSION,
            reason=(
                f"reproduced on {signal.tip_sha[:9]} and did not fail on "
                f"baseline {signal.baseline_sha[:9]} ({base_verdict.value})"
            ),
            matched_issue=matched_issue,
        )

    # Passed single retry (intermittent). Check open individual `Flaky:` issues before
    # spending time on differential stress runs.
    if matched_issue is not None:
        return ClassificationResult(
            bucket=Bucket.KNOWN_FLAKE,
            reason=(
                f"passed single retry on {signal.tip_sha[:9]}; matches open flake issue "
                f"#{matched_issue} for {signal.failed_test}"
            ),
            matched_issue=matched_issue,
        )

    # Only run differential stress on targeted `cargo nextest run` commands
    # (never loop heavy workspace commands like `just fast-ci`).
    if not is_nextest_command(signal.command) or stress_count <= 1:
        return ClassificationResult(
            bucket=Bucket.NEW_INTERMITTENT,
            reason=f"passed single retry on {signal.tip_sha[:9]} (non-nextest command; stress skipped)",
        )

    tip_stress, tip_stress_detail = _run_nextest_stress(run_on_sha, signal.tip_sha, signal.command, stress_count)
    if tip_stress == RunVerdict.INCONCLUSIVE:
        suffix = f" ({tip_stress_detail})" if tip_stress_detail else ""
        return ClassificationResult(
            bucket=Bucket.INFRA_ERROR,
            reason=f"inconclusive stress check on tip {signal.tip_sha[:9]}{suffix}",
        )

    base_stress: RunVerdict | None = None
    has_distinct_baseline = bool(signal.baseline_sha and signal.baseline_sha != signal.tip_sha)
    if has_distinct_baseline:
        base_stress, base_stress_detail = _run_nextest_stress(
            run_on_sha, signal.baseline_sha, signal.command, stress_count
        )
        if base_stress == RunVerdict.INCONCLUSIVE:
            suffix = f" ({base_stress_detail})" if base_stress_detail else ""
            return ClassificationResult(
                bucket=Bucket.INFRA_ERROR,
                reason=f"inconclusive stress check on baseline {signal.baseline_sha[:9]}{suffix}",
            )

    if tip_stress == RunVerdict.FAIL and base_stress == RunVerdict.FAIL:
        return ClassificationResult(
            bucket=Bucket.KNOWN_FLAKE,
            reason=(
                f"reproduced intermittently under {stress_count}x stress on both tip "
                f"{signal.tip_sha[:9]} and baseline {signal.baseline_sha[:9]}"
            ),
        )

    if tip_stress == RunVerdict.FAIL:
        if base_stress is None:
            base_note = "baseline stress skipped: no distinct baseline"
        else:
            base_note = f"baseline {signal.baseline_sha[:9]}: {base_stress.value}"
        return ClassificationResult(
            bucket=Bucket.NEW_INTERMITTENT,
            reason=(
                f"intermittent failure under {stress_count}x stress on tip {signal.tip_sha[:9]} "
                f"({base_note}; manual triage required, never auto-reverted)"
            ),
        )

    if base_stress == RunVerdict.FAIL:
        return ClassificationResult(
            bucket=Bucket.NEW_INTERMITTENT,
            reason=(
                f"intermittent failure under {stress_count}x stress on baseline {signal.baseline_sha[:9]} "
                f"(tip {signal.tip_sha[:9]}: {tip_stress.value}; manual triage required, never auto-reverted)"
            ),
        )

    if base_stress is None:
        return ClassificationResult(
            bucket=Bucket.NEW_INTERMITTENT,
            reason=(
                f"did not reproduce under {stress_count}x stress on tip {signal.tip_sha[:9]} "
                f"({tip_stress.value}; baseline stress skipped: no distinct baseline)"
            ),
        )

    return ClassificationResult(
        bucket=Bucket.NEW_INTERMITTENT,
        reason=(
            f"did not reproduce under {stress_count}x stress "
            f"(tip {signal.tip_sha[:9]}: {tip_stress.value}, "
            f"baseline {signal.baseline_sha[:9]}: {base_stress.value})"
        ),
    )


def _run_nextest_stress(
    run_on_sha: RunCommandOnSha,
    sha: str,
    command: tuple[str, ...],
    stress_count: int,
) -> tuple[RunVerdict, str]:
    """Run a `cargo nextest run` command with `--stress-count` and preserve its observed verdict and detail."""
    scmd = stress_command(command, stress_count)
    return run_on_sha(sha, scmd)
