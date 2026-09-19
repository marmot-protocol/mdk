#!/usr/bin/env python3
"""Compare baseline and candidate MarmotKit release-profile artifacts.

Schema version 1. Missing platform data is recorded as unavailable; never as
zero. This script does not publish artifacts or mutate source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


CRATE = Path(__file__).resolve().parent
ROOT = CRATE.parents[1]
ANDROID_ABIS = {
    "arm64-v8a": "aarch64-linux-android",
    "armeabi-v7a": "armv7-linux-androideabi",
    "x86": "i686-linux-android",
    "x86_64": "x86_64-linux-android",
}
ANDROID_CLANG_PREFIX = {
    "aarch64-linux-android": "aarch64-linux-android",
    "armv7-linux-androideabi": "armv7a-linux-androideabi",
    "i686-linux-android": "i686-linux-android",
    "x86_64-linux-android": "x86_64-linux-android",
}
PRIMARY_ANDROID_TARGETS = (
    "aarch64-linux-android",
    "armv7-linux-androideabi",
)
APPLE_SLICES = {
    "aarch64-apple-ios": "apple_static_archive",
    "aarch64-apple-ios-sim": "apple_static_archive",
    "aarch64-apple-darwin": "apple_static_archive",
}
FEATURES = ["otlp-export", "product-analytics-export"]
BASELINE_PROFILE = {"lto": False, "codegen_units": 16}
CANDIDATE_PROFILE = {"lto": "thin", "codegen_units": 1}
ANDROID_API = os.environ.get("ANDROID_API", "26")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command, env, cwd, log_dir, name):
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    duration = time.monotonic() - started
    (log_dir / f"{name}.stdout").write_text(completed.stdout)
    (log_dir / f"{name}.stderr").write_text(completed.stderr)
    if completed.returncode != 0:
        raise RuntimeError(
            f"{name} failed with {completed.returncode}; see {log_dir / (name + '.stderr')}"
        )
    return duration, completed


def canonical_profile_env() -> dict[str, str]:
    values = {}
    for line in (CRATE / "marmotkit-release-profile.env").read_text().splitlines():
        if not line.startswith("export "):
            continue
        name, _, value = line[len("export ") :].partition("=")
        values[name] = value
    return values


def profile_env(base: dict, variant: str, strip: str) -> dict:
    env = dict(base)
    env.update(canonical_profile_env())
    chosen = BASELINE_PROFILE if variant == "baseline" else CANDIDATE_PROFILE
    # Source canonical settings, then override only the compared knobs.
    env["CARGO_PROFILE_RELEASE_LTO"] = "false" if chosen["lto"] is False else str(chosen["lto"])
    env["CARGO_PROFILE_RELEASE_CODEGEN_UNITS"] = str(chosen["codegen_units"])
    env["CARGO_PROFILE_RELEASE_STRIP"] = strip
    return env


def find_android_ndk() -> Path | None:
    for key in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME"):
        candidate = os.environ.get(key)
        if candidate and Path(candidate, "toolchains/llvm/prebuilt").is_dir():
            return Path(candidate)
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk_root:
        ndk_root = Path(sdk_root) / "ndk"
        if ndk_root.is_dir():
            versions = sorted(path for path in ndk_root.iterdir() if path.is_dir())
            if versions:
                return versions[-1]
    return None


def android_host_tag(ndk: Path) -> str:
    prebuilt = ndk / "toolchains/llvm/prebuilt"
    if (prebuilt / "linux-x86_64").is_dir():
        return "linux-x86_64"
    if (prebuilt / "darwin-x86_64").is_dir():
        return "darwin-x86_64"
    hosts = sorted(path.name for path in prebuilt.iterdir() if path.is_dir())
    if not hosts:
        raise RuntimeError(f"no Android NDK host toolchain under {prebuilt}")
    return hosts[-1]


def configure_android_toolchain(env: dict, ndk: Path, triple: str) -> None:
    host_tag = android_host_tag(ndk)
    toolchain_bin = ndk / "toolchains/llvm/prebuilt" / host_tag / "bin"
    clang = toolchain_bin / f"{ANDROID_CLANG_PREFIX[triple]}{ANDROID_API}-clang"
    if not clang.is_file():
        raise RuntimeError(f"Android clang not found: {clang}")
    cargo_env = triple.upper().replace("-", "_")
    cc_env = triple.replace("-", "_")
    env[f"CARGO_TARGET_{cargo_env}_LINKER"] = str(clang)
    env[f"CARGO_TARGET_{cargo_env}_AR"] = str(toolchain_bin / "llvm-ar")
    env[f"CC_{cc_env}"] = str(clang)
    env[f"AR_{cc_env}"] = str(toolchain_bin / "llvm-ar")
    env[f"RANLIB_{cc_env}"] = str(toolchain_bin / "llvm-ranlib")


def android_reduction_failures(artifacts: list[dict]) -> list[str]:
    failures = []
    for row in artifacts:
        if row["target"] not in PRIMARY_ANDROID_TARGETS:
            continue
        if row["availability"] != "measured":
            failures.append(f"{row['target']} was not measured ({row.get('reason')})")
            continue
        delta = row.get("delta_bytes")
        if not isinstance(delta, int) or delta >= 0:
            failures.append(
                f"{row['target']} did not shrink: baseline={row['baseline_bytes']} "
                f"candidate={row['candidate_bytes']} delta={delta}"
            )
    return failures


def artifact_row(target, kind, strip, baseline, candidate, reason=None):
    row = {
        "target": target,
        "kind": kind,
        "baseline_bytes": None,
        "candidate_bytes": None,
        "baseline_sha256": None,
        "candidate_sha256": None,
        "delta_bytes": None,
        "delta_percent": None,
        "baseline_profile": {**BASELINE_PROFILE, "strip": strip},
        "candidate_profile": {**CANDIDATE_PROFILE, "strip": strip},
        "availability": "unavailable",
        "reason": reason or "artifact files missing",
    }
    if baseline and candidate and baseline.exists() and candidate.exists():
        row["baseline_bytes"] = baseline.stat().st_size
        row["candidate_bytes"] = candidate.stat().st_size
        row["baseline_sha256"] = sha256_file(baseline)
        row["candidate_sha256"] = sha256_file(candidate)
        row["delta_bytes"] = row["candidate_bytes"] - row["baseline_bytes"]
        if row["baseline_bytes"]:
            row["delta_percent"] = (row["delta_bytes"] / row["baseline_bytes"]) * 100
        row["availability"] = "measured"
        row["reason"] = None
    return row


def host_library(target_dir: Path) -> Path:
    if sys.platform == "darwin":
        return target_dir / "release" / "libmarmot_uniffi.dylib"
    return target_dir / "release" / "libmarmot_uniffi.so"


def apply_apple_native_archive_rustflags(env: dict, triple: str) -> dict:
    """Match xcframework.sh: target-scoped -C embed-bitcode=no only."""
    key = f"CARGO_TARGET_{triple.upper().replace('-', '_')}_RUSTFLAGS"
    current = env.get(key, "")
    if "embed-bitcode=no" not in current:
        env[key] = f"{current} -C embed-bitcode=no".strip()
    return env


def rustc_has_target(triple: str) -> bool:
    listed = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        check=False,
        capture_output=True,
        text=True,
    )
    return listed.returncode == 0 and triple in listed.stdout.splitlines()


def measure_library(workspace, env, log_dir, extra_args, name, features=None):
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "-p",
        "marmot-uniffi",
        *extra_args,
    ]
    selected = FEATURES if features is None else features
    if selected:
        command.extend(["--features", ",".join(selected)])
    duration, _ = run(command, env, workspace, log_dir, name)
    return duration, command


def collect_cpu(target_dir: Path):
    root = target_dir / "criterion"
    rows = []
    if not root.is_dir():
        return rows
    for estimates in root.rglob("estimates.json"):
        if estimates.parent.name != "new":
            continue
        data = json.loads(estimates.read_text())
        mean = data.get("mean", {})
        rows.append(
            {
                "benchmark": str(estimates.relative_to(root)),
                "units": "ns",
                "point_estimate": mean.get("point_estimate"),
                "confidence_interval": {
                    "lower": mean.get("confidence_interval", {}).get("lower_bound"),
                    "upper": mean.get("confidence_interval", {}).get("upper_bound"),
                },
                "raw_result": str(estimates),
            }
        )
    return rows


def isolate_criterion_dir(target_dir: Path) -> None:
    root = target_dir / "criterion"
    if root.exists():
        shutil.rmtree(root)


def cpu_rows_from_successful_run(variant: str, profile: dict, rows: list[dict]) -> list[dict]:
    """Publish only fresh create_group estimates from a successful cargo bench."""
    published = []
    for row in rows:
        if "create_group" not in row.get("benchmark", ""):
            continue
        if row.get("point_estimate") is None:
            continue
        published.append(
            {
                **row,
                "variant": variant,
                "profile": dict(profile),
                "availability": "measured",
                "reason": None,
            }
        )
    return published


def unavailable_cpu_row(variant: str, profile: dict, reason: str) -> dict:
    return {
        "benchmark": "group_lifecycle/create_group",
        "variant": variant,
        "profile": dict(profile),
        "units": "ns",
        "point_estimate": None,
        "confidence_interval": None,
        "raw_result": None,
        "availability": "unavailable",
        "reason": reason,
    }


def cpu_slowdown_warnings(cpu_runs: list[dict]) -> list[str]:
    warnings = []
    baseline = {
        row["benchmark"]: row
        for row in cpu_runs
        if row.get("variant") == "baseline" and row.get("availability") == "measured"
    }
    for row in cpu_runs:
        if row.get("variant") != "candidate" or row.get("availability") != "measured":
            continue
        prior = baseline.get(row["benchmark"])
        if not prior or not prior.get("point_estimate") or not row.get("point_estimate"):
            continue
        delta = ((row["point_estimate"] - prior["point_estimate"]) / prior["point_estimate"]) * 100
        if delta > 5:
            warnings.append(
                f"{row['benchmark']} candidate is {delta:.2f}% slower than baseline"
            )
    return warnings


def relocate_cpu_raw_results(cpu_runs: list[dict], work: Path, diagnostics: Path) -> None:
    for row in cpu_runs:
        raw = row.get("raw_result")
        if not raw:
            continue
        raw_path = Path(raw)
        try:
            relative = raw_path.relative_to(work)
        except ValueError:
            continue
        destination = diagnostics / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if raw_path.is_file():
            shutil.copy2(raw_path, destination)
            row["raw_result"] = str(Path("diagnostics") / relative)


def stage_diagnostics(work: Path, diagnostics: Path) -> None:
    diagnostics.mkdir(parents=True, exist_ok=True)
    logs = work / "logs"
    if logs.is_dir():
        destination = diagnostics / "logs"
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(logs, destination)
    for variant in ("baseline", "candidate"):
        criterion = work / f"cpu-{variant}" / "criterion"
        if not criterion.is_dir():
            continue
        destination = diagnostics / f"cpu-{variant}" / "criterion"
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(criterion, destination)


def xcodebuild_version() -> str:
    path = shutil.which("xcodebuild")
    if not path:
        return "unavailable"
    completed = subprocess.run(
        [path, "-version"],
        check=False,
        capture_output=True,
        text=True,
    )
    text = (completed.stdout or completed.stderr or "").strip()
    if completed.returncode != 0 or not text:
        return f"{path} (version unavailable)"
    return " ".join(text.split())


def command_record(name: str, command: list[str], duration, **extra) -> dict:
    record = {
        "name": name,
        "argv": list(command),
        "compile_seconds": duration,
    }
    record.update(extra)
    return record


def render_markdown(report: dict) -> str:
    lines = [
        "# MarmotKit release-profile measurements",
        "",
        f"Schema: {report['schema_version']}",
        f"Source SHA: `{report['source_sha']}`",
        f"Builder SHA: `{report['builder_sha']}`",
        "",
        "| Target | Kind | Baseline bytes | Candidate bytes | Delta bytes | Delta % | Status |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in report["artifacts"]:
        lines.append(
            "| {target} | {kind} | {baseline_bytes} | {candidate_bytes} | {delta_bytes} | {delta} | {availability} |".format(
                target=row["target"],
                kind=row["kind"],
                baseline_bytes=row["baseline_bytes"] if row["baseline_bytes"] is not None else "unavailable",
                candidate_bytes=row["candidate_bytes"] if row["candidate_bytes"] is not None else "unavailable",
                delta_bytes=row["delta_bytes"] if row["delta_bytes"] is not None else "unavailable",
                delta=(
                    f"{row['delta_percent']:.2f}"
                    if isinstance(row.get("delta_percent"), (int, float))
                    else "unavailable"
                ),
                availability=row["availability"],
            )
        )
    lines.extend(["", "## CPU", ""])
    if report.get("cpu_collection_error"):
        lines.append(f"CPU collection failed: {report['cpu_collection_error']}")
        lines.append("")
    if not report["cpu_runs"]:
        lines.append("No CPU measurements were collected.")
    for row in report["cpu_runs"]:
        reason = row.get("reason") or row.get("collection_error")
        availability = row.get("availability")
        estimate = row.get("point_estimate")
        if availability == "unavailable" or reason or estimate is None:
            detail = reason or "missing estimate"
            lines.append(
                f"- `{row['benchmark']}` ({row.get('variant', 'unknown')}): "
                f"unavailable ({detail})"
            )
            continue
        lines.append(
            f"- `{row['benchmark']}` ({row['variant']}): {estimate} {row['units']}"
        )
    for warning in report.get("cpu_slowdown_warnings") or []:
        lines.append(f"- investigation required: {warning}")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--builder-sha", required=True)
    parser.add_argument("--host", action="store_true")
    parser.add_argument("--android", action="store_true")
    parser.add_argument("--apple", action="store_true")
    parser.add_argument("--cpu", action="store_true")
    parser.add_argument(
        "--diagnostics-dir",
        type=Path,
        help="Copy logs and Criterion raw results here using artifact-relative paths",
    )
    parser.add_argument(
        "--require-android-reduction",
        action="store_true",
        help="Fail when a primary ARM Android ABI is unmeasured or does not shrink",
    )
    args = parser.parse_args(argv)
    workspace = args.workspace.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    work = (args.work_dir or (workspace / "target/release-profile-measure")).resolve()
    work.mkdir(parents=True, exist_ok=True)
    log_dir = work / "logs"
    log_dir.mkdir(exist_ok=True)
    lock_sha = sha256_file(workspace / "Cargo.lock")
    rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
    cargo = subprocess.check_output(["cargo", "--version"], text=True).strip()
    commands = []
    artifacts = []
    cpu_runs = []
    cpu_failures = []
    base_env = os.environ.copy()
    base_env["CARGO_INCREMENTAL"] = "0"

    if args.host:
        for variant in ("baseline", "candidate"):
            target_dir = work / f"host-{variant}"
            env = profile_env(base_env, variant, "none")
            env["CARGO_TARGET_DIR"] = str(target_dir)
            duration, command = measure_library(
                workspace, env, log_dir, [], f"host-{variant}"
            )
            commands.append(
                command_record(
                    f"host-{variant}",
                    command,
                    duration,
                    target_dir=str(target_dir),
                )
            )
        artifacts.append(
            artifact_row(
                "host",
                "host_generation_library",
                "none",
                host_library(work / "host-baseline"),
                host_library(work / "host-candidate"),
            )
        )
        default_dir = work / "host-default-features"
        env = profile_env(base_env, "candidate", "none")
        env["CARGO_TARGET_DIR"] = str(default_dir)
        duration, command = measure_library(
            workspace, env, log_dir, [], "host-default-features-candidate", features=[]
        )
        commands.append(
            command_record(
                "host-default-features-candidate",
                command,
                duration,
                target_dir=str(default_dir),
                features=[],
            )
        )
        default_lib = host_library(default_dir)
        artifacts.append(
            {
                "target": "host",
                "kind": "host_generation_library_default_features",
                "baseline_bytes": None,
                "candidate_bytes": default_lib.stat().st_size if default_lib.exists() else None,
                "baseline_sha256": None,
                "candidate_sha256": sha256_file(default_lib) if default_lib.exists() else None,
                "delta_bytes": None,
                "delta_percent": None,
                "baseline_profile": None,
                "candidate_profile": {**CANDIDATE_PROFILE, "strip": "none"},
                "availability": "measured" if default_lib.exists() else "unavailable",
                "reason": None if default_lib.exists() else "default-feature host library missing",
            }
        )
    else:
        artifacts.append(
            artifact_row("host", "host_generation_library", "none", None, None, "not requested")
        )

    for abi, triple in ANDROID_ABIS.items():
        strip = "symbols"
        if not args.android:
            artifacts.append(
                artifact_row(triple, "android_jni_so", strip, None, None, "not requested")
            )
            continue
        ndk = find_android_ndk()
        if not rustc_has_target(triple) or ndk is None:
            artifacts.append(
                artifact_row(
                    triple,
                    "android_jni_so",
                    strip,
                    None,
                    None,
                    "Android NDK or Rust target unavailable",
                )
            )
            continue
        paths = {}
        for variant in ("baseline", "candidate"):
            target_dir = work / f"android-{variant}"
            env = profile_env(base_env, variant, strip)
            env["CARGO_TARGET_DIR"] = str(target_dir)
            configure_android_toolchain(env, ndk, triple)
            duration, command = measure_library(
                workspace,
                env,
                log_dir,
                ["--target", triple],
                f"android-{abi}-{variant}",
            )
            commands.append(
                command_record(
                    f"android-{abi}-{variant}",
                    command,
                    duration,
                    target_dir=str(target_dir),
                )
            )
            paths[variant] = target_dir / triple / "release" / "libmarmot_uniffi.so"
        artifacts.append(
            artifact_row(triple, "android_jni_so", strip, paths["baseline"], paths["candidate"])
        )

    for triple, kind in APPLE_SLICES.items():
        if not args.apple:
            artifacts.append(
                artifact_row(triple, kind, "none", None, None, "not requested")
            )
            continue
        if not rustc_has_target(triple):
            artifacts.append(
                artifact_row(triple, kind, "none", None, None, "Apple Rust target unavailable")
            )
            continue
        paths = {}
        for variant in ("baseline", "candidate"):
            target_dir = work / f"apple-{variant}"
            env = profile_env(base_env, variant, "none")
            env["CARGO_TARGET_DIR"] = str(target_dir)
            apply_apple_native_archive_rustflags(env, triple)
            duration, command = measure_library(
                workspace,
                env,
                log_dir,
                ["--target", triple],
                f"apple-{triple}-{variant}",
            )
            commands.append(
                command_record(
                    f"apple-{triple}-{variant}",
                    command,
                    duration,
                    target_dir=str(target_dir),
                )
            )
            paths[variant] = target_dir / triple / "release" / "libmarmot_uniffi.a"
        artifacts.append(
            artifact_row(triple, kind, "none", paths["baseline"], paths["candidate"])
        )

    if args.cpu:
        for variant in ("baseline", "candidate"):
            target_dir = work / f"cpu-{variant}"
            isolate_criterion_dir(target_dir)
            env = profile_env(base_env, variant, "none")
            env["CARGO_TARGET_DIR"] = str(target_dir)
            env["MDK_RELEASE_PROFILE_CPU_ONLY"] = "1"
            command = [
                "cargo",
                "bench",
                "--locked",
                "--profile",
                "release",
                "-p",
                "cgka-engine",
                "--bench",
                "group_lifecycle",
                "--",
                "create_group/",
                "--sample-size",
                "10",
                "--warm-up-time",
                "1",
                "--measurement-time",
                "3",
                "--noplot",
            ]
            profile = BASELINE_PROFILE if variant == "baseline" else CANDIDATE_PROFILE
            try:
                duration, _ = run(command, env, workspace, log_dir, f"cpu-{variant}")
            except RuntimeError as error:
                reason = str(error)
                cpu_failures.append(reason)
                commands.append(
                    command_record(
                        f"cpu-{variant}",
                        command,
                        None,
                        target_dir=str(target_dir),
                        availability="unavailable",
                        reason=reason,
                    )
                )
                cpu_runs.append(unavailable_cpu_row(variant, profile, reason))
                continue
            published = cpu_rows_from_successful_run(
                variant, profile, collect_cpu(target_dir)
            )
            if not published:
                reason = (
                    "no fresh create_group Criterion estimates after a successful "
                    "benchmark invocation"
                )
                cpu_failures.append(reason)
                commands.append(
                    command_record(
                        f"cpu-{variant}",
                        command,
                        duration,
                        target_dir=str(target_dir),
                        availability="unavailable",
                        reason=reason,
                    )
                )
                cpu_runs.append(unavailable_cpu_row(variant, profile, reason))
                continue
            commands.append(
                command_record(
                    f"cpu-{variant}",
                    command,
                    duration,
                    target_dir=str(target_dir),
                    availability="measured",
                )
            )
            cpu_runs.extend(published)
    else:
        cpu_runs.append(
            {
                "benchmark": "group_lifecycle/create_group",
                "variant": "unmeasured",
                "units": "ns",
                "point_estimate": None,
                "confidence_interval": None,
                "raw_result": None,
                "availability": "unavailable",
                "reason": "not requested",
            }
        )

    diagnostics = args.diagnostics_dir.resolve() if args.diagnostics_dir else None
    if diagnostics is not None:
        stage_diagnostics(work, diagnostics)
        relocate_cpu_raw_results(cpu_runs, work, diagnostics)
    slowdowns = cpu_slowdown_warnings(cpu_runs)
    report = {
        "schema_version": 1,
        "source_sha": args.source_sha,
        "builder_sha": args.builder_sha,
        "lock_sha256": lock_sha,
        "toolchains": {
            "rustc": rustc,
            "cargo": cargo,
            "android_ndk_home": str(find_android_ndk() or "unavailable"),
            "android_api": ANDROID_API,
            "xcodebuild": xcodebuild_version(),
        },
        "features": FEATURES,
        "commands": commands,
        "artifacts": artifacts,
        "cpu_runs": cpu_runs,
        "cpu_collection_error": "; ".join(cpu_failures) if cpu_failures else None,
        "cpu_slowdown_warnings": slowdowns,
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    markdown = render_markdown(report)
    if args.markdown:
        args.markdown.write_text(markdown)
    else:
        sys.stdout.write(markdown)
    failures = []
    if args.require_android_reduction:
        failures.extend(android_reduction_failures(artifacts))
    if args.cpu and cpu_failures:
        failures.extend(cpu_failures)
    if failures:
        sys.stderr.write("Release-profile measurement gate failed:\n")
        for failure in failures:
            sys.stderr.write(f"  {failure}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
