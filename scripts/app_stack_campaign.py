#!/usr/bin/env python3
"""Build once and run the public app-stack catalog with private, immutable evidence."""

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
PACKAGE = "cgka-conformance-simulator"
# Legacy counts select bounded catalog arms; new stateful families sample seeded schedules.
FAMILIES = {
    "public-app-large-group/v1": (6, 1800),
    "public-app-stateful-recovery/v1": (6, 900),
    "public-app-recovery-schedules/v1": (6, 900),
    "public-app-send-leave/v1": (6, 360),
    "public-app-membership-reentry/v1": (6, 360),
    "public-app-offline-recovery/v1": (6, 360),
    "public-app-admin-handoff/v1": (6, 360),
    "public-app-admin-churn/v1": (6, 900),
    "public-app-late-join/v1": (6, 900),
    "public-app-backlog-recovery/v1": (6, 900),
    "cross-route-restart-permutations/v1": (12, 900),
}
TEST_BINARIES = (
    "app_runtime_adapter", "app_runtime_journeys",
    "app_runtime_interaction_journeys", "public_app_families", "app_generated_variance", "process_orchestrator",
)
LEGACY_CONTROL_PACKAGES = ("cgka-engine", PACKAGE)
# These tests exercise the app adapter together with its independent retained
# engine control. Isolated participant-process/container campaigns stay separate.
APP_ROUTE_TESTS = {
    "four_party_cross_route_recovery_app_runtime_matches_unified_route",
}
CANARY_TESTS = {
    "public_app_01_bidirectional_messaging",
    "public_app_13_offline_removal_then_rejoin_preserves_history",
    "public_app_14_two_groups_recover_without_starving_live_traffic",
    "public_backlog_recovery_restart_strict_canary",
}
RACE_DIAGNOSTIC = "public_app_09_strict_concurrent_invite_and_rename_are_never_lost"
ACTIVE = {}
STOPPING = False


def stop_campaign(_signum, _frame):
    global STOPPING
    STOPPING = True
    for process in list(ACTIVE.values()):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    raise KeyboardInterrupt


def positive(value):
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return result


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path, help="fresh evidence directory (must not exist)")
    parser.add_argument("--mode", choices=("canary", "full"), default="full")
    parser.add_argument("--seeds", nargs="+", type=int, default=[7, 42, 17001])
    parser.add_argument("--rounds", type=positive, default=1,
                        help="repeat the complete selection with new sockets and keys")
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    parser.add_argument("--allow-dirty", action="store_true",
                        help="record a WIP patch and untracked file hashes for local validation")
    parser.add_argument("--plan-only", action="store_true", help="print selection without building or writing")
    args = parser.parse_args(argv)
    if any(seed < 0 or seed > 2**64 - 1 for seed in args.seeds):
        parser.error("seeds must be unsigned 64-bit integers")
    args.seeds = list(dict.fromkeys(args.seeds))
    return args


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def write_json(path, value):
    # The parent is already private. Replace only this run's progress file.
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=REPO)


def source_state():
    untracked = git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")
    return {
        "commit": git("rev-parse", "HEAD").decode().strip(),
        "status": git("status", "--porcelain=v1").decode(),
        "patch_sha256": hashlib.sha256(git("diff", "HEAD", "--binary")).hexdigest(),
        "untracked_sha256": {name: digest(REPO / name) for name in untracked if name},
    }


def run_command(command, root, env, timeout):
    """Reap a whole process group on timeout/interruption, including case workers."""
    started = time.monotonic()
    if STOPPING:
        raise RuntimeError("campaign interrupted")
    with (root / "output.log").open("wb") as log:
        process = subprocess.Popen(command, cwd=REPO, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        ACTIVE[process.pid] = process
        if STOPPING:
            os.killpg(process.pid, signal.SIGKILL)
        timed_out = False
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        finally:
            ACTIVE.pop(process.pid, None)
    return {"exit_code": code, "timed_out": timed_out,
            "wall_seconds": time.monotonic() - started}


def build_commands():
    return [
        ["cargo", "build", "--release", "--locked", "-p", PACKAGE,
         "--bin", "cgka-conformance-campaign", "--bin", "cgka-conformance-node", "--message-format=json"],
        ["cargo", "test", "--release", "--locked", "-p", PACKAGE,
         "--no-run", "--message-format=json",
         *[arg for name in TEST_BINARIES if name != "process_orchestrator"
           for arg in ("--test", name)]],
        # Only this comparison needs the engine's debug-only legacy reference.
        # Keep optimized code and pinned app policy; do not enable policy overrides.
        ["cargo", "test", "--release", "--locked", "-p", PACKAGE,
         *[arg for name in LEGACY_CONTROL_PACKAGES
           for arg in ("--config", f"profile.release.package.{name}.debug-assertions=true")],
         "--no-run", "--message-format=json", "--test", "process_orchestrator"],
    ]


def build_profiles():
    return {
        "default_debug_assertions": False,
        "legacy_control": {
            "executable": "process_orchestrator",
            "debug_assertion_packages": list(LEGACY_CONTROL_PACKAGES),
            "purpose": "legacy retained-engine reference; app runtime uses pinned production policy",
        },
    }


def build(root, env):
    executables = {}
    selected_targets = (
        {"cgka-conformance-campaign", "cgka-conformance-node"},
        set(TEST_BINARIES) - {"process_orchestrator"},
        {"process_orchestrator"},
    )
    for index, command in enumerate(build_commands()):
        directory = root / f"build-{index}"
        directory.mkdir(mode=0o700)
        write_json(directory / "command.json", command)
        result = run_command(command, directory, env, 1800)
        if result["exit_code"] != 0:
            raise RuntimeError(f"build failed: {directory / 'output.log'}")
        for line in (directory / "output.log").read_text().splitlines():
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("reason") != "compiler-artifact" or not message.get("executable"):
                if (message.get("reason") == "compiler-artifact"
                        and "test-policy-overrides" in message.get("features", [])):
                    raise RuntimeError("production campaign build enabled test-policy-overrides")
                continue
            name = message["target"]["name"]
            # Cargo may also build incidental bin targets for integration tests.
            # Never let the compatibility build replace a production executable.
            if name in selected_targets[index]:
                source = Path(message["executable"])
                destination = root / "bin" / name
                shutil.copyfile(source, destination)
                destination.chmod(0o700)
                executables[name] = str(destination)
    required = set(TEST_BINARIES) | {"cgka-conformance-campaign", "cgka-conformance-node"}
    if set(executables) != required:
        raise RuntimeError(f"missing build artifacts: {required - set(executables)}")
    return executables


def test_names(executable, env):
    output = subprocess.check_output([executable, "--list", "--format=terse"],
                                     cwd=REPO, env=env, text=True, timeout=60)
    names = [line.removesuffix(": test") for line in output.splitlines() if line.endswith(": test")]
    if not names:
        raise RuntimeError(f"no tests discovered in {executable}")
    return names


def make_plan(args, executables, inventory):
    tasks = []
    for iteration in range(args.rounds):
        for family, (count, timeout) in FAMILIES.items():
            for seed in (args.seeds[:1] if args.mode == "canary" else args.seeds):
                cases = 1 if args.mode == "canary" else count
                tasks.append({"id": f"round-{iteration}/{family.replace('/', '-')}-seed-{seed}",
                              "kind": "generated", "family": family, "seed": seed,
                              "cases": cases, "case_timeout": timeout,
                              "timeout": cases * timeout + 120})
        for binary, names in inventory.items():
            for name in names:
                if binary == "process_orchestrator" and name not in APP_ROUTE_TESTS:
                    continue
                if args.mode == "canary" and name not in CANARY_TESTS:
                    continue
                tasks.append({"id": f"round-{iteration}/{binary}/{name}",
                              "kind": "test", "binary": binary, "test": name,
                              "diagnostic": name == RACE_DIAGNOSTIC, "timeout": 1200})
    for task in tasks:
        if task["kind"] == "test":
            task["command"] = [executables[task["binary"]], task["test"], "--exact",
                               "--include-ignored", "--test-threads=1", "--nocapture"]
        else:
            task["command"] = [executables["cgka-conformance-campaign"], "--family", task["family"],
                               "--seed", str(task["seed"]), "--cases", str(task["cases"]),
                               "--storage", "file", "--case-timeout-secs", str(task["case_timeout"])]
    return tasks


def inspect_generated(task, root):
    paths = list((root / "cases").glob("process-campaign.v1.json"))
    # Use the maintained summary filename rather than accepting an arbitrary report.
    if len(paths) != 1:
        return ["missing or ambiguous process campaign summary"]
    summary = json.loads(paths[0].read_text())
    errors = []
    if (summary.get("family"), summary.get("seed"), summary.get("storage")) != (task["family"], task["seed"], "file"):
        errors.append("campaign provenance mismatch")
    cases = summary.get("cases", [])
    if [case.get("case_index") for case in cases] != list(range(task["cases"])):
        errors.append("missing or unexpected case indices")
    for case in cases:
        if (case.get("exit_code") != 0 or case.get("timed_out")
                or case.get("signal") or case.get("artifact_integrity_errors")):
            errors.append(f"case {case.get('case_index')} failed or lacks valid evidence")
    return errors


def execute(task, root, env):
    directory = root / task["id"]
    directory.mkdir(mode=0o700, parents=True)
    command = list(task["command"])
    scratch = directory / "tmp"
    scratch.mkdir(mode=0o700)
    task_env = dict(env, MDK_APP_JOURNEY_ARTIFACTS=str(directory / "journeys"), TMPDIR=str(scratch))
    task_env["MDK_APP_PROCESS_NODE"] = str(root / "bin" / "cgka-conformance-node")
    if task.get("binary") == "app_generated_variance":
        task_env["MDK_SCENARIO_NODE_BIN"] = str(root / "bin" / "cgka-conformance-node")
    if task["kind"] == "generated":
        command += ["--out", str(directory / "cases")]
    write_json(directory / "command.json", command)
    try:
        result = dict(task, **run_command(command, directory, task_env, task["timeout"]))
        result["command"] = command
    finally:
        # The parent/group has been reaped before removing participant stores.
        # Reports and journey evidence are siblings, never inside this scratch root.
        shutil.rmtree(scratch)
    errors = []
    if task["kind"] == "generated":
        try:
            errors = inspect_generated(task, directory)
        except (ValueError, OSError) as error:
            errors = [str(error)]
    elif result["exit_code"] == 0:
        # libtest returns success for a misspelled exact filter selecting zero tests.
        output = (directory / "output.log").read_text(errors="replace")
        if not re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", output):
            errors.append("exact test did not execute once")
    result["evidence_errors"] = errors
    result["passed"] = result["exit_code"] == 0 and not result["timed_out"] and not errors
    if task.get("diagnostic") and not result["passed"]:
        output = (directory / "output.log").read_text(errors="replace")
        missed_race = any(message in output for message in (
            "the forced losing invitation did not exercise explicit recipient recovery",
            "the strict recovery journey requires both competing mutations to be accepted",
        ))
        result["diagnostic_outcome"] = "inconclusive_race" if missed_race else "failed"
    write_json(directory / "result.json", result)
    return result


def execution_batches(tasks, jobs):
    # Match nextest's exclusive reservation for the timing-sensitive app route.
    def needs_exclusive(task):
        return (task.get("binary") == "process_orchestrator"
                or task.get("test") == "seeded_recovery_schedule_survives_real_process_kills")
    ordinary = [task for task in tasks if not needs_exclusive(task)]
    exclusive = [task for task in tasks if needs_exclusive(task)]
    return [(ordinary, jobs)] + [([task], 1) for task in exclusive]


def main(argv=None):
    args = parse_args(argv)
    if args.plan_only:
        print(json.dumps({"mode": args.mode, "seeds": args.seeds, "rounds": args.rounds,
                          "families": FAMILIES, "test_binaries": TEST_BINARIES,
                          "scope": "fresh app stacks per case; real local relay; production timing"}, indent=2))
        return 0
    os.umask(0o077)
    signal.signal(signal.SIGTERM, stop_campaign)
    signal.signal(signal.SIGINT, stop_campaign)
    root = args.out.resolve()
    before = source_state()
    if before["status"] and not args.allow_dirty:
        raise RuntimeError("dirty source: use --allow-dirty for explicitly recorded WIP validation")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    (root / "bin").mkdir(mode=0o700)
    (root / "source.patch").write_bytes(git("diff", "HEAD", "--binary"))
    write_json(root / "source.json", before)
    env = dict(os.environ, RUST_MIN_STACK="4194304", CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS="false",
               CARGO_INCREMENTAL="0")
    executables = build(root, env)
    after = source_state()
    if before != after:
        raise RuntimeError("source changed during build; this evidence root cannot be used")
    write_json(root / "build.json", {
        "executables_sha256": {name: digest(Path(path)) for name, path in executables.items()},
        "rustc": subprocess.check_output(["rustc", "--version", "--verbose"], text=True),
        "production_policy": True, **build_profiles(),
    })
    inventory = {name: test_names(executables[name], env) for name in TEST_BINARIES}
    selected = {name for names in inventory.values() for name in names}
    if not (CANARY_TESTS | APP_ROUTE_TESTS | {RACE_DIAGNOSTIC}) <= selected:
        raise RuntimeError("maintained campaign test selection drifted")
    phases = [("canary", make_plan(argparse.Namespace(**dict(vars(args), mode="canary", rounds=1)), executables, inventory))]
    if args.mode == "full":
        phases.append(("matrix", make_plan(args, executables, inventory)))
    elif args.rounds > 1:
        phases = [("canary", make_plan(args, executables, inventory))]
    tasks = []
    for phase, phase_tasks in phases:
        for task in phase_tasks:
            task["id"] = f"{phase}/{task['id']}"
            task["phase"] = phase
            tasks.append(task)
    write_json(root / "plan.json", tasks)
    results = []
    try:
        for _phase, phase_tasks in phases:
            for batch, jobs in execution_batches(phase_tasks, args.jobs):
                with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
                    futures = [pool.submit(execute, task, root, env) for task in batch]
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        results.append(result)
                        write_json(root / "summary.json", {"planned": len(tasks), "completed": len(results),
                                   "passed": all(row["passed"] for row in results) and len(results) == len(tasks),
                                   "results": results})
                        print(f"{'PASS' if result['passed'] else 'FAIL'} {result['id']}", flush=True)
            if any(not row["passed"] for row in results):
                break  # Preserve every canary result; never widen a failing canary.
    finally:
        write_json(root / "summary.json", {"planned": len(tasks), "completed": len(results),
                   "passed": len(results) == len(tasks) and all(row["passed"] for row in results),
                   "results": results})
    return 0 if len(results) == len(tasks) and all(row["passed"] for row in results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("app-stack campaign interrupted; partial evidence retained", file=sys.stderr)
        sys.exit(130)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"app-stack campaign: {error}", file=sys.stderr)
        sys.exit(1)
