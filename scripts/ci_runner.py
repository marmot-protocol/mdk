#!/usr/bin/env python3
"""Disk preparation, verified nextest extraction and bounded CI evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import shutil
import subprocess
import sys
import tarfile
import time
import uuid


RESERVE_BYTES = 2 * 1024**3
TAIL_BYTES = 1024**2
# Only unused SDKs on disposable GitHub-hosted Linux runners. Keep Rust,
# Java, Docker and its images, system libraries, and all repository artifacts.
UNUSED_SDKS = (
    "/usr/local/lib/android", "/usr/share/dotnet", "/opt/ghc",
    "/opt/hostedtoolcache/CodeQL",
)


def reports() -> Path:
    root = Path(os.environ["RUNNER_TEMP"]) / "mdk-ci-reports"
    if root.is_symlink():
        raise ValueError("CI report directory must not be a symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def snapshot(stage: str) -> None:
    disk = shutil.disk_usage(Path.cwd())
    row = {"stage": stage, "time": time.time(), "total_bytes": disk.total,
           "used_bytes": disk.used, "free_bytes": disk.free}
    print(json.dumps(row), flush=True)
    with (reports() / "disk.jsonl").open("a") as output:
        output.write(json.dumps(row) + "\n")


def require_space(expanded_bytes: int) -> None:
    available = shutil.disk_usage(Path.cwd()).free
    required = expanded_bytes + RESERVE_BYTES
    if available < required:
        raise ValueError(f"insufficient runner disk: need {required} bytes including "
                         f"{RESERVE_BYTES} reserve, have {available}")


def prepare() -> None:
    if (sys.platform != "linux" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("MDK_RUNNER_ENVIRONMENT") != "github-hosted"):
        raise ValueError("SDK cleanup is only for GitHub-hosted Linux CI runners")
    snapshot("before-sdk-cleanup")
    subprocess.run(["sudo", "rm", "-rf", "--", *UNUSED_SDKS], check=True)
    snapshot("after-sdk-cleanup")
    require_space(0)


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def manifest_path(archive: Path) -> Path:
    return archive.with_name(archive.name + ".manifest.json")


def manifest(archive: Path) -> None:
    # Check every zstd frame, including any bytes after tar's end marker.
    subprocess.run(["zstd", "--test", "--quiet", str(archive)], check=True)
    expanded = 0
    with subprocess.Popen(["zstd", "--decompress", "--stdout", str(archive)],
                          stdout=subprocess.PIPE) as decoder:
        assert decoder.stdout is not None
        with tarfile.open(fileobj=decoder.stdout, mode="r|") as files:
            for member in files:
                expanded += 4096
                if member.isfile():
                    expanded += ((member.size + 4095) // 4096) * 4096
        # Drain tar padding so the decoder cannot block on a full pipe.
        while decoder.stdout.read(1024**2):
            pass
        if decoder.wait() != 0:
            raise ValueError("archive decompression failed")
    document = {"version": 1, "sha256": digest(archive),
                "archive_bytes": archive.stat().st_size, "expanded_bytes": expanded}
    manifest_path(archive).write_text(json.dumps(document) + "\n")
    print(json.dumps(document), flush=True)


def extract(archive: Path, child_umask: int = -1) -> None:
    snapshot("before-archive-verification")
    document = json.loads(manifest_path(archive).read_text())
    if (document.get("version") != 1
            or any(type(document.get(key)) is not int or document[key] < 0
                   for key in ("archive_bytes", "expanded_bytes"))
            or not re.fullmatch(r"[0-9a-f]{64}", str(document.get("sha256")))):
        raise ValueError("invalid nextest archive manifest")
    if archive.stat().st_size != document["archive_bytes"] or digest(archive) != document["sha256"]:
        raise ValueError("nextest archive checksum/size mismatch; refusing extraction")
    require_space(document["expanded_bytes"])
    shutil.copyfile(manifest_path(archive), reports() / manifest_path(archive).name)
    root = str(Path.cwd())
    subprocess.run(["cargo", "nextest", "list", "--archive-file", str(archive),
                    "--extract-to", root, "--workspace-remap", root,
                    "--list-type", "binaries-only"], stdout=subprocess.DEVNULL, check=True, umask=child_umask)
    # Tests reuse the extracted metadata and binaries, so no test holds the
    # multi-gigabyte compressed copy alongside its expanded contents.
    archive.unlink()
    snapshot("after-extraction-and-archive-removal")
    require_space(0)


def run(label: str, command: list[str], child_umask: int = -1) -> int:
    if not re.fullmatch(r"[a-z0-9-]+", label) or not command:
        raise ValueError("a CI label and command are required")
    name = label + "-" + uuid.uuid4().hex
    root = reports()
    if command[:3] == ["cargo", "nextest", "run"]:
        config = root / (name + ".toml")
        # Lower-priority tool config adds reporting without replacing the
        # repository's profiles, test groups, budgets, filters or retry policy.
        config.write_text("\n".join(
            f'[profile.{profile}.junit]\npath = "{name}.xml"\n'
            'store-success-output = false\nstore-failure-output = false\n'
            for profile in ("default", "ci", "precheck")))
        command = [*command[:3], "--tool-config-file", f"mdk-ci:{config}", *command[3:]]
    snapshot("before-" + label)
    tail = bytearray()
    child = None
    interrupted = 0
    evidence_error = False

    def evidence_failed(error):
        nonlocal evidence_error
        if not evidence_error:
            print(f"CI evidence write failed: {error}", file=sys.stderr, flush=True)
        evidence_error = True

    def persist_tail():
        if not evidence_error:
            try:
                (root / (name + ".log")).write_bytes(tail)
            except OSError as error:
                # Keep draining the pipe even if the runner fills up. Raising
                # inside Popen's context could deadlock while waiting for a
                # child blocked on that pipe, hiding its original failure.
                evidence_failed(error)

    def forward(signum, _frame):
        nonlocal interrupted
        interrupted = signum
        if child is not None:
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass

    previous = {sig: signal.signal(sig, forward) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        # A separate process group lets the wrapper forward cancellation once
        # to the command and its descendants, while staying alive to drain it.
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              bufsize=0, start_new_session=True, umask=child_umask) as child:
            if interrupted:
                forward(interrupted, None)
            assert child.stdout is not None
            dirty = False
            last_flush = 0.0
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while True:
                    if selector.select(timeout=1):
                        chunk = os.read(child.stdout.fileno(), 64 * 1024)
                        if not chunk:
                            break
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                        tail.extend(chunk)
                        del tail[:-TAIL_BYTES]
                        dirty = True
                    now = time.monotonic()
                    # Persist during quiet periods too, but at most once per
                    # second instead of rewriting a megabyte for every line.
                    if dirty and now - last_flush >= 1:
                        persist_tail()
                        dirty = False
                        last_flush = now
            if dirty:
                persist_tail()
            code = child.wait()
        try:
            for report in Path("target/nextest").glob(f"*/{name}.xml"):
                shutil.copyfile(report, root / (name + ".xml"))
            outcome = {"label": label, "exit_code": code}
            if interrupted:
                outcome["signal"] = interrupted
            (root / (name + ".json")).write_text(json.dumps(outcome) + "\n")
            snapshot("after-" + label)
        except OSError as error:
            evidence_failed(error)
        if interrupted:
            return 128 + interrupted
        return (code if code >= 0 else 128 - code) or int(evidence_error)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main() -> int:
    # Keep evidence private without changing Cargo/test filesystem semantics.
    child_umask = os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("prepare")
    for action in ("manifest", "extract"):
        commands.add_parser(action).add_argument("archive", type=Path)
    child = commands.add_parser("run")
    child.add_argument("label")
    child.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            prepare()
        elif args.action == "manifest":
            manifest(args.archive)
        elif args.action == "extract":
            extract(args.archive, child_umask)
        else:
            return run(args.label, args.command[1:] if args.command[:1] == ["--"] else args.command, child_umask)
        return 0
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print(f"CI infrastructure error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
