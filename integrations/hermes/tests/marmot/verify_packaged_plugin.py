#!/usr/bin/env python3
"""Verify the release Hermes plugin archive is complete and importable."""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import types


BUNDLE_ROOT = "hermes-marmot-plugin"
EXPECTED_CONTENTS = (
    "plugin.yaml",
    "__init__.py",
    "adapter.py",
    "agent_control.py",
    "ambient_context.py",
    "inbound_spool.py",
    "configure_gateway.py",
    "README.md",
    "manifest.json",
)


def _install_fake_hermes_modules() -> None:
    gateway = types.ModuleType("gateway")
    gateway.__path__ = []
    platforms = types.ModuleType("gateway.platforms")
    platforms.__path__ = []
    config = types.ModuleType("gateway.config")
    base = types.ModuleType("gateway.platforms.base")

    class Platform:
        def __init__(self, value: str):
            self.value = value

    class PlatformConfig:
        pass

    class BasePlatformAdapter:
        pass

    class MessageEvent:
        pass

    class MessageType:
        TEXT = "text"

    class SendResult:
        pass

    setattr(config, "Platform", Platform)
    setattr(config, "PlatformConfig", PlatformConfig)
    setattr(base, "BasePlatformAdapter", BasePlatformAdapter)
    setattr(base, "MessageEvent", MessageEvent)
    setattr(base, "MessageType", MessageType)
    setattr(base, "SendResult", SendResult)
    sys.modules.update(
        {
            "gateway": gateway,
            "gateway.config": config,
            "gateway.platforms": platforms,
            "gateway.platforms.base": base,
        }
    )


def verify(archive: Path) -> None:
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        files: dict[str, tarfile.TarInfo] = {}
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise AssertionError(f"unsafe archive member: {member.name}")
            if member.isdir():
                continue
            if not member.isfile() or len(path.parts) != 2 or path.parts[0] != BUNDLE_ROOT:
                raise AssertionError(f"unexpected archive member: {member.name}")
            if path.name in files:
                raise AssertionError(f"duplicate archive member: {member.name}")
            files[path.name] = member

        manifest_member = files.get("manifest.json")
        if manifest_member is None:
            raise AssertionError("archive is missing manifest.json")
        manifest_file = bundle.extractfile(manifest_member)
        if manifest_file is None:
            raise AssertionError("cannot read manifest.json")
        manifest = json.load(manifest_file)
        declared = manifest.get("contents")
        if not isinstance(declared, list) or not all(isinstance(item, str) for item in declared):
            raise AssertionError("manifest contents must be a string array")
        if declared != list(EXPECTED_CONTENTS):
            raise AssertionError(
                f"manifest contents mismatch: expected {list(EXPECTED_CONTENTS)}, got {declared}"
            )
        if set(files) != set(EXPECTED_CONTENTS):
            raise AssertionError(
                f"archive contents mismatch: expected {sorted(EXPECTED_CONTENTS)}, got {sorted(files)}"
            )

        with tempfile.TemporaryDirectory(prefix="hermes-marmot-artifact-") as directory:
            package_dir = Path(directory) / "marmot"
            package_dir.mkdir()
            for name, member in files.items():
                source = bundle.extractfile(member)
                if source is None:
                    raise AssertionError(f"cannot read archive member: {member.name}")
                (package_dir / name).write_bytes(source.read())
            _install_fake_hermes_modules()
            sys.path.insert(0, directory)
            try:
                module = importlib.import_module("marmot.adapter")
            finally:
                sys.path.remove(directory)
            if not hasattr(module, "MarmotPlatformAdapter"):
                raise AssertionError("packaged adapter import did not define MarmotPlatformAdapter")
            ambient = sys.modules.get("marmot.ambient_context")
            ambient_file = getattr(ambient, "__file__", None)
            if not isinstance(ambient_file, str) or Path(ambient_file).resolve() != (
                package_dir / "ambient_context.py"
            ).resolve():
                raise AssertionError("packaged adapter did not import its bundled ambient_context.py")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    verify(args.archive)
    print(f"packaged Hermes plugin verified: {args.archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
