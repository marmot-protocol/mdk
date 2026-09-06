#!/usr/bin/env python3
"""Exercise the Marmot plugin through a real Hermes source checkout.

The caller supplies a Hermes source tree and an MDK checkout. The test installs
from a pinned local Git revision through Hermes's public plugin command, enables
the plugin, discovers it through PluginManager, and verifies that only the
plugin subdirectory was installed.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hermes-source", type=Path, required=True)
    parser.add_argument("--mdk-source", type=Path, required=True)
    parser.add_argument("--mdk-ref", required=True)
    return parser.parse_args()


async def _exercise_media_routes(adapter_module, platform_config, temp_root: Path) -> int:
    class FakeClient:
        def __init__(self) -> None:
            self.calls = []

        async def send_media(
            self,
            account_id_hex,
            group_id_hex,
            attachments,
            *,
            caption=None,
            idempotency_key=None,
            response_timeout=None,
        ):
            self.calls.append(
                (account_id_hex, group_id_hex, attachments, caption, idempotency_key)
            )
            return {"type": "final_sent", "message_ids_hex": ["33" * 32]}

    media_root = temp_root / "media"
    media_root.mkdir()
    sample = media_root / "sample.bin"
    sample.write_bytes(b"real-hermes-media")
    config = platform_config(
        enabled=True,
        extra={
            "account_id_hex": "11" * 32,
            "home": str(temp_root / "marmot-home"),
            "media_local_roots": [str(media_root)],
        },
    )
    fake = FakeClient()
    adapter = adapter_module.MarmotPlatformAdapter(config, client=fake)
    group_id = "22" * 32

    ordinary = await adapter.send_document(group_id, str(sample), caption="ordinary reply")
    explicit = await adapter.send_image_file(group_id, str(sample), caption="explicit send tool")
    if not ordinary.success or not explicit.success:
        raise AssertionError(
            f"real Hermes explicit/ordinary media adapter route failed: "
            f"ordinary={ordinary!r}, explicit={explicit!r}"
        )

    original_client = adapter_module.MarmotAgentControlClient
    adapter_module.MarmotAgentControlClient = lambda *_args, **_kwargs: fake
    try:
        for label in ("home-cron", "kanban-artifact"):
            sent = await adapter_module._standalone_send(
                config,
                group_id,
                label,
                media_files=[str(sample)],
                force_document=True,
            )
            if not sent:
                raise AssertionError(f"real Hermes standalone {label} media route failed")
    finally:
        adapter_module.MarmotAgentControlClient = original_client

    return len(fake.calls)


def _module_matches_path(module, expected: Path) -> bool:
    module_file = getattr(module, "__file__", None)
    return isinstance(module_file, str) and Path(module_file).resolve() == expected


def _legacy_plugin_repository(mdk_source: Path, mdk_ref: str, temp_root: Path) -> Path:
    """Build an immutable plugin-only source repository for older Hermes."""

    repository = temp_root / "marmot-plugin-source"
    repository.mkdir()
    for name in ("__init__.py", "adapter.py", "agent_control.py", "plugin.yaml", "README.md"):
        content = subprocess.check_output(
            ["git", "show", f"{mdk_ref}:integrations/hermes/marmot/{name}"],
            cwd=mdk_source,
        )
        (repository / name).write_bytes(content)
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=MDK compatibility test",
            "-c",
            "user.email=compatibility-test@example.invalid",
            "commit",
            "-q",
            "-m",
            "Pin Marmot plugin fixture",
        ],
        cwd=repository,
        check=True,
    )
    return repository


def main() -> int:
    args = _parse_args()
    hermes_source = args.hermes_source.resolve()
    mdk_source = args.mdk_source.resolve()
    source_checkout = (hermes_source / "hermes_cli" / "plugins_cmd.py").is_file()
    if not (mdk_source / "integrations/hermes/marmot/plugin.yaml").is_file():
        raise SystemExit(f"invalid MDK source checkout: {mdk_source}")

    resolved_ref = subprocess.run(
        ["git", "rev-parse", args.mdk_ref],
        cwd=mdk_source,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if len(resolved_ref) != 40:
        raise SystemExit("MDK ref must resolve to a full commit")

    with tempfile.TemporaryDirectory(prefix="mdk-hermes-plugin-test-") as temp:
        home = Path(temp)
        os.environ["HOME"] = str(home)
        os.environ["HERMES_HOME"] = str(home / ".hermes")
        if source_checkout:
            sys.path.insert(0, str(hermes_source))

        plugins_module = importlib.import_module("hermes_cli.plugins")
        plugins_cmd_module = importlib.import_module("hermes_cli.plugins_cmd")
        PluginManager = plugins_module.PluginManager
        cmd_install = plugins_cmd_module.cmd_install

        install_parameters = inspect.signature(cmd_install).parameters
        if "ref" in install_parameters:
            identifier = f"file://{mdk_source}#integrations/hermes/marmot"
            cmd_install(identifier, force=False, enable=True, ref=resolved_ref)
        else:
            # Hermes releases before immutable monorepo-subdirectory refs still
            # accept a normal source plugin repository. Materialize only the
            # exact MDK plugin files from resolved_ref so the compatibility
            # probe stays immutable without importing private Hermes helpers.
            legacy_source = _legacy_plugin_repository(mdk_source, resolved_ref, home)
            cmd_install(f"file://{legacy_source}", force=False, enable=True)

        plugin_dir = home / ".hermes" / "plugins" / "marmot"
        required = {
            "__init__.py",
            "adapter.py",
            "agent_control.py",
            "plugin.yaml",
            "README.md",
        }
        missing = sorted(name for name in required if not (plugin_dir / name).is_file())
        if missing:
            raise AssertionError(f"installed plugin is missing files: {missing}")
        if (plugin_dir / ".git").exists() or (plugin_dir / "Cargo.toml").exists():
            raise AssertionError("Hermes installed an MDK workspace instead of the plugin subdirectory")

        manager = PluginManager()
        manager.discover_and_load(force=True)
        if "marmot" not in manager._plugin_platform_names:
            raise AssertionError("real Hermes discovery did not register the Marmot platform")

        loaded = manager._plugins.get("marmot")
        if loaded is None or loaded.manifest.version != "0.1.0":
            raise AssertionError("real Hermes discovery did not load the expected manifest")

        adapter_file = (plugin_dir / "adapter.py").resolve()
        adapter_module = next(
            (
                module
                for module in tuple(sys.modules.values())
                if module is not None
                and _module_matches_path(module, adapter_file)
            ),
            None,
        )
        if adapter_module is None:
            raise AssertionError("real Hermes discovery did not load adapter.py")
        base_module = importlib.import_module("gateway.platforms.base")
        media_calls = asyncio.run(
            _exercise_media_routes(adapter_module, base_module.PlatformConfig, home)
        )

        print(
            "real-hermes plugin install/discovery/media passed "
            f"(hermes_source={hermes_source}, mdk_ref={resolved_ref}, media_calls={media_calls})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
