#!/usr/bin/env python3
"""Exercise the Marmot plugin through a real Hermes source checkout.

The caller supplies a Hermes source tree and an MDK checkout. The test installs
from a pinned local Git revision through Hermes's public plugin command, enables
the plugin, discovers it through PluginManager, and verifies that only the
plugin subdirectory was installed.
"""

from __future__ import annotations

import argparse
import importlib
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


def main() -> int:
    args = _parse_args()
    hermes_source = args.hermes_source.resolve()
    mdk_source = args.mdk_source.resolve()
    if not (hermes_source / "hermes_cli" / "plugins_cmd.py").is_file():
        raise SystemExit(f"invalid Hermes source checkout: {hermes_source}")
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
        sys.path.insert(0, str(hermes_source))

        plugins_module = importlib.import_module("hermes_cli.plugins")
        plugins_cmd_module = importlib.import_module("hermes_cli.plugins_cmd")
        PluginManager = plugins_module.PluginManager
        cmd_install = plugins_cmd_module.cmd_install

        identifier = f"file://{mdk_source}#integrations/hermes/marmot"
        cmd_install(identifier, force=False, enable=True, ref=resolved_ref)

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

        manager.unload_all()

    print(
        "real-hermes plugin install/discovery passed "
        f"(hermes_source={hermes_source}, mdk_ref={resolved_ref})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
