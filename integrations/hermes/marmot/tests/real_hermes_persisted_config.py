#!/usr/bin/env python3
"""Verify Marmot loads from persisted Hermes config with no MARMOT_* env.

Boundary exercised (Hermes gateway startup, without ``hermes gateway run``):

* ``hermes_cli.plugins.discover_plugins()`` registers the Marmot plugin
* ``gateway.config.load_gateway_config()`` loads ``config.yaml`` and runs
  ``_apply_env_overrides()``
* ``gateway.platform_registry.create_adapter()`` constructs the Marmot adapter

This deliberately does not start the long-lived gateway process, dial a model
provider, or connect to a real ``wn-agent`` account.
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path


def main() -> int:
    """Exercise persisted-config adapter construction in a fresh Hermes process."""
    expected_socket = Path(os.environ["HERMES_MARMOT_EXPECTED_SOCKET"])
    inherited_marmot_env = sorted(key for key in os.environ if key.startswith("MARMOT_"))
    if inherited_marmot_env:
        print(
            "fresh Hermes probe inherited MARMOT_* variables: "
            + ", ".join(inherited_marmot_env),
            file=sys.stderr,
        )
        return 1

    from hermes_cli.plugins import discover_plugins
    from gateway.config import Platform, load_gateway_config
    from gateway.platform_registry import platform_registry

    discover_plugins(force=True)
    if not platform_registry.is_registered("marmot"):
        print("marmot platform was not registered by Hermes plugin discovery", file=sys.stderr)
        return 1

    config = load_gateway_config()
    platform = Platform("marmot")
    platform_config = config.platforms.get(platform)
    if platform_config is None:
        print("marmot platform missing from loaded gateway config", file=sys.stderr)
        return 1
    if not platform_config.enabled:
        print("marmot platform is not enabled after load_gateway_config()", file=sys.stderr)
        return 1

    extra = platform_config.extra or {}
    socket_path = extra.get("socket_path") or extra.get("agent_socket") or extra.get("socket")
    if str(socket_path) != str(expected_socket):
        print("persisted socket configuration did not match the probe socket", file=sys.stderr)
        return 1

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(str(expected_socket))
    except OSError:
        print("configured wn-agent socket is not healthy", file=sys.stderr)
        return 1

    adapter = platform_registry.create_adapter("marmot", platform_config)
    if adapter is None:
        print("platform_registry.create_adapter('marmot', ...) returned None", file=sys.stderr)
        return 1

    adapter_socket = getattr(adapter, "socket_path", None)
    if str(adapter_socket) != str(expected_socket):
        print("adapter socket configuration did not match the probe socket", file=sys.stderr)
        return 1

    print("real hermes persisted-config probe ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
