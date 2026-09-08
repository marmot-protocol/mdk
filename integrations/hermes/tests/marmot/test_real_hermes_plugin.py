#!/usr/bin/env python3
"""Exercise the Marmot plugin through a real Hermes source checkout.

The caller supplies a Hermes source tree and an MDK checkout. The test installs
from a pinned local Git revision through Hermes's public plugin command, proves
the user plugin is discovered but disabled by default, enables it through the
public command, and verifies that only the plugin subdirectory was installed.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hermes-source", type=Path, required=True)
    parser.add_argument("--mdk-source", type=Path, required=True)
    parser.add_argument("--mdk-ref", required=True)
    parser.add_argument(
        "--expect-source-install-mode",
        choices=("monorepo", "plugin-only"),
    )
    return parser.parse_args()


async def _exercise_media_routes(adapter_module, platform_config, temp_root: Path):
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
                ("SendMedia", account_id_hex, group_id_hex, attachments, caption)
            )
            return {"type": "final_sent", "message_ids_hex": ["33" * 32]}

        async def send_final(
            self,
            account_id_hex,
            group_id_hex,
            text,
            *,
            idempotency_key=None,
            reply_to_message_id_hex=None,
            operation_events=None,
        ):
            self.calls.append(("SendFinal", account_id_hex, group_id_hex, text))
            return {"type": "final_sent", "message_id_hex": "44" * 32}

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
    routes = []

    before = len(fake.calls)
    ordinary = await adapter.send_document(group_id, str(sample), caption="ordinary reply")
    if not ordinary.success or len(fake.calls) != before + 1 or fake.calls[-1][0] != "SendMedia":
        raise AssertionError(f"real Hermes reply adapter hook failed: {ordinary!r}")
    routes.append("reply-adapter-hook")

    send_tool = importlib.import_module("tools.send_message_tool")
    gateway_run = None
    original_gateway_ref = None
    if hasattr(send_tool, "_live_adapter"):
        live_hook_name = "_live_adapter"
        original_live_hook = send_tool._live_adapter
    elif hasattr(send_tool, "_resolve_live_adapter"):
        live_hook_name = "_resolve_live_adapter"
        original_live_hook = send_tool._resolve_live_adapter
    else:
        live_hook_name = None
        original_live_hook = None
        gateway_run = importlib.import_module("gateway.run")
        original_gateway_ref = gateway_run._gateway_runner_ref
    original_client = adapter_module.MarmotAgentControlClient
    adapter_module.MarmotAgentControlClient = lambda *_args, **_kwargs: fake

    def set_live_adapter(value) -> None:
        if live_hook_name == "_live_adapter":
            setattr(send_tool, live_hook_name, lambda _platform: (None, value))
        elif live_hook_name == "_resolve_live_adapter":
            setattr(send_tool, live_hook_name, lambda _platform: value)
        elif value is None:
            gateway_run._gateway_runner_ref = lambda: None
        else:
            runner = type("Runner", (), {"adapters": {"marmot": value}})()
            gateway_run._gateway_runner_ref = lambda: runner

    try:
        set_live_adapter(adapter)
        before = len(fake.calls)
        explicit = await send_tool._send_via_adapter(
            "marmot",
            config,
            group_id,
            "explicit send tool",
            media_files=[(str(sample), False)],
            force_document=True,
        )
        if not explicit.get("success"):
            raise AssertionError(f"real Hermes send-tool dispatch failed: {explicit!r}")
        live_calls = fake.calls[before:]
        if callable(getattr(send_tool, "_send_live_adapter_media", None)):
            media_calls = [call for call in live_calls if call[0] == "SendMedia"]
            if len(media_calls) != 1:
                raise AssertionError(f"real Hermes live media dispatcher bypassed SendMedia: {live_calls!r}")
            routes.append("send-tool-live")
        else:
            if any(call[0] == "SendMedia" for call in live_calls):
                raise AssertionError("legacy Hermes unexpectedly claimed live media dispatch")
            routes.append("send-tool-live:host-media-unsupported")

        set_live_adapter(None)
        before = len(fake.calls)
        standalone = await send_tool._send_via_adapter(
            "marmot",
            config,
            group_id,
            "standalone send tool",
            media_files=[(str(sample), False)],
            force_document=True,
        )
        standalone_calls = fake.calls[before:]
        if (
            not standalone.get("success")
            or len(standalone_calls) != 1
            or standalone_calls[0][0] != "SendMedia"
        ):
            raise AssertionError(
                f"real Hermes standalone dispatcher failed: result={standalone!r}, "
                f"calls={standalone_calls!r}"
            )
        routes.append("send-tool-standalone")

        try:
            scheduler_delivery = importlib.import_module("cron.scheduler_delivery")
        except ImportError:
            scheduler_delivery = None
        scheduler_send = getattr(scheduler_delivery, "_standalone_send", None)
        if callable(scheduler_send):
            target = type(
                "Target",
                (),
                {
                    "job": {"id": "real-hermes-probe"},
                    "where": f"marmot:{group_id}",
                    "platform": "marmot",
                    "pconfig": config,
                    "chat_id": group_id,
                    "thread_id": None,
                },
            )()
            before = len(fake.calls)
            cron_result, cron_error = await asyncio.to_thread(
                scheduler_send,
                target,
                "home cron",
                [(str(sample), False)],
            )
            cron_calls = fake.calls[before:]
            if (
                cron_error is not None
                or not isinstance(cron_result, dict)
                or not cron_result.get("success")
                or len(cron_calls) != 1
                or cron_calls[0][0] != "SendMedia"
            ):
                raise AssertionError(
                    f"real Hermes cron dispatch failed: result={cron_result!r}, "
                    f"error={cron_error!r}, calls={cron_calls!r}"
                )
            routes.append("cron")
        else:
            routes.append("cron:host-dispatcher-unavailable")
    finally:
        if live_hook_name is not None:
            setattr(send_tool, live_hook_name, original_live_hook)
        else:
            gateway_run._gateway_runner_ref = original_gateway_ref
        adapter_module.MarmotAgentControlClient = original_client

    try:
        kanban_module = importlib.import_module("gateway.kanban_watchers")
        mixin_class = getattr(kanban_module, "GatewayKanbanWatchersMixin")
    except (ImportError, AttributeError):
        routes.append("kanban:host-dispatcher-unavailable")
    else:
        before = len(fake.calls)
        errors = await mixin_class()._deliver_kanban_artifacts(
            adapter=adapter,
            chat_id=group_id,
            metadata={},
            event_payload={"artifacts": [str(sample)]},
            task=None,
        )
        kanban_calls = fake.calls[before:]
        if errors or len(kanban_calls) != 1 or kanban_calls[0][0] != "SendMedia":
            raise AssertionError(
                f"real Hermes Kanban dispatch failed: errors={errors!r}, calls={kanban_calls!r}"
            )
        routes.append("kanban")

    return {"connector_calls": len(fake.calls), "routes": routes}


def _exercise_settings_only_default_target(expected_group_id: str) -> None:
    send_tool = importlib.import_module("tools.send_message_tool")
    captured = {}

    async def fake_send(platform, pconfig, chat_id, text, **kwargs):
        captured.update(platform=platform.value, chat_id=chat_id, text=text)
        return {"success": True, "message_id": "default-target-probe"}

    prepare_platforms = getattr(send_tool, "prepare_send_message_platforms", None)
    if prepare_platforms is None:
        print(
            "skip: settings-only default target (Hermes host lacks plugin preparation hook)"
        )
        return

    with (
        mock.patch.object(send_tool, "prepare_send_message_platforms", return_value=None),
        mock.patch.object(send_tool, "_send_to_platform", side_effect=fake_send),
    ):
        result = json.loads(
            send_tool.send_message_tool(
                {"action": "send", "target": "marmot", "message": "settings-only home"}
            )
        )

    if not result.get("success") or captured.get("chat_id") != expected_group_id:
        raise AssertionError(
            "settings-only Marmot home did not resolve before adapter dispatch: "
            f"result={result!r}, captured={captured!r}"
        )


def _module_matches_path(module, expected: Path) -> bool:
    module_file = getattr(module, "__file__", None)
    return isinstance(module_file, str) and Path(module_file).resolve() == expected


def _pinned_source_checkout(mdk_source: Path, mdk_ref: str, temp_root: Path) -> Path:
    """Clone MDK locally and detach at the exact revision used by old Hermes."""

    checkout = temp_root / "mdk-plugin-source"
    subprocess.run(
        ["git", "clone", "-q", "--no-checkout", f"file://{mdk_source}", str(checkout)],
        check=True,
    )
    subprocess.run(
        ["git", "checkout", "-q", "--detach", mdk_ref],
        cwd=checkout,
        check=True,
    )
    installed_ref = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        text=True,
    ).strip()
    if installed_ref != mdk_ref:
        raise AssertionError(
            f"pinned MDK checkout resolved to {installed_ref}, expected {mdk_ref}"
        )
    return checkout


def _source_install_supports_subdirectories(plugins_cmd_module) -> bool:
    """Probe whether this Hermes source-install parser splits URL fragments."""

    resolver = getattr(plugins_cmd_module, "_resolve_git_url", None)
    if not callable(resolver):
        return False
    probe_url = "file:///tmp/mdk-source-probe#integrations/hermes/marmot"
    try:
        resolved = resolver(probe_url)
    except (TypeError, ValueError):
        return False
    return resolved == (
        "file:///tmp/mdk-source-probe",
        "integrations/hermes/marmot",
    )


def _plugin_only_repository(mdk_source: Path, mdk_ref: str, temp_root: Path) -> Path:
    """Build an exact-content plugin repository for pre-subdirectory Hermes."""

    repository = temp_root / "marmot-plugin-only-source"
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
        supports_subdirectories = _source_install_supports_subdirectories(
            plugins_cmd_module
        )
        if supports_subdirectories and "ref" in install_parameters:
            identifier = f"file://{mdk_source}#integrations/hermes/marmot"
            cmd_install(identifier, force=False, enable=False, ref=resolved_ref)
            source_install_mode = "monorepo"
        elif supports_subdirectories:
            # Hermes 0.19.0 supports local monorepo subdirectories but has no
            # --ref option. Exercise the documented portable path: detach a
            # local checkout at the exact MDK commit, then install its subdir.
            pinned_source = _pinned_source_checkout(mdk_source, resolved_ref, home)
            cmd_install(
                f"file://{pinned_source}#integrations/hermes/marmot",
                force=False,
                enable=False,
            )
            source_install_mode = "monorepo"
        else:
            # Some older candidate builds predate source subdirectories,
            # independently of whether they expose --ref. Avoid passing a URL
            # fragment through to git clone as a literal path.
            plugin_source = _plugin_only_repository(mdk_source, resolved_ref, home)
            cmd_install(f"file://{plugin_source}", force=False, enable=False)
            source_install_mode = "plugin-only"

        if (
            args.expect_source_install_mode is not None
            and source_install_mode != args.expect_source_install_mode
        ):
            raise AssertionError(
                "Hermes source install capability mismatch: "
                f"selected {source_install_mode}, expected {args.expect_source_install_mode}"
            )

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
        if (plugin_dir / "Cargo.toml").exists():
            raise AssertionError("Hermes installed an MDK workspace instead of the plugin subdirectory")

        manager = PluginManager()
        manager.discover_and_load(force=True)
        loaded = manager._plugins.get("marmot")
        if loaded is None or loaded.manifest.version != "0.1.0":
            raise AssertionError("real Hermes discovery did not find the expected manifest")
        if loaded.enabled:
            raise AssertionError("fresh user plugin install was unexpectedly enabled")
        if "marmot" in manager._plugin_platform_names:
            raise AssertionError("disabled Marmot plugin registered its platform")

        cmd_enable = plugins_cmd_module.cmd_enable
        enable_kwargs = {}
        if "allow_tool_override" in inspect.signature(cmd_enable).parameters:
            enable_kwargs["allow_tool_override"] = False
        cmd_enable("marmot", **enable_kwargs)
        manager.discover_and_load(force=True)

        loaded = manager._plugins.get("marmot")
        if loaded is None or not loaded.enabled:
            raise AssertionError("real Hermes enable operation did not activate the plugin")
        if "marmot" not in manager._plugin_platform_names:
            raise AssertionError("real Hermes discovery did not register the enabled Marmot platform")

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
        config_module = importlib.import_module("gateway.config")
        media_calls = asyncio.run(
            _exercise_media_routes(adapter_module, config_module.PlatformConfig, home)
        )

        settings_home = "22" * 32
        config_api = importlib.import_module("hermes_cli.config")
        raw_config = config_api.load_config()
        plugins = raw_config.setdefault("plugins", {})
        entries = plugins.setdefault("entries", {})
        marmot_entry = entries.setdefault("marmot", {})
        marmot_entry["settings"] = {
            "socket_path": str(home / "marmot-agent.sock"),
            "home_channel": settings_home,
        }
        save_kwargs = {}
        if "strip_defaults" in inspect.signature(config_api.save_config).parameters:
            save_kwargs["strip_defaults"] = False
        config_api.save_config(raw_config, **save_kwargs)
        manager.discover_and_load(force=True)
        _exercise_settings_only_default_target(settings_home)

        print(
            "real-hermes plugin install/discovery/media passed "
            f"(hermes_source={hermes_source}, mdk_ref={resolved_ref}, "
            f"source_install_mode={source_install_mode}, media_calls={media_calls})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
