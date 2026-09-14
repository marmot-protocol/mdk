#!/usr/bin/env python3
"""Pinned-Hermes progress-cleanup boundary probe.

Invoked by ``test_real_hermes_plugin.py`` after real plugin
install/enable/discovery. Exercises Hermes configuration resolution,
platform registration, ``GatewayRunner`` agent-turn code, and
``BasePlatformAdapter`` post-delivery callbacks. Model/tool execution is
replaced with a deterministic ``AIAgent`` fixture; ``wn-agent`` is a
recording fake control endpoint.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from unittest import mock


ACCOUNT_ID_HEX = "11" * 32
GROUP_ID_HEX = "22" * 32
SENDER_ACCOUNT_ID_HEX = "44" * 32
EXPLICIT_MESSAGE_ID = "aa" * 32
EXPLICIT_OPERATION_ID = "bb" * 32
PROTOCOL = "marmot.agent-control.v2"
REPO_ROOT = Path(__file__).resolve().parents[4]
HELPER_PATH = REPO_ROOT / "scripts" / "hermes_marmot_configure_gateway.py"
TOOL_PROGRESS_PREFIX = "marmot-tool-progress:"


def _load_helper():
    spec = importlib.util.spec_from_file_location(
        "hermes_marmot_configure_gateway_probe",
        HELPER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load configure-gateway helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _hex_id(index: int) -> str:
    return f"{index:02x}" * 32


class RecordingControlServer:
    def __init__(self, socket_path: Path, *, fail_first_operation: bool = False):
        self.socket_path = socket_path
        self.server: asyncio.AbstractServer | None = None
        self.requests: list[str] = []
        self.operation_sends = 0
        self.final_sends = 0
        self.wire_deletes = 0
        self.durable_operation_ids: list[str] = []
        self.delete_targets: list[str] = []
        self.fail_first_operation = fail_first_operation
        self._operation_failures = 0
        self._next_id = 16
        self.fail_final = False

    async def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        self.server = await asyncio.start_unix_server(self._handle, path=str(self.socket_path))

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    def _alloc(self) -> str:
        self._next_id += 1
        return _hex_id(self._next_id)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                raw = await asyncio.wait_for(reader.readline(), timeout=8.0)
                if not raw:
                    return
                request = json.loads(raw.decode("utf-8"))
                request_type = str(request.get("type") or "unknown")
                self.requests.append(request_type)
                response = self._response_for(request, request_type)
                writer.write(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
                await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            return
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _response_for(self, request: dict[str, Any], request_type: str) -> dict[str, Any]:
        request_id = request.get("id")
        if request_type == "send_agent_operation_event":
            if self.fail_first_operation and self._operation_failures == 0:
                self._operation_failures += 1
                return {
                    "marmot_agent_control": PROTOCOL,
                    "id": request_id,
                    "type": "error",
                    "code": "temporary_unavailable",
                    "retryable": True,
                    "message": "injected operation-send failure",
                }
            durable = self._alloc()
            self.operation_sends += 1
            self.durable_operation_ids.append(durable)
            return {
                "marmot_agent_control": PROTOCOL,
                "id": request_id,
                "type": "app_event_sent",
                "message_ids_hex": [durable],
            }
        if request_type == "send_final":
            if self.fail_final:
                return {
                    "marmot_agent_control": PROTOCOL,
                    "id": request_id,
                    "type": "error",
                    "code": "delivery_failed",
                    "message": "injected final-delivery failure",
                }
            self.final_sends += 1
            return {
                "marmot_agent_control": PROTOCOL,
                "id": request_id,
                "type": "final_sent",
                "message_ids_hex": [self._alloc()],
            }
        if request_type == "delete_message":
            self.wire_deletes += 1
            target = str(request.get("target_message_id_hex") or "")
            self.delete_targets.append(target)
            return {
                "marmot_agent_control": PROTOCOL,
                "id": request_id,
                "type": "app_event_sent",
                "message_ids_hex": [],
            }
        if request_type == "account_list":
            return {
                "marmot_agent_control": PROTOCOL,
                "id": request_id,
                "type": "account_list",
                "accounts": [{"account_id_hex": ACCOUNT_ID_HEX, "local_signing": True}],
            }
        if request_type in {"allowlist_list", "allowlist_add"}:
            return {
                "marmot_agent_control": PROTOCOL,
                "id": request_id,
                "type": "allowlist",
                "entries": [],
            }
        if request_type == "subscribe_inbound":
            return {"marmot_agent_control": PROTOCOL, "id": request_id, "type": "ack"}
        return {
            "marmot_agent_control": PROTOCOL,
            "id": request_id,
            "type": "ack",
        }


class DeterministicAIAgent:
    instances: list["DeterministicAIAgent"] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.tool_progress_callback = None
        self.is_interrupted = False
        self.fail_turn = bool(kwargs.pop("_fail_turn", False))
        self.tool_names = list(
            kwargs.pop("_tool_names", ("probe_alpha", "probe_beta", "probe_gamma"))
        )
        self.created = True
        DeterministicAIAgent.instances.append(self)

    def run_conversation(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        callback = self.tool_progress_callback
        if callback is not None:
            for name in self.tool_names:
                callback("tool.started", name, preview=f"{name}-preview", args={"q": name})
        time.sleep(2.2)
        if self.fail_turn:
            return {
                "final_response": "",
                "messages": [],
                "api_calls": 1,
                "tools": list(self.tool_names),
                "completed": False,
                "failed": True,
            }
        return {
            "final_response": "probe-final-ok",
            "messages": [],
            "api_calls": 1,
            "tools": list(self.tool_names),
            "completed": True,
        }


def _quiet_helper_kwargs(home: Path, *, tool_progress: str = "off") -> dict[str, Any]:
    return {
        "hermes_home": home,
        "platform": "marmot",
        "streaming_enabled": False,
        "streaming_transport": "off",
        "tool_progress": tool_progress,
        "interim_assistant_messages": False,
        "long_running_notifications": False,
        "busy_ack_detail": False,
        "agent_home": home / "marmot-agent",
        "socket_path": home / "marmot-agent" / "wn-agent.sock",
        "account_id_hex": ACCOUNT_ID_HEX,
        "backup": False,
    }


def _write_seed_with_global_cleanup(home: Path, helper) -> None:
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(
        "\n".join(
            [
                "model: probe-model",
                "display:",
                "  cleanup_progress: true",
                "  tool_progress: all",
                "  platforms:",
                "    telegram:",
                "      cleanup_progress: true",
                "      tool_progress: verbose",
                "",
            ]
        ),
        encoding="utf-8",
    )
    helper.configure_gateway_config(**_quiet_helper_kwargs(home))


def _assert_resolver_defaults(config: dict[str, Any]) -> None:
    from gateway.display_config import resolve_display_setting

    resolved = resolve_display_setting(config, "marmot", "cleanup_progress")
    if resolved is not False:
        raise AssertionError("installed Marmot cleanup_progress did not resolve false")
    if config.get("display", {}).get("cleanup_progress") is not True:
        raise AssertionError("global cleanup_progress was rewritten")
    telegram = (config.get("display", {}).get("platforms") or {}).get("telegram") or {}
    if telegram.get("cleanup_progress") is not True:
        raise AssertionError("other-platform cleanup_progress was rewritten")
    marmot = (config.get("display", {}).get("platforms") or {}).get("marmot") or {}
    if marmot.get("tool_progress") != "off":
        raise AssertionError("quiet tool_progress default was not preserved")
    if marmot.get("interim_assistant_messages") is not False:
        raise AssertionError("quiet interim-message default was not preserved")


def _wrap_delete(adapter, attempts: list[str]) -> None:
    original = adapter.delete_message

    async def tracked(chat_id, message_id, *args, **kwargs):
        attempts.append(str(message_id))
        return await original(chat_id, message_id, *args, **kwargs)

    adapter.delete_message = tracked


def _build_event(SessionSource, MessageEvent, Platform):
    source = SessionSource(
        platform=Platform("marmot"),
        chat_id=GROUP_ID_HEX,
        user_id=SENDER_ACCOUNT_ID_HEX,
        user_name="probe",
        chat_name="probe-group",
        chat_type="group",
    )
    return MessageEvent(
        text="probe inbound",
        source=source,
        message_id=EXPLICIT_MESSAGE_ID,
        internal=True,
    )


async def _drain_scheduled_work(timeout: float = 3.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        await asyncio.sleep(0)
        pending = [
            task
            for task in asyncio.all_tasks(loop)
            if task is not asyncio.current_task() and not task.done()
        ]
        if not pending:
            return
        await asyncio.sleep(0.05)


async def _run_gateway_turn(
    *,
    hermes_home: Path,
    adapter_module,
    grouping: str = "accumulate",
    tool_progress: str = "all",
    fail_first_operation: bool = False,
    fail_turn: bool = False,
    fail_final: bool = False,
    cleanup_override: bool | None = None,
    explicit_delete: bool = False,
) -> dict[str, Any]:
    helper = _load_helper()
    hermes_home.mkdir(parents=True, exist_ok=True)
    _write_seed_with_global_cleanup(hermes_home, helper)
    helper.configure_gateway_config(
        **_quiet_helper_kwargs(hermes_home, tool_progress=tool_progress)
    )
    config = helper.load_config(hermes_home / "config.yaml")
    marmot_display = config.setdefault("display", {}).setdefault("platforms", {}).setdefault("marmot", {})
    marmot_display["tool_progress_grouping"] = grouping
    if cleanup_override is True:
        marmot_display["cleanup_progress"] = True
    elif cleanup_override is False or cleanup_override is None:
        marmot_display["cleanup_progress"] = False
    (hermes_home / "config.yaml").write_text(helper.dump_config(config), encoding="utf-8")

    os.environ["HERMES_HOME"] = str(hermes_home)
    os.environ["HOME"] = str(hermes_home.parent)

    socket_path = hermes_home / "marmot-agent" / "wn-agent.sock"
    fake = RecordingControlServer(socket_path, fail_first_operation=fail_first_operation)
    fake.fail_final = fail_final
    await fake.start()

    from hermes_cli.plugins import discover_plugins
    from gateway.config import Platform, PlatformConfig, load_gateway_config
    from gateway.display_config import resolve_display_setting
    from gateway.platforms.base import MessageEvent
    import gateway.run as gateway_run
    from gateway.session import SessionSource
    import run_agent

    discover_plugins(force=True)
    written_config = helper.load_config(hermes_home / "config.yaml")
    original_load_gateway_config = gateway_run._load_gateway_config
    gateway_run._load_gateway_config = lambda: written_config

    loaded = load_gateway_config()
    resolved_cleanup = resolve_display_setting(
        written_config,
        "marmot",
        "cleanup_progress",
    )
    platform_config = PlatformConfig(
        enabled=True,
        extra={
            "socket_path": str(socket_path),
            "home": str(hermes_home / "marmot-agent"),
            "account_id_hex": ACCOUNT_ID_HEX,
            "profile_name_onboarding": False,
        },
    )
    adapter = adapter_module.MarmotPlatformAdapter(platform_config)
    adapter_module._remember_live_adapter(adapter)
    delete_attempts: list[str] = []
    _wrap_delete(adapter, delete_attempts)
    send_ids: list[str] = []
    original_send = adapter.send

    async def tracking_send(chat_id, content, *args, **kwargs):
        result = await original_send(chat_id, content, *args, **kwargs)
        if getattr(result, "message_id", None):
            send_ids.append(str(result.message_id))
        return result

    adapter.send = tracking_send

    DeterministicAIAgent.instances.clear()
    create_kwargs = {"_fail_turn": fail_turn}

    def agent_factory(*args, **kwargs):
        kwargs.update(create_kwargs)
        return DeterministicAIAgent(*args, **kwargs)

    runner = None
    finally_ran = False
    try:
        with mock.patch.object(run_agent, "AIAgent", agent_factory):
            runner = gateway_run.GatewayRunner(config=loaded)
            runner._resolve_session_agent_runtime = lambda **_kwargs: (
                "probe-model",
                {"provider": "local"},
            )
            runner.adapters[Platform("marmot")] = adapter
            adapter.set_message_handler(runner._handle_message)
            event = _build_event(SessionSource, MessageEvent, Platform)
            await asyncio.wait_for(adapter.handle_message(event), timeout=30.0)
            finally_ran = True
            await _drain_scheduled_work()
            if explicit_delete:
                deleted = json.loads(
                    await adapter_module._delete_marmot_message_tool(
                        {
                            "message_id": EXPLICIT_OPERATION_ID,
                            "target": f"marmot:{GROUP_ID_HEX}",
                        }
                    )
                )
                if not deleted.get("ok"):
                    raise AssertionError("explicit delete_marmot_message did not reach the adapter")
    finally:
        gateway_run._load_gateway_config = original_load_gateway_config
        if runner is not None:
            stop = getattr(runner, "stop", None)
            if callable(stop):
                try:
                    result = stop()
                    if asyncio.iscoroutine(result):
                        await asyncio.wait_for(result, timeout=2.0)
                except Exception:
                    pass
        await fake.close()

    return {
        "resolved_cleanup": bool(resolved_cleanup),
        "operation_sends": fake.operation_sends,
        "final_sends": fake.final_sends,
        "wire_deletes": fake.wire_deletes,
        "delete_targets": list(fake.delete_targets),
        "durable_operation_ids": list(fake.durable_operation_ids),
        "logical_send_ids": list(send_ids),
        "delete_attempts": list(delete_attempts),
        "request_types": list(fake.requests),
        "agent_constructed": bool(DeterministicAIAgent.instances),
        "finally_ran": finally_ran,
    }


def _assert_no_automatic_deletes(result: dict[str, Any], *, label: str) -> None:
    if result["wire_deletes"]:
        raise AssertionError(f"{label}: automatic wire deletes were issued")
    if any(target in result["durable_operation_ids"] for target in result["delete_targets"]):
        raise AssertionError(f"{label}: a kind-1202 durable id was targeted")
    if any(target.startswith(TOOL_PROGRESS_PREFIX) for target in result["delete_targets"]):
        raise AssertionError(f"{label}: a synthetic progress handle reached the wire")


async def _run_scenarios(adapter_module, hermes_home: Path) -> dict[str, Any]:
    helper = _load_helper()
    defaults_home = hermes_home / "defaults"
    _write_seed_with_global_cleanup(defaults_home, helper)
    defaults_config = helper.load_config(defaults_home / "config.yaml")
    _assert_resolver_defaults(defaults_config)

    accumulate = await _run_gateway_turn(
        hermes_home=hermes_home / "accumulate",
        adapter_module=adapter_module,
        grouping="accumulate",
    )
    if accumulate["operation_sends"] < 1:
        raise AssertionError("accumulate turn sent no kind-1202 operation events")
    if not accumulate["logical_send_ids"]:
        raise AssertionError("accumulate turn produced no SendResult handles")
    if not accumulate["durable_operation_ids"]:
        raise AssertionError("accumulate turn produced no durable event ids")
    if not accumulate["finally_ran"]:
        raise AssertionError("accumulate turn did not reach the host delivery boundary")
    _assert_no_automatic_deletes(accumulate, label="accumulate")

    separate = await _run_gateway_turn(
        hermes_home=hermes_home / "separate",
        adapter_module=adapter_module,
        grouping="separate",
    )
    if separate["operation_sends"] < 2:
        raise AssertionError(
            "separate grouping did not emit multiple tool-operation sends "
            f"(operations={separate['operation_sends']} logical={len(separate['logical_send_ids'])})"
        )
    _assert_no_automatic_deletes(separate, label="separate")

    control = await _run_gateway_turn(
        hermes_home=hermes_home / "control",
        adapter_module=adapter_module,
        grouping="separate",
        cleanup_override=True,
    )
    if not control["delete_attempts"]:
        raise AssertionError("positive-control cleanup never reached adapter.delete_message")
    if control["wire_deletes"]:
        raise AssertionError("positive-control cleanup sent synthetic handles on the wire")
    if not any(handle.startswith(TOOL_PROGRESS_PREFIX) for handle in control["delete_attempts"]):
        raise AssertionError("positive-control cleanup did not target returned logical ids")

    failed_turn = await _run_gateway_turn(
        hermes_home=hermes_home / "failed-turn",
        adapter_module=adapter_module,
        fail_turn=True,
    )
    if not failed_turn["finally_ran"]:
        raise AssertionError("failed-turn case did not observe the host callback boundary")
    _assert_no_automatic_deletes(failed_turn, label="failed-turn")

    failed_final = await _run_gateway_turn(
        hermes_home=hermes_home / "failed-final",
        adapter_module=adapter_module,
        fail_final=True,
    )
    if failed_final["operation_sends"] < 1:
        raise AssertionError("failed-final case lost acknowledged progress")
    _assert_no_automatic_deletes(failed_final, label="failed-final")

    retry = await _run_gateway_turn(
        hermes_home=hermes_home / "retry",
        adapter_module=adapter_module,
        fail_first_operation=True,
    )
    if retry["operation_sends"] < 1:
        raise AssertionError("partial-send retry did not accept a later operation event")
    _assert_no_automatic_deletes(retry, label="retry")

    restart_home = hermes_home / "restart"
    restart = await _run_gateway_turn(
        hermes_home=restart_home,
        adapter_module=adapter_module,
    )
    helper.configure_gateway_config(**_quiet_helper_kwargs(restart_home, tool_progress="all"))
    persisted = helper.load_config(restart_home / "config.yaml")
    from gateway.display_config import resolve_display_setting

    if resolve_display_setting(persisted, "marmot", "cleanup_progress") is not False:
        raise AssertionError("reconfigured persisted cleanup_progress did not remain false")
    fresh = adapter_module.MarmotPlatformAdapter(
        type("Cfg", (), {"enabled": True, "extra": persisted["platforms"]["marmot"]["extra"]})()
    )
    if getattr(fresh, "_tool_progress_events", None):
        if len(fresh._tool_progress_events) != 0:
            raise AssertionError("fresh adapter reconstructed in-memory synthetic cleanup targets")
    _assert_no_automatic_deletes(restart, label="restart")

    explicit = await _run_gateway_turn(
        hermes_home=hermes_home / "explicit",
        adapter_module=adapter_module,
        explicit_delete=True,
    )
    if explicit["wire_deletes"] != 1:
        raise AssertionError("explicit delete did not issue exactly one control delete")
    if explicit["delete_targets"] != [EXPLICIT_OPERATION_ID]:
        raise AssertionError("explicit delete targeted an unexpected message")

    return {
        "defaults_resolved_false": True,
        "accumulate_operations": accumulate["operation_sends"],
        "separate_operations": separate["operation_sends"],
        "control_delete_attempts": len(control["delete_attempts"]),
        "failed_turn_operations": failed_turn["operation_sends"],
        "retry_operations": retry["operation_sends"],
        "explicit_deletes": explicit["wire_deletes"],
    }


def run(adapter_module, hermes_home: Path) -> dict[str, Any]:
    return asyncio.run(_run_scenarios(adapter_module, hermes_home))
