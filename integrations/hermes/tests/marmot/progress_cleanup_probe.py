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
import contextlib
import importlib
import importlib.util
import inspect
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, ClassVar
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
SCHEDULED_WORK_TIMEOUT_S = 8.0
PROGRESS_WAIT_TIMEOUT_S = 8.0
PROGRESS_QUIET_S = 2.0
UNIX_SOCKET_PATH_LIMIT = 100


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


def _operation_key(attempt: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(attempt.get("name") or ""),
        str(attempt.get("preview") or ""),
        str(attempt.get("status") or ""),
    )


class RecordingControlServer:
    def __init__(
        self,
        socket_path: Path,
        *,
        fail_operation_after: int | None = None,
    ):
        self.socket_path = socket_path
        self.server: asyncio.AbstractServer | None = None
        self.requests: list[str] = []
        self.operation_sends = 0
        self.final_sends = 0
        self.final_failures = 0
        self.wire_deletes = 0
        self.durable_operation_ids: list[str] = []
        self.delete_targets: list[str] = []
        self.operation_attempts: list[dict[str, Any]] = []
        self.fail_operation_after = fail_operation_after
        self._operation_seen = 0
        self._operation_failures = 0
        self._next_id = 16
        self.fail_final = False
        self._progress_event = threading.Event()
        self._state_lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None

    def start_sync(self) -> None:
        """Serve on a private thread so a host-loop turn cannot deadlock."""
        if self._thread is not None and self._thread.is_alive():
            raise AssertionError("recording control server is already running")
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        self._error = None
        self._ready.clear()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._thread_main,
            name="progress-cleanup-control",
            daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(timeout=5.0):
            self.close_sync()
            raise AssertionError("recording control server failed to start")
        if self._error is not None:
            error = self._error
            self.close_sync()
            raise AssertionError("recording control server failed to start") from error

    def close_sync(self) -> None:
        loop = self._loop
        thread = self._thread
        if loop is not None and thread is not None and thread.is_alive():
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=5.0)
        self._loop = None
        self._thread = None
        self.server = None
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    def _thread_main(self) -> None:
        loop = self._loop
        if loop is None:
            self._error = AssertionError("recording control server loop was not created")
            self._ready.set()
            return
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._bind())
        except BaseException as exc:
            self._error = exc
            self._ready.set()
            return
        self._ready.set()
        try:
            loop.run_forever()
            loop.run_until_complete(self._shutdown_server())
        finally:
            loop.close()

    async def _bind(self) -> None:
        self.server = await asyncio.start_unix_server(self._handle, path=str(self.socket_path))

    async def _shutdown_server(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def start(self) -> None:
        self.start_sync()

    async def close(self) -> None:
        self.close_sync()

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
                response = self._response_for(request, request_type)
                writer.write(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
                await writer.drain()
        except (
            asyncio.TimeoutError,
            asyncio.IncompleteReadError,
            ConnectionError,
            ValueError,
        ):
            return
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _response_for(self, request: dict[str, Any], request_type: str) -> dict[str, Any]:
        request_id = request.get("id")
        with self._state_lock:
            self.requests.append(request_type)
            if request_type == "send_agent_operation_event":
                self._operation_seen += 1
                identity = {
                    "name": str(request.get("name") or ""),
                    "preview": str(request.get("preview") or ""),
                    "status": str(request.get("status") or ""),
                }
                should_fail = (
                    self.fail_operation_after is not None
                    and self._operation_seen > self.fail_operation_after
                    and self._operation_failures == 0
                )
                if should_fail:
                    self._operation_failures += 1
                    self.operation_attempts.append({**identity, "outcome": "failed"})
                    self._progress_event.set()
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
                self.operation_attempts.append({**identity, "outcome": "accepted"})
                self._progress_event.set()
                return {
                    "marmot_agent_control": PROTOCOL,
                    "id": request_id,
                    "type": "app_event_sent",
                    "message_ids_hex": [durable],
                }
            if request_type == "send_final":
                if self.fail_final:
                    self.final_failures += 1
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

    def acknowledged_or_failed_operations(self) -> int:
        with self._state_lock:
            return self.operation_sends + self._operation_failures

    def wait_until_idle(
        self,
        *,
        min_operations: int,
        quiet_s: float = PROGRESS_QUIET_S,
        timeout: float = PROGRESS_WAIT_TIMEOUT_S,
    ) -> None:
        deadline = time.monotonic() + timeout
        last_count = -1
        last_change = time.monotonic()
        while True:
            count = self.acknowledged_or_failed_operations()
            now = time.monotonic()
            if count != last_count:
                last_count = count
                last_change = now
            if count >= min_operations and (now - last_change) >= quiet_s:
                return
            remaining = deadline - now
            if remaining <= 0:
                raise AssertionError("progress operations did not settle before timeout")
            self._progress_event.wait(timeout=min(0.05, remaining))
            self._progress_event.clear()


class DeterministicAIAgent:
    instances: list["DeterministicAIAgent"] = []
    progress_server: ClassVar[RecordingControlServer | None] = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.tool_progress_callback = None
        self.is_interrupted = False
        self.fail_turn = bool(kwargs.pop("_fail_turn", False))
        self.stagger_after_first = bool(kwargs.pop("_stagger_after_first", False))
        self.tool_names = list(
            kwargs.pop("_tool_names", ("probe_alpha", "probe_beta", "probe_gamma"))
        )
        self.last_result: dict[str, Any] | None = None
        self.created = True
        DeterministicAIAgent.instances.append(self)

    def _wait_progress(self, *, min_operations: int, quiet_s: float) -> None:
        server = type(self).progress_server
        if server is None:
            return
        server.wait_until_idle(min_operations=min_operations, quiet_s=quiet_s)

    def run_conversation(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        callback = self.tool_progress_callback
        if callback is not None:
            if self.stagger_after_first and len(self.tool_names) >= 2:
                first, *rest = self.tool_names
                callback("tool.started", first, preview=f"{first}-preview", args={"q": first})
                self._wait_progress(min_operations=1, quiet_s=PROGRESS_QUIET_S)
                for name in rest:
                    callback("tool.started", name, preview=f"{name}-preview", args={"q": name})
            else:
                for name in self.tool_names:
                    callback("tool.started", name, preview=f"{name}-preview", args={"q": name})
            self._wait_progress(min_operations=1, quiet_s=PROGRESS_QUIET_S)
        if self.fail_turn:
            self.last_result = {
                "final_response": "",
                "messages": [],
                "api_calls": 1,
                "tools": list(self.tool_names),
                "completed": False,
                "failed": True,
            }
            return self.last_result
        self.last_result = {
            "final_response": "probe-final-ok",
            "messages": [],
            "api_calls": 1,
            "tools": list(self.tool_names),
            "completed": True,
        }
        return self.last_result


def _restore_home_env(original_home: str | None, original_hermes_home: str | None) -> None:
    if original_home is None:
        os.environ.pop("HOME", None)
    else:
        os.environ["HOME"] = original_home
    if original_hermes_home is None:
        os.environ.pop("HERMES_HOME", None)
    else:
        os.environ["HERMES_HOME"] = original_hermes_home


@contextlib.contextmanager
def _preserve_home_env():
    original_home = os.environ.get("HOME")
    original_hermes_home = os.environ.get("HERMES_HOME")
    try:
        yield
    finally:
        _restore_home_env(original_home, original_hermes_home)


def _bind_home_env(hermes_home: Path) -> None:
    os.environ["HERMES_HOME"] = str(hermes_home)
    os.environ["HOME"] = str(hermes_home.parent)


def _registered_hermes_home() -> Path:
    raw = os.environ.get("HERMES_HOME")
    if not raw:
        raise AssertionError("progress cleanup probe requires HERMES_HOME from the real install/enable fixture")
    home = Path(raw)
    if not (home / "plugins" / "marmot" / "adapter.py").is_file():
        raise AssertionError("registered HERMES_HOME does not contain an installed Marmot plugin")
    return home


def _scenario_control_socket(label: str) -> Path:
    ident = "".join(ch for ch in label if ch.isalnum())[:8] or "turn"
    tmp = Path(os.environ.get("TMPDIR") or tempfile.gettempdir())
    path = tmp / f"pcp{os.getpid()}{ident}.sock"
    if len(os.fsencode(path)) >= UNIX_SOCKET_PATH_LIMIT:
        path = Path("/tmp") / f"pcp{os.getpid()}{ident}.sock"
    if len(os.fsencode(path)) >= UNIX_SOCKET_PATH_LIMIT:
        raise AssertionError("scenario control socket path exceeds the Unix socket limit")
    return path


def _apply_scenario_transport(platform_config, *, socket_path: Path, agent_home: Path):
    extra = dict(getattr(platform_config, "extra", {}) or {})
    extra["socket_path"] = str(socket_path)
    extra["home"] = str(agent_home)
    extra["account_id_hex"] = ACCOUNT_ID_HEX
    extra["profile_name_onboarding"] = False
    try:
        platform_config.extra = extra
    except AttributeError:
        from gateway.config import PlatformConfig

        return PlatformConfig(enabled=True, extra=extra)
    if hasattr(platform_config, "enabled"):
        try:
            platform_config.enabled = True
        except AttributeError:
            pass
    return platform_config


def _quiet_helper_kwargs(
    home: Path,
    *,
    tool_progress: str = "off",
    agent_home: Path | None = None,
    socket_path: Path | None = None,
) -> dict[str, Any]:
    agent = agent_home if agent_home is not None else home / "marmot-agent"
    socket = socket_path if socket_path is not None else agent / "wn-agent.sock"
    return {
        "hermes_home": home,
        "platform": "marmot",
        "streaming_enabled": False,
        "streaming_transport": "off",
        "tool_progress": tool_progress,
        "interim_assistant_messages": False,
        "long_running_notifications": False,
        "busy_ack_detail": False,
        "agent_home": agent,
        "socket_path": socket,
        "account_id_hex": ACCOUNT_ID_HEX,
        "backup": False,
    }


def _write_seed_with_global_cleanup(
    home: Path,
    helper,
    *,
    agent_home: Path | None = None,
) -> None:
    home.mkdir(parents=True, exist_ok=True)
    config_path = home / "config.yaml"
    existing: dict[str, Any] = {}
    if config_path.is_file():
        existing = helper.load_config(config_path)
    display = existing.setdefault("display", {})
    display["cleanup_progress"] = True
    display["tool_progress"] = "all"
    platforms = display.setdefault("platforms", {})
    telegram = platforms.setdefault("telegram", {})
    telegram["cleanup_progress"] = True
    telegram["tool_progress"] = "verbose"
    if not existing.get("model"):
        existing["model"] = "probe-model"
    config_path.write_text(helper.dump_config(existing), encoding="utf-8")
    helper.configure_gateway_config(
        **_quiet_helper_kwargs(home, agent_home=agent_home)
    )


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


def _safe_schedule_modules() -> list[Any]:
    modules: list[Any] = []
    import gateway.run as gateway_run

    modules.append(gateway_run)
    try:
        from agent import async_utils
    except ImportError:
        async_utils = None
    if async_utils is not None:
        modules.append(async_utils)
    try:
        import gateway.run_turn as gateway_run_turn
    except ImportError:
        gateway_run_turn = None
    if gateway_run_turn is not None:
        modules.append(gateway_run_turn)
    return modules


@contextlib.contextmanager
def _capture_safe_schedules(bucket: list[Any]):
    originals: dict[Any, Any] = {}
    impl = None
    for module in _safe_schedule_modules():
        current = getattr(module, "safe_schedule_threadsafe", None)
        if not callable(current):
            continue
        originals[module] = current
        if impl is None:
            impl = current
    if impl is None:
        raise AssertionError("host safe_schedule_threadsafe was not importable")

    def tracked(coro, loop, **kwargs):
        future = impl(coro, loop, **kwargs)
        if future is not None:
            bucket.append(future)
        return future

    for module in originals:
        setattr(module, "safe_schedule_threadsafe", tracked)
    try:
        yield
    finally:
        for module, original in originals.items():
            setattr(module, "safe_schedule_threadsafe", original)


def _wrap_post_delivery_boundary(
    adapter,
    *,
    callback_registrations: list[bool],
    callback_invocations: list[bool],
    pop_calls: list[bool],
) -> None:
    original_register = adapter.register_post_delivery_callback
    original_pop = adapter.pop_post_delivery_callback

    def tracking_register(session_key, callback, *args, **kwargs):
        callback_registrations.append(True)

        def wrapped_callback(*cb_args, **cb_kwargs):
            callback_invocations.append(True)
            return callback(*cb_args, **cb_kwargs)

        return original_register(session_key, wrapped_callback, *args, **kwargs)

    def tracking_pop(*args, **kwargs):
        popped = original_pop(*args, **kwargs)
        pop_calls.append(popped is not None)
        return popped

    adapter.register_post_delivery_callback = tracking_register
    adapter.pop_post_delivery_callback = tracking_pop


def _open_host_tasks(adapter) -> set[asyncio.Task]:
    tasks: set[asyncio.Task] = set()
    background = getattr(adapter, "_background_tasks", None)
    if background:
        tasks.update(task for task in background if isinstance(task, asyncio.Task) and not task.done())
    session_tasks = getattr(adapter, "_session_tasks", None)
    if isinstance(session_tasks, dict):
        tasks.update(
            task
            for task in session_tasks.values()
            if isinstance(task, asyncio.Task) and not task.done()
        )
    return tasks


async def _await_host_turn(adapter, *, timeout: float) -> None:
    tasks = _open_host_tasks(adapter)
    if tasks:
        _done, pending = await asyncio.wait(tasks, timeout=timeout)
        if pending:
            raise AssertionError("host turn task did not finish before timeout")
        return
    if any(inst.last_result is not None for inst in DeterministicAIAgent.instances):
        return
    raise AssertionError("handle_message returned without a host turn task")


async def _await_scheduled_work(scheduled: list[Any], *, timeout: float) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    seen = 0
    while seen < len(scheduled):
        awaitables: list[Any] = []
        for item in scheduled[seen:]:
            if asyncio.isfuture(item) or isinstance(item, asyncio.Task):
                awaitables.append(item)
            else:
                awaitables.append(asyncio.wrap_future(item, loop=loop))
        seen = len(scheduled)
        if not awaitables:
            continue
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise AssertionError("scheduled post-delivery cleanup work did not finish before timeout")
        done, pending = await asyncio.wait(awaitables, timeout=remaining)
        if pending:
            for task in pending:
                task.cancel()
            raise AssertionError("scheduled post-delivery cleanup work did not finish before timeout")
        for item in done:
            exc = item.exception() if hasattr(item, "exception") else None
            if exc is not None:
                raise AssertionError("scheduled post-delivery cleanup work failed")


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


def _registered_delete_handler():
    from tools.registry import registry

    entry = registry.get_entry("delete_marmot_message")
    handler = getattr(entry, "handler", None) if entry is not None else None
    if not callable(handler):
        raise AssertionError("delete_marmot_message was not registered with Hermes")
    return handler


def _create_registered_adapter(platform_config):
    from gateway.platform_registry import platform_registry

    adapter = platform_registry.create_adapter("marmot", platform_config)
    if adapter is None:
        raise AssertionError("registered platform factory returned no adapter")
    return adapter


def _assert_fresh_progress_state(adapter) -> None:
    if not hasattr(adapter, "_tool_progress_events"):
        raise AssertionError("fresh adapter is missing _tool_progress_events")
    events = adapter._tool_progress_events
    if events is None or len(events) != 0:
        raise AssertionError("fresh adapter reconstructed in-memory synthetic cleanup targets")


def _assert_missing_delete_registration_fails() -> None:
    from tools.registry import registry

    with mock.patch.object(registry, "get_entry", return_value=None):
        try:
            _registered_delete_handler()
        except AssertionError as exc:
            if "was not registered" not in str(exc):
                raise
        else:
            raise AssertionError("missing delete registry entry was accepted")


def _assert_missing_factory_fails() -> None:
    from gateway.platform_registry import platform_registry

    with mock.patch.object(platform_registry, "create_adapter", return_value=None):
        try:
            _create_registered_adapter(object())
        except AssertionError as exc:
            if "returned no adapter" not in str(exc):
                raise
        else:
            raise AssertionError("missing platform factory was accepted")


async def _dispatch_registered_delete() -> dict[str, Any]:
    handler = _registered_delete_handler()
    raw = handler(
        {
            "message_id": EXPLICIT_OPERATION_ID,
            "target": f"marmot:{GROUP_ID_HEX}",
        },
        task_id="progress-cleanup-explicit-delete",
        session_id="progress-cleanup-explicit-delete",
    )
    if inspect.isawaitable(raw):
        raw = await raw
    if not isinstance(raw, str):
        raise AssertionError("registered delete_marmot_message returned a non-string result")
    payload = json.loads(raw)
    if not payload.get("ok"):
        raise AssertionError("registered delete_marmot_message did not reach the adapter")
    return payload


def _fresh_persisted_gateway(hermes_home: Path, helper):
    from gateway.config import Platform, load_gateway_config
    from gateway.display_config import resolve_display_setting
    import gateway.run as gateway_run

    with _preserve_home_env():
        _bind_home_env(hermes_home)
        persisted = helper.load_config(hermes_home / "config.yaml")
        if resolve_display_setting(persisted, "marmot", "cleanup_progress") is not False:
            raise AssertionError("reconfigured persisted cleanup_progress did not remain false")
        loaded = load_gateway_config()
        platform_config = loaded.platforms.get(Platform("marmot"))
        if platform_config is None:
            raise AssertionError("persisted gateway load missing marmot platform")
        adapter = _create_registered_adapter(platform_config)
        runner = gateway_run.GatewayRunner(config=loaded)
        return persisted, runner, adapter


async def _run_gateway_turn(
    *,
    hermes_home: Path,
    adapter_module,
    grouping: str = "accumulate",
    tool_progress: str = "all",
    fail_operation_after: int | None = None,
    fail_turn: bool = False,
    fail_final: bool = False,
    cleanup_override: bool | None = None,
    explicit_delete: bool = False,
    stagger_after_first: bool = False,
) -> dict[str, Any]:
    helper = _load_helper()
    original_home = os.environ.get("HOME")
    original_hermes_home = os.environ.get("HERMES_HOME")
    try:
        return await _run_gateway_turn_body(
            hermes_home=hermes_home,
            adapter_module=adapter_module,
            helper=helper,
            grouping=grouping,
            tool_progress=tool_progress,
            fail_operation_after=fail_operation_after,
            fail_turn=fail_turn,
            fail_final=fail_final,
            cleanup_override=cleanup_override,
            explicit_delete=explicit_delete,
            stagger_after_first=stagger_after_first,
        )
    finally:
        _restore_home_env(original_home, original_hermes_home)


async def _run_gateway_turn_body(
    *,
    hermes_home: Path,
    adapter_module,
    helper,
    grouping: str,
    tool_progress: str,
    fail_operation_after: int | None,
    fail_turn: bool,
    fail_final: bool,
    cleanup_override: bool | None,
    explicit_delete: bool,
    stagger_after_first: bool,
) -> dict[str, Any]:
    registered_home = _registered_hermes_home()
    _bind_home_env(registered_home)
    hermes_home.mkdir(parents=True, exist_ok=True)
    agent_home = hermes_home / "marmot-agent"
    socket_path = _scenario_control_socket(hermes_home.name)
    _write_seed_with_global_cleanup(registered_home, helper, agent_home=agent_home)
    helper.configure_gateway_config(
        **_quiet_helper_kwargs(
            registered_home,
            tool_progress=tool_progress,
            agent_home=agent_home,
            socket_path=socket_path,
        )
    )
    config = helper.load_config(registered_home / "config.yaml")
    marmot_display = config.setdefault("display", {}).setdefault("platforms", {}).setdefault("marmot", {})
    marmot_display["tool_progress_grouping"] = grouping
    if cleanup_override is True:
        marmot_display["cleanup_progress"] = True
    (registered_home / "config.yaml").write_text(helper.dump_config(config), encoding="utf-8")

    fake = RecordingControlServer(socket_path, fail_operation_after=fail_operation_after)
    fake.fail_final = fail_final
    await fake.start()
    original_load_gateway_config = None
    gateway_run = None
    runner = None
    previous_progress_server = DeterministicAIAgent.progress_server
    DeterministicAIAgent.progress_server = fake
    try:
        from gateway.config import Platform, load_gateway_config
        from gateway.display_config import resolve_display_setting
        from gateway.platforms.base import MessageEvent
        import gateway.run as gateway_run
        from gateway.session import SessionSource
        import run_agent

        written_config = helper.load_config(registered_home / "config.yaml")
        original_load_gateway_config = gateway_run._load_gateway_config
        gateway_run._load_gateway_config = lambda: written_config

        loaded = load_gateway_config()
        resolved_cleanup = resolve_display_setting(
            written_config,
            "marmot",
            "cleanup_progress",
        )
        platform_config = loaded.platforms.get(Platform("marmot"))
        if platform_config is None:
            raise AssertionError("persisted gateway load missing marmot platform")
        platform_config = _apply_scenario_transport(
            platform_config,
            socket_path=socket_path,
            agent_home=agent_home,
        )
        adapter = _create_registered_adapter(platform_config)
        delete_attempts: list[str] = []
        _wrap_delete(adapter, delete_attempts)
        callback_registrations: list[bool] = []
        callback_invocations: list[bool] = []
        pop_calls: list[bool] = []
        scheduled: list[Any] = []
        _wrap_post_delivery_boundary(
            adapter,
            callback_registrations=callback_registrations,
            callback_invocations=callback_invocations,
            pop_calls=pop_calls,
        )
        send_ids: list[str] = []
        original_send = adapter.send

        async def tracking_send(chat_id, content, *args, **kwargs):
            result = await original_send(chat_id, content, *args, **kwargs)
            if getattr(result, "message_id", None):
                send_ids.append(str(result.message_id))
            return result

        adapter.send = tracking_send

        DeterministicAIAgent.instances.clear()
        create_kwargs = {
            "_fail_turn": fail_turn,
            "_stagger_after_first": stagger_after_first,
        }

        def agent_factory(*args, **kwargs):
            kwargs.update(create_kwargs)
            return DeterministicAIAgent(*args, **kwargs)

        delivery_boundary_observed = False
        scheduled_work_drained = False
        with mock.patch.object(run_agent, "AIAgent", agent_factory):
            runner = gateway_run.GatewayRunner(config=loaded)
            runner._resolve_session_agent_runtime = lambda **_kwargs: (
                "probe-model",
                {"provider": "local"},
            )
            runner.adapters[Platform("marmot")] = adapter
            adapter.set_message_handler(runner._handle_message)
            event = _build_event(SessionSource, MessageEvent, Platform)
            with _capture_safe_schedules(scheduled):
                await asyncio.wait_for(adapter.handle_message(event), timeout=30.0)
                await _await_host_turn(adapter, timeout=30.0)
                delivery_boundary_observed = bool(pop_calls)
                await _await_scheduled_work(scheduled, timeout=SCHEDULED_WORK_TIMEOUT_S)
                scheduled_work_drained = True
                if explicit_delete:
                    await _dispatch_registered_delete()
    finally:
        if gateway_run is not None and original_load_gateway_config is not None:
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
        DeterministicAIAgent.progress_server = previous_progress_server

    agent_results = [
        inst.last_result for inst in DeterministicAIAgent.instances if inst.last_result is not None
    ]
    agent_failed = any(bool(result.get("failed")) for result in agent_results)
    return {
        "resolved_cleanup": resolved_cleanup,
        "operation_sends": fake.operation_sends,
        "operation_failures": fake._operation_failures,
        "operation_attempts": list(fake.operation_attempts),
        "final_sends": fake.final_sends,
        "final_failures": fake.final_failures,
        "wire_deletes": fake.wire_deletes,
        "delete_targets": list(fake.delete_targets),
        "durable_operation_ids": list(fake.durable_operation_ids),
        "logical_send_ids": list(send_ids),
        "delete_attempts": list(delete_attempts),
        "request_types": list(fake.requests),
        "agent_constructed": bool(DeterministicAIAgent.instances),
        "agent_failed": agent_failed,
        "fail_turn_injected": fail_turn,
        "fail_final_injected": fail_final,
        "fail_operation_injected": fail_operation_after is not None,
        "delivery_boundary_observed": delivery_boundary_observed,
        "scheduled_work_drained": scheduled_work_drained,
        "cleanup_callback_registered": bool(callback_registrations),
        "cleanup_callback_invoked": bool(callback_invocations),
    }


def _assert_no_automatic_deletes(result: dict[str, Any], *, label: str) -> None:
    if result["delete_attempts"]:
        raise AssertionError(f"{label}: automatic adapter delete attempts occurred")
    if result["wire_deletes"]:
        raise AssertionError(f"{label}: automatic wire deletes were issued")
    if any(target in result["durable_operation_ids"] for target in result["delete_targets"]):
        raise AssertionError(f"{label}: a kind-1202 durable id was targeted")
    if any(target.startswith(TOOL_PROGRESS_PREFIX) for target in result["delete_targets"]):
        raise AssertionError(f"{label}: a synthetic progress handle reached the wire")


def _assert_retained_success(
    result: dict[str, Any],
    *,
    label: str,
    min_operations: int = 1,
) -> None:
    if result["resolved_cleanup"] is not False:
        raise AssertionError(f"{label}: installed cleanup did not resolve false")
    if result["operation_sends"] < min_operations:
        raise AssertionError(f"{label}: missing acknowledged operation events")
    if not result["logical_send_ids"]:
        raise AssertionError(f"{label}: produced no SendResult handles")
    if not result["durable_operation_ids"]:
        raise AssertionError(f"{label}: produced no durable event ids")
    if result["final_sends"] < 1:
        raise AssertionError(f"{label}: expected final delivery did not succeed")
    if not result["delivery_boundary_observed"]:
        raise AssertionError(f"{label}: host delivery-finally boundary was not observed")
    if not result["scheduled_work_drained"]:
        raise AssertionError(f"{label}: scheduled post-delivery work was not drained")
    _assert_no_automatic_deletes(result, label=label)


def _assert_failure_retention(
    result: dict[str, Any],
    *,
    label: str,
) -> None:
    if result["resolved_cleanup"] is not False:
        raise AssertionError(f"{label}: installed cleanup did not resolve false")
    if result["operation_sends"] < 1:
        raise AssertionError(f"{label}: lost acknowledged progress before the injected failure")
    if not result["delivery_boundary_observed"]:
        raise AssertionError(f"{label}: host delivery-finally boundary was not observed")
    if not result["scheduled_work_drained"]:
        raise AssertionError(f"{label}: scheduled post-delivery work was not drained")
    _assert_no_automatic_deletes(result, label=label)


def _assert_partial_retry(result: dict[str, Any]) -> None:
    _assert_failure_retention(result, label="retry")
    attempts = result["operation_attempts"]
    failed = [item for item in attempts if item["outcome"] == "failed"]
    if not result["fail_operation_injected"] or not failed:
        raise AssertionError("partial-send retry did not record an injected failure")
    first_fail_idx = next(
        index for index, item in enumerate(attempts) if item["outcome"] == "failed"
    )
    accepted_before = [
        item for item in attempts[:first_fail_idx] if item["outcome"] == "accepted"
    ]
    if not accepted_before:
        raise AssertionError("partial-send retry failed before any acknowledgement")
    failed_key = _operation_key(attempts[first_fail_idx])
    retried = [
        item
        for item in attempts[first_fail_idx + 1 :]
        if item["outcome"] == "accepted" and _operation_key(item) == failed_key
    ]
    if not retried:
        raise AssertionError("failed operation was not retried on the same logical surface")
    accepted_key = _operation_key(accepted_before[0])
    resent = [
        item
        for item in attempts[first_fail_idx:]
        if item["outcome"] == "accepted" and _operation_key(item) == accepted_key
    ]
    if resent:
        raise AssertionError("accepted operation was resent after the injected failure")
    progress_ids = [
        message_id
        for message_id in result["logical_send_ids"]
        if message_id.startswith(TOOL_PROGRESS_PREFIX)
    ]
    if len(set(progress_ids)) != 1:
        raise AssertionError("partial-send retry used more than one logical progress surface")


async def _run_scenarios(adapter_module, hermes_home: Path) -> dict[str, Any]:
    helper = _load_helper()
    registered_home = _registered_hermes_home()
    _bind_home_env(registered_home)
    defaults_home = hermes_home / "defaults"
    _write_seed_with_global_cleanup(defaults_home, helper)
    defaults_config = helper.load_config(defaults_home / "config.yaml")
    _assert_resolver_defaults(defaults_config)

    accumulate = await _run_gateway_turn(
        hermes_home=hermes_home / "accumulate",
        adapter_module=adapter_module,
        grouping="accumulate",
    )
    _assert_retained_success(accumulate, label="accumulate")

    separate = await _run_gateway_turn(
        hermes_home=hermes_home / "separate",
        adapter_module=adapter_module,
        grouping="separate",
    )
    _assert_retained_success(separate, label="separate", min_operations=2)

    control = await _run_gateway_turn(
        hermes_home=hermes_home / "control",
        adapter_module=adapter_module,
        grouping="separate",
        cleanup_override=True,
    )
    if control["resolved_cleanup"] is not True:
        raise AssertionError("positive-control cleanup did not resolve true")
    if not control["cleanup_callback_registered"]:
        raise AssertionError("positive-control never registered a post-delivery cleanup callback")
    if not control["cleanup_callback_invoked"]:
        raise AssertionError("positive-control cleanup callback was never invoked")
    if not control["delivery_boundary_observed"]:
        raise AssertionError("positive-control did not observe the host delivery-finally boundary")
    if not control["scheduled_work_drained"]:
        raise AssertionError("positive-control scheduled cleanup work was not drained")
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
    if not failed_turn["fail_turn_injected"] or not failed_turn["agent_failed"]:
        raise AssertionError("failed-turn host outcome was not a failed agent")
    _assert_failure_retention(failed_turn, label="failed-turn")

    failed_final = await _run_gateway_turn(
        hermes_home=hermes_home / "failed-final",
        adapter_module=adapter_module,
        fail_final=True,
    )
    if not failed_final["fail_final_injected"] or failed_final["final_failures"] < 1:
        raise AssertionError("failed-final did not observe a failed send_final")
    if failed_final["final_sends"]:
        raise AssertionError("failed-final unexpectedly acknowledged a final")
    if failed_final["agent_failed"]:
        raise AssertionError("failed-final unexpectedly marked the agent as failed")
    _assert_failure_retention(failed_final, label="failed-final")

    retry = await _run_gateway_turn(
        hermes_home=hermes_home / "retry",
        adapter_module=adapter_module,
        grouping="accumulate",
        fail_operation_after=1,
        stagger_after_first=True,
    )
    _assert_partial_retry(retry)

    restart_home = hermes_home / "restart"
    restart = await _run_gateway_turn(
        hermes_home=restart_home,
        adapter_module=adapter_module,
    )
    registered_home = _registered_hermes_home()
    helper.configure_gateway_config(
        **_quiet_helper_kwargs(
            registered_home,
            tool_progress="all",
            agent_home=restart_home / "marmot-agent",
        )
    )
    _persisted, fresh_runner, fresh = _fresh_persisted_gateway(registered_home, helper)
    try:
        _assert_fresh_progress_state(fresh)
    finally:
        stop = getattr(fresh_runner, "stop", None)
        if callable(stop):
            try:
                result = stop()
                if asyncio.iscoroutine(result):
                    await asyncio.wait_for(result, timeout=2.0)
            except Exception:
                pass
    _assert_retained_success(restart, label="restart")

    explicit = await _run_gateway_turn(
        hermes_home=hermes_home / "explicit",
        adapter_module=adapter_module,
        explicit_delete=True,
    )
    if explicit["resolved_cleanup"] is not False:
        raise AssertionError("explicit-delete installed cleanup did not resolve false")
    if explicit["wire_deletes"] != 1:
        raise AssertionError("explicit delete did not issue exactly one control delete")
    if explicit["delete_targets"] != [EXPLICIT_OPERATION_ID]:
        raise AssertionError("explicit delete targeted an unexpected message")
    extra_attempts = [
        handle
        for handle in explicit["delete_attempts"]
        if handle != EXPLICIT_OPERATION_ID
    ]
    if extra_attempts:
        raise AssertionError("explicit delete was accompanied by automatic cleanup attempts")

    _assert_missing_delete_registration_fails()
    _assert_missing_factory_fails()

    return {
        "defaults_resolved_false": True,
        "accumulate_operations": accumulate["operation_sends"],
        "separate_operations": separate["operation_sends"],
        "control_delete_attempts": len(control["delete_attempts"]),
        "failed_turn_operations": failed_turn["operation_sends"],
        "failed_final_operations": failed_final["operation_sends"],
        "retry_operations": retry["operation_sends"],
        "retry_failures": retry["operation_failures"],
        "explicit_deletes": explicit["wire_deletes"],
        "registration_fail_closed": True,
    }


def run(adapter_module, hermes_home: Path) -> dict[str, Any]:
    with _preserve_home_env():
        return asyncio.run(_run_scenarios(adapter_module, hermes_home))
