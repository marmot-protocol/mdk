"""Pinned Hermes progress callback and executor context regression."""
import ast
import asyncio
import os
import threading
import types
import unittest
from pathlib import Path
from test_adapter import load_adapter_module, _DeliveryRoutingFakeClient
import sys


@unittest.skipUnless(os.getenv("HERMES_PRESENCE_CONTRACT") == "1", "requires pinned Hermes source")
class PresenceHostContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_host_authorization_gates_active_turn_retarget(self):
        from unittest.mock import AsyncMock, patch
        import gateway.run as host
        from gateway.platforms.base import BasePlatformAdapter
        from enum import Enum
        platform = Enum("PluginPlatform", {"MARMOT": "marmot"}).MARMOT
        runner = object.__new__(host.GatewayRunner)
        runner.config = types.SimpleNamespace(multiplex_profiles=False)
        runner.adapters = {}
        runner._pairing_store_for = lambda source: None
        module = load_adapter_module()
        adapter = module.MarmotPlatformAdapter(
            sys.modules["gateway.config"].PlatformConfig(extra={
                "account_id_hex": "11" * 32, "presence_reactions": True,
            }), client=_DeliveryRoutingFakeClient(),
        )
        self.addAsyncCleanup(adapter.disconnect)
        adapter._is_sender_authorized = types.MethodType(BasePlatformAdapter._is_sender_authorized, adapter)
        BasePlatformAdapter.set_authorization_check(adapter, runner._make_adapter_auth_check(platform))
        adapter._should_run_turn = AsyncMock(return_value=True)
        adapter._maybe_handle_profile_name_onboarding = AsyncMock(return_value=False)
        group, original, allowed = "22" * 16, "33" * 32, "44" * 32
        operations = []
        adapter._presence._enqueue = lambda *args: operations.append(args)
        await adapter.on_processing_start(module.MessageEvent(
            text="active", message_id=original, source=types.SimpleNamespace(chat_id=group)))
        before = len(operations)
        with patch.dict(os.environ, {"GATEWAY_ALLOWED_USERS": allowed,
                "GATEWAY_ALLOW_ALL_USERS": "false", "MARMOT_ALLOWED_USERS": "",
                "MARMOT_ALLOW_ALL_USERS": "false"}), patch.dict(sys.modules, {"gateway.run": host}):
            for sender, target in [("55" * 32, "66" * 32), (allowed, "77" * 32)]:
                await adapter._dispatch_inbound_message({
                    "group_id_hex": group, "message_id_hex": target,
                    "sender_account_id_hex": sender, "text": "activated",
                })
                if sender != allowed:
                    self.assertEqual(adapter._presence.groups[group].target, original)
                    self.assertEqual(len(operations), before)
                else:
                    self.assertEqual(adapter._presence.groups[group].target, target)
                    self.assertGreater(len(operations), before)

    async def test_late_host_tool_callback_keeps_originating_turn(self):
        import gateway.run as host
        module = load_adapter_module()
        adapter = module.MarmotPlatformAdapter(
            sys.modules["gateway.config"].PlatformConfig(extra={
                "account_id_hex": "11" * 32, "presence_reactions": True,
            }), client=_DeliveryRoutingFakeClient(),
        )
        self.addAsyncCleanup(adapter.disconnect)
        group = "22" * 16
        old = module.MessageEvent(text="old", message_id="33" * 32,
                                  source=types.SimpleNamespace(chat_id=group))
        new = module.MessageEvent(text="new", message_id="44" * 32, source=old.source)
        # No transport assertions here: existing socket tests cover reaction IO.
        adapter._presence._enqueue = lambda *args: None
        tree = ast.parse(Path(host.__file__).read_text())
        callback = next(n for n in ast.walk(tree)
                        if isinstance(n, ast.FunctionDef) and n.name == "progress_callback"
                        and any(isinstance(x, ast.Name) and x.id == "_live_status_adapter"
                                for x in ast.walk(n)))
        env = dict(vars(host))
        env.update(_live_status_adapter=adapter, _live_status_mode="short",
                   source=old.source, _run_still_current=lambda: True,
                   log_queue=None, progress_queue=None)
        exec(compile(ast.Module(body=[callback], type_ignores=[]), host.__file__, "exec"), env)
        progress = env["progress_callback"]
        started, release = threading.Event(), threading.Event()
        runner = types.SimpleNamespace(_get_executor=lambda: None)
        def late_tools():
            started.set()
            release.wait(5)
            progress("tool.started", "terminal")
            progress("tool.completed", "terminal")
        await adapter.on_processing_start(old)
        task = asyncio.create_task(host.GatewayRunner._run_in_executor_with_context(runner, late_tools))
        try:
            await asyncio.to_thread(started.wait, 5)
            await adapter.on_processing_start(new)
            release.set()
            await task
            await asyncio.sleep(0)
            state = adapter._presence.groups[group]
            self.assertIs(state.owner, new)
            self.assertEqual(state.mode, "accepted")
            self.assertEqual(state.active_tools, 0)
            # Current-turn host callbacks still drive the indicator.
            await host.GatewayRunner._run_in_executor_with_context(
                runner, progress, "tool.started", "terminal")
            await asyncio.sleep(0)
            self.assertEqual(state.mode, "tool")
            await host.GatewayRunner._run_in_executor_with_context(
                runner, progress, "tool.completed", "terminal")
            await asyncio.sleep(0)
            self.assertEqual(state.mode, "thinking")
        finally:
            release.set()
            await task
