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
        BasePlatformAdapter = host.BasePlatformAdapter
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
        with patch.dict(os.environ, {"GATEWAY_ALLOWED_USERS": allowed,
                "GATEWAY_ALLOW_ALL_USERS": "false", "MARMOT_ALLOWED_USERS": "",
                "MARMOT_ALLOW_ALL_USERS": "false"}), patch.dict(sys.modules, {"gateway.run": host}):
            await adapter.on_processing_start(module.MessageEvent(
                text="active", message_id=original,
                source=types.SimpleNamespace(chat_id=group, user_id=allowed, chat_type="group")))
            before = len(operations)
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

    async def test_real_background_lifecycle_does_not_start_denied_presence(self):
        from unittest.mock import AsyncMock, patch
        from enum import Enum
        import gateway.run as host
        base = types.SimpleNamespace(BasePlatformAdapter=host.BasePlatformAdapter,
                                     MessageEvent=host.MessageEvent)
        PlatformConfig = host.PlatformConfig
        platform = Enum("PluginPlatform", {"MARMOT": "marmot"}).MARMOT
        # Preserve real host modules while the transport fixture loads its stubs.
        real_modules = {name: value for name, value in sys.modules.items()
                        if name == "gateway" or name.startswith("gateway.")}
        module = load_adapter_module()
        fixture = module.MarmotPlatformAdapter(
            sys.modules["gateway.config"].PlatformConfig(extra={
                "account_id_hex": "11" * 32, "presence_reactions": True,
                "approval_reactions": True,
            }), client=_DeliveryRoutingFakeClient())
        self.addAsyncCleanup(fixture.disconnect)
        # Only transport is substituted: handle_message, background task and
        # completion classification are the pinned BasePlatformAdapter methods.
        class LifecycleAdapter(base.BasePlatformAdapter):
            connect = AsyncMock()
            disconnect = AsyncMock()
            send = AsyncMock()
            get_chat_info = AsyncMock()

        adapter = LifecycleAdapter(PlatformConfig(extra={}, typing_indicator=False), platform)
        adapter.on_processing_start = fixture.on_processing_start
        adapter.on_processing_complete = fixture.on_processing_complete
        fixture._is_sender_authorized = adapter._is_sender_authorized
        runner = object.__new__(host.GatewayRunner)
        runner.config = types.SimpleNamespace(multiplex_profiles=False)
        runner.adapters = {platform: adapter}
        runner._pairing_store_for = lambda source: None
        runner._scale_to_zero_note_real_inbound = lambda: None
        runner.session_store = None
        adapter.set_authorization_check(runner._make_adapter_auth_check(platform))
        adapter._message_handler = AsyncMock(wraps=runner._handle_message)
        operations = []
        fixture._presence._enqueue = lambda *args: operations.append(args)
        allowed, group = "44" * 32, "22" * 16
        with patch.dict(sys.modules, real_modules), patch.dict(os.environ, {
                "GATEWAY_ALLOWED_USERS": allowed, "GATEWAY_ALLOW_ALL_USERS": "false",
                "MARMOT_ALLOWED_USERS": "", "MARMOT_ALLOW_ALL_USERS": "false"}):
            for existing, denied_sender in ((False, "55" * 32), (False, None),
                                             (True, "55" * 32), (True, None)):
                if existing:
                    active = base.MessageEvent(text="active", message_id="33" * 32,
                        source=adapter.build_source(chat_id=group, user_id=allowed, chat_type="group"))
                    await fixture.on_processing_start(active)
                before = list(operations)
                rejected = base.MessageEvent(text="activated", message_id="66" * 32,
                    source=adapter.build_source(chat_id=group, user_id=denied_sender, chat_type="group"))
                await adapter.handle_message(rejected)
                tasks = list(adapter._session_tasks.values())
                self.assertTrue(tasks, "real handle_message must spawn the host lifecycle")
                await asyncio.wait_for(asyncio.gather(*tasks), 5)
                adapter._message_handler.assert_awaited_with(rejected)
                self.assertEqual(operations, before)
                if existing:
                    self.assertIs(fixture._presence.groups[group].owner, active)
                else:
                    self.assertEqual(fixture._presence.groups, {})

    async def test_late_host_tool_callback_keeps_originating_turn(self):
        import gateway.run as host
        module = load_adapter_module()
        adapter = module.MarmotPlatformAdapter(
            sys.modules["gateway.config"].PlatformConfig(extra={
                "account_id_hex": "11" * 32, "presence_reactions": True,
            }), client=_DeliveryRoutingFakeClient(),
        )
        self.addAsyncCleanup(adapter.disconnect)
        adapter._is_sender_authorized = lambda user, chat_type, chat: True
        group = "22" * 16
        old = module.MessageEvent(text="old", message_id="33" * 32,
                                  source=types.SimpleNamespace(chat_id=group, user_id="44" * 32, chat_type="group"))
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
