"""Deterministic presence tests through a fake agent-control daemon socket."""
import asyncio
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from test_adapter import load_adapter_module, wire_event


class FakeClock:
    def __init__(self):
        self.waits = asyncio.Queue()

    async def sleep(self, delay):
        future = asyncio.get_running_loop().create_future()
        self.waits.put_nowait((delay, future))
        await future

    async def next(self):
        return await asyncio.wait_for(self.waits.get(), 1)


class PresenceTests(unittest.IsolatedAsyncioTestCase):
    ACCOUNT = "11" * 32
    GROUP = "22" * 16
    MESSAGE = "33" * 32

    async def asyncSetUp(self):
        self.module = load_adapter_module()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.socket = str(Path(self.temp.name) / "daemon.sock")
        self.requests = []
        self.fail = False
        self.block = None
        self.arrived = asyncio.Event()
        self.connections = set()
        self.server = await asyncio.start_unix_server(self.serve, path=self.socket)
        self.addAsyncCleanup(self.stop_server)
        self.adapter = self.make_adapter(True)
        self.adapter._is_sender_authorized = lambda user, chat_type, chat: True
        self.addAsyncCleanup(self.adapter._presence.close)
        self.clock = FakeClock()
        self.adapter._presence.sleep = self.clock.sleep

    async def serve(self, reader, writer):
        self.connections.add(writer)
        try:
            request = json.loads(await reader.readline())
            self.requests.append(request)
            self.arrived.set()
            if self.block is not None:
                await self.block.wait()
            payload = ({"type": "error", "code": "unavailable", "message": "unavailable",
                        "retryable": True} if self.fail else
                       {"type": "app_event_sent", "message_ids_hex": ["ee" * 32]})
            writer.write((json.dumps({"marmot_agent_control": "marmot.agent-control.v2",
                                      "id": request["id"], **payload}) + "\n").encode())
            await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            self.connections.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def stop_server(self):
        if self.block is not None:
            self.block.set()
        self.server.close()
        await self.server.wait_closed()
        for writer in tuple(self.connections):
            writer.close()
        await asyncio.sleep(0)

    def make_adapter(self, enabled=None, emojis=None):
        extra = {"account_id_hex": self.ACCOUNT, "group_activation": "always"}
        if enabled is not None:
            extra["presence_reactions"] = enabled
        if emojis is not None:
            extra["presence_emojis"] = emojis
        return self.module.MarmotPlatformAdapter(
            sys.modules["gateway.config"].PlatformConfig(extra=extra),
            client=self.module.MarmotAgentControlClient(self.socket),
        )

    def event(self, message=None, group=None):
        return self.module.MessageEvent(
            text="work", message_id=message or self.MESSAGE,
            source=self.adapter.build_source(chat_id=group or self.GROUP, user_id="44" * 32),
        )

    async def flush(self):
        await asyncio.sleep(0)
        for state in self.adapter._presence.groups.values():
            await asyncio.wait_for(state.queue.join(), 2)
        await asyncio.sleep(0)

    def ops(self):
        return [(req["type"], req["target_message_id_hex"], req.get("emoji")) for req in self.requests
                if req["type"] in {"send_reaction", "remove_reaction"}]

    async def test_default_off_and_invalid_anchors_send_nothing(self):
        for enabled in [None, False, "true"]:
            adapter = self.make_adapter(enabled)
            event = self.event()
            await adapter.on_processing_start(event)
            adapter.set_status_text(self.GROUP, "tool")
            await adapter.on_processing_complete(event, "success")
            self.assertFalse(adapter.supports_status_text)
            self.assertEqual(adapter._presence.groups, {})
            await adapter._presence.close()
        await self.adapter.on_processing_start(self.event(message="synthetic-not-hex"))
        await asyncio.sleep(0)
        self.assertEqual(self.requests, [])

    async def test_lifecycle_mapping_and_idempotent_thinking(self):
        event = self.event()
        await self.adapter.on_processing_start(event)
        await self.flush()
        self.adapter.set_status_text(self.GROUP, None)
        await self.flush()
        self.adapter.set_status_text(self.GROUP, None)
        await self.flush()
        await self.adapter.on_processing_complete(event, "success")
        await self.flush()
        self.assertEqual(self.ops(), [
            ("send_reaction", self.MESSAGE, "👀"),
            ("remove_reaction", self.MESSAGE, "👀"),
            ("send_reaction", self.MESSAGE, "⏳"),
            ("remove_reaction", self.MESSAGE, "⏳"),
            ("send_reaction", self.MESSAGE, "✅"),
        ])
        await self.adapter.on_processing_complete(event, "failure")
        await self.flush()
        self.assertEqual(len(self.requests), 5)
        self.assertFalse(self.adapter._presence.tasks)

    async def test_fake_clock_backoff_reset_and_timer_cleanup(self):
        event = self.event()
        await self.adapter.on_processing_start(event)
        await self.flush()
        self.adapter.set_status_text(self.GROUP, "tool.started")
        for expected in [120, 240, 480, 600, 600]:
            delay, waiter = await self.clock.next()
            self.assertEqual(delay, expected)
            await self.flush()
            waiter.set_result(None)
        delay, old_waiter = await self.clock.next()
        self.assertEqual(delay, 600)
        self.adapter.set_status_text(self.GROUP, "another tool.started")
        delay, new_waiter = await self.clock.next()
        self.assertEqual(delay, 120)
        self.assertTrue(old_waiter.cancelled())
        self.adapter.set_status_text(self.GROUP, None)
        await self.flush()
        self.assertFalse(new_waiter.cancelled(), "one concurrent tool is still active")
        self.adapter.set_status_text(self.GROUP, None)
        await self.flush()
        self.assertTrue(new_waiter.cancelled())
        self.assertIsNone(self.adapter._presence.groups[self.GROUP].timer)
        adds = [emoji for op, _, emoji in self.ops() if op == "send_reaction"]
        self.assertEqual(adds[:6], ["👀", "🛠️", "🔨", "⚙️", "🧱", "🛠️"])
        self.assertEqual(adds[-1], "⏳")
        await self.adapter.on_processing_complete(event, "success")
        await self.flush()
        self.assertFalse(self.adapter._presence.tasks)

    async def test_retarget_mid_turn_but_complete_on_reply_anchor(self):
        event = self.event()
        await self.adapter.on_processing_start(event)
        await self.flush()
        self.adapter.set_status_text(self.GROUP, "running")
        await self.clock.next()
        await self.flush()
        newest = "55" * 32
        await self.adapter._handle_control_event(wire_event({
            "type": "inbound_message", "account_id_hex": self.ACCOUNT,
            "group_id_hex": self.GROUP, "message_id_hex": newest,
            "sender_account_id_hex": "44" * 32, "text": "more context",
        }))
        await self.adapter._inbound_queue.join()
        await self.flush()
        self.assertEqual(self.ops()[-2:], [("remove_reaction", self.MESSAGE, "🛠️"),
                                           ("send_reaction", newest, "🛠️")])
        await self.adapter.on_processing_complete(event, "success")
        await self.flush()
        self.assertEqual(self.ops()[-2:], [("remove_reaction", newest, "🛠️"),
                                           ("send_reaction", self.MESSAGE, "✅")])

    async def test_supersession_ignores_late_old_completion(self):
        old, new = self.event(), self.event(message="66" * 32)
        await self.adapter.on_processing_start(old)
        await self.flush()
        await self.adapter.on_processing_start(new)
        await self.flush()
        await self.adapter.on_processing_complete(old, "success")
        await self.flush()
        self.assertEqual(self.ops()[-2:], [("send_reaction", self.MESSAGE, "➡️"),
                                           ("send_reaction", "66" * 32, "👀")])
        await self.adapter.on_processing_complete(new, "failure")
        await self.flush()
        self.assertEqual(self.ops()[-1], ("send_reaction", "66" * 32, "❌"))
        self.assertNotIn(("remove_reaction", self.MESSAGE, "➡️"), self.ops())

    async def test_bounded_retries_never_block_or_fail_turn(self):
        self.fail = True
        with patch.object(self.module, "PRESENCE_RETRY_DELAYS", (0, 0, 0)):
            event = self.event()
            await asyncio.wait_for(self.adapter.on_processing_start(event), .1)
            await self.flush()
            self.assertEqual(len(self.requests), 3)
            await asyncio.wait_for(self.adapter.on_processing_complete(event, "failure"), .1)
            await self.flush()
            self.assertEqual(len(self.requests), 6)
            self.assertFalse(self.adapter._presence.tasks)

    async def test_disconnect_cancels_blocked_io_and_cycle(self):
        self.block = asyncio.Event()
        event = self.event()
        await self.adapter.on_processing_start(event)
        await self.arrived.wait()
        self.adapter.set_status_text(self.GROUP, "tool")
        _, timer = await self.clock.next()
        await asyncio.wait_for(self.adapter.disconnect(), 1)
        self.assertTrue(timer.cancelled())
        self.assertFalse(self.adapter._presence.tasks)
        self.assertFalse(self.adapter._presence.groups)
        self.adapter.set_status_text(self.GROUP, "late callback")
        self.assertFalse(self.adapter._presence.tasks)

    async def test_streamed_text_enters_thinking_without_tool_progress(self):
        event = self.event()
        await self.adapter.on_processing_start(event)
        await self.flush()
        stream_events = types.ModuleType("gateway.stream_events")
        stream_events.MessageChunk = type("MessageChunk", (), {})
        stream_events.MessageStop = type("MessageStop", (), {})
        stream_events.Commentary = type("Commentary", (), {})
        chunk = stream_events.MessageChunk()
        chunk.text = "answer"
        deltas = []
        sink = types.SimpleNamespace(chat_id=self.GROUP, on_delta=deltas.append)
        with patch.dict(sys.modules, {"gateway.stream_events": stream_events}):
            self.adapter.render_message_event(chunk, sink)
        await self.flush()
        self.assertEqual(deltas, ["answer"])
        self.assertEqual(self.ops()[-1], ("send_reaction", self.MESSAGE, "⏳"))

    async def test_configuration_and_group_bound(self):
        custom = self.make_adapter(True, {"thinking": "🤔", "construction": ["🔧", "🔩"],
                                          "failed": "invalid\nemoji"})
        self.assertEqual(custom._presence.emojis["thinking"], "🤔")
        self.assertEqual(custom._presence.construction, ("🔧", "🔩"))
        self.assertEqual(custom._presence.emojis["failed"], "❌")
        await custom._presence.close()
        with patch.object(self.module, "PRESENCE_MAX_GROUPS", 2):
            for group in ["aa", "bb", "cc"]:
                await self.adapter.on_processing_start(self.event(group=group))
            await self.flush()
            self.assertEqual(len(self.adapter._presence.groups), 2)
            self.assertEqual(len(self.requests), 2)



    async def test_unactivated_inbound_cannot_retarget(self):
        from unittest.mock import AsyncMock
        event = self.event()
        await self.adapter.on_processing_start(event)
        self.adapter._should_run_turn = AsyncMock(return_value=False)
        await self.adapter._handle_control_event(wire_event({
            "type": "inbound_message", "account_id_hex": self.ACCOUNT,
            "group_id_hex": self.GROUP, "message_id_hex": "66" * 32,
            "sender_account_id_hex": "44" * 32, "text": "ambient",
        }))
        await self.adapter._inbound_queue.join()
        self.assertEqual(self.adapter._presence.groups[self.GROUP].target, self.MESSAGE)
        await self.adapter.disconnect()

    async def test_queue_rejection_cannot_retarget(self):
        event = self.event()
        await self.adapter.on_processing_start(event)
        self.adapter._inbound_queue = self.module.KeyedAsyncQueue(max_depth_per_key=1)
        release = asyncio.Event()
        self.adapter._inbound_queue.enqueue(self.GROUP, release.wait)
        try:
            await self.adapter._handle_control_event(wire_event({
                "type": "inbound_message", "account_id_hex": self.ACCOUNT,
                "group_id_hex": self.GROUP, "message_id_hex": "66" * 32,
                "sender_account_id_hex": "44" * 32, "text": "shed",
            }))
            self.assertEqual(self.adapter._presence.groups[self.GROUP].target, self.MESSAGE)
        finally:
            release.set()
            await self.adapter.disconnect()

    async def test_start_requires_explicit_authorization_before_ownership(self):
        from unittest.mock import Mock
        original_owner = object()
        token = self.module._PRESENCE_OWNER.set(original_owner)
        self.addCleanup(self.module._PRESENCE_OWNER.reset, token)
        for decision in (False, None, 1, "true"):
            with self.subTest(decision=decision):
                self.adapter._is_sender_authorized = Mock(return_value=decision)
                event = self.event()
                await self.adapter.on_processing_start(event)
                await self.adapter.on_processing_complete(event, "success")
                await self.flush()
                self.assertEqual(self.ops(), [])
                self.assertEqual(self.adapter._presence.groups, {})
                self.assertIs(self.module._PRESENCE_OWNER.get(), original_owner)
        self.adapter._is_sender_authorized = lambda *args: True
        active = self.event()
        await self.adapter.on_processing_start(active)
        await self.flush()
        before = self.ops()
        for decision in (False, None):
            self.adapter._is_sender_authorized = lambda *args: decision
            rejected = self.event(message="66" * 32)
            await self.adapter.on_processing_start(rejected)
            await self.adapter.on_processing_complete(rejected, "success")
            await self.flush()
            self.assertIs(self.module._PRESENCE_OWNER.get(), active)
            self.assertIs(self.adapter._presence.groups[self.GROUP].owner, active)
            self.assertEqual(self.ops(), before)

    async def test_activated_unauthorized_sender_cannot_retarget(self):
        from unittest.mock import AsyncMock, Mock
        await self.adapter.on_processing_start(self.event())
        await self.flush()
        initial_ops = self.ops()
        self.adapter._should_run_turn = AsyncMock(return_value=True)
        for index, decision in enumerate((False, None)):
            check = Mock(return_value=decision)
            self.adapter._is_sender_authorized = check
            await self.adapter._handle_control_event(wire_event({
                "type": "inbound_message", "account_id_hex": self.ACCOUNT,
                "group_id_hex": self.GROUP, "message_id_hex": f"{index + 100:064x}",
                "sender_account_id_hex": "55" * 32, "text": "activated but unauthorized",
            }))
            await self.adapter._inbound_queue.join()
            await self.flush()
            check.assert_called_once_with("55" * 32, "group", self.GROUP)
            self.assertEqual(self.adapter._presence.groups[self.GROUP].target, self.MESSAGE)
            self.assertEqual(self.ops(), initial_ops)
        self.adapter._should_run_turn.assert_awaited()
        await self.adapter.disconnect()


if __name__ == "__main__":
    unittest.main()
