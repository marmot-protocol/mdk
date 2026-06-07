import asyncio
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass, field
from pathlib import Path


PLUGIN_DIR = Path(__file__).resolve().parents[1]
ADAPTER_PATH = PLUGIN_DIR / "adapter.py"


def install_fake_hermes_modules():
    gateway = types.ModuleType("gateway")
    gateway_platforms = types.ModuleType("gateway.platforms")
    gateway_base = types.ModuleType("gateway.platforms.base")
    gateway_config = types.ModuleType("gateway.config")

    class MessageType:
        TEXT = "text"

    @dataclass
    class SendResult:
        success: bool
        message_id: str | None = None
        error: str | None = None
        raw_response: object = None
        retryable: bool = False
        continuation_message_ids: tuple = ()

    @dataclass
    class SessionSource:
        platform: object
        chat_id: str
        chat_name: str | None = None
        chat_type: str = "dm"
        user_id: str | None = None
        user_name: str | None = None
        thread_id: str | None = None
        message_id: str | None = None

    @dataclass
    class MessageEvent:
        text: str
        message_type: object = MessageType.TEXT
        source: object = None
        raw_message: object = None
        message_id: str | None = None
        media_urls: list = field(default_factory=list)
        media_types: list = field(default_factory=list)

    class Platform:
        def __init__(self, value):
            self.value = value

    @dataclass
    class PlatformConfig:
        enabled: bool = True
        token: str | None = None
        api_key: str | None = None
        home_channel: object = None
        reply_to_mode: str = "first"
        gateway_restart_notification: bool = True
        extra: dict = field(default_factory=dict)

    class BasePlatformAdapter:
        def __init__(self, config, platform):
            self.config = config
            self.platform = platform
            self._running = False
            self.events = []

        @property
        def enforces_own_access_policy(self):
            return False

        def _mark_connected(self):
            self._running = True

        def _mark_disconnected(self):
            self._running = False

        def build_source(self, **kwargs):
            return SessionSource(platform=self.platform, **kwargs)

        async def handle_message(self, event):
            self.events.append(event)

    gateway_base.BasePlatformAdapter = BasePlatformAdapter
    gateway_base.MessageEvent = MessageEvent
    gateway_base.MessageType = MessageType
    gateway_base.SendResult = SendResult
    gateway_config.Platform = Platform
    gateway_config.PlatformConfig = PlatformConfig

    sys.modules["gateway"] = gateway
    sys.modules["gateway.platforms"] = gateway_platforms
    sys.modules["gateway.platforms.base"] = gateway_base
    sys.modules["gateway.config"] = gateway_config
    return PlatformConfig


def load_adapter_module():
    for name in [
        "marmot_hermes_adapter",
        "gateway",
        "gateway.platforms",
        "gateway.platforms.base",
        "gateway.config",
    ]:
        sys.modules.pop(name, None)
    install_fake_hermes_modules()
    spec = importlib.util.spec_from_file_location("marmot_hermes_adapter", ADAPTER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["marmot_hermes_adapter"] = module
    spec.loader.exec_module(module)
    return module


async def read_json_line(reader):
    raw = await reader.readline()
    return json.loads(raw.decode("utf-8"))


async def write_json_line(writer, value):
    writer.write(json.dumps(value).encode("utf-8") + b"\n")
    await writer.drain()


class AgentControlClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter = load_adapter_module()
        self.tempdir = tempfile.TemporaryDirectory()
        self.socket_path = str(Path(self.tempdir.name) / "dm-agent.sock")
        self.server = None

    async def asyncTearDown(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        self.tempdir.cleanup()

    async def start_server(self, handler):
        self.server = await asyncio.start_unix_server(handler, path=self.socket_path)

    async def test_send_final_writes_protocol_envelope_and_reads_response(self):
        requests = []

        async def handler(reader, writer):
            request = await read_json_line(reader)
            requests.append(request)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "final_sent",
                    "message_ids_hex": ["aa", "bb"],
                },
            )
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        response = await client.send_final(
            "11" * 32,
            "22" * 32,
            "hello",
            reply_to_message_id_hex="33" * 32,
        )

        self.assertEqual(response["type"], "final_sent")
        self.assertEqual(response["message_ids_hex"], ["aa", "bb"])
        self.assertEqual(requests[0]["marmot_agent_control"], "marmot.agent-control.v1")
        self.assertEqual(requests[0]["type"], "send_final")
        self.assertEqual(requests[0]["account_id_hex"], "11" * 32)
        self.assertEqual(requests[0]["group_id_hex"], "22" * 32)
        self.assertEqual(requests[0]["reply_to_message_id_hex"], "33" * 32)

    async def test_inbound_subscription_requires_ack_then_yields_events(self):
        async def handler(reader, writer):
            request = await read_json_line(reader)
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "ack",
                },
            )
            await write_json_line(
                writer,
                {
                    "marmot_agent_control": "marmot.agent-control.v1",
                    "id": request["id"],
                    "type": "inbound_message",
                    "account_id_hex": "11" * 32,
                    "group_id_hex": "22" * 32,
                    "message_id_hex": "33" * 32,
                    "sender_account_id_hex": "44" * 32,
                    "text": "ping",
                },
            )
            await writer.drain()
            writer.close()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path)

        events = client.inbound_events(account_id_hex="11" * 32)
        event = await anext(events)
        await events.aclose()

        self.assertEqual(event["type"], "inbound_message")
        self.assertEqual(event["text"], "ping")

    async def test_request_timeout_is_retryable_agent_control_error(self):
        release = asyncio.Event()

        async def handler(reader, writer):
            await read_json_line(reader)
            await release.wait()
            writer.close()
            await writer.wait_closed()

        await self.start_server(handler)
        client = self.adapter.MarmotAgentControlClient(self.socket_path, request_timeout=0.01)

        try:
            with self.assertRaises(self.adapter.AgentControlError) as raised:
                await client.account_list()
        finally:
            release.set()
            await asyncio.sleep(0)

        self.assertEqual(raised.exception.code, "timeout")
        self.assertTrue(raised.exception.retryable)

    async def test_write_timeout_is_retryable_agent_control_error(self):
        class SlowWriter:
            def write(self, _frame):
                pass

            async def drain(self):
                await asyncio.sleep(1)

        client = self.adapter.MarmotAgentControlClient(self.socket_path, request_timeout=0.01)

        with self.assertRaises(self.adapter.AgentControlError) as raised:
            await client._write_envelope(
                SlowWriter(),
                {"type": "account_list"},
                request_id="req-timeout",
            )

        self.assertEqual(raised.exception.code, "timeout")
        self.assertTrue(raised.exception.retryable)


class TranscriptTests(unittest.TestCase):
    def setUp(self):
        self.adapter = load_adapter_module()

    def test_transcript_matches_rust_status_hash_fixture(self):
        transcript = self.adapter.AgentTextStreamTranscript(
            stream_id_hex="11" * 32,
            start_message_id_hex="22" * 32,
            chunk_bytes=1024,
        )

        transcript.append_text("hello")
        transcript.append_status("thinking")

        self.assertEqual(transcript.chunk_count, 2)
        self.assertEqual(
            transcript.hash_hex,
            "455be8152d19c352ee9f982274cf5d9b6b7d929a4f198be4ef05f75328921b32",
        )

    def test_append_only_delta_rejects_replacements(self):
        state = self.adapter.AppendOnlyTextState()

        self.assertEqual(state.suffix_for("hello"), "hello")
        self.assertEqual(state.suffix_for("hello world"), " world")
        with self.assertRaises(self.adapter.NonAppendOnlyUpdate):
            state.suffix_for("goodbye")


class MarmotPlatformAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter_module = load_adapter_module()
        self.config_cls = sys.modules["gateway.config"].PlatformConfig

    async def test_chat_info_uses_marmot_group_metadata(self):
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=object(),
        )

        info = await adapter.get_chat_info("22" * 32)

        self.assertEqual(
            info,
            {
                "name": "Marmot 222222222222",
                "type": "group",
                "id": "22" * 32,
            },
        )

    async def test_invalid_explicit_account_hex_is_rejected(self):
        with self.assertRaisesRegex(
            self.adapter_module.AgentControlError,
            "MARMOT_ACCOUNT_ID_HEX must be hexadecimal",
        ):
            self.adapter_module.MarmotPlatformAdapter(
                self.config_cls(extra={"account_id_hex": "not-hex"}),
                client=object(),
            )

    async def test_send_maps_hermes_chat_to_marmot_send_final(self):
        class FakeClient:
            def __init__(self):
                self.calls = []

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.calls.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {
                    "type": "final_sent",
                    "message_ids_hex": ["aa", "bb", "cc"],
                }

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=fake_client,
        )

        result = await adapter.send(
            chat_id="22" * 32,
            content="pong",
            reply_to="33" * 32,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.message_id, "cc")
        self.assertEqual(result.continuation_message_ids, ("aa", "bb"))
        self.assertEqual(fake_client.calls, [("11" * 32, "22" * 32, "pong", "33" * 32)])

    async def test_inbound_event_is_forwarded_to_hermes_message_event(self):
        events = [
            {
                "type": "inbound_message",
                "account_id_hex": "11" * 32,
                "group_id_hex": "22" * 32,
                "message_id_hex": "33" * 32,
                "sender_account_id_hex": "44" * 32,
                "text": "ping",
            }
        ]

        class FakeClient:
            async def inbound_events(self, account_id_hex=None, group_id_hex=None):
                for event in events:
                    yield event

        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(extra={"account_id_hex": "11" * 32}),
            client=FakeClient(),
        )

        await adapter._consume_inbound_once()

        self.assertEqual(len(adapter.events), 1)
        event = adapter.events[0]
        self.assertEqual(event.text, "ping")
        self.assertEqual(event.message_id, "33" * 32)
        self.assertEqual(event.source.chat_id, "22" * 32)
        self.assertEqual(event.source.chat_type, "group")
        self.assertEqual(event.source.user_id, "44" * 32)

    async def test_progressive_edit_stream_finalizes_then_sends_durable_message(self):
        class FakeClient:
            def __init__(self):
                self.stream_appends = []
                self.stream_finalizes = []
                self.final_sends = []

            async def stream_begin(self, account_id_hex, group_id_hex, *, stream_id_hex=None, quic_candidates=()):
                self.stream_begin_args = (account_id_hex, group_id_hex, tuple(quic_candidates))
                return {
                    "type": "stream_begun",
                    "stream_id_hex": "55" * 32,
                    "start_message_id_hex": "66" * 32,
                    "quic_candidates": list(quic_candidates),
                }

            async def stream_append(self, stream_id_hex, append_text):
                self.stream_appends.append((stream_id_hex, append_text))
                return {"type": "ack"}

            async def stream_finalize(self, stream_id_hex, final_text, transcript_hash_hex, chunk_count):
                self.stream_finalizes.append((stream_id_hex, final_text, transcript_hash_hex, chunk_count))
                return {
                    "type": "stream_finalized",
                    "stream_id_hex": stream_id_hex,
                    "message_ids_hex": ["77" * 32],
                }

            async def send_final(self, account_id_hex, group_id_hex, text, reply_to_message_id_hex=None):
                self.final_sends.append((account_id_hex, group_id_hex, text, reply_to_message_id_hex))
                return {
                    "type": "final_sent",
                    "message_ids_hex": ["88" * 32],
                }

        fake_client = FakeClient()
        adapter = self.adapter_module.MarmotPlatformAdapter(
            self.config_cls(
                extra={
                    "account_id_hex": "11" * 32,
                    "quic_candidates": ["quic://127.0.0.1:4433"],
                }
            ),
            client=fake_client,
        )

        first = await adapter.send("22" * 32, "hel\u2589")
        self.assertTrue(first.success)
        self.assertEqual(first.message_id, "marmot-stream:" + "55" * 32)

        edited = await adapter.edit_message("22" * 32, first.message_id, "hello\u2589")
        self.assertTrue(edited.success)

        final = await adapter.edit_message("22" * 32, first.message_id, "hello", finalize=True)

        self.assertTrue(final.success)
        self.assertEqual(final.message_id, "88" * 32)
        self.assertEqual(
            fake_client.stream_appends,
            [("55" * 32, "hel"), ("55" * 32, "lo")],
        )
        self.assertEqual(len(fake_client.stream_finalizes), 1)
        self.assertEqual(fake_client.stream_finalizes[0][1], "hello")
        self.assertEqual(fake_client.stream_finalizes[0][3], 2)
        self.assertEqual(fake_client.final_sends, [("11" * 32, "22" * 32, "hello", None)])


if __name__ == "__main__":
    unittest.main()
